"""Semantic retrieval engine for AegisOps Copilot.

Provides persistent vector search, metadata filtering, similarity thresholds,
and full source attribution across runbooks, policies, documentation, and incidents.

CRITICAL SAFETY INVARIANT:
Vector similarity scores are strictly for retrieval and informational context.
Vector similarity MUST NEVER be used to authorize or execute a remediation action.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence
import chromadb
from chromadb.api import ClientAPI
from sqlalchemy import select

from aegisops.config import CHROMA_DIR, COPILOT_DB_PATH, EMBEDDING_PROVIDER, SOURCE_CSV_DIR
from aegisops.copilot.documents import (
    IndexableDocument,
    incident_to_summary_document,
    markdown_to_documents,
    policy_to_document,
    runbook_to_document,
)
from aegisops.copilot.embeddings import get_embedding_function
from aegisops.copilot.ingestion import compute_dataset_hash, get_readonly_sessionmaker, ingest_dataset
from aegisops.copilot.schema import DocArtifact, KBIncident, KBPolicy, KBRunbook, KnowledgeMetadata

COLLECTION_NAME = "aegisops_copilot_kb"


@dataclass
class SearchResult:
    doc_id: str
    text: str
    metadata: dict[str, Any]
    distance: float
    similarity: float
    source_type: str
    source_filename: str
    source_record_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _build_where_clause(filters: dict[str, Any]) -> dict[str, Any] | None:
    active = {k: v for k, v in filters.items() if v is not None and v != ""}
    if not active:
        return None
    if len(active) == 1:
        return active
    return {"$and": [{k: v} for k, v in active.items()]}


class SemanticIndex:
    """Manages persistent ChromaDB vector store and semantic search operations."""

    def __init__(
        self,
        chroma_dir: Path | str | None = None,
        embedding_provider: str | None = None,
        client: ClientAPI | None = None,
    ):
        self.chroma_dir = Path(chroma_dir) if chroma_dir else CHROMA_DIR
        self.embedding_provider = embedding_provider or EMBEDDING_PROVIDER
        self.embedding_fn = get_embedding_function(self.embedding_provider)

        if client is not None:
            self.client = client
        else:
            self.chroma_dir.mkdir(parents=True, exist_ok=True)
            self.client = chromadb.PersistentClient(path=str(self.chroma_dir.resolve()))

        self.collection = self.client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=self.embedding_fn,
            metadata={"description": "AegisOps Copilot Semantic Knowledge Index"},
        )

    def count(self) -> int:
        return self.collection.count()

    def build_index(
        self,
        source_dir: Path | str | None = None,
        db_path: Path | str | None = None,
        force: bool = False,
        include_incidents: bool = True,
    ) -> dict[str, Any]:
        source_path = Path(source_dir) if source_dir else SOURCE_CSV_DIR
        target_db = Path(db_path) if db_path else COPILOT_DB_PATH

        # Ensure sqlite knowledge base exists
        if not target_db.exists():
            ingest_dataset(source_dir=source_path, db_path=target_db, force=False)

        dataset_hash, _ = compute_dataset_hash(source_path)

        # Check existing collection metadata for cache hit
        meta_id = "meta:index_state"
        existing_meta = None
        if not force and self.count() > 0:
            try:
                res = self.collection.get(ids=[meta_id], include=["metadatas"])
                if res and res["metadatas"] and len(res["metadatas"]) > 0:
                    existing_meta = res["metadatas"][0]
                    if (
                        existing_meta
                        and existing_meta.get("dataset_hash") == dataset_hash
                        and existing_meta.get("embedding_provider") == self.embedding_provider
                    ):
                        return {
                            "status": "cached",
                            "doc_count": self.count() - 1,  # exclude meta doc
                            "dataset_hash": dataset_hash,
                            "embedding_provider": self.embedding_provider,
                        }
            except Exception:
                pass

        # Load records from SQLite knowledge base
        SessionLocal = get_readonly_sessionmaker(target_db)
        docs_to_index: list[IndexableDocument] = []

        with SessionLocal() as s:
            # 1. Runbooks
            for rb in s.scalars(select(KBRunbook)):
                docs_to_index.append(
                    runbook_to_document(
                        {
                            "runbook_id": rb.runbook_id,
                            "name": rb.name,
                            "incident_type": rb.incident_type,
                            "risk_level": rb.risk_level,
                            "allowlisted_action": rb.allowlisted_action,
                            "verification_rule": rb.verification_rule,
                            "compensation_action": rb.compensation_action,
                            "service_category": rb.service_category,
                            "max_attempts": rb.max_attempts,
                            "timeout_seconds": rb.timeout_seconds,
                        }
                    )
                )

            # 2. Policies
            for pol in s.scalars(select(KBPolicy)):
                docs_to_index.append(
                    policy_to_document(
                        {
                            "policy_id": pol.policy_id,
                            "runbook_id": pol.runbook_id,
                            "risk_level": pol.risk_level,
                            "auto_execute": pol.auto_execute,
                            "approval_required": pol.approval_required,
                            "approval_role": pol.approval_role,
                            "allowed_environment": pol.allowed_environment,
                            "max_attempts": pol.max_attempts,
                            "timeout_seconds": pol.timeout_seconds,
                            "cooldown_seconds": pol.cooldown_seconds,
                            "rollback_required": pol.rollback_required,
                            "change_record_required": pol.change_record_required,
                            "kill_switch_enforced": pol.kill_switch_enforced,
                            "policy_version": pol.policy_version,
                        }
                    )
                )

            # 3. Documentation (README)
            for doc in s.scalars(select(DocArtifact)):
                docs_to_index.extend(
                    markdown_to_documents(content=doc.content, filename=doc.filename)
                )

            # 4. Incident summaries (optional / capped for semantic overview)
            if include_incidents:
                for inc in s.scalars(select(KBIncident)):
                    docs_to_index.append(
                        incident_to_summary_document(
                            {
                                "incident_id": inc.incident_id,
                                "environment": inc.environment,
                                "service_id": inc.service_id,
                                "incident_type": inc.incident_type,
                                "severity": inc.severity,
                                "risk_level": inc.risk_level,
                                "anomaly_score": inc.anomaly_score,
                                "runbook_id": inc.runbook_id,
                                "policy_id": inc.policy_id,
                                "policy_decision": inc.policy_decision,
                                "approval_status": inc.approval_status,
                                "execution_status": inc.execution_status,
                                "verification_status": inc.verification_status,
                                "rollback_status": inc.rollback_status,
                                "final_status": inc.final_status,
                                "data_split": inc.data_split,
                            }
                        )
                    )

        # Batch upsert into Chroma
        batch_size = 250
        for i in range(0, len(docs_to_index), batch_size):
            chunk = docs_to_index[i : i + batch_size]
            self.collection.upsert(
                ids=[d.doc_id for d in chunk],
                documents=[d.text for d in chunk],
                metadatas=[d.metadata for d in chunk],
            )

        # Save metadata record
        self.collection.upsert(
            ids=[meta_id],
            documents=["AegisOps Index State and Integrity Record"],
            metadatas=[
                {
                    "source_type": "index_metadata",
                    "dataset_hash": dataset_hash,
                    "embedding_provider": self.embedding_provider,
                    "doc_count": len(docs_to_index),
                    "indexed_at": datetime.now(timezone.utc).isoformat(),
                }
            ],
        )

        return {
            "status": "rebuilt",
            "doc_count": len(docs_to_index),
            "dataset_hash": dataset_hash,
            "embedding_provider": self.embedding_provider,
        }

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        min_similarity: float = 0.0,
        where: dict[str, Any] | None = None,
    ) -> list[SearchResult]:
        if not query.strip():
            return []

        # Avoid returning the index_metadata document
        safe_where: dict[str, Any]
        if where:
            safe_where = {"$and": [where, {"source_type": {"$ne": "index_metadata"}}]}
        else:
            safe_where = {"source_type": {"$ne": "index_metadata"}}

        total = self.count()
        if total == 0:
            return []

        actual_k = min(top_k, total)
        res = self.collection.query(
            query_texts=[query],
            n_results=actual_k,
            where=safe_where,
            include=["documents", "metadatas", "distances"],
        )

        results: list[SearchResult] = []
        if not res or not res["ids"] or not res["ids"][0]:
            return results

        ids = res["ids"][0]
        docs = res["documents"][0] if res["documents"] else [""] * len(ids)
        metas = res["metadatas"][0] if res["metadatas"] else [{}] * len(ids)
        dists = res["distances"][0] if res["distances"] else [0.0] * len(ids)

        for doc_id, text_val, meta_val, dist in zip(ids, docs, metas, dists):
            meta = meta_val or {}
            # Normalized similarity score (1 / (1 + distance))
            similarity = 1.0 / (1.0 + max(0.0, float(dist)))
            if similarity < min_similarity:
                continue

            results.append(
                SearchResult(
                    doc_id=doc_id,
                    text=text_val,
                    metadata=meta,
                    distance=float(dist),
                    similarity=round(similarity, 4),
                    source_type=str(meta.get("source_type", "")),
                    source_filename=str(meta.get("source_filename", "")),
                    source_record_id=str(meta.get("source_record_id", "")),
                )
            )

        return results

    def retrieve_runbooks(
        self,
        query: str,
        top_k: int = 5,
        min_similarity: float = 0.0,
        incident_type: str | None = None,
        risk_level: str | None = None,
    ) -> list[SearchResult]:
        """Retrieve runbook procedures matching query."""
        filters = {"source_type": "runbook"}
        if incident_type:
            filters["incident_type"] = incident_type
        if risk_level:
            filters["risk_level"] = risk_level
        return self.retrieve(
            query=query,
            top_k=top_k,
            min_similarity=min_similarity,
            where=_build_where_clause(filters),
        )

    def retrieve_policies(
        self,
        query: str,
        top_k: int = 5,
        min_similarity: float = 0.0,
        runbook_id: str | None = None,
        risk_level: str | None = None,
    ) -> list[SearchResult]:
        """Retrieve policies matching query."""
        filters = {"source_type": "policy"}
        if runbook_id:
            filters["runbook_id"] = runbook_id
        if risk_level:
            filters["risk_level"] = risk_level
        return self.retrieve(
            query=query,
            top_k=top_k,
            min_similarity=min_similarity,
            where=_build_where_clause(filters),
        )

    def retrieve_documentation(
        self, query: str, top_k: int = 5, min_similarity: float = 0.0
    ) -> list[SearchResult]:
        """Retrieve schema/README documentation matching query."""
        return self.retrieve(
            query=query,
            top_k=top_k,
            min_similarity=min_similarity,
            where={"source_type": "documentation"},
        )

    def retrieve_incident_summaries(
        self,
        query: str,
        top_k: int = 5,
        min_similarity: float = 0.0,
        incident_type: str | None = None,
        environment: str | None = None,
        final_status: str | None = None,
    ) -> list[SearchResult]:
        """Retrieve historically similar incident summaries."""
        filters = {"source_type": "incident_summary"}
        if incident_type:
            filters["incident_type"] = incident_type
        if environment:
            filters["environment"] = environment
        if final_status:
            filters["final_status"] = final_status
        return self.retrieve(
            query=query,
            top_k=top_k,
            min_similarity=min_similarity,
            where=_build_where_clause(filters),
        )

    def authorize_remediation_action(self, *args, **kwargs):
        """Guardrail method: strictly refuses execution authorization via vector retrieval."""
        raise RuntimeError(
            "CRITICAL SAFETY VIOLATION: Vector similarity cannot authorize remediation actions. "
            "Remediation decisions must be performed strictly by aegisops.policy."
        )

