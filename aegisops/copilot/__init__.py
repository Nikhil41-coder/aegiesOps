"""AegisOps Copilot — Safe Operational Assistant for AegisOps."""

from aegisops.copilot.documents import IndexableDocument
from aegisops.copilot.embeddings import FastDeterministicEmbeddingFunction, get_embedding_function
from aegisops.copilot.engine import AegisOpsCopilot
from aegisops.copilot.ingestion import (
    IngestionReport,
    get_readonly_engine,
    get_readonly_sessionmaker,
    ingest_dataset,
)
from aegisops.copilot.models import Citation, CopilotResponse, EvidenceItem, QueryClassification
from aegisops.copilot.query import (
    get_full_incident_dossier,
    get_incident_actions,
    get_incident_approvals,
    get_incident_audits,
    get_incident_metrics,
    get_incident_record,
    get_policy_by_runbook,
    get_policy_record,
    get_runbook_record,
)
from aegisops.copilot.retriever import SearchResult, SemanticIndex

__all__ = [
    "AegisOpsCopilot",
    "Citation",
    "CopilotResponse",
    "EvidenceItem",
    "FastDeterministicEmbeddingFunction",
    "IndexableDocument",
    "IngestionReport",
    "QueryClassification",
    "SearchResult",
    "SemanticIndex",
    "get_embedding_function",
    "get_full_incident_dossier",
    "get_incident_actions",
    "get_incident_approvals",
    "get_incident_audits",
    "get_incident_metrics",
    "get_incident_record",
    "get_policy_by_runbook",
    "get_policy_record",
    "get_readonly_engine",
    "get_readonly_sessionmaker",
    "get_runbook_record",
    "ingest_dataset",
]
