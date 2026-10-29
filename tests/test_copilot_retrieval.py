"""Automated tests for AegisOps Copilot semantic retrieval layer."""

from pathlib import Path
import shutil
import pytest
from aegisops.config import CHROMA_DIR, COPILOT_DB_PATH, SOURCE_CSV_DIR
from aegisops.copilot.documents import (
    IndexableDocument,
    markdown_to_documents,
    policy_to_document,
    runbook_to_document,
)
from aegisops.copilot.retriever import SemanticIndex


@pytest.fixture(scope="module")
def shared_index(tmp_path_factory):
    """Module-scoped persistent index initialized with the actual repository dataset."""
    test_chroma = tmp_path_factory.mktemp("chroma_shared")
    test_db = tmp_path_factory.mktemp("db_shared") / "copilot_knowledge.db"

    # Use fast deterministic embedder for fast, reproducible, offline tests
    index = SemanticIndex(chroma_dir=test_chroma, embedding_provider="fast")
    res = index.build_index(
        source_dir=SOURCE_CSV_DIR,
        db_path=test_db,
        force=True,
        include_incidents=True,
    )
    assert res["status"] == "rebuilt"
    assert res["doc_count"] > 20
    return index, test_chroma, test_db


def test_runbook_lookup_exact_wording(shared_index):
    index, _, _ = shared_index

    # 1. Exact runbook title
    results = index.retrieve_runbooks("Restart isolated background worker", top_k=3)
    assert len(results) > 0
    top = results[0]
    assert top.source_record_id == "RB001"
    assert top.metadata["runbook_id"] == "RB001"
    assert "restart_worker" in top.text
    assert top.source_filename == "runbooks.csv"
    assert top.source_type == "runbook"

    # 2. Exact action name
    res_cache = index.retrieve_runbooks("purge_approved_cache", top_k=3)
    assert len(res_cache) > 0
    assert any(r.source_record_id == "RB002" for r in res_cache)


def test_runbook_lookup_paraphrased_wording(shared_index):
    index, _, _ = shared_index

    # Paraphrased query for disk pressure
    results = index.retrieve_runbooks("clean up application cache when disk is full", top_k=3)
    assert len(results) > 0
    assert any(r.source_record_id == "RB002" for r in results)

    # Paraphrased query for background worker
    worker_res = index.retrieve_runbooks("worker job crashed need to restart it", top_k=3)
    assert len(worker_res) > 0
    assert any(r.source_record_id == "RB001" for r in worker_res)


def test_policy_retrieval(shared_index):
    index, _, _ = shared_index

    # Retrieve policy by runbook ID
    res = index.retrieve_policies("What policy governs RB002?", runbook_id="RB002", top_k=1)
    assert len(res) == 1
    pol = res[0]
    assert pol.metadata["policy_id"] == "POL_RB002"
    assert pol.metadata["runbook_id"] == "RB002"
    assert pol.source_filename == "policies.csv"
    assert pol.source_type == "policy"
    assert "approval_role" in pol.metadata

    # Retrieve high-risk policies
    high_res = index.retrieve_policies("High risk policies requiring incident commander", risk_level="high", top_k=5)
    assert len(high_res) > 0
    for r in high_res:
        assert r.metadata["risk_level"] == "high"


def test_documentation_retrieval(shared_index):
    index, _, _ = shared_index

    # Query documentation / README sections
    docs = index.retrieve_documentation("synthetic dataset relationships and files", top_k=3)
    assert len(docs) > 0
    assert any(d.source_filename == "README.md" for d in docs)
    assert any(d.source_type == "documentation" for d in docs)


def test_missing_source_records(shared_index):
    index, _, _ = shared_index

    # Nonsense query with high similarity threshold
    results = index.retrieve_runbooks(
        "superconducting quantum teleporter tachyon flux emitter",
        top_k=5,
        min_similarity=0.95,
    )
    assert len(results) == 0


def test_metadata_and_source_attribution(shared_index):
    index, _, _ = shared_index

    results = index.retrieve("worker_not_running", top_k=5)
    assert len(results) > 0
    for r in results:
        assert r.doc_id != ""
        assert r.source_type in ("runbook", "policy", "documentation", "incident_summary")
        assert r.source_filename in ("runbooks.csv", "policies.csv", "README.md", "incidents.csv")
        assert r.source_record_id != ""
        assert 0.0 <= r.similarity <= 1.0
        assert r.distance >= 0.0


def test_repeated_indexing(tmp_path):
    chroma_dir = tmp_path / "repeated_chroma"
    db_path = tmp_path / "repeated_db.db"

    index = SemanticIndex(chroma_dir=chroma_dir, embedding_provider="fast")

    # First build
    res1 = index.build_index(source_dir=SOURCE_CSV_DIR, db_path=db_path, force=True, include_incidents=False)
    assert res1["status"] == "rebuilt"
    count1 = index.count()

    # Second build without force -> should be cached
    res2 = index.build_index(source_dir=SOURCE_CSV_DIR, db_path=db_path, force=False, include_incidents=False)
    assert res2["status"] == "cached"
    assert index.count() == count1

    # Third build with force=True -> updates in-place with stable IDs, no duplicates
    res3 = index.build_index(source_dir=SOURCE_CSV_DIR, db_path=db_path, force=True, include_incidents=False)
    assert res3["status"] == "rebuilt"
    assert index.count() == count1


def test_index_persistence_across_restarts(tmp_path):
    persist_dir = tmp_path / "persist_chroma"
    db_path = tmp_path / "persist_db.db"

    # Step 1: create and build
    idx1 = SemanticIndex(chroma_dir=persist_dir, embedding_provider="fast")
    idx1.build_index(source_dir=SOURCE_CSV_DIR, db_path=db_path, force=True, include_incidents=False)
    c1 = idx1.count()
    del idx1

    # Step 2: reload from disk in a fresh instance
    idx2 = SemanticIndex(chroma_dir=persist_dir, embedding_provider="fast")
    assert idx2.count() == c1

    # Query immediately without re-indexing
    hits = idx2.retrieve_runbooks("Restart isolated background worker", top_k=1)
    assert len(hits) == 1
    assert hits[0].source_record_id == "RB001"


def test_index_rebuilding_after_source_change(tmp_path):
    custom_src = tmp_path / "custom_src"
    custom_src.mkdir()
    chroma_dir = tmp_path / "change_chroma"
    db_path = tmp_path / "change_db.db"

    # Copy files
    for f in ("README.md", "runbooks.csv", "policies.csv", "incidents.csv", "metrics.csv", "approvals.csv", "execution_actions.csv", "audit_events.csv"):
        src = SOURCE_CSV_DIR / f
        if src.exists():
            shutil.copy(src, custom_src / f)

    idx = SemanticIndex(chroma_dir=chroma_dir, embedding_provider="fast")
    res1 = idx.build_index(source_dir=custom_src, db_path=db_path, force=False, include_incidents=False)
    assert res1["status"] == "rebuilt"

    # Modify runbook text
    rb_path = custom_src / "runbooks.csv"
    txt = rb_path.read_text(encoding="utf-8")
    rb_path.write_text(txt.replace("Clear allowlisted application cache", "Purge designated ephemeral cache records"), encoding="utf-8")

    # Ingest source changes into sqlite first
    from aegisops.copilot.ingestion import ingest_dataset
    ingest_dataset(source_dir=custom_src, db_path=db_path, force=False)

    # Re-run index build without force: hash change should trigger automatic rebuild
    res2 = idx.build_index(source_dir=custom_src, db_path=db_path, force=False, include_incidents=False)
    assert res2["status"] == "rebuilt"

    # Search for new wording
    hits = idx.retrieve_runbooks("Purge designated ephemeral cache records", top_k=1)
    assert len(hits) == 1
    assert "Purge designated ephemeral cache" in hits[0].text


def test_retrieval_from_conflicting_or_incomplete_documents():
    """Verify document conversion handles incomplete or sparse rows cleanly."""
    incomplete_row = {
        "runbook_id": "RB_SPARSE",
        "name": "Partial Runbook",
        "incident_type": "unknown_anomaly",
    }
    doc = runbook_to_document(incomplete_row)
    assert doc.doc_id == "runbook:RB_SPARSE"
    assert doc.metadata["risk_level"] == ""
    assert doc.metadata["source_filename"] == "runbooks.csv"

    # Markdown with missing headers
    plain_text = "This is a plain document without any markdown headers."
    docs = markdown_to_documents(plain_text, filename="custom.md")
    assert len(docs) == 1
    assert docs[0].doc_id.startswith("doc:custom.md:")


def test_vector_similarity_cannot_authorize(shared_index):
    index, _, _ = shared_index

    # Guardrail test: attempting to authorize through similarity raises RuntimeError
    with pytest.raises(RuntimeError) as exc_info:
        index.authorize_remediation_action("RB001", 0.99)
    assert "CRITICAL SAFETY VIOLATION" in str(exc_info.value)

