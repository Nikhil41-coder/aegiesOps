"""Tests for AegisOps Copilot dataset ingestion layer."""

import csv
from pathlib import Path
import shutil
import pytest
from sqlalchemy import select, text
from aegisops.config import COPILOT_DB_PATH, SOURCE_CSV_DIR
from aegisops.copilot.ingestion import (
    EXPECTED_FILES,
    compute_dataset_hash,
    get_readonly_engine,
    get_readonly_sessionmaker,
    ingest_dataset,
)
from aegisops.copilot.schema import (
    DocArtifact,
    KBAuditEvent,
    KBApproval,
    KBExecutionAction,
    KBIncident,
    KBMetric,
    KBPolicy,
    KBRunbook,
    KnowledgeMetadata,
)


@pytest.fixture(scope="module")
def ingested_db(tmp_path_factory):
    """Module-scoped fixture that ingests the actual repo dataset into a test db."""
    test_db = tmp_path_factory.mktemp("copilot_db") / "test_knowledge.db"
    report = ingest_dataset(source_dir=SOURCE_CSV_DIR, db_path=test_db, force=True)
    assert report.success, f"Fixture ingestion failed: {report.summary()}"
    return test_db, report


def test_correct_row_counts(ingested_db):
    test_db, report = ingested_db
    expected = {
        "README.md": 1,
        "runbooks.csv": 10,
        "policies.csv": 10,
        "incidents.csv": 3000,
        "metrics.csv": 3000,
        "approvals.csv": 1633,
        "execution_actions.csv": 2020,
        "audit_events.csv": 19644,
    }
    for file_name, count in expected.items():
        assert report.imported_rows.get(file_name) == count, f"Mismatch in {file_name}"
        assert report.input_rows.get(file_name) == count, f"Input mismatch in {file_name}"

    assert sum(report.imported_rows.values()) == 29318

    # Query DB to confirm actual rows match
    SessionLocal = get_readonly_sessionmaker(test_db)
    with SessionLocal() as s:
        assert len(list(s.scalars(select(KBRunbook)))) == 10
        assert len(list(s.scalars(select(KBPolicy)))) == 10
        assert len(list(s.scalars(select(KBIncident)))) == 3000
        assert len(list(s.scalars(select(KBMetric)))) == 3000
        assert len(list(s.scalars(select(KBApproval)))) == 1633
        assert len(list(s.scalars(select(KBExecutionAction)))) == 2020
        assert len(list(s.scalars(select(KBAuditEvent)))) == 19644
        assert len(list(s.scalars(select(DocArtifact)))) == 1


def test_correct_relationships(ingested_db):
    test_db, report = ingested_db
    assert len(report.relationship_errors) == 0

    SessionLocal = get_readonly_sessionmaker(test_db)
    with SessionLocal() as s:
        rb_ids = set(s.scalars(select(KBRunbook.runbook_id)))
        pol_ids = set(s.scalars(select(KBPolicy.policy_id)))
        inc_ids = set(s.scalars(select(KBIncident.incident_id)))

        # Policies reference valid runbooks
        for pol in s.scalars(select(KBPolicy)):
            assert pol.runbook_id in rb_ids

        # Incidents reference valid runbooks and policies
        for inc in s.scalars(select(KBIncident)):
            if inc.runbook_id:
                assert inc.runbook_id in rb_ids
            if inc.policy_id:
                assert inc.policy_id in pol_ids

        # Metrics reference valid incidents
        for met in s.scalars(select(KBMetric)):
            assert met.incident_id in inc_ids

        # Approvals reference valid incidents and policies
        for app in s.scalars(select(KBApproval)):
            assert app.incident_id in inc_ids
            assert app.policy_id in pol_ids

        # Actions reference valid incidents and runbooks
        for act in s.scalars(select(KBExecutionAction)):
            assert act.incident_id in inc_ids
            assert act.runbook_id in rb_ids

        # Audit events reference valid incidents
        for evt in s.scalars(select(KBAuditEvent)):
            assert evt.incident_id in inc_ids


def test_data_preservation_and_provenance(ingested_db):
    test_db, _ = ingested_db
    SessionLocal = get_readonly_sessionmaker(test_db)
    with SessionLocal() as s:
        # Check source_file is populated
        sample_inc = s.scalars(select(KBIncident)).first()
        assert sample_inc is not None
        assert sample_inc.source_file.endswith("incidents.csv")
        assert sample_inc.data_split in ("train", "val", "test")
        assert sample_inc.detected_at.startswith("2026-")

        # Check metadata
        meta = s.scalars(select(KnowledgeMetadata)).first()
        assert meta is not None
        assert len(meta.dataset_hash) == 64
        assert "incidents.csv" in meta.source_file_hashes


def test_repeated_ingestion_and_caching(tmp_path):
    test_db = tmp_path / "repeated_knowledge.db"

    # First run: force=True
    rep1 = ingest_dataset(source_dir=SOURCE_CSV_DIR, db_path=test_db, force=True)
    assert rep1.success is True
    assert rep1.cached is False
    total_1 = sum(rep1.imported_rows.values())

    # Second run: force=False (should be cached)
    rep2 = ingest_dataset(source_dir=SOURCE_CSV_DIR, db_path=test_db, force=False)
    assert rep2.success is True
    assert rep2.cached is True

    # Third run: force=True (should re-ingest without duplicating rows)
    rep3 = ingest_dataset(source_dir=SOURCE_CSV_DIR, db_path=test_db, force=True)
    assert rep3.success is True
    assert rep3.cached is False
    total_3 = sum(rep3.imported_rows.values())
    assert total_1 == total_3

    SessionLocal = get_readonly_sessionmaker(test_db)
    with SessionLocal() as s:
        assert len(list(s.scalars(select(KBIncident)))) == 3000


def test_invalid_and_missing_identifiers(tmp_path):
    bad_dir = tmp_path / "bad_data"
    bad_dir.mkdir()
    test_db = tmp_path / "bad_test.db"

    # Create runbooks.csv with one good row
    with open(bad_dir / "runbooks.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["runbook_id", "incident_type", "name", "risk_level", "allowlisted_action", "verification_rule", "compensation_action", "service_category", "max_attempts", "timeout_seconds"])
        writer.writerow(["RB001", "disk_pressure", "Purge cache", "low", "purge", "rule", "comp", "storage", "1", "300"])

    # Create policies.csv with an invalid foreign key reference to unknown runbook
    with open(bad_dir / "policies.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["policy_id", "runbook_id", "risk_level", "auto_execute", "approval_required", "approval_role", "allowed_environment", "max_attempts", "timeout_seconds", "cooldown_seconds", "rollback_required", "change_record_required", "kill_switch_enforced", "policy_version"])
        writer.writerow(["POL_UNKNOWN", "RB_NONEXISTENT", "low", "True", "False", "none", "sandbox", "1", "300", "300", "True", "True", "True", "1.0"])

    # Create incidents.csv with:
    # 1. Missing primary key
    # 2. Duplicate primary key
    with open(bad_dir / "incidents.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["incident_id", "detected_at", "service_id", "environment", "incident_type", "runbook_id", "policy_id", "severity", "risk_level", "anomaly_score", "ambiguous_signal", "kill_switch_active", "rate_limit_hit", "policy_decision", "approval_id", "approval_status", "execution_status", "verification_status", "rollback_status", "rollback_success", "final_status", "auto_resolved", "human_intervention", "resolution_minutes", "data_split"])
        writer.writerow(["", "2026-09-01T00:00:00Z", "svc1", "prod", "disk_pressure", "RB001", "", "P1", "low", "0.5", "False", "False", "False", "AUTO", "", "not_required", "succeeded", "passed", "not_needed", "", "RESOLVED", "True", "False", "5", "train"])
        writer.writerow(["INC_DUP", "2026-09-01T00:00:00Z", "svc1", "prod", "disk_pressure", "RB001", "", "P1", "low", "0.5", "False", "False", "False", "AUTO", "", "not_required", "succeeded", "passed", "not_needed", "", "RESOLVED", "True", "False", "5", "train"])
        writer.writerow(["INC_DUP", "2026-09-01T00:00:00Z", "svc1", "prod", "disk_pressure", "RB001", "", "P1", "low", "0.5", "False", "False", "False", "AUTO", "", "not_required", "succeeded", "passed", "not_needed", "", "RESOLVED", "True", "False", "5", "train"])

    report = ingest_dataset(source_dir=bad_dir, db_path=test_db, force=True)

    assert report.success is False
    assert len(report.relationship_errors) > 0
    assert any("RB_NONEXISTENT" in err for err in report.relationship_errors)

    # Missing and duplicate PKs caught
    rejected = report.rejected_rows.get("incidents.csv", [])
    assert len(rejected) == 2
    reasons = [r["reason"] for r in rejected]
    assert any("Missing primary key" in r for r in reasons)
    assert any("Duplicate primary key" in r for r in reasons)


def test_empty_datasets(tmp_path):
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    test_db = tmp_path / "empty_test.db"

    report = ingest_dataset(source_dir=empty_dir, db_path=test_db, force=True)
    assert report.success is False
    assert any("No source files found" in w for w in report.validation_warnings)


def test_malformed_timestamps(tmp_path):
    bad_dir = tmp_path / "bad_time_dir"
    bad_dir.mkdir()
    test_db = tmp_path / "bad_time_test.db"

    with open(bad_dir / "incidents.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["incident_id", "detected_at", "service_id", "environment", "incident_type", "runbook_id", "policy_id", "severity", "risk_level", "anomaly_score", "ambiguous_signal", "kill_switch_active", "rate_limit_hit", "policy_decision", "approval_id", "approval_status", "execution_status", "verification_status", "rollback_status", "rollback_success", "final_status", "auto_resolved", "human_intervention", "resolution_minutes", "data_split"])
        writer.writerow(["INC_TIME_BAD", "not-a-valid-timestamp-at-all", "svc1", "prod", "disk_pressure", "", "", "P1", "low", "0.5", "False", "False", "False", "AUTO", "", "not_required", "succeeded", "passed", "not_needed", "", "RESOLVED", "True", "False", "5", "train"])

    report = ingest_dataset(source_dir=bad_dir, db_path=test_db, force=True)
    assert report.success is False
    rejected = report.rejected_rows.get("incidents.csv", [])
    assert len(rejected) == 1
    assert "invalid ISO timestamp" in rejected[0]["reason"]


def test_source_data_changes(tmp_path):
    custom_dir = tmp_path / "custom_data"
    custom_dir.mkdir()
    test_db = tmp_path / "custom_test.db"

    # Copy files
    for fname in EXPECTED_FILES:
        src = SOURCE_CSV_DIR / fname
        if src.exists():
            shutil.copy(src, custom_dir / fname)

    # Initial ingestion
    rep1 = ingest_dataset(source_dir=custom_dir, db_path=test_db, force=True)
    assert rep1.success is True
    initial_hash = rep1.dataset_hash

    # Modify one file
    rb_path = custom_dir / "runbooks.csv"
    content = rb_path.read_text(encoding="utf-8")
    rb_path.write_text(content.replace("Restart isolated background worker", "Restart worker modified version"), encoding="utf-8")

    # Re-run without force
    rep2 = ingest_dataset(source_dir=custom_dir, db_path=test_db, force=False)
    assert rep2.success is True
    assert rep2.cached is False  # Hash changed so cache was invalidated!
    assert rep2.dataset_hash != initial_hash

    # Verify updated content is present in DB
    SessionLocal = get_readonly_sessionmaker(test_db)
    with SessionLocal() as s:
        rb = s.scalars(select(KBRunbook).where(KBRunbook.runbook_id == "RB001")).first()
        assert rb is not None
        assert "modified version" in rb.name


def test_readonly_enforcement(ingested_db):
    test_db, _ = ingested_db
    engine = get_readonly_engine(test_db)

    # Reading succeeds
    with engine.connect() as conn:
        count = conn.execute(text("SELECT count(*) FROM kb_incidents")).scalar()
        assert count == 3000

        # Any mutating query is strictly rejected by SQLite PRAGMA query_only
        with pytest.raises(Exception) as exc_info:
            conn.execute(text("DELETE FROM kb_incidents"))
        assert "readonly" in str(exc_info.value).lower()

        with pytest.raises(Exception) as exc_info2:
            conn.execute(text("UPDATE kb_incidents SET severity='P99'"))
        assert "readonly" in str(exc_info2.value).lower()

