"""Dataset ingestion engine for AegisOps Copilot.

Loads, validates, and stores the historical incident and policy dataset into
a dedicated read-only SQLite knowledge store with full relationship checks,
provenance tracking, and immutable audit metadata.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import time
from typing import Any
import csv

from sqlalchemy import create_engine, event, select, text
from sqlalchemy.orm import Session, sessionmaker

from aegisops.config import COPILOT_DB_PATH, SOURCE_CSV_DIR
from aegisops.copilot.schema import (
    DocArtifact,
    KBAuditEvent,
    KBApproval,
    KBBase,
    KBExecutionAction,
    KBIncident,
    KBMetric,
    KBPolicy,
    KBRunbook,
    KnowledgeMetadata,
)

EXPECTED_FILES = (
    "README.md",
    "runbooks.csv",
    "policies.csv",
    "incidents.csv",
    "metrics.csv",
    "approvals.csv",
    "execution_actions.csv",
    "audit_events.csv",
)


@dataclass
class IngestionReport:
    dataset_hash: str = ""
    version: str = "1.0.0"
    source_dir: str = ""
    db_path: str = ""
    input_rows: dict[str, int] = field(default_factory=dict)
    imported_rows: dict[str, int] = field(default_factory=dict)
    rejected_rows: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    validation_warnings: list[str] = field(default_factory=list)
    relationship_errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    success: bool = False
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def summary(self) -> str:
        lines = [
            f"Ingestion Report (success={self.success}, cached={self.cached})",
            f"  Dataset hash: {self.dataset_hash[:16]}...",
            f"  Source directory: {self.source_dir}",
            f"  Target DB: {self.db_path}",
            f"  Duration: {self.duration_seconds:.3f}s",
            "  Row summary:",
        ]
        for name in sorted(self.input_rows.keys()):
            inp = self.input_rows.get(name, 0)
            imp = self.imported_rows.get(name, 0)
            rej = len(self.rejected_rows.get(name, []))
            lines.append(f"    - {name}: input={inp}, imported={imp}, rejected={rej}")
        if self.relationship_errors:
            lines.append(f"  Relationship errors ({len(self.relationship_errors)}):")
            for err in self.relationship_errors[:5]:
                lines.append(f"    * {err}")
            if len(self.relationship_errors) > 5:
                lines.append(f"    ... and {len(self.relationship_errors) - 5} more")
        if self.validation_warnings:
            lines.append(f"  Validation warnings ({len(self.validation_warnings)}):")
            for warn in self.validation_warnings[:5]:
                lines.append(f"    * {warn}")
        return "\n".join(lines)


def compute_file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def compute_dataset_hash(source_dir: Path) -> tuple[str, dict[str, str]]:
    individual = {}
    combined = hashlib.sha256()
    for filename in sorted(EXPECTED_FILES):
        p = source_dir / filename
        if p.exists() and p.is_file():
            fh = compute_file_hash(p)
            individual[filename] = fh
            combined.update(filename.encode("utf-8"))
            combined.update(fh.encode("utf-8"))
    return combined.hexdigest(), individual


def parse_bool(val: Any, field_name: str) -> bool:
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("true", "1", "t", "yes"):
        return True
    if s in ("false", "0", "f", "no"):
        return False
    raise ValueError(f"Field '{field_name}' invalid boolean: {val!r}")


def parse_optional_bool(val: Any, field_name: str) -> bool | None:
    if val is None or str(val).strip() == "":
        return None
    return parse_bool(val, field_name)


def parse_int(val: Any, field_name: str, nullable: bool = False) -> int | None:
    if val is None or str(val).strip() == "":
        if nullable:
            return None
        raise ValueError(f"Field '{field_name}' cannot be empty")
    try:
        return int(float(str(val).strip()))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Field '{field_name}' invalid integer: {val!r}") from exc


def parse_float(val: Any, field_name: str, nullable: bool = False) -> float | None:
    if val is None or str(val).strip() == "":
        if nullable:
            return None
        raise ValueError(f"Field '{field_name}' cannot be empty")
    try:
        return float(str(val).strip())
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Field '{field_name}' invalid float: {val!r}") from exc


def parse_iso_timestamp(val: Any, field_name: str, nullable: bool = False) -> str | None:
    if val is None or str(val).strip() == "":
        if nullable:
            return None
        raise ValueError(f"Field '{field_name}' cannot be empty")
    s = str(val).strip()
    try:
        # Normalize Z to +00:00 for standard datetime parsing
        normalized = s[:-1] + "+00:00" if s.endswith("Z") else s
        datetime.fromisoformat(normalized)
        return s
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Field '{field_name}' invalid ISO timestamp: {val!r}") from exc


def read_csv_safely(path: Path) -> list[dict[str, str]]:
    with open(path, mode="r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def ingest_dataset(
    source_dir: Path | str | None = None,
    db_path: Path | str | None = None,
    force: bool = False,
) -> IngestionReport:
    start_time = time.time()
    source_path = Path(source_dir) if source_dir else SOURCE_CSV_DIR
    target_db = Path(db_path) if db_path else COPILOT_DB_PATH
    target_db.parent.mkdir(parents=True, exist_ok=True)

    report = IngestionReport(
        source_dir=str(source_path.resolve()),
        db_path=str(target_db.resolve()),
    )

    if not source_path.exists():
        report.duration_seconds = time.time() - start_time
        report.validation_warnings.append(f"Source directory does not exist: {source_path}")
        report.success = False
        return report

    dataset_hash, file_hashes = compute_dataset_hash(source_path)
    report.dataset_hash = dataset_hash

    # Check for empty dataset directory
    if not file_hashes:
        report.duration_seconds = time.time() - start_time
        report.validation_warnings.append(f"No source files found in {source_path}")
        report.success = False
        return report

    # Check if target db already has this exact dataset ingested and not forced
    write_engine = create_engine(f"sqlite:///{target_db.resolve().as_posix()}", connect_args={"check_same_thread": False})
    KBBase.metadata.create_all(write_engine)

    if not force and target_db.exists():
        with Session(write_engine) as session:
            existing = session.scalars(
                select(KnowledgeMetadata).where(KnowledgeMetadata.dataset_hash == dataset_hash)
            ).first()
            if existing:
                report.cached = True
                report.success = True
                report.imported_rows = existing.row_counts or {}
                report.input_rows = existing.row_counts or {}
                report.duration_seconds = time.time() - start_time
                return report

    # Collect and validate each dataset
    all_runbooks: list[KBRunbook] = []
    all_policies: list[KBPolicy] = []
    all_incidents: list[KBIncident] = []
    all_metrics: list[KBMetric] = []
    all_approvals: list[KBApproval] = []
    all_actions: list[KBExecutionAction] = []
    all_audits: list[KBAuditEvent] = []
    all_docs: list[DocArtifact] = []

    seen_pks: dict[str, set[str]] = {
        "runbooks": set(),
        "policies": set(),
        "incidents": set(),
        "metrics": set(),
        "approvals": set(),
        "execution_actions": set(),
        "audit_events": set(),
        "docs": set(),
    }

    # 1. README.md
    readme_path = source_path / "README.md"
    if readme_path.exists():
        content = readme_path.read_text(encoding="utf-8")
        chk = file_hashes.get("README.md", "")
        all_docs.append(
            DocArtifact(
                doc_id="DOC_README",
                filename="README.md",
                title="AegisOps Remediation Dataset README",
                content=content,
                checksum=chk,
                source_file=str(readme_path.relative_to(source_path.parent)),
            )
        )
        report.input_rows["README.md"] = 1
        report.imported_rows["README.md"] = 1
    else:
        report.validation_warnings.append("README.md was not found in source directory")

    # Helper for row validation and error tracking
    def record_rejected(dataset_name: str, row: dict, reason: str):
        if dataset_name not in report.rejected_rows:
            report.rejected_rows[dataset_name] = []
        report.rejected_rows[dataset_name].append({"row": row, "reason": reason})

    # 2. runbooks.csv
    rb_file = source_path / "runbooks.csv"
    if rb_file.exists():
        rows = read_csv_safely(rb_file)
        report.input_rows["runbooks.csv"] = len(rows)
        for r in rows:
            pk = r.get("runbook_id", "").strip()
            if not pk:
                record_rejected("runbooks.csv", r, "Missing primary key 'runbook_id'")
                continue
            if pk in seen_pks["runbooks"]:
                record_rejected("runbooks.csv", r, f"Duplicate primary key 'runbook_id': {pk}")
                continue
            seen_pks["runbooks"].add(pk)
            try:
                all_runbooks.append(
                    KBRunbook(
                        runbook_id=pk,
                        incident_type=r.get("incident_type", "").strip(),
                        name=r.get("name", "").strip(),
                        risk_level=r.get("risk_level", "").strip(),
                        allowlisted_action=r.get("allowlisted_action", "").strip(),
                        verification_rule=r.get("verification_rule", "").strip(),
                        compensation_action=r.get("compensation_action", "").strip(),
                        service_category=r.get("service_category", "").strip(),
                        max_attempts=parse_int(r.get("max_attempts"), "max_attempts"),
                        timeout_seconds=parse_int(r.get("timeout_seconds"), "timeout_seconds"),
                        source_file=str(rb_file.relative_to(source_path.parent)),
                    )
                )
            except ValueError as e:
                record_rejected("runbooks.csv", r, str(e))
        report.imported_rows["runbooks.csv"] = len(all_runbooks)

    # 3. policies.csv
    pol_file = source_path / "policies.csv"
    if pol_file.exists():
        rows = read_csv_safely(pol_file)
        report.input_rows["policies.csv"] = len(rows)
        for r in rows:
            pk = r.get("policy_id", "").strip()
            if not pk:
                record_rejected("policies.csv", r, "Missing primary key 'policy_id'")
                continue
            if pk in seen_pks["policies"]:
                record_rejected("policies.csv", r, f"Duplicate primary key 'policy_id': {pk}")
                continue
            seen_pks["policies"].add(pk)
            rb_ref = r.get("runbook_id", "").strip()
            if rb_ref and rb_ref not in seen_pks["runbooks"]:
                report.relationship_errors.append(
                    f"policies.csv: policy '{pk}' references unknown runbook_id '{rb_ref}'"
                )
            try:
                all_policies.append(
                    KBPolicy(
                        policy_id=pk,
                        runbook_id=rb_ref,
                        risk_level=r.get("risk_level", "").strip(),
                        auto_execute=parse_bool(r.get("auto_execute"), "auto_execute"),
                        approval_required=parse_bool(r.get("approval_required"), "approval_required"),
                        approval_role=r.get("approval_role", "").strip(),
                        allowed_environment=r.get("allowed_environment", "").strip(),
                        max_attempts=parse_int(r.get("max_attempts"), "max_attempts"),
                        timeout_seconds=parse_int(r.get("timeout_seconds"), "timeout_seconds"),
                        cooldown_seconds=parse_int(r.get("cooldown_seconds"), "cooldown_seconds"),
                        rollback_required=parse_bool(r.get("rollback_required"), "rollback_required"),
                        change_record_required=parse_bool(r.get("change_record_required"), "change_record_required"),
                        kill_switch_enforced=parse_bool(r.get("kill_switch_enforced"), "kill_switch_enforced"),
                        policy_version=r.get("policy_version", "").strip(),
                        source_file=str(pol_file.relative_to(source_path.parent)),
                    )
                )
            except ValueError as e:
                record_rejected("policies.csv", r, str(e))
        report.imported_rows["policies.csv"] = len(all_policies)

    # 4. incidents.csv
    inc_file = source_path / "incidents.csv"
    if inc_file.exists():
        rows = read_csv_safely(inc_file)
        report.input_rows["incidents.csv"] = len(rows)
        for r in rows:
            pk = r.get("incident_id", "").strip()
            if not pk:
                record_rejected("incidents.csv", r, "Missing primary key 'incident_id'")
                continue
            if pk in seen_pks["incidents"]:
                record_rejected("incidents.csv", r, f"Duplicate primary key 'incident_id': {pk}")
                continue
            seen_pks["incidents"].add(pk)

            rb_ref = r.get("runbook_id", "").strip() or None
            pol_ref = r.get("policy_id", "").strip() or None
            if rb_ref and rb_ref not in seen_pks["runbooks"]:
                report.relationship_errors.append(
                    f"incidents.csv: incident '{pk}' references unknown runbook_id '{rb_ref}'"
                )
            if pol_ref and pol_ref not in seen_pks["policies"]:
                report.relationship_errors.append(
                    f"incidents.csv: incident '{pk}' references unknown policy_id '{pol_ref}'"
                )

            try:
                det_at = parse_iso_timestamp(r.get("detected_at"), "detected_at")
                all_incidents.append(
                    KBIncident(
                        incident_id=pk,
                        detected_at=det_at,
                        service_id=r.get("service_id", "").strip(),
                        environment=r.get("environment", "").strip(),
                        incident_type=r.get("incident_type", "").strip(),
                        runbook_id=rb_ref,
                        policy_id=pol_ref,
                        severity=r.get("severity", "").strip(),
                        risk_level=r.get("risk_level", "").strip(),
                        anomaly_score=parse_float(r.get("anomaly_score"), "anomaly_score"),
                        ambiguous_signal=parse_bool(r.get("ambiguous_signal"), "ambiguous_signal"),
                        kill_switch_active=parse_bool(r.get("kill_switch_active"), "kill_switch_active"),
                        rate_limit_hit=parse_bool(r.get("rate_limit_hit"), "rate_limit_hit"),
                        policy_decision=r.get("policy_decision", "").strip(),
                        approval_id=r.get("approval_id", "").strip() or None,
                        approval_status=r.get("approval_status", "").strip(),
                        execution_status=r.get("execution_status", "").strip(),
                        verification_status=r.get("verification_status", "").strip(),
                        rollback_status=r.get("rollback_status", "").strip(),
                        rollback_success=parse_optional_bool(r.get("rollback_success"), "rollback_success"),
                        final_status=r.get("final_status", "").strip(),
                        auto_resolved=parse_bool(r.get("auto_resolved"), "auto_resolved"),
                        human_intervention=parse_bool(r.get("human_intervention"), "human_intervention"),
                        resolution_minutes=parse_float(r.get("resolution_minutes"), "resolution_minutes", nullable=True),
                        data_split=r.get("data_split", "").strip(),
                        source_file=str(inc_file.relative_to(source_path.parent)),
                    )
                )
            except ValueError as e:
                record_rejected("incidents.csv", r, str(e))
        report.imported_rows["incidents.csv"] = len(all_incidents)

    # 5. metrics.csv
    met_file = source_path / "metrics.csv"
    if met_file.exists():
        rows = read_csv_safely(met_file)
        report.input_rows["metrics.csv"] = len(rows)
        for r in rows:
            pk = r.get("metric_id", "").strip()
            if not pk:
                record_rejected("metrics.csv", r, "Missing primary key 'metric_id'")
                continue
            if pk in seen_pks["metrics"]:
                record_rejected("metrics.csv", r, f"Duplicate primary key 'metric_id': {pk}")
                continue
            seen_pks["metrics"].add(pk)

            inc_ref = r.get("incident_id", "").strip()
            if inc_ref not in seen_pks["incidents"]:
                report.relationship_errors.append(
                    f"metrics.csv: metric '{pk}' references unknown incident_id '{inc_ref}'"
                )

            try:
                obs_at = parse_iso_timestamp(r.get("observed_at"), "observed_at")
                all_metrics.append(
                    KBMetric(
                        metric_id=pk,
                        incident_id=inc_ref,
                        observed_at=obs_at,
                        metric_name=r.get("metric_name", "").strip(),
                        value_before=parse_float(r.get("value_before"), "value_before", nullable=True),
                        value_after=parse_float(r.get("value_after"), "value_after", nullable=True),
                        unit=r.get("unit", "").strip(),
                        threshold=parse_float(r.get("threshold"), "threshold", nullable=True),
                        anomaly_score=parse_float(r.get("anomaly_score"), "anomaly_score"),
                        is_synthetic=parse_bool(r.get("is_synthetic"), "is_synthetic"),
                        source_file=str(met_file.relative_to(source_path.parent)),
                    )
                )
            except ValueError as e:
                record_rejected("metrics.csv", r, str(e))
        report.imported_rows["metrics.csv"] = len(all_metrics)

    # 6. approvals.csv
    app_file = source_path / "approvals.csv"
    if app_file.exists():
        rows = read_csv_safely(app_file)
        report.input_rows["approvals.csv"] = len(rows)
        for r in rows:
            pk = r.get("approval_id", "").strip()
            if not pk:
                record_rejected("approvals.csv", r, "Missing primary key 'approval_id'")
                continue
            if pk in seen_pks["approvals"]:
                record_rejected("approvals.csv", r, f"Duplicate primary key 'approval_id': {pk}")
                continue
            seen_pks["approvals"].add(pk)

            inc_ref = r.get("incident_id", "").strip()
            pol_ref = r.get("policy_id", "").strip()
            if inc_ref not in seen_pks["incidents"]:
                report.relationship_errors.append(
                    f"approvals.csv: approval '{pk}' references unknown incident_id '{inc_ref}'"
                )
            if pol_ref not in seen_pks["policies"]:
                report.relationship_errors.append(
                    f"approvals.csv: approval '{pk}' references unknown policy_id '{pol_ref}'"
                )

            try:
                req_at = parse_iso_timestamp(r.get("requested_at"), "requested_at")
                res_at = parse_iso_timestamp(r.get("resolved_at"), "resolved_at", nullable=True)
                all_approvals.append(
                    KBApproval(
                        approval_id=pk,
                        incident_id=inc_ref,
                        policy_id=pol_ref,
                        requested_at=req_at,
                        resolved_at=res_at,
                        requested_role=r.get("requested_role", "").strip(),
                        reviewer_id=r.get("reviewer_id", "").strip() or None,
                        status=r.get("status", "").strip(),
                        decision_reason=r.get("decision_reason", "").strip() or None,
                        expires_after_seconds=parse_int(r.get("expires_after_seconds"), "expires_after_seconds", nullable=True),
                        source_file=str(app_file.relative_to(source_path.parent)),
                    )
                )
            except ValueError as e:
                record_rejected("approvals.csv", r, str(e))
        report.imported_rows["approvals.csv"] = len(all_approvals)

    # 7. execution_actions.csv
    act_file = source_path / "execution_actions.csv"
    if act_file.exists():
        rows = read_csv_safely(act_file)
        report.input_rows["execution_actions.csv"] = len(rows)
        for r in rows:
            pk = r.get("action_id", "").strip()
            if not pk:
                record_rejected("execution_actions.csv", r, "Missing primary key 'action_id'")
                continue
            if pk in seen_pks["execution_actions"]:
                record_rejected("execution_actions.csv", r, f"Duplicate primary key 'action_id': {pk}")
                continue
            seen_pks["execution_actions"].add(pk)

            inc_ref = r.get("incident_id", "").strip()
            rb_ref = r.get("runbook_id", "").strip()
            if inc_ref not in seen_pks["incidents"]:
                report.relationship_errors.append(
                    f"execution_actions.csv: action '{pk}' references unknown incident_id '{inc_ref}'"
                )
            if rb_ref not in seen_pks["runbooks"]:
                report.relationship_errors.append(
                    f"execution_actions.csv: action '{pk}' references unknown runbook_id '{rb_ref}'"
                )

            try:
                st_at = parse_iso_timestamp(r.get("started_at"), "started_at")
                fin_at = parse_iso_timestamp(r.get("finished_at"), "finished_at", nullable=True)
                all_actions.append(
                    KBExecutionAction(
                        action_id=pk,
                        incident_id=inc_ref,
                        runbook_id=rb_ref,
                        action=r.get("action", "").strip(),
                        started_at=st_at,
                        finished_at=fin_at,
                        attempt_number=parse_int(r.get("attempt_number"), "attempt_number"),
                        timeout_seconds=parse_int(r.get("timeout_seconds"), "timeout_seconds"),
                        precondition_passed=parse_bool(r.get("precondition_passed"), "precondition_passed"),
                        execution_status=r.get("execution_status", "").strip(),
                        verification_rule=r.get("verification_rule", "").strip() or None,
                        verification_status=r.get("verification_status", "").strip() or None,
                        rollback_action=r.get("rollback_action", "").strip() or None,
                        rollback_status=r.get("rollback_status", "").strip() or None,
                        change_record_id=r.get("change_record_id", "").strip() or None,
                        dry_run=parse_bool(r.get("dry_run"), "dry_run"),
                        source_file=str(act_file.relative_to(source_path.parent)),
                    )
                )
            except ValueError as e:
                record_rejected("execution_actions.csv", r, str(e))
        report.imported_rows["execution_actions.csv"] = len(all_actions)

    # 8. audit_events.csv
    evt_file = source_path / "audit_events.csv"
    if evt_file.exists():
        rows = read_csv_safely(evt_file)
        report.input_rows["audit_events.csv"] = len(rows)
        for r in rows:
            pk = r.get("event_id", "").strip()
            if not pk:
                record_rejected("audit_events.csv", r, "Missing primary key 'event_id'")
                continue
            if pk in seen_pks["audit_events"]:
                record_rejected("audit_events.csv", r, f"Duplicate primary key 'event_id': {pk}")
                continue
            seen_pks["audit_events"].add(pk)

            inc_ref = r.get("incident_id", "").strip()
            if inc_ref not in seen_pks["incidents"]:
                report.relationship_errors.append(
                    f"audit_events.csv: event '{pk}' references unknown incident_id '{inc_ref}'"
                )

            try:
                ev_time = parse_iso_timestamp(r.get("timestamp"), "timestamp")
                all_audits.append(
                    KBAuditEvent(
                        event_id=pk,
                        incident_id=inc_ref,
                        timestamp=ev_time,
                        event_type=r.get("event_type", "").strip(),
                        actor=r.get("actor", "").strip(),
                        policy_version=r.get("policy_version", "").strip(),
                        details=r.get("details", "").strip(),
                        success=parse_bool(r.get("success"), "success"),
                        correlation_id=r.get("correlation_id", "").strip(),
                        source_file=str(evt_file.relative_to(source_path.parent)),
                    )
                )
            except ValueError as e:
                record_rejected("audit_events.csv", r, str(e))
        report.imported_rows["audit_events.csv"] = len(all_audits)

    # Atomic write inside single transaction
    with Session(write_engine) as session:
        # Recreate tables to ensure clean, repeatable idempotency
        KBBase.metadata.drop_all(write_engine)
        KBBase.metadata.create_all(write_engine)

        if all_docs:
            session.add_all(all_docs)
        if all_runbooks:
            session.add_all(all_runbooks)
        if all_policies:
            session.add_all(all_policies)
        if all_incidents:
            session.add_all(all_incidents)
        if all_metrics:
            session.add_all(all_metrics)
        if all_approvals:
            session.add_all(all_approvals)
        if all_actions:
            session.add_all(all_actions)
        if all_audits:
            session.add_all(all_audits)

        meta = KnowledgeMetadata(
            dataset_hash=dataset_hash,
            ingested_at=datetime.now(timezone.utc).isoformat(),
            source_file_hashes=file_hashes,
            row_counts=report.imported_rows,
            version="1.0.0",
        )
        session.add(meta)
        session.commit()

    report.duration_seconds = time.time() - start_time
    total_rejected = sum(len(items) for items in report.rejected_rows.values())
    report.success = total_rejected == 0 and len(report.relationship_errors) == 0
    return report


def get_readonly_engine(db_path: Path | str | None = None):
    target = Path(db_path) if db_path else COPILOT_DB_PATH
    if not target.exists():
        raise FileNotFoundError(f"Copilot knowledge base does not exist at {target}. Run ingestion first.")

    engine = create_engine(
        f"sqlite:///{target.resolve().as_posix()}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def set_readonly(dbapi_conn, _):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA query_only = ON;")
        cursor.execute("PRAGMA busy_timeout = 5000;")
        cursor.close()

    return engine


def get_readonly_sessionmaker(db_path: Path | str | None = None):
    engine = get_readonly_engine(db_path)
    return sessionmaker(engine, expire_on_commit=False)

