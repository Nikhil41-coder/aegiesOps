"""SQLAlchemy models for the read-only AegisOps Copilot Knowledge Base."""

from sqlalchemy import Boolean, Float, Integer, JSON, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class KBBase(DeclarativeBase):
    pass


class KnowledgeMetadata(KBBase):
    __tablename__ = "kb_metadata"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dataset_hash: Mapped[str] = mapped_column(String, index=True)
    ingested_at: Mapped[str] = mapped_column(String)
    source_file_hashes: Mapped[dict] = mapped_column(JSON)
    row_counts: Mapped[dict] = mapped_column(JSON)
    version: Mapped[str] = mapped_column(String, default="1.0.0")


class DocArtifact(KBBase):
    __tablename__ = "kb_doc_artifacts"

    doc_id: Mapped[str] = mapped_column(String, primary_key=True)
    filename: Mapped[str] = mapped_column(String, index=True)
    title: Mapped[str] = mapped_column(String)
    content: Mapped[str] = mapped_column(String)
    checksum: Mapped[str] = mapped_column(String)
    source_file: Mapped[str] = mapped_column(String)


class KBRunbook(KBBase):
    __tablename__ = "kb_runbooks"

    runbook_id: Mapped[str] = mapped_column(String, primary_key=True)
    incident_type: Mapped[str] = mapped_column(String, index=True)
    name: Mapped[str] = mapped_column(String)
    risk_level: Mapped[str] = mapped_column(String)
    allowlisted_action: Mapped[str] = mapped_column(String)
    verification_rule: Mapped[str] = mapped_column(String)
    compensation_action: Mapped[str] = mapped_column(String)
    service_category: Mapped[str] = mapped_column(String)
    max_attempts: Mapped[int] = mapped_column(Integer)
    timeout_seconds: Mapped[int] = mapped_column(Integer)
    source_file: Mapped[str] = mapped_column(String)


class KBPolicy(KBBase):
    __tablename__ = "kb_policies"

    policy_id: Mapped[str] = mapped_column(String, primary_key=True)
    runbook_id: Mapped[str] = mapped_column(String, index=True)
    risk_level: Mapped[str] = mapped_column(String)
    auto_execute: Mapped[bool] = mapped_column(Boolean)
    approval_required: Mapped[bool] = mapped_column(Boolean)
    approval_role: Mapped[str] = mapped_column(String)
    allowed_environment: Mapped[str] = mapped_column(String)
    max_attempts: Mapped[int] = mapped_column(Integer)
    timeout_seconds: Mapped[int] = mapped_column(Integer)
    cooldown_seconds: Mapped[int] = mapped_column(Integer)
    rollback_required: Mapped[bool] = mapped_column(Boolean)
    change_record_required: Mapped[bool] = mapped_column(Boolean)
    kill_switch_enforced: Mapped[bool] = mapped_column(Boolean)
    policy_version: Mapped[str] = mapped_column(String)
    source_file: Mapped[str] = mapped_column(String)


class KBIncident(KBBase):
    __tablename__ = "kb_incidents"

    incident_id: Mapped[str] = mapped_column(String, primary_key=True)
    detected_at: Mapped[str] = mapped_column(String, index=True)
    service_id: Mapped[str] = mapped_column(String, index=True)
    environment: Mapped[str] = mapped_column(String, index=True)
    incident_type: Mapped[str] = mapped_column(String, index=True)
    runbook_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    policy_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    severity: Mapped[str] = mapped_column(String)
    risk_level: Mapped[str] = mapped_column(String)
    anomaly_score: Mapped[float] = mapped_column(Float)
    ambiguous_signal: Mapped[bool] = mapped_column(Boolean)
    kill_switch_active: Mapped[bool] = mapped_column(Boolean)
    rate_limit_hit: Mapped[bool] = mapped_column(Boolean)
    policy_decision: Mapped[str] = mapped_column(String)
    approval_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    approval_status: Mapped[str] = mapped_column(String)
    execution_status: Mapped[str] = mapped_column(String)
    verification_status: Mapped[str] = mapped_column(String)
    rollback_status: Mapped[str] = mapped_column(String)
    rollback_success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    final_status: Mapped[str] = mapped_column(String, index=True)
    auto_resolved: Mapped[bool] = mapped_column(Boolean)
    human_intervention: Mapped[bool] = mapped_column(Boolean)
    resolution_minutes: Mapped[float | None] = mapped_column(Float, nullable=True)
    data_split: Mapped[str] = mapped_column(String, index=True)
    source_file: Mapped[str] = mapped_column(String)


class KBMetric(KBBase):
    __tablename__ = "kb_metrics"

    metric_id: Mapped[str] = mapped_column(String, primary_key=True)
    incident_id: Mapped[str] = mapped_column(String, index=True)
    observed_at: Mapped[str] = mapped_column(String)
    metric_name: Mapped[str] = mapped_column(String, index=True)
    value_before: Mapped[float | None] = mapped_column(Float, nullable=True)
    value_after: Mapped[float | None] = mapped_column(Float, nullable=True)
    unit: Mapped[str] = mapped_column(String)
    threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    anomaly_score: Mapped[float] = mapped_column(Float)
    is_synthetic: Mapped[bool] = mapped_column(Boolean)
    source_file: Mapped[str] = mapped_column(String)


class KBApproval(KBBase):
    __tablename__ = "kb_approvals"

    approval_id: Mapped[str] = mapped_column(String, primary_key=True)
    incident_id: Mapped[str] = mapped_column(String, index=True)
    policy_id: Mapped[str] = mapped_column(String, index=True)
    requested_at: Mapped[str] = mapped_column(String)
    resolved_at: Mapped[str | None] = mapped_column(String, nullable=True)
    requested_role: Mapped[str] = mapped_column(String)
    reviewer_id: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, index=True)
    decision_reason: Mapped[str | None] = mapped_column(String, nullable=True)
    expires_after_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_file: Mapped[str] = mapped_column(String)


class KBExecutionAction(KBBase):
    __tablename__ = "kb_execution_actions"

    action_id: Mapped[str] = mapped_column(String, primary_key=True)
    incident_id: Mapped[str] = mapped_column(String, index=True)
    runbook_id: Mapped[str] = mapped_column(String, index=True)
    action: Mapped[str] = mapped_column(String)
    started_at: Mapped[str] = mapped_column(String)
    finished_at: Mapped[str | None] = mapped_column(String, nullable=True)
    attempt_number: Mapped[int] = mapped_column(Integer)
    timeout_seconds: Mapped[int] = mapped_column(Integer)
    precondition_passed: Mapped[bool] = mapped_column(Boolean)
    execution_status: Mapped[str] = mapped_column(String, index=True)
    verification_rule: Mapped[str | None] = mapped_column(String, nullable=True)
    verification_status: Mapped[str | None] = mapped_column(String, nullable=True)
    rollback_action: Mapped[str | None] = mapped_column(String, nullable=True)
    rollback_status: Mapped[str | None] = mapped_column(String, nullable=True)
    change_record_id: Mapped[str | None] = mapped_column(String, nullable=True)
    dry_run: Mapped[bool] = mapped_column(Boolean)
    source_file: Mapped[str] = mapped_column(String)


class KBAuditEvent(KBBase):
    __tablename__ = "kb_audit_events"

    event_id: Mapped[str] = mapped_column(String, primary_key=True)
    incident_id: Mapped[str] = mapped_column(String, index=True)
    timestamp: Mapped[str] = mapped_column(String, index=True)
    event_type: Mapped[str] = mapped_column(String, index=True)
    actor: Mapped[str] = mapped_column(String)
    policy_version: Mapped[str] = mapped_column(String)
    details: Mapped[str] = mapped_column(String)
    success: Mapped[bool] = mapped_column(Boolean)
    correlation_id: Mapped[str] = mapped_column(String, index=True)
    source_file: Mapped[str] = mapped_column(String)

