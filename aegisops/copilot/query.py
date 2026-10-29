"""Parameterized, read-only repository query functions for structured retrieval.

All queries execute against the isolated SQLite knowledge store with query_only=ON
and strictly avoid string concatenation or unparameterized queries.
"""

from pathlib import Path
from typing import Any
from sqlalchemy import select

from aegisops.copilot.ingestion import get_readonly_sessionmaker
from aegisops.copilot.schema import (
    KBAuditEvent,
    KBApproval,
    KBExecutionAction,
    KBIncident,
    KBMetric,
    KBPolicy,
    KBRunbook,
)


def get_incident_record(incident_id: str, db_path: Path | str | None = None) -> dict[str, Any] | None:
    SessionLocal = get_readonly_sessionmaker(db_path)
    with SessionLocal() as s:
        row = s.scalars(
            select(KBIncident).where(KBIncident.incident_id == incident_id)
        ).first()
        if not row:
            import re
            m = re.match(r"^INC[-_]?(\d{1,6})$", incident_id, re.IGNORECASE)
            if m:
                norm = f"INC{m.group(1).zfill(6)}"
                row = s.scalars(
                    select(KBIncident).where(KBIncident.incident_id == norm)
                ).first()
        if not row:
            return None
        return {
            "incident_id": row.incident_id,
            "detected_at": row.detected_at,
            "service_id": row.service_id,
            "environment": row.environment,
            "incident_type": row.incident_type,
            "runbook_id": row.runbook_id,
            "policy_id": row.policy_id,
            "severity": row.severity,
            "risk_level": row.risk_level,
            "anomaly_score": row.anomaly_score,
            "ambiguous_signal": row.ambiguous_signal,
            "kill_switch_active": row.kill_switch_active,
            "rate_limit_hit": row.rate_limit_hit,
            "policy_decision": row.policy_decision,
            "approval_id": row.approval_id,
            "approval_status": row.approval_status,
            "execution_status": row.execution_status,
            "verification_status": row.verification_status,
            "rollback_status": row.rollback_status,
            "rollback_success": row.rollback_success,
            "final_status": row.final_status,
            "auto_resolved": row.auto_resolved,
            "human_intervention": row.human_intervention,
            "resolution_minutes": row.resolution_minutes,
            "data_split": row.data_split,
            "source_file": row.source_file,
        }


def get_incident_metrics(incident_id: str, db_path: Path | str | None = None) -> list[dict[str, Any]]:
    SessionLocal = get_readonly_sessionmaker(db_path)
    with SessionLocal() as s:
        rows = s.scalars(
            select(KBMetric).where(KBMetric.incident_id == incident_id).order_by(KBMetric.observed_at)
        ).all()
        return [
            {
                "metric_id": m.metric_id,
                "incident_id": m.incident_id,
                "observed_at": m.observed_at,
                "metric_name": m.metric_name,
                "value_before": m.value_before,
                "value_after": m.value_after,
                "unit": m.unit,
                "threshold": m.threshold,
                "anomaly_score": m.anomaly_score,
                "is_synthetic": m.is_synthetic,
                "source_file": m.source_file,
            }
            for m in rows
        ]


def get_incident_approvals(incident_id: str, db_path: Path | str | None = None) -> list[dict[str, Any]]:
    SessionLocal = get_readonly_sessionmaker(db_path)
    with SessionLocal() as s:
        rows = s.scalars(
            select(KBApproval).where(KBApproval.incident_id == incident_id).order_by(KBApproval.requested_at)
        ).all()
        return [
            {
                "approval_id": a.approval_id,
                "incident_id": a.incident_id,
                "policy_id": a.policy_id,
                "requested_at": a.requested_at,
                "resolved_at": a.resolved_at,
                "requested_role": a.requested_role,
                "reviewer_id": a.reviewer_id,
                "status": a.status,
                "decision_reason": a.decision_reason,
                "expires_after_seconds": a.expires_after_seconds,
                "source_file": a.source_file,
            }
            for a in rows
        ]


def get_incident_actions(incident_id: str, db_path: Path | str | None = None) -> list[dict[str, Any]]:
    SessionLocal = get_readonly_sessionmaker(db_path)
    with SessionLocal() as s:
        rows = s.scalars(
            select(KBExecutionAction).where(KBExecutionAction.incident_id == incident_id).order_by(KBExecutionAction.started_at)
        ).all()
        return [
            {
                "action_id": act.action_id,
                "incident_id": act.incident_id,
                "runbook_id": act.runbook_id,
                "action": act.action,
                "started_at": act.started_at,
                "finished_at": act.finished_at,
                "attempt_number": act.attempt_number,
                "timeout_seconds": act.timeout_seconds,
                "precondition_passed": act.precondition_passed,
                "execution_status": act.execution_status,
                "verification_rule": act.verification_rule,
                "verification_status": act.verification_status,
                "rollback_action": act.rollback_action,
                "rollback_status": act.rollback_status,
                "change_record_id": act.change_record_id,
                "dry_run": act.dry_run,
                "source_file": act.source_file,
            }
            for act in rows
        ]


def get_incident_audits(incident_id: str, db_path: Path | str | None = None) -> list[dict[str, Any]]:
    SessionLocal = get_readonly_sessionmaker(db_path)
    with SessionLocal() as s:
        rows = s.scalars(
            select(KBAuditEvent).where(KBAuditEvent.incident_id == incident_id).order_by(KBAuditEvent.timestamp)
        ).all()
        return [
            {
                "event_id": ev.event_id,
                "incident_id": ev.incident_id,
                "timestamp": ev.timestamp,
                "event_type": ev.event_type,
                "actor": ev.actor,
                "policy_version": ev.policy_version,
                "details": ev.details,
                "success": ev.success,
                "correlation_id": ev.correlation_id,
                "source_file": ev.source_file,
            }
            for ev in rows
        ]


def get_runbook_record(runbook_id: str, db_path: Path | str | None = None) -> dict[str, Any] | None:
    SessionLocal = get_readonly_sessionmaker(db_path)
    with SessionLocal() as s:
        row = s.scalars(
            select(KBRunbook).where(KBRunbook.runbook_id == runbook_id)
        ).first()
        if not row:
            import re
            m = re.match(r"^RB[-_]?(\d{1,3})$", runbook_id, re.IGNORECASE)
            if m:
                norm = f"RB{m.group(1).zfill(3)}"
                row = s.scalars(
                    select(KBRunbook).where(KBRunbook.runbook_id == norm)
                ).first()
        if not row:
            return None
        return {
            "runbook_id": row.runbook_id,
            "incident_type": row.incident_type,
            "name": row.name,
            "risk_level": row.risk_level,
            "allowlisted_action": row.allowlisted_action,
            "verification_rule": row.verification_rule,
            "compensation_action": row.compensation_action,
            "service_category": row.service_category,
            "max_attempts": row.max_attempts,
            "timeout_seconds": row.timeout_seconds,
            "source_file": row.source_file,
        }


def get_policy_record(policy_id: str, db_path: Path | str | None = None) -> dict[str, Any] | None:
    SessionLocal = get_readonly_sessionmaker(db_path)
    with SessionLocal() as s:
        row = s.scalars(
            select(KBPolicy).where(KBPolicy.policy_id == policy_id)
        ).first()
        if not row:
            import re
            m = re.match(r"^POL(?:[-_]?RB)?[-_]?(\d{1,3})$", policy_id, re.IGNORECASE)
            if m:
                norm = f"POL_RB{m.group(1).zfill(3)}"
                row = s.scalars(
                    select(KBPolicy).where(KBPolicy.policy_id == norm)
                ).first()
        if not row:
            return None
        return {
            "policy_id": row.policy_id,
            "runbook_id": row.runbook_id,
            "risk_level": row.risk_level,
            "auto_execute": row.auto_execute,
            "approval_required": row.approval_required,
            "approval_role": row.approval_role,
            "allowed_environment": row.allowed_environment,
            "max_attempts": row.max_attempts,
            "timeout_seconds": row.timeout_seconds,
            "cooldown_seconds": row.cooldown_seconds,
            "rollback_required": row.rollback_required,
            "change_record_required": row.change_record_required,
            "kill_switch_enforced": row.kill_switch_enforced,
            "policy_version": row.policy_version,
            "source_file": row.source_file,
        }


def get_policy_by_runbook(runbook_id: str, db_path: Path | str | None = None) -> dict[str, Any] | None:
    SessionLocal = get_readonly_sessionmaker(db_path)
    with SessionLocal() as s:
        row = s.scalars(
            select(KBPolicy).where(KBPolicy.runbook_id == runbook_id)
        ).first()
        if not row:
            return None
        return {
            "policy_id": row.policy_id,
            "runbook_id": row.runbook_id,
            "risk_level": row.risk_level,
            "auto_execute": row.auto_execute,
            "approval_required": row.approval_required,
            "approval_role": row.approval_role,
            "allowed_environment": row.allowed_environment,
            "max_attempts": row.max_attempts,
            "timeout_seconds": row.timeout_seconds,
            "cooldown_seconds": row.cooldown_seconds,
            "rollback_required": row.rollback_required,
            "change_record_required": row.change_record_required,
            "kill_switch_enforced": row.kill_switch_enforced,
            "policy_version": row.policy_version,
            "source_file": row.source_file,
        }


def get_full_incident_dossier(incident_id: str, db_path: Path | str | None = None) -> dict[str, Any] | None:
    inc = get_incident_record(incident_id, db_path)
    if not inc:
        return None
    canonical_id = inc["incident_id"]
    audits = get_incident_audits(canonical_id, db_path)
    return {
        "incident": inc,
        "metrics": get_incident_metrics(canonical_id, db_path),
        "approvals": get_incident_approvals(canonical_id, db_path),
        "actions": get_incident_actions(canonical_id, db_path),
        "audits": audits,
        "audit_events": audits,
        "runbook": get_runbook_record(inc["runbook_id"], db_path) if inc.get("runbook_id") else None,
        "policy": get_policy_record(inc["policy_id"], db_path) if inc.get("policy_id") else None,
    }

