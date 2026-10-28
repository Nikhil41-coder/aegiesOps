from copy import deepcopy
from datetime import datetime, timezone
import time
from sqlalchemy import select
from .models import AuditRecord, ChangeRecord, RuntimeEvent, database

REQUIRED = {
    "id",
    "timestamp",
    "action_id",
    "runbook_id",
    "tier",
    "observation",
    "decision",
    "reasons",
    "checks",
    "approver",
    "step_results",
    "health_result",
    "rollback_status",
    "final_outcome",
    "event",
}


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def check_complete(record):
    missing = sorted(REQUIRED - record.keys())
    for key in REQUIRED & record.keys():
        if record[key] is None and key not in {"approver"}:
            missing.append(key)
    if not isinstance(record.get("reasons"), list) or not record.get("reasons"):
        missing.append("reasons.nonempty")
    for key, expected_type in (
        ("observation", dict),
        ("checks", dict),
        ("step_results", list),
    ):
        if key in record and not isinstance(record[key], expected_type):
            missing.append(key + ".valid_type")
    if record.get("final_outcome") == "RESOLVED":
        if record.get("health_result") != "PASSED":
            missing.append("health_result.PASSED")
        if not record.get("step_results"):
            missing.append("step_results.nonempty")
        if record.get("tier") == "T2":
            approval = record.get("approver") or {}
            missing.extend(
                "approver." + key
                for key in ("name", "timestamp", "reason")
                if not approval.get(key)
            )
    return sorted(set(missing))


def completeness_score(record):
    invalid_fields = {missing.split(".")[0] for missing in check_complete(record)}
    return round(100 * (len(REQUIRED) - len(invalid_fields)) / len(REQUIRED))


class AuditStore:
    def __init__(self, url="sqlite:///:memory:", clock=time.time):
        self.engine, self.Session = database(url)
        self.clock = clock

    def write(
        self,
        action_id,
        runbook,
        observation,
        decision,
        event="decision",
        final_outcome=None,
        approver=None,
        step_results=None,
        health_result="NOT_RUN",
        rollback_status="NOT_NEEDED",
        start=None,
    ):
        stamp = utcnow()
        rb = runbook or {}
        record = dict(
            timestamp=stamp,
            action_id=action_id,
            runbook_id=rb.get("id", "UNMATCHED"),
            tier=rb.get("tier", "N/A"),
            observation=deepcopy(observation),
            decision=decision.outcome,
            reasons=list(decision.reasons),
            checks=dict(decision.checks),
            approver=deepcopy(approver),
            step_results=deepcopy(step_results or []),
            health_result=health_result,
            rollback_status=rollback_status,
            final_outcome=final_outcome or decision.outcome,
            event=event,
        )
        terminal = event in {
            "closed",
            "approval_timeout",
            "approval_denied",
            "approval_revoked",
            "recovered",
        } or (event == "decision" and decision.outcome in {"REFUSE", "ESCALATE"})
        change = dict(
            change_id=action_id,
            type=(
                "normal"
                if rb.get("tier") == "T2"
                else ("standard" if rb.get("tier") in ("T0", "T1") else "assessment")
            ),
            requester="aegisops",
            approver=deepcopy(approver),
            start=start or stamp,
            end=stamp if terminal else None,
            outcome=record["final_outcome"],
            rollback_status=rollback_status,
            event=event,
        )
        with self.Session.begin() as session:
            previous = session.scalar(
                select(ChangeRecord)
                .where(ChangeRecord.change_id == action_id)
                .order_by(ChangeRecord.id)
                .limit(1)
            )
            if previous and start is None:
                change["start"] = previous.payload["start"]
            row = AuditRecord(action_id=action_id, timestamp=stamp, payload=record)
            session.add(row)
            session.flush()
            record["id"] = row.id
            # Assign a fresh JSON object while this row is still an INSERT.
            # ID is exposed by serialization, not persisted via an UPDATE.
            session.add(ChangeRecord(change_id=action_id, payload=change))
        return {**record, "id": row.id}

    def records(self, action_id=None):
        with self.Session() as session:
            query = select(AuditRecord).order_by(AuditRecord.id)
            if action_id:
                query = query.where(AuditRecord.action_id == action_id)
            return [{**r.payload, "id": r.id} for r in session.scalars(query)]

    def changes(self):
        with self.Session() as session:
            return [
                r.payload
                for r in session.scalars(select(ChangeRecord).order_by(ChangeRecord.id))
            ]

    def runtime(self, kind, payload):
        with self.Session.begin() as session:
            session.add(
                RuntimeEvent(
                    kind=kind, timestamp=self.clock(), payload=deepcopy(payload)
                )
            )

    def runtime_events(self, kind=None):
        with self.Session() as session:
            query = select(RuntimeEvent).order_by(RuntimeEvent.id)
            if kind:
                query = query.where(RuntimeEvent.kind == kind)
            return [
                {"timestamp": r.timestamp, **r.payload} for r in session.scalars(query)
            ]
