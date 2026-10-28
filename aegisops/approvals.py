"""Append-only approvals bound to one frozen action and incident."""

from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4
from functools import wraps
from threading import RLock
from sqlalchemy import select
from .models import ApprovalEvent
from .policy import Decision


def synchronized(fn):
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        with self.lock:
            return fn(self, *args, **kwargs)

    return wrapped


class ApprovalQueue:
    def __init__(self, store, policy, incident_getter):
        self.store, self.policy, self.incident_getter = store, policy, incident_getter
        self.lock = RLock()

    def _append(self, request, status, **extra):
        data = {**deepcopy(request), **deepcopy(extra), "status": status}
        with self.store.Session.begin() as s:
            s.add(
                ApprovalEvent(
                    request_id=data["request_id"],
                    action_id=data["action_id"],
                    status=status,
                    payload=data,
                )
            )
        return data

    @synchronized
    def all(self):
        with self.store.Session() as s:
            rows = list(s.scalars(select(ApprovalEvent).order_by(ApprovalEvent.id)))
            latest = {r.request_id: r.payload for r in rows}
            return list(latest.values())

    @synchronized
    def get(self, request_id):
        return next((r for r in self.all() if r["request_id"] == request_id), None)

    @synchronized
    def create(self, action_id, runbook, observation):
        now = self.store.clock()
        request = dict(
            request_id=str(uuid4()),
            action_id=action_id,
            runbook_id=runbook["id"],
            runbook=deepcopy(runbook),
            observation=deepcopy(observation),
            incident_id=self.incident_getter(),
            created_at=now,
            expires_at=now + self.policy["approval"]["timeout_minutes"] * 60,
            approver=None,
        )
        result = self._append(request, "PENDING")
        self.store.write(
            action_id,
            runbook,
            observation,
            Decision(
                "NEEDS_APPROVAL", ["Approval request recorded"], {"approval": False}
            ),
            event="approval_requested",
        )
        return result

    @synchronized
    def approve(self, request_id, approver, reason):
        self.expire()
        request = self.get(request_id)
        if not request or request["status"] != "PENDING":
            raise ValueError("Approval is missing, expired, or already decided")
        if (
            not isinstance(approver, str)
            or not approver.strip()
            or not isinstance(reason, str)
            or not reason.strip()
        ):
            raise ValueError("Approver and reason are required")
        metadata = {
            "name": approver.strip(),
            "timestamp": datetime.fromtimestamp(
                self.store.clock(), timezone.utc
            ).isoformat(),
            "reason": reason.strip(),
        }
        approved = self._append(request, "APPROVED", approver=metadata)
        self.store.write(
            request["action_id"],
            request["runbook"],
            request["observation"],
            Decision(
                "NEEDS_APPROVAL",
                ["Human approval recorded; policy recheck still required"],
                {"approval": True},
            ),
            event="approval_granted",
            approver=metadata,
        )
        return approved

    @synchronized
    def valid(self, request_id, action_id, unconsumed=False):
        self.expire()
        r = self.get(request_id)
        statuses = ("APPROVED",) if unconsumed else ("APPROVED", "CONSUMED")
        return bool(
            r
            and r["action_id"] == action_id
            and r["status"] in statuses
            and r["expires_at"] > self.store.clock()
            and r.get("approver")
            and all(r["approver"].get(k) for k in ("name", "timestamp", "reason"))
        )

    @synchronized
    def approver(self, request_id):
        r = self.get(request_id)
        return deepcopy(r["approver"]) if r else None

    @synchronized
    def consume(self, request_id, action_id):
        if not self.valid(request_id, action_id, unconsumed=True):
            raise PermissionError("Approval cannot be reused")
        return self._append(self.get(request_id), "CONSUMED")

    @synchronized
    def invalidate(self, request_id, reason):
        self.expire()
        request = self.get(request_id)
        if not request or request["status"] not in ("PENDING", "APPROVED", "CONSUMED"):
            return request
        metadata = {
            "name": "aegisops",
            "timestamp": datetime.fromtimestamp(
                self.store.clock(), timezone.utc
            ).isoformat(),
            "reason": reason,
        }
        revoked = self._append(request, "REVOKED", revoked_by=metadata)
        self.store.write(
            request["action_id"],
            request["runbook"],
            request["observation"],
            Decision("REFUSE", [f"Approval revoked: {reason}"], {"approval": False}),
            event="approval_revoked",
            final_outcome="ESCALATE",
            approver=metadata,
        )
        return revoked

    @synchronized
    def close(self, request_id):
        r = self.get(request_id)
        if r and r["status"] == "CONSUMED":
            self._append(r, "COMPLETED")

    @synchronized
    def deny(self, request_id, approver, reason):
        self.expire()
        r = self.get(request_id)
        if not r or r["status"] not in ("PENDING", "APPROVED", "CONSUMED"):
            raise ValueError("No active approval")
        if (
            not isinstance(approver, str)
            or not approver.strip()
            or not isinstance(reason, str)
            or not reason.strip()
        ):
            raise ValueError("Approver and reason required")
        revoked = r["status"] != "PENDING"
        metadata = dict(
            name=approver.strip(),
            timestamp=datetime.fromtimestamp(
                self.store.clock(), timezone.utc
            ).isoformat(),
            reason=reason.strip(),
        )
        status = "REVOKED" if revoked else "DENIED"
        result = self._append(r, status, denied_by=metadata)
        self.store.write(
            r["action_id"],
            r["runbook"],
            r["observation"],
            Decision(
                "REFUSE", [f"Approval {status.lower()}: {reason}"], {"approval": False}
            ),
            event="approval_revoked" if revoked else "approval_denied",
            approver=metadata,
        )
        return result

    @synchronized
    def expire(self):
        for r in self.all():
            if (
                r["status"] in ("PENDING", "APPROVED", "CONSUMED")
                and self.store.clock() >= r["expires_at"]
            ):
                self._append(r, "DENIED_TIMEOUT")
                self.store.write(
                    r["action_id"],
                    r["runbook"],
                    r["observation"],
                    Decision(
                        "REFUSE",
                        ["Approval timeout: denied and escalated to operator"],
                        {"approval": False},
                    ),
                    event="approval_timeout",
                    final_outcome="ESCALATE",
                    approver=r.get("approver"),
                )
