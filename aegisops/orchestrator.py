"""Single-process coordinator; every mutation crosses the policy boundary."""

from copy import deepcopy
from pathlib import Path
import os
from threading import RLock
from uuid import uuid4
from .adapters.mock import MockAdapter
from .approvals import ApprovalQueue
from .killswitch import KillSwitch
from .audit import AuditStore
from .config import DATA
from .executor import Executor, ExecutionAborted
from .loader import load_policy, load_runbooks, validate_policy, validate_runbooks
from .matcher import match
from .observer import observe
from .policy import Decision, PolicyAuthority, decide
from .verifier import verify, rollback_once


class Engine:
    def __init__(
        self,
        adapter=None,
        store=None,
        runbooks=None,
        policy=None,
        killswitch=None,
        approvals=None,
    ):
        self.adapter = adapter or MockAdapter()
        self.store = store or AuditStore()
        self.runbooks = validate_runbooks(
            {
                "runbooks": deepcopy(
                    runbooks
                    if runbooks is not None
                    else load_runbooks(DATA / "runbooks/runbooks.yaml")
                )
            }
        )
        self.policy = validate_policy(
            deepcopy(
                policy if policy is not None else load_policy(DATA / "policy.yaml")
            )
        )
        self.killswitch = killswitch or KillSwitch(self.store)
        self.approvals = approvals or ApprovalQueue(
            self.store, self.policy, lambda: getattr(self.adapter, "incident_id", None)
        )
        self.authority = PolicyAuthority()
        self.lock = RLock()
        self.active = {}
        self._dashboard_kill = False

    def killed(self):
        if self.killswitch:
            return self.killswitch.active()
        return (
            self._dashboard_kill
            or os.getenv("AUTOMATION_KILL", "").lower() not in ("", "0", "false", "no")
            or Path("/etc/automation/KILL").exists()
        )

    def context(self, own_action=None):
        now = self.store.clock()
        starts = self.store.runtime_events("execution_start")
        ends = self.store.runtime_events("execution_end")
        completed = {e["action_id"] for e in ends}
        incomplete = any(
            s["action_id"] not in completed and s["action_id"] not in self.active
            for s in starts
        )
        count = sum(
            s["timestamp"] > now - self.policy["rate_limit"]["window_seconds"]
            and s["action_id"] != own_action
            for s in starts
        )
        failures = 0
        for e in reversed(ends):
            if (
                e["outcome"] == "RESOLVED"
                or e["timestamp"]
                <= now - self.policy["circuit_breaker"]["reset_seconds"]
            ):
                break
            failures += 1
        return {
            "policy": self.policy,
            "kill": self.killed(),
            "circuit_open": incomplete
            or failures >= self.policy["circuit_breaker"]["failure_threshold"],
            "actions_in_window": count,
        }

    def _record(self, action_id, rb, obs, decision, **kwargs):
        return self.store.write(action_id, rb, obs, decision, **kwargs)

    def _finish_without_execution(self, action_id, rb, obs, decision, **kwargs):
        record = self._record(
            action_id,
            rb,
            obs,
            decision,
            event="closed",
            final_outcome=decision.outcome,
            **kwargs,
        )
        return {
            "action_id": action_id,
            "outcome": decision.outcome,
            "decision": decision.as_dict(),
            "audit": record,
        }

    def run(self, dry_run=False):
        with self.lock:
            if self.approvals:
                self.approvals.expire()
            action_id = str(uuid4())
            obs = {}
            rb = None
            try:
                obs = observe(self.adapter)
                candidate = match(self.runbooks, obs)
                rb = candidate["runbook"]
                decision = decide(candidate, obs, self.context())
                if dry_run:
                    record = self._record(
                        action_id,
                        rb,
                        obs,
                        decision,
                        event="closed",
                        final_outcome="DRY_RUN",
                    )
                    return {
                        "action_id": action_id,
                        "outcome": "DRY_RUN",
                        "decision": decision.as_dict(),
                        "plan": deepcopy(rb["steps"]) if rb else [],
                        "audit": record,
                    }
                if decision.outcome in ("REFUSE", "ESCALATE"):
                    return self._finish_without_execution(action_id, rb, obs, decision)
                # Incidents are assigned by the observer, never by an approver.
                incident = getattr(self.adapter, "incident_id", "observed-state")
                if any(
                    e["incident_id"] == incident and e["runbook_id"] == rb["id"]
                    for e in self.store.runtime_events("execution_start")
                ):
                    return self._finish_without_execution(
                        action_id,
                        rb,
                        obs,
                        Decision(
                            "ESCALATE",
                            [
                                "Remediation already attempted for this incident; no retry"
                            ],
                            {"never_repeat": False},
                        ),
                    )
                self._record(action_id, rb, obs, decision)
                if decision.outcome == "NEEDS_APPROVAL":
                    if not self.approvals:
                        return self._finish_without_execution(
                            action_id,
                            rb,
                            obs,
                            Decision(
                                "ESCALATE",
                                ["Approval service unavailable"],
                                {"approval": False},
                            ),
                        )
                    request = self.approvals.create(action_id, rb, obs)
                    return {
                        "action_id": action_id,
                        "outcome": "NEEDS_APPROVAL",
                        "decision": decision.as_dict(),
                        "approval_id": request["request_id"],
                    }
                return self._execute(action_id, rb, obs, decision, incident)
            except Exception as exc:
                return self._finish_without_execution(
                    action_id,
                    rb,
                    obs,
                    Decision(
                        "ESCALATE", [f"Fail-closed error: {exc}"], {"runtime": False}
                    ),
                )

    def _execute(self, action_id, rb, obs, decision, incident, request_id=None):
        if any(
            e["incident_id"] == incident and e["runbook_id"] == rb["id"]
            for e in self.store.runtime_events("execution_start")
        ):
            return self._finish_without_execution(
                action_id,
                rb,
                obs,
                Decision(
                    "ESCALATE",
                    ["Remediation already attempted for this incident; no retry"],
                    {"never_repeat": False},
                ),
            )
        approver = (
            self.approvals.approver(request_id)
            if request_id and self.approvals
            else None
        )
        approval_check = lambda: bool(
            request_id
            and self.approvals
            and self.approvals.valid(request_id, action_id)
        )
        candidate = match(self.runbooks, obs)
        token = self.authority.authorize(
            action_id, candidate, obs, self.context(), approval_valid=approval_check()
        )
        self.active[action_id] = {"runbook_id": rb["id"], "status": "EXECUTING"}
        execution = None
        rollback = "NOT_NEEDED"
        health = "NOT_RUN"
        outcome = "ESCALATE"
        error = None
        try:
            self.store.runtime(
                "execution_start",
                {
                    "action_id": action_id,
                    "incident_id": incident,
                    "runbook_id": rb["id"],
                },
            )
            if request_id:
                self.approvals.consume(request_id, action_id)

            def log(event, steps):
                results = steps if isinstance(steps, list) else [steps]
                self._record(
                    action_id,
                    rb,
                    observe(self.adapter),
                    decision,
                    event=event,
                    approver=approver,
                    step_results=results,
                )

            def boundary(expected, verification=False):
                current = observe(self.adapter)
                ctx = self.context(own_action=action_id)
                if ctx["kill"]:
                    raise ExecutionAborted("Kill switch activated at boundary")
                if ctx["circuit_open"]:
                    raise ExecutionAborted("Circuit breaker opened")
                if request_id and not approval_check():
                    raise ExecutionAborted("Approval expired or revoked")
                if current != expected:
                    raise ExecutionAborted(
                        "Observation changed since the previous authorized boundary"
                    )
                if not verification:
                    fresh = match(self.runbooks, current)
                    d = decide(fresh, current, ctx)
                    self._record(
                        action_id,
                        rb,
                        current,
                        d,
                        event="precondition_recheck",
                        approver=approver,
                    )
                    if (fresh.get("runbook") or {}).get("id") != rb[
                        "id"
                    ] or d.outcome not in ("AUTO", "NEEDS_APPROVAL"):
                        raise ExecutionAborted("; ".join(d.reasons))

            execution = Executor(self.adapter, self.authority).run(
                action_id, rb, token, obs, boundary, log
            )
            if execution["error"]:
                raise ExecutionAborted(execution["error"])
            health = (
                "PASSED"
                if verify(
                    self.adapter, rb["health_check"], boundary, execution["expected"]
                )
                else "FAILED"
            )
            self._record(
                action_id,
                rb,
                observe(self.adapter),
                decision,
                event="health_check",
                approver=approver,
                step_results=execution["steps"],
                health_result=health,
            )
            if health != "PASSED":
                raise ExecutionAborted(
                    "Health check failed; no remediation retry permitted"
                )
            outcome = "RESOLVED"
        except Exception as exc:
            error = str(exc)
            if execution:
                rollback = rollback_once(
                    rb,
                    execution,
                    lambda event, result: self._record(
                        action_id,
                        rb,
                        observe(self.adapter),
                        Decision("ESCALATE", [error], {"execution": False}),
                        event=event,
                        approver=approver,
                        step_results=[result],
                        rollback_status="IN_PROGRESS",
                    ),
                )
            decision = Decision(
                "ESCALATE",
                [error]
                + (
                    ["Rollback failed; operator intervention required"]
                    if rollback == "FAILED"
                    else []
                ),
                {"execution": False},
            )
        finally:
            self.authority.revoke(token)
            if request_id:
                self.approvals.close(request_id)
            self.active.pop(action_id, None)
        self.store.runtime(
            "execution_end", {"action_id": action_id, "outcome": outcome}
        )
        record = self._record(
            action_id,
            rb,
            observe(self.adapter),
            decision,
            event="closed",
            final_outcome=outcome,
            approver=approver,
            step_results=execution["steps"] if execution else [],
            health_result=health,
            rollback_status=rollback,
        )
        return {
            "action_id": action_id,
            "outcome": outcome,
            "decision": decision.as_dict(),
            "audit": record,
        }

    def resume(self, request_id):
        with self.lock:
            if not self.approvals:
                raise ValueError("Approval service unavailable")
            request = self.approvals.get(request_id)
            if not request:
                raise ValueError("Unknown approval")
            rb = next(
                (r for r in self.runbooks if r["id"] == request["runbook_id"]), None
            )
            obs = observe(self.adapter)
            action_id = request["action_id"]
            if not self.approvals.valid(request_id, action_id, unconsumed=True):
                return self._finish_without_execution(
                    action_id,
                    rb,
                    obs,
                    Decision(
                        "ESCALATE",
                        ["No valid unconsumed action-bound approval"],
                        {"approval": False},
                    ),
                )
            if (
                obs != request["observation"]
                or rb != request["runbook"]
                or getattr(self.adapter, "incident_id", None) != request["incident_id"]
            ):
                self.approvals.invalidate(
                    request_id,
                    "Approved observation, runbook, or incident binding changed",
                )
                return self._finish_without_execution(
                    action_id,
                    rb,
                    obs,
                    Decision(
                        "ESCALATE",
                        ["Approved action changed; obtain a new approval"],
                        {"approval_binding": False},
                    ),
                )
            candidate = match(self.runbooks, obs)
            d = decide(candidate, obs, self.context())
            self._record(
                action_id,
                rb,
                obs,
                d,
                event="approved_recheck",
                approver=self.approvals.approver(request_id),
            )
            if d.outcome != "NEEDS_APPROVAL":
                self.approvals.invalidate(
                    request_id,
                    "Policy no longer permits the approved action: "
                    + "; ".join(d.reasons),
                )
                return self._finish_without_execution(action_id, rb, obs, d)
            try:
                return self._execute(
                    action_id, rb, obs, d, request["incident_id"], request_id
                )
            except Exception as exc:
                return self._finish_without_execution(
                    action_id,
                    rb,
                    obs,
                    Decision("ESCALATE", [str(exc)], {"runtime": False}),
                )
