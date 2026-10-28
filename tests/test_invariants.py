"""Explicit evidence for each of the nine hard invariants."""

from copy import deepcopy
import pytest
from aegisops.adapters.mock import MockAdapter
from aegisops.audit import AuditStore, check_complete
from aegisops.config import DATA
from aegisops.executor import CapabilityGuard, Executor
from aegisops.loader import SchemaError, load_runbooks, validate_runbooks
from aegisops.orchestrator import Engine
from aegisops.policy import PolicyAuthority


def test_invariant_1_only_policy_can_authorize():
    e = Engine()
    e.adapter.inject("log_full")
    rb = e.runbooks[0]
    with pytest.raises(PermissionError):
        Executor(e.adapter, e.authority).run(
            "attacker",
            rb,
            "AUTO",
            e.adapter.read_state(),
            lambda _: None,
            lambda *_: None,
        )
    assert not e.adapter.calls
    raw = {"runbooks": deepcopy(e.runbooks)}
    raw["runbooks"][0]["steps"][0]["shell"] = "touch /etc/unsafe"
    with pytest.raises(SchemaError):
        validate_runbooks(raw)


def test_invariant_2_unknown_errors_and_missing_fail_closed():
    for case in ("unknown", "observer_error", "no_match"):
        e = Engine()
        e.adapter.inject("log_full")
        if case == "unknown":
            e.adapter.state["disk_used_pct"] = None
        if case == "no_match":
            e.adapter.state.update(disk_used_pct=30, largest_consumer="none")
        if case == "observer_error":

            def broken():
                raise RuntimeError("Unavailable telemetry")

            e.adapter.read_state = broken
        assert e.run()["outcome"] == "ESCALATE"
        assert not e.adapter.calls and e.store.records()


def test_invariant_3_t3_never_mutates():
    e = Engine()
    e.adapter.inject("core_dump")
    assert e.run()["outcome"] == "REFUSE" and not e.adapter.calls
    books = deepcopy(e.runbooks)
    books[0]["tier"] = "T3"
    with pytest.raises(SchemaError):
        Engine(runbooks=books)


def test_invariant_4_t2_requires_complete_action_bound_approval():
    e = Engine()
    e.adapter.inject("cert_expiring")
    r = e.run()
    assert r["outcome"] == "NEEDS_APPROVAL" and not e.adapter.calls
    assert e.resume(r["approval_id"])["outcome"] == "ESCALATE"
    assert not e.adapter.calls
    e.approvals.approve(r["approval_id"], "on-call", "Reviewed scope")
    assert not e.approvals.valid(r["approval_id"], "other-action")
    assert e.resume(r["approval_id"])["outcome"] == "RESOLVED"
    record = e.store.records()[-1]
    assert all(record["approver"][k] for k in ("name", "timestamp", "reason"))


def test_invariant_5_recheck_before_every_step():
    books = load_runbooks(DATA / "runbooks/runbooks.yaml")
    step = {"action": "observe", "target": "logs", "path": "/data/log"}
    books[0]["steps"].insert(0, step)
    books[0]["capabilities"].append(step)
    e = Engine(runbooks=books)
    e.adapter.inject("log_full")
    e.adapter.after_step = lambda a, _: a.state.update(largest_consumer="core")
    assert e.run()["outcome"] == "ESCALATE"
    assert [c["step"]["action"] for c in e.adapter.calls] == ["observe"]


def test_invariant_6_rollback_once_no_retry_even_if_rollback_fails():
    e = Engine()
    e.adapter.inject("log_full")
    e.adapter.fail_remediation = True
    e.adapter.fail_rollback = True
    r = e.run()
    assert r["outcome"] == "ESCALATE" and r["audit"]["rollback_status"] == "FAILED"
    assert [c["kind"] for c in e.adapter.calls] == ["step", "rollback"]
    assert e.run()["outcome"] == "ESCALATE" and len(e.adapter.calls) == 2


def test_invariant_7_every_decision_has_complete_audit_and_change():
    for fault in ("log_full", "core_dump", "logs_and_core", "cert_expiring"):
        e = Engine()
        e.adapter.inject(fault)
        e.run()
        assert e.store.records() and all(
            not check_complete(r) for r in e.store.records()
        )
        assert len(e.store.records()) == len(e.store.changes())


def test_invariant_8_new_and_inflight_kill_switches():
    e = Engine()
    e.adapter.inject("log_full")
    e.killswitch.set(True)
    assert e.run()["outcome"] == "REFUSE" and not e.adapter.calls
    e.killswitch.set(False)
    e.adapter.after_step = lambda *_: e.killswitch.set(True)
    r = e.run()
    assert r["outcome"] == "ESCALATE" and r["audit"]["rollback_status"] == "COMPLETED"
    assert e.adapter.state["disk_used_pct"] == 95


def test_invariant_9_credentials_are_per_runbook_and_scoped():
    e = Engine()
    rb = e.runbooks[0]
    guard = CapabilityGuard(e.adapter, rb)
    assert guard.credential.runbook_id == "RB-01"
    for fields in (
        {"action": "deploy"},
        {"target": "app"},
        {"path": "/data/crash"},
        {"bytes": 999999999},
    ):
        step = {**rb["steps"][0], **fields}
        with pytest.raises(PermissionError):
            guard.run(step)
    assert not e.adapter.calls
    assert guard.credential != CapabilityGuard(e.adapter, e.runbooks[4]).credential
