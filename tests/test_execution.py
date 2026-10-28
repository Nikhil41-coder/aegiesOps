from copy import deepcopy
import pytest
from sqlalchemy import text
from aegisops.audit import AuditStore, check_complete
from aegisops.config import DATA
from aegisops.loader import load_policy, load_runbooks
from aegisops.policy import PolicyAuthority, decide
from aegisops.adapters.mock import MockAdapter
from aegisops.executor import Executor, CapabilityGuard
from aegisops.verifier import rollback_once


def test_audit_and_changes_append_only():
    store = AuditStore()
    d = decide(None, {}, {"kill": True})
    r = store.write("a", None, {}, d)
    assert check_complete(r) == []
    assert check_complete(store.records()[0]) == []
    assert len(store.changes()) == 1
    for table in ("audit_records", "change_records"):
        for op in ("UPDATE " + table + " SET payload='{}'", "DELETE FROM " + table):
            with pytest.raises(Exception), store.engine.begin() as con:
                con.execute(text(op))


def test_guard_denies_before_adapter_call():
    rb = load_runbooks(DATA / "runbooks/runbooks.yaml")[0]
    a = MockAdapter()
    g = CapabilityGuard(a, rb)
    bad = deepcopy(rb["steps"][0])
    bad["path"] = "/data/crash"
    with pytest.raises(PermissionError):
        g.run(bad)
    assert a.calls == []


def test_execution_requires_grant():
    rb = load_runbooks(DATA / "runbooks/runbooks.yaml")[0]
    a = MockAdapter()
    authority = PolicyAuthority()
    with pytest.raises(PermissionError):
        Executor(a, authority).run(
            "a", rb, "fake", a.read_state(), lambda _: None, lambda *_: None
        )
    assert not a.calls


def test_completeness_detects_missing_resolution_evidence():
    record = {
        "final_outcome": "RESOLVED",
        "tier": "T2",
        "health_result": "NOT_RUN",
        "approver": None,
        "step_results": [],
    }
    missing = check_complete(record)
    assert "health_result.PASSED" in missing
    assert "approver.reason" in missing
    assert "step_results.nonempty" in missing
