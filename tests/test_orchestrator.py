from aegisops.orchestrator import Engine
from aegisops.audit import check_complete


def test_auto_resolves_and_no_retry():
    e = Engine()
    e.adapter.inject("log_full")
    assert e.run()["outcome"] == "RESOLVED"
    assert len(e.adapter.calls) == 1
    assert all(not check_complete(r) for r in e.store.records())
    assert e.run()["outcome"] == "ESCALATE"  # healthy, no matching runbook


def test_one_rollback_and_persistent_no_retry():
    e = Engine()
    e.adapter.inject("log_full")
    e.adapter.fail_remediation = True
    result = e.run()
    assert result["outcome"] == "ESCALATE"
    assert result["audit"]["rollback_status"] == "COMPLETED"
    assert [c["kind"] for c in e.adapter.calls] == ["step", "rollback"]
    assert e.run()["outcome"] == "ESCALATE"
    assert len(e.adapter.calls) == 2


def test_forbidden_and_ambiguous_do_nothing():
    for fault, outcome in [("core_dump", "REFUSE"), ("logs_and_core", "ESCALATE")]:
        e = Engine()
        e.adapter.inject(fault)
        assert e.run()["outcome"] == outcome
        assert e.adapter.calls == []
