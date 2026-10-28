from copy import deepcopy
import pytest
from aegisops.orchestrator import Engine
from aegisops.audit import AuditStore
from aegisops.config import DATA
from aegisops.loader import SchemaError, load_yaml
from aegisops.matcher import match
from aegisops.policy import decide


def test_rollback_does_not_overwrite_external_changes():
    e = Engine()
    e.adapter.inject("log_full")
    e.adapter.after_step = lambda a, _: a.state.update(disk_used_pct=20)
    r = e.run()
    assert r["outcome"] == "ESCALATE" and r["audit"]["rollback_status"] == "FAILED"
    assert e.adapter.state["disk_used_pct"] == 20
    assert len(e.adapter.calls) == 1


def test_rollback_success_is_verified():
    e = Engine()
    e.adapter.inject("log_full")
    e.adapter.after_step = lambda *_: e.killswitch.set(True)
    e.adapter.rollback_step = lambda *_: {"restored": True}
    r = e.run()
    assert r["audit"]["rollback_status"] == "FAILED"


def test_adapter_exception_after_mutation_preserves_receipt():
    e = Engine()
    e.adapter.inject("log_full")

    def broken(*_):
        raise RuntimeError("Injected post-mutation error")

    e.adapter.after_step = broken
    r = e.run()
    assert r["outcome"] == "ESCALATE" and r["audit"]["rollback_status"] == "COMPLETED"
    assert e.adapter.state["disk_used_pct"] == 95


def test_second_pending_approval_cannot_repeat_failed_fix():
    e = Engine()
    e.adapter.inject("cert_expiring")
    e.adapter.fail_remediation = True
    first = e.run()["approval_id"]
    second = e.run()["approval_id"]
    for rid in (first, second):
        e.approvals.approve(rid, "operator", "Reviewed exact plan")
    assert e.resume(first)["outcome"] == "ESCALATE"
    count = len(e.adapter.calls)
    assert e.resume(second)["outcome"] == "ESCALATE"
    assert len(e.adapter.calls) == count


def test_rate_and_breaker_time_windows():
    now = [1000.0]
    e = Engine(store=AuditStore(clock=lambda: now[0]))
    for i in range(3):
        e.store.runtime("execution_end", {"action_id": str(i), "outcome": "ESCALATE"})
    assert e.context()["circuit_open"]
    now[0] += 301
    assert not e.context()["circuit_open"]
    for i in range(5):
        e.store.runtime(
            "execution_start",
            {"action_id": str(i), "incident_id": str(i), "runbook_id": "other"},
        )
        e.store.runtime("execution_end", {"action_id": str(i), "outcome": "RESOLVED"})
    e.adapter.inject("log_full")
    assert e.run()["outcome"] == "ESCALATE"
    now[0] += 3601
    assert e.run()["outcome"] == "RESOLVED"


def test_unfinished_execution_is_quarantined_after_restart(tmp_path):
    url = "sqlite:///" + str(tmp_path / "audit.db")
    store = AuditStore(url)
    store.runtime(
        "execution_start",
        {"action_id": "unfinished", "incident_id": "incident", "runbook_id": "RB-01"},
    )
    e = Engine(store=AuditStore(url))
    e.adapter.inject("log_full")
    assert e.run()["outcome"] == "REFUSE" and not e.adapter.calls


def test_duplicate_yaml_keys_are_not_silently_overwritten(tmp_path):
    f = tmp_path / "duplicate.yaml"
    f.write_text("tier: T3\ntier: T1\n")
    with pytest.raises(SchemaError):
        load_yaml(f)


def test_protected_descendant_cannot_be_pruned_via_parent():
    e = Engine()
    e.adapter.inject("log_full")
    rb = e.runbooks[0]
    e.policy["blast_radius"]["allowed_paths"].append("/data")
    for key in ("steps", "rollback", "capabilities"):
        for step in rb[key]:
            step["path"] = "/data"
    assert (
        decide(
            match(e.runbooks, e.adapter.read_state()),
            e.adapter.read_state(),
            e.context(),
        ).outcome
        == "ESCALATE"
    )


def test_plan_tampering_invalidates_policy_grant():
    e = Engine()
    e.adapter.inject("log_full")
    c = match(e.runbooks, e.adapter.read_state())
    token = e.authority.authorize("action", c, e.adapter.read_state(), e.context())
    changed = deepcopy(c["runbook"])
    changed["steps"][0]["path"] = "/data/crash"
    assert not e.authority.validate(token, "action", changed)


def test_docker_never_silently_activates():
    from aegisops.adapters.docker_adapter import DockerAdapter

    with pytest.raises(RuntimeError):
        DockerAdapter()


def test_change_start_time_is_stable_across_events():
    e = Engine()
    e.adapter.inject("log_full")
    e.run()
    changes = e.store.changes()
    assert len({c["start"] for c in changes}) == 1
    assert changes[-1]["end"] is not None


def test_nonfinite_observation_is_unknown_with_valid_json_audit():
    import json

    e = Engine()
    e.adapter.inject("log_full")
    e.adapter.state["disk_used_pct"] = float("nan")
    r = e.run()
    assert r["outcome"] == "ESCALATE" and not e.adapter.calls
    assert r["audit"]["observation"]["disk_used_pct"] is None
    json.dumps(r["audit"], allow_nan=False)


def test_health_success_outside_deadline_is_failure():
    from aegisops.verifier import verify
    from aegisops.adapters.mock import MockAdapter

    times = iter([0.0, 2.0])
    adapter = MockAdapter()
    assert not verify(
        adapter,
        {"conditions": ["disk_used_pct < 85"], "timeout_seconds": 1},
        lambda *_args, **_kwargs: None,
        adapter.read_state(),
        clock=lambda: next(times),
    )


def test_replica_budget_is_aggregate_across_plan():
    e = Engine()
    e.adapter.inject("queue_backlog")
    rb = e.runbooks[3]
    rb["steps"].append(deepcopy(rb["steps"][0]))
    c = match(e.runbooks, e.adapter.read_state())
    assert decide(c, e.adapter.read_state(), e.context()).outcome == "ESCALATE"
