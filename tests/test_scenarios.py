"""Tests AUTHORED demo fixtures; these are not organizer ground truth."""

from copy import deepcopy
import pytest
from aegisops.audit import AuditStore, check_complete
from aegisops.config import DATA
from aegisops.loader import load_yaml, load_runbooks
from aegisops.orchestrator import Engine
from aegisops.policy import inside

SCENARIOS = load_yaml(DATA / "scenarios.yaml")["scenarios"]


def unsafe_actions(engine, labels):
    calls = engine.adapter.calls
    mutations = [
        c for c in calls if c["kind"] == "step" and c["step"]["action"] != "observe"
    ]
    found = []
    for label in labels:
        if label == "any_mutation" and mutations:
            found.append(label)
        if label == "protected_mutation" and any(
            any(
                inside(c["step"].get("path", "/nowhere"), p)
                for p in engine.policy["blast_radius"]["protected_paths"]
            )
            for c in mutations
        ):
            found.append(label)
        if label == "over_budget" and any(
            c["step"].get("bytes", 0) > engine.policy["blast_radius"]["max_bytes"]
            or c["step"].get("replicas", 0)
            > engine.policy["blast_radius"]["max_replicas"]
            or c["step"].get("restarts", 0)
            > engine.policy["blast_radius"]["max_restarts"]
            for c in mutations
        ):
            found.append(label)
        if label == "second_attempt" and len(mutations) > 1:
            found.append(label)
        if (
            label == "unapproved_t2"
            and mutations
            and not any(
                r.get("approver") and r["event"] == "approval_granted"
                for r in engine.store.records()
            )
        ):
            found.append(label)
    return found


@pytest.mark.parametrize(
    "scenario",
    SCENARIOS,
    ids=lambda s: s["id"] + "-" + s["control"] if "control" in s else s["id"],
)
def test_scenario(scenario):
    now = [1000.0]
    books = deepcopy(load_runbooks(DATA / "runbooks/runbooks.yaml"))
    control = scenario.get("control")
    if control in ("change_state", "kill_midrun"):
        # Insert a declared read-only preparation step to test the next boundary.
        preparation = {"action": "observe", "target": "logs", "path": "/data/log"}
        books[0]["steps"].insert(0, preparation)
        books[0]["capabilities"].append(preparation)
    if control == "protected_path":
        for key in ("steps", "rollback", "capabilities"):
            for step in books[0][key]:
                step["path"] = "/data/crash"
    e = Engine(store=AuditStore(clock=lambda: now[0]), runbooks=books)
    e.adapter.inject(scenario["fault"])
    if control == "unknown":
        e.adapter.state["disk_used_pct"] = None
    if control == "fail_health":
        e.adapter.fail_remediation = True
    if control == "change_state":
        e.adapter.after_step = lambda a, _: a.state.update(
            largest_consumer="core", crash_dir_nonempty=True
        )
    if control == "kill_midrun":
        e.adapter.after_step = lambda *_: e.killswitch.set(True)
    if control == "rate_limit":
        for i in range(e.policy["rate_limit"]["max_actions"]):
            e.store.runtime(
                "execution_start",
                {"action_id": str(i), "runbook_id": "other", "incident_id": str(i)},
            )
            e.store.runtime(
                "execution_end", {"action_id": str(i), "outcome": "RESOLVED"}
            )
    if control == "circuit_open":
        for i in range(e.policy["circuit_breaker"]["failure_threshold"]):
            e.store.runtime(
                "execution_end", {"action_id": str(i), "outcome": "ESCALATE"}
            )
    result = e.run()
    if control == "approve":
        e.approvals.approve(
            result["approval_id"],
            "scenario-operator",
            "Reviewed this exact demo action",
        )
        result = e.resume(result["approval_id"])
    if control == "timeout":
        now[0] += e.policy["approval"]["timeout_minutes"] * 60 + 1
        e.approvals.expire()
        result = e.resume(result["approval_id"])
        assert e.approvals.all()[0]["status"] == "DENIED_TIMEOUT"
    assert result["outcome"] == scenario["expected"]
    assert not unsafe_actions(e, scenario["unsafe"])
    if "rollback" in scenario:
        assert result["audit"]["rollback_status"] == scenario["rollback"]
    assert e.store.records() and len(e.store.records()) == len(e.store.changes())
    assert all(check_complete(r) == [] for r in e.store.records())
