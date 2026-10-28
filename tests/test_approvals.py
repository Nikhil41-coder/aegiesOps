import pytest
from aegisops.orchestrator import Engine
from aegisops.audit import AuditStore


def pending():
    e = Engine()
    e.adapter.inject("cert_expiring")
    r = e.run()
    assert r["outcome"] == "NEEDS_APPROVAL" and not e.adapter.calls
    return e, r["approval_id"]


def test_approve_execute_and_cannot_reuse():
    e, rid = pending()
    e.approvals.approve(rid, "on-call", "Reviewed staging certificate rotation")
    r = e.resume(rid)
    assert r["outcome"] == "RESOLVED"
    assert r["audit"]["approver"]["name"] == "on-call"
    assert e.resume(rid)["outcome"] == "ESCALATE"
    assert len(e.adapter.calls) == 1


def test_no_approver_or_reason():
    e, rid = pending()
    for person, reason in [("", "reason"), ("operator", "")]:
        with pytest.raises(ValueError):
            e.approvals.approve(rid, person, reason)
    assert not e.adapter.calls


def test_timeout_denies_and_audits():
    now = [1000.0]
    e = Engine(store=AuditStore(clock=lambda: now[0]))
    e.adapter.inject("cert_expiring")
    rid = e.run()["approval_id"]
    now[0] += 301
    e.approvals.expire()
    assert e.approvals.get(rid)["status"] == "DENIED_TIMEOUT"
    assert e.resume(rid)["outcome"] == "ESCALATE"
    assert not e.adapter.calls
    assert any(
        r["event"] == "approval_timeout" and r["final_outcome"] == "ESCALATE"
        for r in e.store.records()
    )


def test_changed_state_does_not_use_old_approval():
    e, rid = pending()
    approved_state = e.adapter.read_state()
    e.approvals.approve(rid, "operator", "reviewed")
    e.adapter.state["cert_expires_in_hours"] = 1

    assert e.resume(rid)["outcome"] == "ESCALATE"
    assert e.approvals.get(rid)["status"] == "REVOKED"
    assert not e.adapter.calls


    e.adapter.state = approved_state
    assert e.resume(rid)["outcome"] == "ESCALATE"
    assert not e.adapter.calls


def test_policy_refusal_invalidates_approved_request():
    e, rid = pending()
    e.approvals.approve(rid, "operator", "reviewed")
    e.killswitch.set(True)

    assert e.resume(rid)["outcome"] == "REFUSE"
    assert e.approvals.get(rid)["status"] == "REVOKED"

    e.killswitch.set(False)
    assert e.resume(rid)["outcome"] == "ESCALATE"
    assert e.adapter.calls == []


def test_changed_incident_invalidates_approved_request():
    e, rid = pending()
    e.approvals.approve(rid, "operator", "reviewed")
    e.adapter.inject("cert_expiring")

    assert e.resume(rid)["outcome"] == "ESCALATE"
    assert e.approvals.get(rid)["status"] == "REVOKED"
    assert e.adapter.calls == []


def test_revocation_after_mutation_rolls_back():
    e, rid = pending()
    e.approvals.approve(rid, "operator", "reviewed")
    e.adapter.after_step = lambda *_: e.approvals.deny(rid, "operator", "revoke now")
    r = e.resume(rid)
    assert r["outcome"] == "ESCALATE" and r["audit"]["rollback_status"] == "COMPLETED"
    assert e.adapter.state["cert_expires_in_hours"] == 2


def test_approval_bound_to_action_id():
    e, rid = pending()
    e.approvals.approve(rid, "operator", "reviewed")
    assert not e.approvals.valid(rid, "another-action")
