from aegisops.orchestrator import Engine
from aegisops.killswitch import KillSwitch
from aegisops.audit import AuditStore


def test_file_environment_and_dashboard(tmp_path, monkeypatch):
    store = AuditStore()
    path = tmp_path / "KILL"
    k = KillSwitch(store, path)
    assert not k.active()
    path.touch()
    assert k.active()
    path.unlink()
    monkeypatch.setenv("AUTOMATION_KILL", "1")
    assert k.active()
    k.set(False)
    assert k.active()
    monkeypatch.delenv("AUTOMATION_KILL")
    assert not k.active()
    k.set(True)
    assert KillSwitch(store, path).active()


def test_inflight_kill_compensates():
    e = Engine()
    e.adapter.inject("log_full")
    e.adapter.after_step = lambda *_: e.killswitch.set(True)
    r = e.run()
    assert r["outcome"] == "ESCALATE" and r["audit"]["rollback_status"] == "COMPLETED"
    assert e.adapter.state["disk_used_pct"] == 95
    assert e.run()["outcome"] == "REFUSE"
