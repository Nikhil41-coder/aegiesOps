"""Simulation only: effects are fixture data, never real commands."""

from copy import deepcopy
from uuid import uuid4
from .base import Adapter, StepError

BASELINE = dict(
    disk_used_pct=35,
    largest_consumer="none",
    crash_dir_nonempty=False,
    heartbeat_age_s=1,
    restarts_last_hour=0,
    queue_depth=0,
    queue_growing=False,
    consumer_count=1,
    cert_expires_in_hours=720,
    tmp_used_pct=15,
    replication_lag_s=0,
    pool_used_pct=20,
    idle_in_txn_count=0,
    recent_deploy_minutes=999,
    resolution_failures_1m=0,
    app_healthy=True,
)
FAULTS = {
    "log_full": {"disk_used_pct": 95, "largest_consumer": "logs"},
    "core_dump": {
        "disk_used_pct": 95,
        "largest_consumer": "core",
        "crash_dir_nonempty": True,
    },
    "logs_and_core": {
        "disk_used_pct": 95,
        "largest_consumer": "logs",
        "crash_dir_nonempty": True,
    },
    "worker_stalled": {"heartbeat_age_s": 120},
    "queue_backlog": {"queue_depth": 500, "queue_growing": True},
    "cert_expiring": {"cert_expires_in_hours": 2},
    "temp_full": {"tmp_used_pct": 95},
    "replication_lag": {"replication_lag_s": 120},
    "pool_full": {"pool_used_pct": 98},
    "recent_deploy": {"recent_deploy_minutes": 1, "app_healthy": False},
    "dns_failures": {"resolution_failures_1m": 60},
}


class MockAdapter(Adapter):
    def __init__(self, state=None):
        self.state = {**BASELINE, **(state or {})}
        self.calls = []
        self.incident_id = str(uuid4())
        self.fail_remediation = False
        self.fail_rollback = False
        self.after_step = None

    def inject(self, fault):
        names = fault if isinstance(fault, list) else [fault]
        if not names or any(not isinstance(n, str) or n not in FAULTS for n in names):
            raise ValueError("Unknown fault")
        self.state = deepcopy(BASELINE)
        combined = {}
        for name in names:
            for key, value in FAULTS[name].items():
                # Conflicting observations are UNKNOWN, never last-writer guesses.
                combined[key] = (
                    None if key in combined and combined[key] != value else value
                )
        self.state.update(combined)
        self.incident_id = str(uuid4())
        self.fail_remediation = False
        return self.read_state()

    def read_state(self):
        return deepcopy(self.state)

    def run_step(self, step, credential):
        self.calls.append(
            {
                "kind": "step",
                "step": deepcopy(step),
                "runbook_id": credential.runbook_id,
                "state_before": self.read_state(),
            }
        )
        effects = (
            step.get("simulation_effects", {}) if step["action"] != "observe" else {}
        )
        receipt = {
            "before": {k: self.state.get(k) for k in effects},
            "target": step["target"],
            "after": None,
        }
        if not self.fail_remediation:
            self.state.update(effects)
        receipt["after"] = self.read_state()
        if self.after_step:
            try:
                self.after_step(self, step)
            except Exception as exc:
                raise StepError(str(exc), receipt) from exc
        return receipt

    def rollback_step(self, step, credential, receipt):
        self.calls.append(
            {
                "kind": "rollback",
                "step": deepcopy(step),
                "runbook_id": credential.runbook_id,
                "state_before": self.read_state(),
            }
        )
        if self.fail_rollback:
            raise RuntimeError("Injected rollback failure")
        self.state.update(receipt["before"])
        return {"restored": True, "target": step["target"]}
