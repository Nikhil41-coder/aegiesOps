"""Three cold runbooks: only data/policy inputs change, no engine code."""

from copy import deepcopy
import pytest
from aegisops.config import DATA
from aegisops.loader import validate_runbooks, load_policy
from aegisops.orchestrator import Engine
from aegisops.adapters.mock import MockAdapter

# Deliberately inline and absent from the shipped registry.
COLD_BOOKS = [
    {
        "id": "COLD-SWAP",
        "name": "Refresh exhausted swap fixture",
        "tier": "T1",
        "applies_when": ["swap_used_pct >= 95"],
        "not_when": [],
        "steps": [
            {
                "action": "refresh",
                "target": "swap",
                "simulation_effects": {"swap_used_pct": 30},
            }
        ],
        "health_check": {"conditions": ["swap_used_pct < 80"], "timeout_seconds": 0.05},
        "rollback": [{"action": "restore", "target": "swap"}],
        "reversible": True,
        "capabilities": [
            {"action": "refresh", "target": "swap"},
            {"action": "restore", "target": "swap"},
        ],
    },
    {
        "id": "COLD-ZOMBIES",
        "name": "Clean isolated zombie fixture",
        "tier": "T0",
        "applies_when": ["zombie_count > 10"],
        "not_when": ["critical_process == true"],
        "steps": [
            {
                "action": "cleanup",
                "target": "zombies",
                "path": "/data/tmp",
                "bytes": 1,
                "simulation_effects": {"zombie_count": 0},
            }
        ],
        "health_check": {"conditions": ["zombie_count == 0"], "timeout_seconds": 0.05},
        "rollback": [{"action": "restore", "target": "zombies", "path": "/data/tmp"}],
        "reversible": True,
        "capabilities": [
            {"action": "cleanup", "target": "zombies", "path": "/data/tmp", "bytes": 1},
            {"action": "restore", "target": "zombies", "path": "/data/tmp"},
        ],
    },
    {
        "id": "COLD-TOKEN",
        "name": "Rotate expired isolated token fixture",
        "tier": "T2",
        "applies_when": ["token_expires_in_s < 0"],
        "not_when": [],
        "steps": [
            {
                "action": "rotate",
                "target": "token",
                "path": "/data/certs",
                "simulation_effects": {"token_expires_in_s": 3600},
            }
        ],
        "health_check": {
            "conditions": ["token_expires_in_s > 600"],
            "timeout_seconds": 0.05,
        },
        "rollback": [{"action": "restore", "target": "token", "path": "/data/certs"}],
        "reversible": True,
        "capabilities": [
            {"action": "rotate", "target": "token", "path": "/data/certs"},
            {"action": "restore", "target": "token", "path": "/data/certs"},
        ],
    },
]
BASE = {
    "swap_used_pct": 0,
    "zombie_count": 0,
    "critical_process": False,
    "token_expires_in_s": 3600,
}


@pytest.mark.parametrize(
    "index,state",
    [
        (0, {"swap_used_pct": 98}),
        (1, {"zombie_count": 20}),
        (2, {"token_expires_in_s": -5}),
    ],
)
def test_cold_runbooks(index, state):
    books = validate_runbooks({"runbooks": deepcopy(COLD_BOOKS)})
    policy = load_policy(DATA / "policy.yaml")
    # New resource names must be explicitly authorized in POLICY DATA.
    policy["blast_radius"]["targets"] += ["swap", "zombies", "token"]
    engine = Engine(
        adapter=MockAdapter({**BASE, **state}), runbooks=books, policy=policy
    )
    result = engine.run()
    if index == 2:
        assert not engine.adapter.calls
        engine.approvals.approve(
            result["approval_id"], "cold-run-reviewer", "Reviewed new runbook scope"
        )
        result = engine.resume(result["approval_id"])
    assert result["outcome"] == "RESOLVED"
    assert result["audit"]["runbook_id"] == COLD_BOOKS[index]["id"]


def test_cold_unknown_and_ambiguous_still_escalate():
    policy = load_policy(DATA / "policy.yaml")
    policy["blast_radius"]["targets"] += ["swap", "zombies", "token"]
    for state in ({"swap_used_pct": None}, {"swap_used_pct": 98, "zombie_count": 20}):
        e = Engine(
            adapter=MockAdapter({**BASE, **state}),
            runbooks=deepcopy(COLD_BOOKS),
            policy=policy,
        )
        assert e.run()["outcome"] == "ESCALATE" and not e.adapter.calls
