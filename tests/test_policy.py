from copy import deepcopy
import pytest
from aegisops.config import DATA
from aegisops.loader import load_policy, load_runbooks
from aegisops.policy import decide


@pytest.fixture
def case():
    rb = load_runbooks(DATA / "runbooks/runbooks.yaml")[0]
    return (
        {"runbook": rb, "confidence": 1.0, "ambiguous": False, "unknown": False},
        {"disk_used_pct": 95, "largest_consumer": "logs"},
        {
            "policy": load_policy(DATA / "policy.yaml"),
            "kill": False,
            "circuit_open": False,
            "actions_in_window": 0,
        },
    )


@pytest.mark.parametrize(
    "change,expected,check",
    [
        ("none", "AUTO", "global_rate_limit"),
        ("kill", "REFUSE", "kill_switch"),
        ("circuit", "REFUSE", "circuit_breaker"),
        ("no_match", "ESCALATE", "match"),
        ("unknown", "ESCALATE", "match"),
        ("ambiguous", "ESCALATE", "match"),
        ("confidence", "ESCALATE", "match"),
        ("t3", "REFUSE", "tier"),
        ("t2", "NEEDS_APPROVAL", "approval_required"),
        ("target", "ESCALATE", "blast_radius"),
        ("path", "ESCALATE", "blast_radius"),
        ("prefix", "ESCALATE", "blast_radius"),
        ("bytes", "ESCALATE", "blast_radius"),
        ("replicas", "ESCALATE", "blast_radius"),
        ("restarts", "ESCALATE", "blast_radius"),
        ("rate", "ESCALATE", "global_rate_limit"),
        ("missing", "ESCALATE", "kill_switch"),
        ("observation", "ESCALATE", "match"),
        ("budget_missing", "ESCALATE", "global_rate_limit"),
    ],
)
def test_table(case, change, expected, check):
    c, o, ctx = deepcopy(case)
    rb = c["runbook"]
    if change == "kill":
        ctx["kill"] = True
    if change == "circuit":
        ctx["circuit_open"] = True
    if change == "no_match":
        c["runbook"] = None
    if change in ("unknown", "ambiguous"):
        c[change] = True
    if change == "confidence":
        c["confidence"] = 0.8
    if change in ("t2", "t3"):
        rb["tier"] = change.upper()
    if change == "target":
        rb["steps"][0]["target"] = "production-admin"
    if change == "path":
        rb["steps"][0]["path"] = "/etc/passwd"
    if change == "prefix":
        rb["steps"][0]["path"] = "/data/log-other"
    if change == "bytes":
        rb["steps"][0]["bytes"] = 999999999
    if change == "replicas":
        rb["steps"][0]["replicas"] = 4
    if change == "restarts":
        rb["steps"][0]["restarts"] = 2
    if change == "rate":
        ctx["actions_in_window"] = 5
    if change == "missing":
        ctx.pop("kill")
    if change == "observation":
        o["disk_used_pct"] = None
    if change == "budget_missing":
        ctx.pop("actions_in_window")
    decision = decide(c, o, ctx)
    assert decision.outcome == expected
    assert check in decision.checks
    assert decision == decide(c, o, ctx)  # deterministic and inputs unchanged


def test_stop_at_first_failure(case):
    c, o, ctx = case
    ctx.update(kill=True, circuit_open=True)
    assert decide(c, o, ctx).checks == {"kill_switch": False}
