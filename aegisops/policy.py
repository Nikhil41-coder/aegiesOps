"""Pure, ordered policy decisions. No adapter, model, shell, or network access."""

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from .loader import parse_condition, path_ok, validate_step


@dataclass(frozen=True)
class Decision:
    outcome: str
    reasons: list[str]
    checks: dict[str, bool] = field(default_factory=dict)

    def as_dict(self):
        return {"outcome": self.outcome, "reasons": self.reasons, "checks": self.checks}


def inside(path, root):
    return path == root or PurePosixPath(root) in PurePosixPath(path).parents


def blast_safe(runbook, policy):
    b = policy["blast_radius"]
    totals = {"bytes": 0, "restarts": 0, "replicas": 0}
    for step in runbook["steps"] + runbook["rollback"]:
        validate_step(step)
        if step["action"] == "observe":
            continue
        if step["target"] not in b["targets"]:
            return False
        path = step.get("path")
        if path and (
            not path_ok(path)
            or not any(inside(path, r) for r in b["allowed_paths"])
            or any(inside(path, r) or inside(r, path) for r in b["protected_paths"])
        ):
            return False
        for key in totals:
            totals[key] += step.get(key, 0)
        if step.get("replicas", 0) > b["max_replicas"]:
            return False
    return (
        totals["bytes"] <= b["max_bytes"]
        and totals["restarts"] <= b["max_restarts"]
        and totals["replicas"] <= b["max_replicas"]
    )


def decide(candidate, observation, context):
    """candidate: {runbook, confidence, ambiguous, unknown}; context carries facts."""
    checks = {}

    def check(name, passed, outcome, reason):
        checks[name] = bool(passed)
        return None if passed else Decision(outcome, [reason], dict(checks))

    try:
        # Missing safety context is itself an unknown, never an implicit pass.
        if "kill" not in context or type(context["kill"]) is not bool:
            return Decision(
                "ESCALATE", ["Kill switch state unavailable"], {"kill_switch": False}
            )
        failed = check(
            "kill_switch", not context["kill"], "REFUSE", "Kill switch is active"
        )
        if failed:
            return failed
        if "circuit_open" not in context or type(context["circuit_open"]) is not bool:
            return Decision(
                "ESCALATE",
                ["Circuit state unavailable"],
                {**checks, "circuit_breaker": False},
            )
        failed = check(
            "circuit_breaker",
            not context["circuit_open"],
            "REFUSE",
            "Circuit breaker is open",
        )
        if failed:
            return failed
        p = context["policy"]
        rb = candidate.get("runbook") if candidate else None
        match_ok = bool(
            rb
            and not candidate.get("ambiguous", True)
            and not candidate.get("unknown", True)
            and type(candidate.get("confidence")) in (int, float)
            and candidate["confidence"] >= p["ambiguity"]["min_confidence"]
        )
        if match_ok:
            applies = [parse_condition(c).test(observation) for c in rb["applies_when"]]
            excludes = [parse_condition(c).test(observation) for c in rb["not_when"]]
            match_ok = all(v is True for v in applies) and all(
                v is False for v in excludes
            )
        failed = check(
            "match",
            match_ok,
            "ESCALATE",
            "No unique confident match, unknown state, or changed preconditions",
        )
        if failed:
            return failed
        failed = check(
            "tier",
            rb["tier"] != "T3",
            "REFUSE",
            "T3 is read-only: page a human with observation context",
        )
        if failed:
            return failed
        failed = check(
            "blast_radius",
            blast_safe(rb, p),
            "ESCALATE",
            "Blast radius exceeds an allowlist or bound",
        )
        if failed:
            return failed
        count = context.get("actions_in_window")
        failed = check(
            "global_rate_limit",
            type(count) is int and 0 <= count < p["rate_limit"]["max_actions"],
            "ESCALATE",
            "Global action rate limit reached or unavailable",
        )
        if failed:
            return failed
        if rb["tier"] == "T2":
            checks["approval_required"] = True
            return Decision(
                "NEEDS_APPROVAL",
                ["T2 requires a recorded, unexpired action-bound approval"],
                checks,
            )
        if rb["tier"] not in ("T0", "T1"):
            return Decision("ESCALATE", ["Unknown tier"], {**checks, "tier": False})
        return Decision("AUTO", ["All deterministic policy checks passed"], checks)
    except (KeyError, TypeError, ValueError, AttributeError):
        return Decision(
            "ESCALATE",
            ["Invalid or missing policy input"],
            {**checks, "valid_input": False},
        )


# Runtime authority mints opaque, action-bound grants only after deterministic checks.
# Grants are not exposed through HTTP and are invalid for changed plans.
import hashlib
import json
import secrets


def plan_hash(runbook):
    return hashlib.sha256(
        json.dumps(runbook, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class PolicyAuthority:
    def __init__(self):
        self._grants = {}

    def authorize(
        self, action_id, candidate, observation, context, approval_valid=False
    ):
        decision = decide(candidate, observation, context)
        allowed = decision.outcome == "AUTO" or (
            decision.outcome == "NEEDS_APPROVAL" and approval_valid is True
        )
        if not allowed:
            raise PermissionError("; ".join(decision.reasons))
        token = secrets.token_urlsafe(32)
        self._grants[token] = (action_id, plan_hash(candidate["runbook"]))
        return token

    def validate(self, token, action_id, runbook):
        return self._grants.get(token) == (action_id, plan_hash(runbook))

    def revoke(self, token):
        self._grants.pop(token, None)
