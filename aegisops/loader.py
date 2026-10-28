"""Strict schemas and a deliberately small comparison language; never eval."""

from dataclasses import dataclass
import math
import operator
from pathlib import PurePosixPath
import re
import yaml


class SchemaError(ValueError):
    pass


OPS = {
    "==": operator.eq,
    "!=": operator.ne,
    ">=": operator.ge,
    "<=": operator.le,
    ">": operator.gt,
    "<": operator.lt,
}
ACTIONS = {
    "observe",
    "prune",
    "restart",
    "scale",
    "rotate",
    "recycle",
    "deploy",
    "refresh",
    "cleanup",
    "restore",
}
PATTERN = re.compile(
    r'^([a-z][a-z0-9_]*)\s*(==|!=|>=|<=|>|<)\s*(true|false|-?\d+(?:\.\d+)?|"[^"\\\n]*"|\x27[^\x27\\\n]*\x27)$'
)


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    value: object

    def test(self, observation):
        actual = observation.get(self.field)
        if (
            actual is None
            or type(actual) is not type(self.value)
            and not (type(actual) in (int, float) and type(self.value) in (int, float))
        ):
            return None
        if isinstance(actual, float) and not math.isfinite(actual):
            return None
        try:
            return bool(OPS[self.op](actual, self.value))
        except (TypeError, ValueError):
            return None


def parse_condition(text):
    match = PATTERN.fullmatch(text.strip()) if isinstance(text, str) else None
    if not match:
        raise SchemaError(f"Invalid comparison: {text!r}")
    field, op, literal = match.groups()
    value = yaml.safe_load(literal)
    if op not in ("==", "!=") and type(value) not in (int, float):
        raise SchemaError("Ordering requires a numeric literal")
    return Condition(field, op, value)


def require(condition, message):
    if not condition:
        raise SchemaError(message)


def path_ok(path):
    return (
        isinstance(path, str)
        and path.startswith("/")
        and str(PurePosixPath(path)) == path
        and ".." not in PurePosixPath(path).parts
        and "\x00" not in path
    )


def _keys(value, required, optional=()):
    require(isinstance(value, dict), "Expected mapping")
    require(
        set(required) <= value.keys(), f"Missing fields: {set(required) - value.keys()}"
    )
    require(
        not value.keys() - set(required) - set(optional),
        f"Unknown fields: {value.keys() - set(required) - set(optional)}",
    )


def validate_step(step, capability=False):
    _keys(
        step,
        {"action", "target"},
        {"path", "bytes", "replicas", "restarts", "simulation_effects"},
    )
    require(step["action"] in ACTIONS, "Unsupported action")
    require(
        isinstance(step["target"], str)
        and bool(re.fullmatch(r"[a-zA-Z0-9_-]+", step["target"])),
        "Invalid target",
    )
    if "path" in step:
        require(path_ok(step["path"]), "Path must be absolute and canonical")
    for key in ("bytes", "replicas", "restarts"):
        if key in step:
            require(type(step[key]) is int and step[key] >= 0, f"Invalid {key}")
    for action, fields in {
        "restart": ("restarts",),
        "scale": ("replicas",),
        "prune": ("path", "bytes"),
        "cleanup": ("path", "bytes"),
    }.items():
        if step["action"] == action:
            require(all(f in step for f in fields), f"{action} requires {fields}")
    if step["action"] == "observe":
        require(
            not step.get("simulation_effects"),
            "Read-only steps cannot declare mutations",
        )
    if "simulation_effects" in step:
        require(
            not capability and isinstance(step["simulation_effects"], dict),
            "Invalid simulation effects",
        )
        for key, val in step["simulation_effects"].items():
            require(
                isinstance(key, str) and re.fullmatch(r"[a-z][a-z0-9_]*", key),
                "Invalid metric",
            )
            require(type(val) in (int, float, str, bool), "Invalid effect value")
    return step


def validate_runbooks(raw):
    _keys(raw, {"runbooks"})
    require(isinstance(raw["runbooks"], list) and raw["runbooks"], "No runbooks")
    ids = set()
    for rb in raw["runbooks"]:
        _keys(
            rb,
            {
                "id",
                "name",
                "tier",
                "applies_when",
                "not_when",
                "steps",
                "health_check",
                "rollback",
                "reversible",
                "capabilities",
            },
        )
        require(
            isinstance(rb["id"], str) and rb["id"] not in ids,
            "Duplicate or invalid runbook ID",
        )
        ids.add(rb["id"])
        require(isinstance(rb["name"], str) and rb["name"], "Missing name")
        require(rb["tier"] in {"T0", "T1", "T2", "T3"}, "Invalid tier")
        for key in ("applies_when", "not_when"):
            require(isinstance(rb[key], list), f"{key} must be a list")
            if key == "applies_when":
                require(bool(rb[key]), "Empty applies_when")
            for condition in rb[key]:
                parse_condition(condition)
        require(type(rb["reversible"]) is bool, "reversible must be boolean")
        for key in ("steps", "rollback", "capabilities"):
            require(isinstance(rb[key], list) and rb[key], f"Empty {key}")
            for step in rb[key]:
                validate_step(step, capability=key == "capabilities")
        if rb["tier"] == "T3":
            require(
                all(
                    s["action"] == "observe"
                    for k in ("steps", "rollback", "capabilities")
                    for s in rb[k]
                ),
                "T3 must be read-only",
            )
        else:
            require(
                rb["reversible"]
                and all(s["action"] == "restore" for s in rb["rollback"]),
                "Mutating runbooks require explicit restore rollback",
            )
        _keys(rb["health_check"], {"conditions", "timeout_seconds"})
        require(
            isinstance(rb["health_check"]["conditions"], list)
            and rb["health_check"]["conditions"],
            "Missing health conditions",
        )
        for c in rb["health_check"]["conditions"]:
            parse_condition(c)
        require(
            type(rb["health_check"]["timeout_seconds"]) in (int, float)
            and 0 < rb["health_check"]["timeout_seconds"] <= 600,
            "Invalid health timeout",
        )
    return raw["runbooks"]


def validate_policy(p):
    _keys(
        p,
        {
            "version",
            "tiers",
            "blast_radius",
            "rate_limit",
            "circuit_breaker",
            "approval",
            "ambiguity",
            "kill_switch",
        },
    )
    require(
        p["tiers"]
        == {"T0": "AUTO", "T1": "AUTO", "T2": "NEEDS_APPROVAL", "T3": "REFUSE"},
        "Unsafe tier mapping",
    )
    _keys(
        p["blast_radius"],
        {
            "targets",
            "allowed_paths",
            "protected_paths",
            "max_bytes",
            "max_replicas",
            "max_restarts",
        },
    )
    b = p["blast_radius"]
    require(
        isinstance(b["targets"], list)
        and b["targets"]
        and all(isinstance(t, str) for t in b["targets"]),
        "Invalid target allowlist",
    )
    for key in ("allowed_paths", "protected_paths"):
        require(
            isinstance(b[key], list) and b[key] and all(path_ok(v) for v in b[key]),
            "Invalid path list",
        )
    for key in ("max_bytes", "max_replicas", "max_restarts"):
        require(type(b[key]) is int and b[key] >= 0, f"Invalid {key}")
    for group, keys in (
        ("rate_limit", {"max_actions", "window_seconds"}),
        ("circuit_breaker", {"failure_threshold", "reset_seconds"}),
        ("approval", {"timeout_minutes"}),
    ):
        _keys(p[group], keys)
        require(
            all(type(p[group][k]) is int and p[group][k] > 0 for k in keys),
            f"Invalid {group}",
        )
    _keys(p["ambiguity"], {"min_confidence", "on_ambiguity"})
    require(
        type(p["ambiguity"]["min_confidence"]) in (int, float)
        and 0.85 <= p["ambiguity"]["min_confidence"] <= 1,
        "Confidence too permissive",
    )
    require(p["ambiguity"]["on_ambiguity"] == "ESCALATE", "Ambiguity must escalate")
    require(p["kill_switch"] is True, "Kill switch required")
    return p


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            require(key not in mapping, f"Duplicate YAML key: {key}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        except TypeError as exc:
            raise SchemaError("Invalid YAML mapping key") from exc
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping
)


def load_yaml(path):
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.load(f, Loader=UniqueKeyLoader)
    except (OSError, yaml.YAMLError) as exc:
        raise SchemaError(str(exc)) from exc


def load_runbooks(path):
    return validate_runbooks(load_yaml(path))


def load_policy(path):
    return validate_policy(load_yaml(path))
