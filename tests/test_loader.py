from copy import deepcopy
import pytest
from aegisops.loader import (
    SchemaError,
    parse_condition,
    load_policy,
    load_runbooks,
    validate_runbooks,
)
from aegisops.config import DATA


@pytest.mark.parametrize(
    "text", ["x >= 90", "x == true", 'x == "logs"', "x != 'core'", "x < -0.5"]
)
def test_comparisons(text):
    assert parse_condition(text).field == "x"


@pytest.mark.parametrize(
    "text",
    [
        '__import__("os")',
        "x > 0 or y > 0",
        "x == None",
        "x == [1]",
        'x >= "a"',
        "x = 2",
        'x == float("nan")',
    ],
)
def test_no_code(text):
    with pytest.raises(SchemaError):
        parse_condition(text)


def test_unknown_is_not_false():
    c = parse_condition("disk_used_pct >= 90")
    for value in [None, "95", True, float("nan")]:
        assert c.test({"disk_used_pct": value}) is None
    assert c.test({"disk_used_pct": 95}) is True


def test_fixtures_load():
    assert len(load_runbooks(DATA / "runbooks/runbooks.yaml")) == 10
    assert load_policy(DATA / "policy.yaml")["kill_switch"] is True


def test_credentials_and_schema_required():
    raw = {"runbooks": load_runbooks(DATA / "runbooks/runbooks.yaml")}
    for mutate in ["missing", "command", "traversal", "duplicate", "t3_mutation"]:
        bad = deepcopy(raw)
        if mutate == "missing":
            del bad["runbooks"][0]["capabilities"]
        if mutate == "command":
            bad["runbooks"][0]["steps"][0]["command"] = "rm -rf /"
        if mutate == "traversal":
            bad["runbooks"][0]["steps"][0]["path"] = "/data/log/../crash"
        if mutate == "duplicate":
            bad["runbooks"].append(deepcopy(bad["runbooks"][0]))
        if mutate == "t3_mutation":
            bad["runbooks"][0]["tier"] = "T3"
        with pytest.raises(SchemaError):
            validate_runbooks(bad)
