from copy import deepcopy
from aegisops.adapters.mock import MockAdapter
from aegisops.config import DATA
from aegisops.loader import load_runbooks
from aegisops.matcher import match

BOOKS = load_runbooks(DATA / "runbooks/runbooks.yaml")


def test_unique_and_combined():
    a = MockAdapter()
    a.inject("log_full")
    assert match(BOOKS, a.read_state())["runbook"]["id"] == "RB-01"
    a.inject("logs_and_core")
    assert match(BOOKS, a.read_state())["ambiguous"]
    a.inject("core_dump")
    assert match(BOOKS, a.read_state())["runbook"]["tier"] == "T3"


def test_partial_and_unknown():
    books = deepcopy(BOOKS)
    books[0]["applies_when"].append("queue_depth > 100")
    a = MockAdapter()
    a.inject("log_full")
    assert match(books, a.read_state())["ambiguous"]
    a.state["queue_depth"] = None
    assert match(books, a.read_state())["unknown"]


def test_mock_has_no_external_side_effects():
    a = MockAdapter()
    snapshot = a.read_state()
    snapshot["disk_used_pct"] = 100
    assert a.read_state()["disk_used_pct"] == 35
