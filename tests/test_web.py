import pytest
from aegisops.orchestrator import Engine
from aegisops.web.app import create_app


@pytest.fixture
def client():
    e = Engine()
    app = create_app(e, operator_token="test-operator")
    app.testing = True
    return app.test_client(), e


HEADERS = {"Authorization": "Bearer test-operator"}


def post(client, url, data):
    return client.post(url, json=data, headers=HEADERS)


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/approvals",
        "/evaluation",
        "/audit",
        "/runbooks",
        "/api/status",
        "/api/audit",
        "/static/app.css",
        "/static/incident.css",
        "/static/app.js",
    ],
)
def test_pages(client, path):
    c, _ = client
    assert c.get(path).status_code == 200


def test_controls_require_auth_and_no_cross_origin(client):
    c, e = client
    assert c.post("/api/run", json={}).status_code == 401
    assert (
        c.post(
            "/api/run",
            json={},
            headers={**HEADERS, "Origin": "https://attacker.invalid"},
        ).status_code
        == 403
    )
    assert not e.adapter.calls


def test_dashboard_flow(client):
    c, e = client
    assert post(c, "/api/inject", {"fault": "cert_expiring"}).status_code == 200
    result = post(c, "/api/run", {}).get_json()
    rid = result["approval_id"]
    assert result["outcome"] == "NEEDS_APPROVAL"
    assert post(c, "/api/approve/" + rid, {}).status_code == 400
    assert (
        post(c, "/api/approve/" + rid, {"reason": "Reviewed fixture"}).get_json()[
            "outcome"
        ]
        == "RESOLVED"
    )
    assert all(
        r["completeness"] == 100 for r in c.get("/api/audit").get_json()["records"]
    )
    assert post(c, "/api/killswitch", {"enabled": True}).get_json()["kill_switch"]
    assert post(c, "/api/run", {}).get_json()["outcome"] == "REFUSE"
    assert post(c, "/api/killswitch", {"enabled": False}).status_code == 200


def test_deny_and_bad_inputs(client):
    c, e = client
    post(c, "/api/inject", {"fault": "cert_expiring"})
    rid = post(c, "/api/run", {}).get_json()["approval_id"]
    assert (
        post(c, "/api/deny/" + rid, {"reason": "Unsafe timing"}).get_json()["status"]
        == "DENIED"
    )
    assert not e.adapter.calls
    for url, payload in [
        ("/api/inject", {"fault": "unknown"}),
        ("/api/killswitch", {"enabled": "false"}),
        ("/api/run", {"dry_run": "true"}),
    ]:
        assert post(c, url, payload).status_code == 400


def test_dry_run_never_executes(client):
    c, e = client
    post(c, "/api/inject", {"fault": "log_full"})
    r = post(c, "/api/run", {"dry_run": True}).get_json()
    assert r["outcome"] == "DRY_RUN" and r["decision"]["outcome"] == "AUTO"
    assert not e.adapter.calls and not e.store.runtime_events("execution_start")


def test_evaluation_scorecard_uses_isolated_simulations(client):
    c, e = client
    response = c.get("/evaluation")
    assert response.status_code == 200
    assert b"6 of 6 scenarios passed" in response.data
    assert b"/ 1</small>" in response.data
    assert b"NEEDS_APPROVAL" in response.data
    assert b"UNAUTHORIZED ACTIONS" in response.data
    assert b"100% audit completeness" in response.data
    assert b"simulation" in response.data.lower()
    assert not e.adapter.calls
    assert not e.store.records()
    assert not e.store.runtime_events()


def test_combined_faults_preserve_conflict_instead_of_guessing(client):
    c, e = client
    assert (
        post(c, "/api/inject", {"fault": ["log_full", "core_dump"]}).status_code == 200
    )
    result = post(c, "/api/run", {}).get_json()
    assert result["outcome"] == "ESCALATE"
    assert not e.adapter.calls


def test_malformed_fault_is_bad_request(client):
    c, e = client
    assert post(c, "/api/inject", {"fault": {"shell": "unsafe"}}).status_code == 400
    assert not e.adapter.calls
