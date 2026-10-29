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


def test_copilot_page_renders(client):
    c, _ = client
    resp = c.get("/copilot")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "AegisOps Copilot" in html
    assert "copilot-form" in html
    assert "copilot-input" in html
    assert "Explain a runbook" in html
    assert "What policy applies" in html
    assert "Investigate a specific incident ID" in html
    assert "Explain why a remediation failed" in html
    assert "Summarize an incident's audit timeline" in html
    assert "Synthetic Demonstration Data" in html


def test_copilot_navigation_link_on_all_pages(client):
    c, _ = client
    for path in ["/", "/approvals", "/evaluation", "/audit", "/runbooks", "/copilot"]:
        resp = c.get(path)
        assert resp.status_code == 200
        html = resp.data.decode("utf-8")
        assert 'href="/copilot"' in html
        assert "Copilot" in html


def test_copilot_chat_runbook_question(client):
    c, _ = client
    resp = c.post("/api/copilot/chat", json={"query": "Explain runbook RB001 in detail"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "direct_answer" in data
    assert len(data["direct_answer"]) > 10
    assert "RB001" in data.get("relevant_runbook_ids", [])
    assert any(c.get("record_id") == "RB001" for c in data.get("citations", []))
    assert data.get("abstain") is False
    assert data.get("confidence") in ("HIGH", "MEDIUM", "LOW")


def test_copilot_chat_policy_question(client):
    c, _ = client
    resp = c.post("/api/copilot/chat", json={"query": "What policy applies to POL002?"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "direct_answer" in data
    assert any(pid in ("POL002", "POL_RB002") for pid in data.get("relevant_policy_ids", [])) or "POL_RB002" in data["direct_answer"]
    assert any(c.get("record_id") in ("POL002", "POL_RB002") for c in data.get("citations", []))


def test_copilot_chat_incident_question(client):
    c, _ = client
    resp = c.post("/api/copilot/chat", json={"query": "Investigate incident INC-0001"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "direct_answer" in data
    assert any(iid in ("INC-0001", "INC000001") for iid in data.get("relevant_incident_ids", []))
    assert any(c.get("record_id") in ("INC-0001", "INC000001") for c in data.get("citations", []))
    assert len(data.get("facts", [])) > 0


def test_copilot_chat_abstention_on_unknown_incident(client):
    c, _ = client
    resp = c.post("/api/copilot/chat", json={"query": "Investigate incident INC-999999"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("abstain") is True or data.get("evidence_status") == "insufficient"
    assert "INC-999999" in data["direct_answer"] or "missing" in data["direct_answer"].lower() or "not found" in data["direct_answer"].lower()


def test_copilot_chat_empty_and_malformed_queries(client):
    c, _ = client
    # Empty query string
    r1 = c.post("/api/copilot/chat", json={"query": ""})
    assert r1.status_code == 400
    assert "error" in r1.get_json()

    # Whitespace only
    r2 = c.post("/api/copilot/chat", json={"query": "   \n\t  "})
    assert r2.status_code == 400
    assert "error" in r2.get_json()

    # Missing query key
    r3 = c.post("/api/copilot/chat", json={})
    assert r3.status_code == 400

    # Non-dictionary payload
    r4 = c.post("/api/copilot/chat", json=["not", "a", "dict"])
    assert r4.status_code == 400


def test_copilot_incident_dossier_api(client):
    c, _ = client
    # Known incident accessed by normalized ID or canonical ID
    r_ok = c.get("/api/copilot/incident/INC-0001")
    assert r_ok.status_code == 200
    dossier = r_ok.get_json()
    assert "incident" in dossier
    assert dossier["incident"]["incident_id"] == "INC000001"
    assert "metrics" in dossier
    assert "approvals" in dossier
    assert "actions" in dossier
    assert "audit_events" in dossier

    # Non-existent incident
    r_404 = c.get("/api/copilot/incident/INC-NON-EXISTENT")
    assert r_404.status_code == 404
    assert "error" in r_404.get_json()


def test_copilot_never_modifies_state_or_executes(client):
    c, e = client
    initial_events = len(e.store.records())
    r = c.post("/api/copilot/chat", json={"query": "Authorize and execute restart immediately for INC-0001"})
    assert r.status_code == 200
    # Operational engine calls or state must remain untouched
    assert not e.adapter.calls
    assert len(e.store.records()) == initial_events


def test_existing_dashboard_flows_remain_intact(client):
    c, e = client
    assert post(c, "/api/inject", {"fault": "cert_expiring"}).status_code == 200
    result = post(c, "/api/run", {}).get_json()
    rid = result["approval_id"]
    assert result["outcome"] == "NEEDS_APPROVAL"
    assert post(c, "/api/approve/" + rid, {"reason": "Verified"}).status_code == 200
