"""Exercise real HTTP in one process; no external service or browser required."""

import json
from pathlib import Path
import sys
from threading import Thread
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from werkzeug.serving import make_server
from aegisops.orchestrator import Engine
from aegisops.web.app import create_app


def main():
    engine = Engine()
    app = create_app(engine, operator_token="ephemeral-smoke-token")
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer ephemeral-smoke-token",
    }

    def get(path):
        with opener.open(base + path, timeout=5) as response:
            assert response.status == 200
            assert response.headers["X-Content-Type-Options"] == "nosniff"
            return response.read()

    def post(path, data):
        req = urllib.request.Request(
            base + path, data=json.dumps(data).encode(), headers=headers, method="POST"
        )
        with opener.open(req, timeout=5) as response:
            return json.load(response)

    try:
        for path in [
            "/",
            "/approvals",
            "/evaluation",
            "/audit",
            "/runbooks",
            "/static/app.css",
            "/static/incident.css",
            "/static/app.js",
        ]:
            assert len(get(path)) > 0
        post("/api/inject", {"fault": "log_full"})
        assert post("/api/run", {})["outcome"] == "RESOLVED"
        post("/api/inject", {"fault": "cert_expiring"})
        pending = post("/api/run", {})
        assert (
            post(
                "/api/approve/" + pending["approval_id"],
                {"reason": "HTTP smoke review"},
            )["outcome"]
            == "RESOLVED"
        )
        post("/api/inject", {"fault": "cert_expiring"})
        pending = post("/api/run", {})
        assert (
            post(
                "/api/deny/" + pending["approval_id"], {"reason": "HTTP smoke refusal"}
            )["status"]
            == "DENIED"
        )
        assert post("/api/killswitch", {"enabled": True})["kill_switch"]
        assert post("/api/run", {})["outcome"] == "REFUSE"
        assert not post("/api/killswitch", {"enabled": False})["kill_switch"]
        print(
            "HTTP smoke passed: five pages, assets, resolve, approve, deny, kill/refuse/release"
        )
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


if __name__ == "__main__":
    main()
