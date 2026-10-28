"""Local operator dashboard; bearer credentials protect every mutating endpoint."""

from functools import wraps
import hmac
import os
from uuid import uuid4
from flask import Flask, jsonify, render_template, request, g
from ..adapters.mock import MockAdapter, FAULTS
from ..audit import AuditStore, check_complete, completeness_score
from ..config import DATABASE_URL, MODE
from ..evaluation import run_evaluation
from ..orchestrator import Engine
from ..policy import Decision
from .accounts import install_accounts


def create_app(engine=None, operator_token=None):
    app = Flask(__name__)
    if engine is None:
        if MODE != "simulate":
            raise RuntimeError(
                "Live mode is disabled: authorized Docker environment was not supplied"
            )
        engine = Engine(store=AuditStore(DATABASE_URL))
    app.config["ENGINE"] = engine
    app.config["MAX_CONTENT_LENGTH"] = 16384
    token = (
        operator_token
        if operator_token is not None
        else os.getenv("AEGISOPS_OPERATOR_TOKEN", "")
    )
    actor = os.getenv("AEGISOPS_APPROVER", "local-operator")

    auth_mode = 'token' if operator_token is not None else os.getenv('AEGISOPS_AUTH_MODE', 'supabase')
    if auth_mode not in ('supabase', 'token'):
        raise ValueError('Unknown authentication mode')
    install_accounts(app, engine, auth_mode)

    def current_actor():
        user = getattr(g, 'account', None)
        return ('Account ' + user['id']) if user else actor

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def operator_only(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if auth_mode == 'supabase':
                permission = {'inject': 'inject', 'run': 'run', 'approve': 'approve', 'deny': 'deny', 'kill': 'kill'}[fn.__name__]
                return app.config['ACCOUNT_REQUIRE'](permission)(fn)(*args, **kwargs)
            auth = request.headers.get("Authorization", "")
            if not token or not hmac.compare_digest(auth, "Bearer " + token):
                return (
                    jsonify(
                        error="Operator bearer token required; configure AEGISOPS_OPERATOR_TOKEN"
                    ),
                    401,
                )
            origin = request.headers.get("Origin")
            if origin and origin != request.host_url.rstrip("/"):
                return jsonify(error="Cross-origin control request refused"), 403
            return fn(*args, **kwargs)

        return wrapped

    def body():
        value = request.get_json(silent=True)
        if not isinstance(value, dict):
            raise ValueError("Expected JSON object")
        return value

    @app.errorhandler(ValueError)
    def invalid(exc):
        return jsonify(error=str(exc)), 400

    def status():
        engine.approvals.expire()
        ctx = engine.context()
        return dict(
            mode="SIMULATE",
            state=engine.adapter.read_state(),
            active_actions=dict(engine.active),
            kill_switch=ctx["kill"],
            dashboard_kill=engine.killswitch.dashboard(),
            circuit_open=ctx["circuit_open"],
            actions_in_window=ctx["actions_in_window"],
            rate_limit=engine.policy["rate_limit"],
            approvals=[
                r
                for r in engine.approvals.all()
                if r["status"] in ("PENDING", "APPROVED", "CONSUMED")
            ],
            audit_events=len(engine.store.records()),
            operator_controls=(auth_mode == "supabase" or bool(token)),
            auth_mode=auth_mode,
            provenance="Authored demo fixtures; organizer YAML and scenarios were not supplied",
        )

    def context():
        return dict(status=status(), faults=sorted(FAULTS), operator_name=actor, auth_mode=auth_mode)

    @app.get("/")
    def dashboard():
        return render_template("dashboard.html", **context())

    @app.get("/approvals")
    def approvals():
        engine.approvals.expire()
        return render_template(
            "approvals.html",
            requests=list(reversed(engine.approvals.all())),
            **context(),
        )

    @app.get("/audit")
    def audit():
        records = engine.store.records()
        for key in ("runbook_id", "tier", "final_outcome"):
            if request.args.get(key):
                records = [r for r in records if r[key] == request.args[key]]
        return render_template(
            "audit.html",
            records=list(reversed(records)),
            changes=engine.store.changes(),
            check_complete=check_complete,
            completeness_score=completeness_score,
            **context(),
        )

    @app.get("/runbooks")
    def runbooks():
        return render_template("runbooks.html", runbooks=engine.runbooks, **context())

    @app.get("/evaluation")
    def evaluation():
        return render_template(
            "evaluation.html", evaluation=run_evaluation(), **context()
        )

    @app.get("/accounts")
    def accounts_page():
        return render_template("accounts.html", **context())

    @app.get("/api/status")
    def api_status():
        return jsonify(status())

    @app.get("/api/audit")
    def api_audit():
        records = engine.store.records(request.args.get("action_id"))
        for key in ("runbook_id", "tier", "final_outcome"):
            if request.args.get(key):
                records = [r for r in records if r[key] == request.args[key]]
        return jsonify(
            records=[
                {
                    **r,
                    "missing_fields": check_complete(r),
                    "completeness": completeness_score(r),
                }
                for r in records
            ],
            changes=engine.store.changes(),
        )

    @app.post("/api/inject")
    @operator_only
    def inject():
        if not isinstance(engine.adapter, MockAdapter):
            return jsonify(error="Fault injection is simulate-only"), 403
        data = body()
        with engine.lock:
            if engine.active:
                return jsonify(error="An action is active"), 409
            state = engine.adapter.inject(data.get("fault"))
            engine.store.runtime(
                "injection",
                {"fault": data["fault"], "incident_id": engine.adapter.incident_id},
            )
        return jsonify(state=state)

    @app.post("/api/run")
    @operator_only
    def run():
        data = body()
        dry = data.get("dry_run", False)
        if type(dry) is not bool:
            raise ValueError("dry_run must be boolean")
        return jsonify(engine.run(dry_run=dry))

    @app.post("/api/approve/<request_id>")
    @operator_only
    def approve(request_id):
        data = body()
        with engine.lock:
            engine.approvals.approve(request_id, current_actor(), data.get("reason"))
            return jsonify(engine.resume(request_id))

    @app.post("/api/deny/<request_id>")
    @operator_only
    def deny(request_id):
        data = body()
        # No engine lock: in-flight revocations must be visible at the next boundary.
        return jsonify(engine.approvals.deny(request_id, current_actor(), data.get("reason")))

    @app.post("/api/killswitch")
    @operator_only
    def kill():
        enabled = body().get("enabled")
        active = engine.killswitch.set(enabled)
        engine.store.write(
            str(uuid4()),
            None,
            engine.adapter.read_state(),
            Decision(
                "REFUSE" if active else "AUTO",
                ["Operator kill switch updated"],
                {"kill_switch": not active},
            ),
            event="closed",
            final_outcome="KILL_ENABLED" if active else "KILL_DISABLED",
            approver={"name": current_actor()},
        )
        return jsonify(kill_switch=active, dashboard_kill=enabled)

    return app
