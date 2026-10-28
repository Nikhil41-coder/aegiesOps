"""Authentication/authorization boundaries, independent of the remediation policy."""
from copy import deepcopy
from uuid import uuid4
import hashlib
from pathlib import Path
import pytest
from flask import g
from aegisops.orchestrator import Engine
from aegisops.web.app import create_app
from aegisops.web.accounts import AuthFailure, SupabaseAccounts

USER = {'id': 'b0c63523-7d45-447d-bb08-8623781a10a1', 'email': 'operator@example.invalid', 'role': 'operator'}


@pytest.fixture
def account_app(monkeypatch):
    monkeypatch.delenv('AEGISOPS_AUTH_MODE', raising=False)
    engine = Engine()
    app = create_app(engine)
    app.testing = True
    identities = {'operator-token': dict(USER), 'viewer-token': {**USER, 'role': 'viewer'}, 'approver-token': {**USER, 'role': 'approver'}, 'admin-token': {**USER, 'role': 'admin'}}
    calls = []
    def identity(token):
        if token not in identities:
            raise AuthFailure('Session ended.')
        return dict(identities[token])
    def call(path, data=None, token=None, method='POST'):
        calls.append((path, deepcopy(data), token))
        if path.startswith('/auth/v1/token'):
            return {'access_token': 'operator-token', 'refresh_token': 'private-refresh'}
        if path == '/rest/v1/rpc/aegisops_users':
            return [{'user_id': USER['id'], 'email': USER['email'], 'role': 'operator'}]
        return {}
    monkeypatch.setattr(app.config['ACCOUNTS'], 'identity', identity)
    monkeypatch.setattr(app.config['ACCOUNTS'], 'call', call)
    return app, engine, identities, calls


def post(app, url, token=None, data=None, **kwargs):
    headers = {'Authorization': 'Bearer ' + token} if token else {}
    return app.test_client().post(url, json=data or {}, headers=headers, **kwargs)


@pytest.mark.parametrize('path', ['/api/inject','/api/run','/api/killswitch','/api/approve/request','/api/deny/request','/api/auth/role'])
@pytest.mark.parametrize('token,expected', [(None,401), ('viewer-token',403)])
def test_guest_and_viewer_cannot_control(account_app, path, token, expected):
    app, engine, _, _ = account_app
    assert post(app, path, token).status_code == expected
    assert not engine.adapter.calls
    assert not engine.store.records()
    assert not engine.store.runtime_events()


def test_operator_and_approver_permissions_are_distinct(account_app):
    app, engine, _, _ = account_app
    assert post(app, '/api/inject', 'operator-token', {'fault':'cert_expiring'}).status_code == 200
    result = post(app, '/api/run', 'operator-token').get_json()
    rid = result['approval_id']
    assert post(app, '/api/approve/'+rid, 'operator-token', {'reason':'reviewed'}).status_code == 403
    assert post(app, '/api/run', 'approver-token').status_code == 403
    assert post(app, '/api/approve/'+rid, 'approver-token', {'reason':'Reviewed exact plan','approver':'forged-user'}).get_json()['outcome'] == 'RESOLVED'
    final = engine.store.records()[-1]
    assert final['actor']['role'] == 'approver'
    assert USER['email'] not in final['approver']['name']
    assert 'email' not in final['actor']
    assert USER['id'] in final['approver']['name']
    assert 'forged-user' not in final['approver']['name']
    assert all('actor' in r for r in engine.store.records())


def test_fresh_demotion_and_logout_block_old_token(account_app):
    app, engine, identities, _ = account_app
    assert post(app, '/api/run', 'operator-token', {'dry_run':True}).status_code == 200
    before = len(engine.store.records())
    identities['operator-token']['role'] = 'viewer'
    assert post(app, '/api/run', 'operator-token').status_code == 403
    del identities['operator-token']
    assert post(app, '/api/run', 'operator-token').status_code == 401
    assert len(engine.store.records()) == before
    assert not engine.adapter.calls


def test_legacy_shared_token_not_a_fallback(account_app, monkeypatch):
    monkeypatch.setenv('AEGISOPS_OPERATOR_TOKEN','old-shared-secret')
    app, engine, _, _ = account_app
    assert post(app, '/api/run', 'old-shared-secret').status_code == 401
    assert not engine.adapter.calls


def test_outage_fails_closed_without_leaking_details(account_app, monkeypatch):
    app, engine, _, _ = account_app
    def down(_): raise AuthFailure('Sign-in service unavailable.',503)
    monkeypatch.setattr(app.config['ACCOUNTS'],'identity',down)
    assert post(app, '/api/run', 'operator-token').status_code == 503
    assert not engine.store.records() and not engine.adapter.calls


def test_auth_csrf_checks_apply_to_all_posts(account_app):
    app, engine, _, calls = account_app
    for path in ['/api/auth/signin','/api/auth/signup','/api/auth/refresh','/api/auth/signout','/api/run']:
        response = app.test_client().post(path,json={},headers={'Origin':'https://attacker.invalid','Authorization':'Bearer operator-token'})
        assert response.status_code == 403
    assert not calls and not engine.adapter.calls
    assert app.test_client().post('/api/auth/signin',data='not-json').status_code == 415


def test_login_refresh_token_is_http_only_cookie(account_app):
    app, _, _, _ = account_app
    client = app.test_client()
    result = client.post('/api/auth/signin',json={'email':USER['email'],'password':'test-password-only'},base_url='https://demo.example')
    assert result.status_code == 200
    cookie = result.headers['Set-Cookie']
    assert 'HttpOnly' in cookie and 'Secure' in cookie and 'SameSite=Strict' in cookie
    assert 'private-refresh' not in result.get_data(as_text=True)
    assert result.get_json()['user'] == USER
    assert client.post('/api/auth/refresh',json={},base_url='https://demo.example').status_code == 200


def test_signup_ignores_injected_role_and_user_metadata(account_app):
    app, _, _, calls = account_app
    result = post(app,'/api/auth/signup',data={'email':USER['email'],'password':'test-password-only','role':'admin','app_metadata':{'aegisops_role':'admin'}})
    assert result.status_code == 200
    assert calls[-1][1] == {'email':USER['email'],'password':'test-password-only'}


def test_admin_routes_validate_permission_and_target(account_app):
    app, _, _, calls = account_app
    assert post(app,'/api/auth/role','operator-token',{'user_id':str(uuid4()),'role':'admin'}).status_code == 403
    assert post(app,'/api/auth/role','admin-token',{'user_id':'not-a-uuid','role':'admin'}).status_code == 400
    assert post(app,'/api/auth/role','admin-token',{'user_id':str(uuid4()),'role':'superuser'}).status_code == 400
    assert app.test_client().get('/api/auth/users',headers={'Authorization':'Bearer admin-token'}).status_code == 200


def test_account_ui_csp_and_empty_state(account_app):
    app, _, _, _ = account_app
    result = app.test_client().get('/')
    assert b'account-email' in result.data and b'account-password' in result.data
    assert b'id="operator-token"' not in result.data
    assert "script-src 'self'" in result.headers['Content-Security-Policy']
    assert b'Admin sign-in' not in app.test_client().get('/accounts').data or b'account-users' in app.test_client().get('/accounts').data


def test_rpc_identity_rejects_empty_malformed_and_unknown_role(monkeypatch):
    client = SupabaseAccounts()
    for payload in ([],[{'user_id':USER['id'],'email':USER['email'],'role':'superuser'}],[{'user_id':'bad','email':USER['email'],'role':'admin'}]):
        monkeypatch.setattr(client,'call',lambda *args,payload=payload:payload)
        with pytest.raises(AuthFailure): client.identity('signed-token')


def test_no_engine_files_changed():
    root = Path(__file__).resolve().parents[1]
    import json
    hashes = json.loads((root/'docs/auth-engine-baseline.json').read_text())
    for path, digest in hashes.items():
        assert hashlib.sha256((root/path).read_bytes()).hexdigest() == digest, path


def test_logout_revokes_remote_session_and_clears_cookie(account_app):
    app, _, _, calls = account_app
    result = post(app,'/api/auth/signout','operator-token')
    assert result.status_code == 200
    assert calls[-1][0] == '/auth/v1/logout?scope=local'
    assert 'Max-Age=0' in result.headers['Set-Cookie']


def test_admin_role_request_and_auth_identity_not_trusted_from_body(account_app):
    app, _, _, calls = account_app
    target = str(uuid4())
    assert post(app,'/api/auth/role','admin-token',{'user_id':target,'role':'operator','actor':'forged'}).status_code == 200
    assert calls[-1] == ('/rest/v1/rpc/aegisops_set_role',{'target_user':target,'new_role':'operator'},'admin-token')


def test_auth_provider_errors_are_sanitized(monkeypatch):
    from urllib.error import HTTPError, URLError
    import io
    import aegisops.web.accounts as accounts
    client = SupabaseAccounts()
    def fail(*a, **k):
        raise HTTPError('https://provider.invalid',500,'SECRET',{},io.BytesIO(b'{"error":"PRIVATE PASSWORD"}'))
    monkeypatch.setattr(accounts,'urlopen',fail)
    with pytest.raises(AuthFailure) as exc: client.call('/auth/v1/token',{})
    assert exc.value.status == 503 and 'PRIVATE' not in str(exc.value) and 'SECRET' not in str(exc.value)


def test_secret_key_is_not_accepted_as_publishable_config(monkeypatch):
    monkeypatch.setenv('AEGISOPS_SUPABASE_PUBLISHABLE_KEY','sb_secret_test_not_real')
    with pytest.raises(ValueError): SupabaseAccounts()
