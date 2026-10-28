"""Supabase Auth via same-origin endpoints; engine authority remains separate."""
import json
import os
from functools import wraps
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from uuid import UUID
from flask import Blueprint, g, jsonify, request
from sqlalchemy import event
from ..models import AuditRecord, ChangeRecord, RuntimeEvent

ROLES = {'viewer', 'operator', 'approver', 'admin'}
PERMISSIONS = {
    'viewer': set(),
    'operator': {'run', 'inject', 'kill'},
    'approver': {'approve', 'deny'},
    'admin': {'run', 'inject', 'kill', 'approve', 'deny', 'users'},
}
PROJECT_URL = 'https://ulyopcyopyiaquarczua.supabase.co'
# Publishable project identifier, not a service-role or database credential.
PUBLISHABLE_KEY = 'sb_publishable_rSqqEPmgVDxrFS5V8Z2smQ_9b0ch8VN'


class AuthFailure(Exception):
    def __init__(self, message, status=401):
        super().__init__(message)
        self.status = status


class SupabaseAccounts:
    def __init__(self):
        self.url = os.getenv('AEGISOPS_SUPABASE_URL', PROJECT_URL).rstrip('/')
        self.key = os.getenv('AEGISOPS_SUPABASE_PUBLISHABLE_KEY', PUBLISHABLE_KEY)
        parsed = urlparse(self.url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.query or parsed.fragment or parsed.path:
            raise ValueError('Supabase URL must be an HTTPS origin')
        if not self.key.startswith('sb_publishable_'):
            raise ValueError('Use a Supabase publishable key, never a secret/service-role key')

    def call(self, path, data=None, token=None, method='POST'):
        headers = {'apikey': self.key, 'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        req = Request(self.url + path, data=json.dumps(data).encode() if data is not None else None,
                      headers=headers, method=method)
        try:
            with urlopen(req, timeout=12) as response:
                raw = response.read(1024 * 1024)
                return json.loads(raw) if raw else {}
        except HTTPError as exc:
            if exc.code == 429:
                raise AuthFailure('Too many attempts. Please try again later.', 429) from None
            try:
                code = json.loads(exc.read(8192)).get('error_code', '')
            except (ValueError, AttributeError):
                code = ''
            if code == 'email_address_not_authorized':
                raise AuthFailure('Email delivery is limited to project team members until custom SMTP is configured.', 503) from None
            if code == 'email_not_confirmed':
                raise AuthFailure('Confirm your email before signing in.', 401) from None
            if exc.code == 403:
                raise AuthFailure('Your account cannot perform this operation.', 403) from None
            if exc.code >= 500:
                raise AuthFailure('Sign-in service unavailable. Please try again.', 503) from None
            raise AuthFailure('Sign-in or access denied. Check your details and email confirmation.', 401) from None
        except (URLError, TimeoutError, OSError, ValueError):
            raise AuthFailure('Sign-in service unavailable. Please try again.', 503) from None

    def identity(self, token):
        if not token or len(token) > 16384:
            raise AuthFailure('Please sign in to continue.')
        rows = self.call('/rest/v1/rpc/aegisops_identity', {}, token)
        if not isinstance(rows, list) or len(rows) != 1:
            raise AuthFailure('Session ended. Please sign in again.')
        user = rows[0]
        try:
            UUID(user['user_id'])
            if user['role'] not in ROLES or not isinstance(user['email'], str):
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            raise AuthFailure('Invalid account response.', 503) from None
        return {'id': user['user_id'], 'email': user['email'], 'role': user['role']}


def bearer():
    header = request.headers.get('Authorization', '')
    return header[7:] if header.startswith('Bearer ') else ''


def install_accounts(app, engine, mode):
    client = SupabaseAccounts()
    app.config['ACCOUNTS'] = client
    bp = Blueprint('accounts', __name__, url_prefix='/api/auth')

    @app.before_request
    def same_origin_posts():
        if request.method == 'POST':
            origin = request.headers.get('Origin')
            if (origin and origin != request.host_url.rstrip('/')) or request.headers.get('Sec-Fetch-Site') == 'cross-site':
                return jsonify(error='Cross-origin control request refused'), 403
            if not request.is_json:
                return jsonify(error='JSON body required'), 415

    @app.errorhandler(AuthFailure)
    def failure(exc):
        return jsonify(error=str(exc)), exc.status

    def require(permission=None):
        def decorate(fn):
            @wraps(fn)
            def wrapped(*args, **kwargs):
                g.account = client.identity(bearer())
                if permission and permission not in PERMISSIONS[g.account['role']]:
                    raise AuthFailure('Your role does not permit this action.', 403)
                return fn(*args, **kwargs)
            return wrapped
        return decorate
    app.config['ACCOUNT_REQUIRE'] = require

    def body():
        value = request.get_json(silent=True)
        if not isinstance(value, dict):
            raise ValueError('Expected JSON object')
        return value

    def credentials():
        data = body()
        email, password = data.get('email'), data.get('password')
        if not isinstance(email, str) or not 3 <= len(email) <= 254 or '@' not in email:
            raise ValueError('Enter your email address.')
        if not isinstance(password, str) or not 8 <= len(password) <= 1024:
            raise ValueError('Use a password of at least 8 characters.')
        return {'email': email.strip(), 'password': password}

    def session_response(tokens):
        token, refresh = tokens.get('access_token'), tokens.get('refresh_token')
        if not isinstance(token, str) or not isinstance(refresh, str):
            raise AuthFailure('Invalid session response.', 503)
        user = client.identity(token)
        response = jsonify(access_token=token, user=user)
        response.set_cookie('aegisops_refresh', refresh, httponly=True, secure=request.is_secure,
                            samesite='Strict', path='/api/auth', max_age=30 * 86400)
        return response

    @bp.get('/config')
    def config():
        return jsonify(mode=mode)

    @bp.post('/signin')
    def signin():
        if mode != 'supabase':
            raise AuthFailure('Account sign-in is disabled in token test mode.', 403)
        return session_response(client.call('/auth/v1/token?grant_type=password', credentials()))

    @bp.post('/signup')
    def signup():
        if mode != 'supabase':
            raise AuthFailure('Account sign-up is disabled in token test mode.', 403)
        client.call('/auth/v1/signup', credentials())  # Never forward user-supplied roles or metadata.
        return jsonify(message='Check your email to confirm your account, then sign in. New accounts are viewers.')

    @bp.post('/refresh')
    def refresh():
        if mode != 'supabase':
            raise AuthFailure('Account refresh disabled.', 403)
        token = request.cookies.get('aegisops_refresh')
        if not token:
            raise AuthFailure('Please sign in.')
        return session_response(client.call('/auth/v1/token?grant_type=refresh_token', {'refresh_token': token}))

    @bp.get('/session')
    @require()
    def session():
        return jsonify(user=g.account)

    @bp.post('/signout')
    @require()
    def signout():
        client.call('/auth/v1/logout?scope=local', {}, bearer())
        response = jsonify(message='Signed out.')
        response.delete_cookie('aegisops_refresh', path='/api/auth', secure=request.is_secure, httponly=True, samesite='Strict')
        return response

    @bp.get('/users')
    @require('users')
    def users():
        return jsonify(users=client.call('/rest/v1/rpc/aegisops_users', {}, bearer()))

    @bp.post('/role')
    @require('users')
    def role():
        data = body()
        try:
            target = str(UUID(data.get('user_id', '')))
        except (ValueError, AttributeError, TypeError):
            raise ValueError('Choose a valid user.') from None
        if data.get('role') not in ROLES:
            raise ValueError('Choose viewer, operator, approver or admin.')
        client.call('/rest/v1/rpc/aegisops_set_role', {'target_user': target, 'new_role': data['role']}, bearer())
        return jsonify(message='Role updated. It applies on the next control request.')

    app.register_blueprint(bp)

    # Enrich new records before INSERT; no audit UPDATE, trigger or engine changes.
    def attribute_actor(session, *_):
        from flask import has_request_context
        if not has_request_context() or not getattr(g, 'account', None):
            return
        actor = {'id': g.account['id'], 'role': g.account['role']}
        for row in session.new:
            if isinstance(row, (AuditRecord, ChangeRecord, RuntimeEvent)):
                row.payload = {**row.payload, 'actor': actor}
    event.listen(engine.store.Session, 'before_flush', attribute_actor)
