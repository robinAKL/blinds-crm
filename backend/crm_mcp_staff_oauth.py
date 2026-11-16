"""MCP authorization backed by existing CRM staff sessions."""
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from contextlib import contextmanager
from html import escape
from threading import Lock
from urllib.parse import urlsplit

from fastapi import Form, HTTPException, Request
from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError, RefreshToken,
    RegistrationError, TokenError, construct_redirect_uri,
)
from mcp.server.auth.handlers.token import TokenHandler, TokenErrorResponse
from mcp.server.auth.middleware.client_auth import ClientAuthenticator
from mcp.server.auth.routes import create_auth_routes
from mcp.server.transport_security import RequestBodyLimitMiddleware
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl
from starlette.concurrency import run_in_threadpool
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route, request_response

from crm_mcp_oauth import MCP_PATH, METADATA_PATH, READ, SCOPES, Principal, ResourceMetadata, https_url

AUTH_PATH = '/api/mcp-auth'
DISCOVERY_PATH = '/.well-known/oauth-authorization-server' + AUTH_PATH
CONSENT = AUTH_PATH + '/consent'
COOKIE = '__Host-vera-mcp-consent'
ACCESS_SECONDS = 900
DEFAULT_CALLBACKS = {
    'https://chatgpt.com/connector_platform_oauth_redirect',
    'https://claude.ai/api/mcp/auth_callback',
    'https://sa-staging-web.victoriousplant-926ad8d5.australiaeast.azurecontainerapps.io/mcp/vera/callback',
}
TOKEN_CHARS = re.compile(r'[A-Za-z0-9_-]{43}')
VERIFIER = re.compile(r'[A-Za-z0-9._~-]{43,128}')
PAGE_HEADERS = {
    'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    'X-Content-Type-Options': 'nosniff',
}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class StaffOAuth(ResourceMetadata):
    def __init__(self, crm, resource):
        url = https_url(resource, 'VERA_MCP_OAUTH_RESOURCE')
        if url.path != MCP_PATH:
            raise ValueError(f'VERA_MCP_OAUTH_RESOURCE must end with {MCP_PATH}')
        origin = f'{url.scheme}://{url.netloc}'
        super().__init__(resource, origin + AUTH_PATH, origin + METADATA_PATH)
        self.crm = crm
        self.ready = False
        self.schema_lock = Lock()
        self.callbacks = DEFAULT_CALLBACKS | {
            value.strip() for value in os.getenv('VERA_MCP_OAUTH_CALLBACKS', '').split(',') if value.strip()
        }
        for callback in self.callbacks:
            https_url(callback, 'OAuth callback')

    @contextmanager
    def db(self, write=False):
        with self.schema_lock:
            if not self.ready:
                with self.crm.db() as c:
                    c.execute('BEGIN IMMEDIATE')
                    c.executescript("""
                        CREATE TABLE IF NOT EXISTS mcp_oauth_records (
                            kind TEXT NOT NULL, id TEXT NOT NULL, expires_at REAL NOT NULL,
                            session_hash TEXT, data TEXT NOT NULL, PRIMARY KEY(kind,id)
                        );
                        CREATE INDEX IF NOT EXISTS mcp_oauth_expiry ON mcp_oauth_records(expires_at);
                        CREATE INDEX IF NOT EXISTS mcp_oauth_session ON mcp_oauth_records(session_hash);
                    """)
                self.ready = True
        with self.crm.db() as c:
            if write:
                c.execute('BEGIN IMMEDIATE')
            yield c

    def save(self, c, kind, key, data, expires, session=None):
        c.execute('INSERT INTO mcp_oauth_records(kind,id,expires_at,session_hash,data) VALUES(?,?,?,?,?)',
                  (kind, key, expires, session, json.dumps(data)))

    def get(self, c, kind, key):
        row = c.execute('SELECT data,expires_at,session_hash FROM mcp_oauth_records '
                        'WHERE kind=? AND id=? AND expires_at>?',
                        (kind, key, time.time())).fetchone()
        if row:
            return {**json.loads(row['data']), 'expires_at': row['expires_at'], 'session': row['session_hash']}

    def session(self, c, session_hash):
        return c.execute('SELECT s.username,s.expires_at,u.role FROM sessions s JOIN users u ON u.username=s.username '
                         'WHERE s.token_hash=? AND s.expires_at>? AND u.active=1',
                         (session_hash, time.time())).fetchone()

    async def get_client(self, client_id):
        def read():
            with self.db() as c:
                row = self.get(c, 'client', client_id)
                return OAuthClientInformationFull.model_validate(row) if row else None
        return await run_in_threadpool(read)

    async def register_client(self, client):
        if not client.redirect_uris or any(str(uri) not in self.callbacks for uri in client.redirect_uris):
            raise RegistrationError('invalid_redirect_uri', 'This callback URL is not enabled for VERA CRM')
        def store():
            with self.db(write=True) as c:
                c.execute('DELETE FROM mcp_oauth_records WHERE expires_at<=?', (time.time(),))
                self.save(c, 'client', client.client_id, client.model_dump(mode='json'), time.time() + 86400 * 365)
        await run_in_threadpool(store)

    async def authorize(self, client, params):
        if params.resource not in (None, self.resource):
            raise AuthorizeError('invalid_request', 'Unknown MCP resource')
        if not TOKEN_CHARS.fullmatch(params.code_challenge):
            raise AuthorizeError('invalid_request', 'A valid S256 PKCE challenge is required')
        ticket = secrets.token_urlsafe(32)
        def store():
            with self.db(write=True) as c:
                c.execute('DELETE FROM mcp_oauth_records WHERE expires_at<=?', (time.time(),))
                self.save(c, 'consent', digest(ticket), {
                    'client_id': client.client_id, 'params': params.model_dump(mode='json'),
                }, time.time() + 300)
        await run_in_threadpool(store)
        return construct_redirect_uri(self.issuer + '/consent', ticket=ticket)

    def consent_page(self, ticket, csrf, scopes, redirect_uri):
        descriptions = {
            'crm:read': 'Read CRM orders, invoices, customers and shipments',
            'crm:orders:write': 'Update orders, shipments and supplier assignments',
            'crm:knowledge:read': 'Read internal pricing knowledge (administrators only)',
        }
        permissions = ''.join(f'<li>{escape(descriptions[scope])}</li>' for scope in scopes)
        destination = escape(urlsplit(redirect_uri).hostname or '')
        page = HTMLResponse(f"""<!doctype html><html lang="en"><meta charset="utf-8">
<title>VERA CRM authorization</title><main><h1>Connect VERA CRM</h1>
<p>Sign in with your VERA CRM staff account to grant these permissions to {destination}.</p><ul>{permissions}</ul>
<form method="post" action="{CONSENT}">
<input type="hidden" name="ticket" value="{escape(ticket)}">
<input type="hidden" name="csrf" value="{escape(csrf)}">
<p><label>CRM username <input name="username" autocomplete="username" maxlength="200" required></label></p>
<p><label>CRM password <input name="password" type="password" autocomplete="current-password" maxlength="200" required></label></p>
<button name="decision" value="allow">Sign in and authorize</button>
<button name="decision" value="deny" formnovalidate>Cancel</button></form></main></html>""",
                            headers=PAGE_HEADERS)
        page.set_cookie(COOKIE, digest(ticket + csrf), max_age=300, secure=True, httponly=True, samesite='lax')
        return page

    def consent(self, ticket: str):
        if not TOKEN_CHARS.fullmatch(ticket):
            raise HTTPException(400, 'Invalid authorization request')
        with self.db() as c:
            pending = self.get(c, 'consent', digest(ticket))
        if not pending:
            raise HTTPException(400, 'Authorization request expired')
        params = pending['params']
        return self.consent_page(ticket, secrets.token_urlsafe(32), params['scopes'] or [READ], params['redirect_uri'])

    def approve(self, request: Request, ticket: str = Form(max_length=43), csrf: str = Form(max_length=43),
                decision: str = Form(max_length=8), username: str = Form('', max_length=200),
                password: str = Form('', max_length=200)):
        if (not TOKEN_CHARS.fullmatch(ticket) or not TOKEN_CHARS.fullmatch(csrf)
                or not hmac.compare_digest(request.cookies.get(COOKIE, '').encode(), digest(ticket + csrf).encode())):
            raise HTTPException(403, 'Invalid authorization form')
        key = digest(ticket)
        with self.db(write=True) as c:
            pending = self.get(c, 'consent', key)
            if pending:
                c.execute("DELETE FROM mcp_oauth_records WHERE kind='consent' AND id=?", (key,))
        if not pending:
            raise HTTPException(400, 'Authorization request expired')
        params = AuthorizationParams.model_validate(pending['params'])
        result = {'state': params.state, 'iss': self.issuer}
        if decision == 'deny':
            result['error'] = 'access_denied'
        elif decision == 'allow':
            attempt_key = digest(username.casefold())
            with self.db(write=True) as c:
                attempt = self.get(c, 'sign_in_limit', attempt_key)
                count = attempt['count'] if attempt else 0
                if count >= 10:
                    raise HTTPException(429, 'Too many sign-in attempts. Try again in a few minutes.')
                c.execute("DELETE FROM mcp_oauth_records WHERE kind='sign_in_limit' AND id=?", (attempt_key,))
                expiry = attempt['expires_at'] if attempt else time.time() + 300
                self.save(c, 'sign_in_limit', attempt_key, {'count': count + 1}, expiry)
            try:
                signed_in = self.crm.login(self.crm.Login(username=username, password=password))
            except HTTPException:
                raise HTTPException(401, 'CRM sign-in failed. Restart authorization and check your credentials.') from None
            session_hash = digest(signed_in['token'])
            code = secrets.token_urlsafe(32)
            with self.db(write=True) as c:
                c.execute("DELETE FROM mcp_oauth_records WHERE kind='sign_in_limit' AND id=?", (attempt_key,))
                self.save(c, 'code', digest(code), {
                    'client_id': pending['client_id'], 'scopes': params.scopes or [READ],
                    'code_challenge': params.code_challenge, 'redirect_uri': str(params.redirect_uri),
                    'redirect_uri_provided_explicitly': params.redirect_uri_provided_explicitly,
                    'resource': self.resource, 'subject': signed_in['user']['username'],
                }, time.time() + 120, session_hash)
            result['code'] = code
        else:
            raise HTTPException(400, 'Invalid authorization decision')
        redirect = RedirectResponse(construct_redirect_uri(str(params.redirect_uri), **result), status_code=303,
                                    headers=PAGE_HEADERS)
        redirect.delete_cookie(COOKIE, secure=True, httponly=True, samesite='lax')
        return redirect

    async def load_authorization_code(self, client, code):
        def load():
            with self.db() as c:
                row = self.get(c, 'code', digest(code))
                if row:
                    return AuthorizationCode(code=code, **row)
        return await run_in_threadpool(load)

    def issue(self, c, row, scopes, session):
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        data = {'client_id': row['client_id'], 'subject': session['username'],
                'scopes': scopes, 'resource': self.resource}
        access_expiry = min(time.time() + ACCESS_SECONDS, session['expires_at'])
        self.save(c, 'access', digest(access), data, access_expiry, row['session'])
        self.save(c, 'refresh', digest(refresh), data, session['expires_at'], row['session'])
        return OAuthToken(access_token=access, refresh_token=refresh, token_type='Bearer',
                          expires_in=int(access_expiry - time.time()), scope=' '.join(scopes))

    def redeem(self, kind, key, client_id, scopes):
        with self.db(write=True) as c:
            row = self.get(c, kind, key)
            session = self.session(c, row['session']) if row and row['client_id'] == client_id else None
            if session:
                c.execute('DELETE FROM mcp_oauth_records WHERE kind=? AND id=?', (kind, key))
                if kind == 'refresh':
                    self.save(c, 'used_refresh', key, row, session['expires_at'], row['session'])
                    c.execute("DELETE FROM mcp_oauth_records WHERE kind='access' AND session_hash=?", (row['session'],))
                return self.issue(c, row, scopes, session)
            if kind == 'refresh':
                used = self.get(c, 'used_refresh', key)
                if used and used['client_id'] == client_id:
                    c.execute('DELETE FROM sessions WHERE token_hash=?', (used['session'],))
        raise TokenError('invalid_grant', 'Authorization expired or already used')

    async def exchange_authorization_code(self, client, authorization_code):
        return await run_in_threadpool(self.redeem, 'code', digest(authorization_code.code),
                                       client.client_id, authorization_code.scopes)

    async def load_refresh_token(self, client, refresh_token):
        def load():
            with self.db() as c:
                key = digest(refresh_token)
                row = self.get(c, 'refresh', key) or self.get(c, 'used_refresh', key)
                if row:
                    row['expires_at'] = int(row['expires_at'])
                    return RefreshToken(token=refresh_token, **row)
        return await run_in_threadpool(load)

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        return await run_in_threadpool(self.redeem, 'refresh', digest(refresh_token.token), client.client_id, scopes)

    def access(self, token):
        with self.db() as c:
            row = self.get(c, 'access', digest(token))
            if row and row['resource'] == self.resource and self.session(c, row['session']):
                row['expires_at'] = int(row['expires_at'])
                return AccessToken(token=token, **row)

    async def load_access_token(self, token):
        return await run_in_threadpool(self.access, token)

    def authenticate(self, token):
        access = self.access(token)
        if not access:
            raise HTTPException(401, 'Invalid MCP access token',
                                headers={'WWW-Authenticate': self.challenge(error='invalid_token')})
        return Principal(access.subject, frozenset(access.scopes))

    async def revoke_token(self, token):
        def revoke():
            with self.db(write=True) as c:
                key = digest(token.token)
                row = self.get(c, 'access', key) or self.get(c, 'refresh', key) or self.get(c, 'used_refresh', key)
                if row:
                    c.execute('DELETE FROM sessions WHERE token_hash=?', (row['session'],))
        await run_in_threadpool(revoke)

    def register_routes(self, app):
        routes = create_auth_routes(
            self, AnyHttpUrl(self.issuer),
            client_registration_options=ClientRegistrationOptions(enabled=True, valid_scopes=list(SCOPES),
                                                                  default_scopes=list(SCOPES)),
            revocation_options=RevocationOptions(enabled=True),
        )
        for route in routes:
            if route.path not in ('/.well-known/oauth-authorization-server', '/token'):
                app.router.routes.append(Route(AUTH_PATH + route.path, route.endpoint, methods=route.methods))
        token_handler = TokenHandler(self, ClientAuthenticator(self))

        async def token(request):
            form = await request.form()
            resource = form.getlist('resource')
            if resource and resource != [self.resource]:
                return JSONResponse({'error': 'invalid_target'}, status_code=400,
                                    headers={'Cache-Control': 'no-store', 'Pragma': 'no-cache'})
            if form.get('grant_type') == 'authorization_code':
                verifier = form.get('code_verifier')
                if not isinstance(verifier, str) or not VERIFIER.fullmatch(verifier):
                    return token_handler.response(TokenErrorResponse(error='invalid_grant'))
            return await token_handler.handle(request)

        endpoint = RequestBodyLimitMiddleware(request_response(token), 16_384)
        app.router.routes.append(Route(AUTH_PATH + '/token', endpoint, methods=['POST']))
        app.get(DISCOVERY_PATH, include_in_schema=False)(self.discovery)
        app.get(CONSENT, include_in_schema=False)(self.consent)
        app.post(CONSENT, include_in_schema=False)(self.approve)

    def discovery(self):
        return {
            'issuer': self.issuer, 'authorization_endpoint': self.issuer + '/authorize',
            'token_endpoint': self.issuer + '/token', 'registration_endpoint': self.issuer + '/register',
            'revocation_endpoint': self.issuer + '/revoke',
            'response_types_supported': ['code'], 'grant_types_supported': ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported': ['S256'], 'authorization_response_iss_parameter_supported': True,
            'token_endpoint_auth_methods_supported': ['none', 'client_secret_post', 'client_secret_basic'],
            'revocation_endpoint_auth_methods_supported': ['none', 'client_secret_post', 'client_secret_basic'],
            'scopes_supported': list(SCOPES),
        }
