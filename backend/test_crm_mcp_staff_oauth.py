"""Exercise staff sign-in, consent and MCP with an isolated SQLite database."""
import base64
import hashlib
import json
import os
import re
import time
from pathlib import Path
from unittest.mock import patch
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

ORIGIN = 'https://vera.example.test'
RESOURCE = ORIGIN + '/api/mcp'
CALLBACK = 'https://claude.ai/api/mcp/auth_callback'
SUPER_AGENT_CALLBACK = 'https://sa-staging-web.victoriousplant-926ad8d5.australiaeast.azurecontainerapps.io/mcp/oauth/callback'
VERIFIER = 'v' * 43
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip('=')


def main(folder):
    os.environ.update(VERA_DB_BACKEND='sqlite', VERA_DB=str(Path(folder) / 'oauth.db'),
                      VERA_STORAGE_BACKEND='local', VERA_MCP_OAUTH_MODE='staff',
                      VERA_MCP_OAUTH_RESOURCE=RESOURCE, VERA_MCP_ALLOWED_ORIGINS='')
    from service import app, db
    from crm_mcp_staff_oauth import CONSENT, DISCOVERY_PATH, digest

    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        accept = {'Accept': 'application/json, text/event-stream'}
        assert client.get('/api/health').status_code == 200
        missing = client.post('/api/mcp', headers=accept)
        assert missing.status_code == 401
        resource = client.get('/.well-known/oauth-protected-resource/api/mcp').json()
        discovery = client.get(DISCOVERY_PATH).json()
        assert discovery['issuer'] == resource['authorization_servers'][0]
        assert discovery['code_challenge_methods_supported'] == ['S256']
        registration = {'grant_types': ['authorization_code', 'refresh_token'],
                        'response_types': ['code'], 'token_endpoint_auth_method': 'none'}
        assert client.post(discovery['registration_endpoint'], json={
            **registration, 'redirect_uris': ['https://untrusted.example.test/steal'],
        }).status_code == 400
        assert client.post(discovery['registration_endpoint'], json={
            **registration, 'redirect_uris': [SUPER_AGENT_CALLBACK + '/other'],
        }).status_code == 400
        super_agent = client.post(discovery['registration_endpoint'], json={
            **registration, 'redirect_uris': [SUPER_AGENT_CALLBACK],
            'client_name': 'Super Agent', 'scope': 'crm:read crm:knowledge:read',
        })
        assert super_agent.status_code == 201, super_agent.text
        registered = client.post(discovery['registration_endpoint'], json={**registration, 'redirect_uris': [CALLBACK]})
        assert registered.status_code == 201, registered.text
        client_id = registered.json()['client_id']

        authorization = {'response_type': 'code', 'client_id': client_id, 'redirect_uri': CALLBACK,
                         'code_challenge': CHALLENGE, 'code_challenge_method': 'S256', 'resource': RESOURCE,
                         'scope': 'crm:read crm:orders:write', 'state': 'client-state'}

        def form_from(page):
            return {name: re.search(f'name="{name}" value="([^"]+)"', page.text)[1] for name in ('ticket', 'csrf')}

        def consent_form():
            requested = client.get(discovery['authorization_endpoint'], params=authorization)
            assert requested.is_redirect, requested.text
            page = client.get(requested.headers['location'])
            assert page.status_code == 200 and 'Sign in and authorize' in page.text
            assert f"form-action 'self' {CALLBACK};" in page.headers['Content-Security-Policy']
            assert "style-src 'sha256-" in page.headers['Content-Security-Policy']
            return form_from(page)

        form = consent_form()
        other_tab = consent_form()
        rejected = client.post(CONSENT, data={**form, 'csrf': other_tab['csrf'], 'decision': 'deny'})
        assert rejected.status_code == 403 and 'Reload authorization' in rejected.text
        denied = client.post(CONSENT, data={**form, 'decision': 'deny'})
        assert denied.status_code == 303
        assert parse_qs(urlsplit(denied.headers['location']).query)['error'] == ['access_denied']
        assert client.post(CONSENT, data={**other_tab, 'decision': 'deny'}).status_code == 303
        expired = client.post(CONSENT, data={**form, 'decision': 'deny'})
        assert expired.status_code == 400 and 'connect again' in expired.text

        form = consent_form()
        failed = client.post(CONSENT, data={**form, 'decision': 'allow', 'username': 'dylan',
                                            'password': 'not-the-fixture-password'})
        assert failed.status_code == 401 and 'Check your CRM username and password' in failed.text
        assert 'not-the-fixture-password' not in failed.text
        retry = form_from(failed)
        assert retry['ticket'] == form['ticket'] and retry['csrf'] != form['csrf']
        signed_in = client.post(CONSENT, data={**retry, 'decision': 'allow', 'username': 'dylan',
                                               'password': os.getenv('VERA_DEMO_PASSWORD', 'vera-demo')})
        assert signed_in.status_code == 303, signed_in.text
        returned = parse_qs(urlsplit(signed_in.headers['location']).query)
        assert returned['state'] == ['client-state'] and returned['iss'] == [discovery['issuer']]
        code = {'grant_type': 'authorization_code', 'client_id': client_id, 'redirect_uri': CALLBACK,
                'code': returned['code'][0], 'code_verifier': VERIFIER, 'resource': RESOURCE}
        assert client.post(discovery['token_endpoint'], data={**code, 'code_verifier': 'w' * 43}).status_code == 400
        assert client.post(discovery['token_endpoint'], data={**code, 'resource': ORIGIN + '/elsewhere'}).status_code == 400
        exchanged = client.post(discovery['token_endpoint'], data=code)
        assert exchanged.status_code == 200, exchanged.text
        assert client.post(discovery['token_endpoint'], data=code).status_code == 400
        tokens = exchanged.json()

        def rpc(access, method, params=None):
            return client.post('/api/mcp', headers={**accept, 'Authorization': 'Bearer ' + access},
                               json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})

        query = rpc(tokens['access_token'], 'tools/call', {'name': 'search_orders', 'arguments': {}})
        assert query.json()['result']['structuredContent']['total'] == 0, query.text
        with db() as c:
            row = c.execute("SELECT data FROM mcp_oauth_records WHERE kind='access' AND id=?",
                            (digest(tokens['access_token']),)).fetchone()
        assert json.loads(row['data'])['subject'] == 'dylan'
        with db() as c:
            order = {'id': 'oauth-order', 'customer_id': None, 'status': 'supplier_ordered', 'history': []}
            c.execute('INSERT INTO operations_records(id,kind,data) VALUES(?,?,?)',
                      ('oauth-order', 'project', json.dumps(order)))
        moved = rpc(tokens['access_token'], 'tools/call', {
            'name': 'mark_orders_in_transit',
            'arguments': {'batch': {'order_ids': ['oauth-order'], 'operation_key': 'staff-oauth-transit'}},
        })
        assert moved.json()['result']['structuredContent']['results'][0]['status'] == 'success', moved.text
        with db() as c:
            saved = c.execute('SELECT data FROM operations_records WHERE id=?', ('oauth-order',)).fetchone()
        assert json.loads(saved['data'])['history'][-1]['actor'] == 'dylan'
        with db() as c:
            session = c.execute('SELECT s.expires_at FROM sessions s JOIN mcp_oauth_records r ON r.session_hash=s.token_hash '
                                "WHERE r.kind='refresh' AND r.id=?", (digest(tokens['refresh_token']),)).fetchone()
        assert session['expires_at'] > time.time() + 29 * 86400, 'MCP grant must outlive the 8-hour browser session'
        refresh = {'grant_type': 'refresh_token', 'client_id': client_id,
                   'refresh_token': tokens['refresh_token'], 'resource': RESOURCE}
        later = time.time() + 9 * 3600
        with patch('time.time', lambda: later):
            assert rpc(tokens['access_token'], 'tools/list').status_code == 401
            renewed = client.post(discovery['token_endpoint'], data=refresh)
            assert renewed.status_code == 200, renewed.text
            assert rpc(renewed.json()['access_token'], 'tools/list').status_code == 200
            assert client.post(discovery['token_endpoint'], data=refresh).status_code == 400
            assert rpc(renewed.json()['access_token'], 'tools/list').status_code == 401
        print('PASS CRM staff OAuth discovery, sign-in, consent, PKCE, 30-day grant and token rotation')


if __name__ == '__main__':
    with TemporaryDirectory() as folder:
        main(folder)
