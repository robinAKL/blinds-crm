"""Exercise staff sign-in, consent and MCP with an isolated SQLite database."""
import base64
import hashlib
import json
import os
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

ORIGIN = 'https://vera.example.test'
RESOURCE = ORIGIN + '/api/mcp'
CALLBACK = 'https://claude.ai/api/mcp/auth_callback'
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
        registered = client.post(discovery['registration_endpoint'], json={**registration, 'redirect_uris': [CALLBACK]})
        assert registered.status_code == 201, registered.text
        client_id = registered.json()['client_id']

        authorization = {'response_type': 'code', 'client_id': client_id, 'redirect_uri': CALLBACK,
                         'code_challenge': CHALLENGE, 'code_challenge_method': 'S256', 'resource': RESOURCE,
                         'scope': 'crm:read crm:orders:write', 'state': 'client-state'}

        def consent_form():
            requested = client.get(discovery['authorization_endpoint'], params=authorization)
            assert requested.is_redirect, requested.text
            page = client.get(requested.headers['location'])
            assert page.status_code == 200 and 'Sign in and authorize' in page.text
            return {name: re.search(f'name="{name}" value="([^"]+)"', page.text)[1] for name in ('ticket', 'csrf')}

        form = consent_form()
        assert client.post(CONSENT, data={**form, 'csrf': 'x' * 43, 'decision': 'deny'}).status_code == 403
        denied = client.post(CONSENT, data={**form, 'decision': 'deny'})
        assert parse_qs(urlsplit(denied.headers['location']).query)['error'] == ['access_denied']

        form = consent_form()
        signed_in = client.post(CONSENT, data={**form, 'decision': 'allow', 'username': 'dylan',
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
        refresh = {'grant_type': 'refresh_token', 'client_id': client_id,
                   'refresh_token': tokens['refresh_token'], 'resource': RESOURCE}
        renewed = client.post(discovery['token_endpoint'], data=refresh)
        assert renewed.status_code == 200, renewed.text
        assert rpc(tokens['access_token'], 'tools/list').status_code == 401
        assert rpc(renewed.json()['access_token'], 'tools/list').status_code == 200
        assert client.post(discovery['token_endpoint'], data=refresh).status_code == 400
        assert rpc(renewed.json()['access_token'], 'tools/list').status_code == 401
        print('PASS CRM staff OAuth discovery, sign-in, consent, PKCE and token rotation')


if __name__ == '__main__':
    with TemporaryDirectory() as folder:
        main(folder)
