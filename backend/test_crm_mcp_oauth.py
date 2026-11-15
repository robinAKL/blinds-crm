"""Exercise discovery and OAuth tool authorization with signed JWT access tokens."""
import json
import os
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

RESOURCE = 'https://vera.example.test/api/mcp'
ISSUER = 'https://login.example.test/'
METADATA = '/.well-known/oauth-protected-resource/api/mcp'
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = jwt.algorithms.RSAAlgorithm.to_jwk(PRIVATE_KEY.public_key(), as_dict=True)
JWK.update(kid='test-key', alg='RS256', use='sig')


def token(scope='crm:read', *, typ='at+jwt', kid='test-key', **claims):
    now = int(time.time())
    payload = {'iss': ISSUER, 'aud': RESOURCE, 'sub': 'staff-subject', 'scope': scope,
               'exp': now + 300, 'iat': now, 'jti': 'test-jwt', 'client_id': 'test-client'}
    return jwt.encode({**payload, **claims}, PRIVATE_KEY, algorithm='RS256', headers={'typ': typ, 'kid': kid})


def main(folder):
    os.environ.update(
        VERA_DB_BACKEND='sqlite', VERA_DB=str(Path(folder) / 'mcp-oauth.db'), VERA_STORAGE_BACKEND='local',
        VERA_MCP_TOKEN='legacy-test-token-' * 3, VERA_MCP_USERNAME='dylan',
        VERA_MCP_OAUTH_RESOURCE=RESOURCE, VERA_MCP_OAUTH_ISSUER=ISSUER,
        VERA_MCP_OAUTH_JWKS_URL=ISSUER + '.well-known/jwks.json',
        VERA_MCP_OAUTH_SUBJECT_MAP='{"staff-subject":"test-staff","admin-subject":"dylan","inactive-subject":"inactive"}',
        VERA_MCP_ALLOWED_ORIGINS='',
    )
    from service import app, db

    with db() as connection:
        for username, active in [('test-staff', 1), ('inactive', 0)]:
            connection.execute('INSERT INTO users(username,name,password_hash,role,active) VALUES(?,?,?,?,?)',
                               (username, username, 'unused', 'staff', active))
        order = {'id': 'test-order', 'customer_id': None, 'status': 'supplier_ordered', 'history': []}
        connection.execute('INSERT INTO operations_records(id,kind,data) VALUES(?,?,?)',
                           ('test-order', 'project', json.dumps(order)))

    with patch.object(jwt.PyJWKClient, 'get_signing_keys', return_value=[jwt.PyJWK.from_dict(JWK)]), TestClient(app) as client:
        def rpc(method, access_token=None, **params):
            headers = {'Accept': 'application/json, text/event-stream'}
            if access_token:
                headers['Authorization'] = 'Bearer ' + access_token
            return client.post('/api/mcp', headers=headers,
                               json={'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params})

        def call(access_token, name, **arguments):
            response = rpc('tools/call', access_token, name=name, arguments=arguments)
            assert response.status_code == 200, response.text
            return response.json()['result']

        missing = rpc('tools/list')
        assert missing.status_code == 401
        assert 'https://vera.example.test' + METADATA in missing.headers['WWW-Authenticate']
        assert client.get(METADATA).json() == {
            'resource': RESOURCE, 'authorization_servers': [ISSUER],
            'scopes_supported': ['crm:read', 'crm:orders:write', 'crm:knowledge:read'],
            'bearer_methods_supported': ['header'],
        }

        invalid = [os.environ['VERA_MCP_TOKEN'], token(aud='https://another.example.test/api/mcp'),
                   token(iss='https://wrong-issuer.example.test/'), token(exp=1), token(typ='JWT'),
                   token(kid='unknown-key'), token(scope=['crm:read'])]
        valid = token()
        header, payload, signature = valid.split('.')
        invalid.append('.'.join([header, payload, ('B' if signature.startswith('A') else 'A') + signature[1:]]))
        for access_token in invalid:
            response = rpc('tools/list', access_token)
            assert response.status_code == 401, response.text
            assert 'invalid_token' in response.headers['WWW-Authenticate']

        for subject in ['unknown-subject', 'inactive-subject']:
            assert rpc('tools/list', token(sub=subject)).status_code == 403
        discovered = rpc('tools/list', valid).json()['result']['tools']
        tools = {tool['name']: tool['_meta']['securitySchemes'][0]['scopes'] for tool in discovered}
        assert tools['search_orders'] == ['crm:read']
        assert tools['approve_order'] == ['crm:orders:write']
        assert tools['get_pricing_knowledge'] == ['crm:knowledge:read']
        assert call(valid, 'search_orders')['structuredContent']['total'] == 1
        no_scope = call(valid, 'approve_order', order_id='missing')
        assert no_scope['isError']
        assert 'insufficient_scope' in no_scope['_meta']['mcp/www_authenticate'][0]
        assert 'crm:orders:write' in no_scope['_meta']['mcp/www_authenticate'][0]
        staff_write = token('crm:orders:write')
        moved = call(staff_write, 'mark_orders_in_transit',
                     batch={'order_ids': ['test-order'], 'operation_key': 'oauth-transit-test'})
        assert moved['structuredContent']['results'][0]['status'] == 'success'
        with db() as connection:
            stored = connection.execute('SELECT data FROM operations_records WHERE id=?', ('test-order',)).fetchone()
        history = json.loads(stored['data'])['history']
        assert history[-1]['action'] == 'in_transit' and history[-1]['actor'] == 'test-staff'
        denied = call(staff_write, 'approve_order', order_id='missing')
        assert denied['isError'] and 'Admin only' in denied['content'][0]['text']
        admin_write = token('crm:orders:write', sub='admin-subject')
        missing_order = call(admin_write, 'approve_order', order_id='missing')
        assert missing_order['isError'] and '404' in missing_order['content'][0]['text']
        assert 'Admin only' in call(token('crm:knowledge:read'), 'get_pricing_knowledge')['content'][0]['text']
        print('PASS MCP OAuth discovery, JWT verification, identity mapping, scopes and CRM roles')


if __name__ == '__main__':
    with TemporaryDirectory() as folder:
        main(folder)
