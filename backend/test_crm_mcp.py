"""Run directly to exercise MCP discovery and CRM operations on an isolated SQLite database."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient

from _pricing_test_helpers import publish_fixture_knowledge
from demo_workbook import fixture


def main(folder):
    os.environ.update(VERA_DB_BACKEND='sqlite', VERA_DB=str(Path(folder) / 'mcp.db'),
                      VERA_STORAGE_BACKEND='local', VERA_MCP_TOKEN='test-only-' * 4,
                      VERA_MCP_USERNAME='dylan',
                      VERA_MCP_ALLOWED_ORIGINS='')
    import service
    from crm_mcp import register_crm_mcp
    from fastapi import FastAPI

    partial_app = FastAPI()
    partial_app.add_api_route('/api/health', service.health)
    with patch.dict(os.environ, VERA_MCP_OAUTH_RESOURCE='https://vera.example.test/api/mcp'):
        register_crm_mcp(partial_app, service)
    with TestClient(partial_app) as partial_client:
        assert partial_client.get('/api/health').status_code == 200
        assert partial_client.get('/api/mcp').status_code == 404

    app = service.app

    headers = {'Authorization': 'Bearer ' + os.environ['VERA_MCP_TOKEN'],
               'Accept': 'application/json, text/event-stream'}
    with TestClient(app) as client, patch('email_service.configuration', return_value=({'configured': False}, None)):
        def rpc(method, params=None, **extra_headers):
            body = {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}}
            return client.post('/api/mcp', json=body, headers={**headers, **extra_headers})

        def result(response):
            assert response.status_code == 200, response.text
            return response.json()['result']

        def call(name, **arguments):
            return result(rpc('tools/call', {'name': name, 'arguments': arguments}))

        def payload(name, **arguments):
            output = call(name, **arguments)
            assert not output.get('isError'), output
            return output['structuredContent']

        def post(path, body, auth=None):
            response = client.post('/api/' + path, json=body, headers=auth)
            assert response.status_code == 200, response.text
            return response.json()

        assert rpc('tools/list', Authorization='Bearer wrong').status_code == 401
        assert rpc('tools/list', Origin='https://unknown.invalid').status_code == 403
        with patch.dict(os.environ, VERA_MCP_TOKEN=''):
            assert rpc('tools/list').status_code == 404
        assert result(rpc('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
                                         'clientInfo': {'name': 'vera-test', 'version': '1'}}))['serverInfo']['name'] == 'VERA CRM'
        tools = {tool['name']: tool for tool in result(rpc('tools/list'))['tools']}
        assert tools['search_orders']['annotations']['readOnlyHint']
        assert not tools['approve_order']['annotations']['readOnlyHint']
        assert tools['get_crm_guide']['annotations']['readOnlyHint']
        guide = payload('get_crm_guide')
        assert [step['id'] for step in guide['steps']] == guide['step_ids']
        assert {status['value'] for status in guide['order_statuses']} >= {'pending_review', 'complete'}
        step = payload('get_crm_guide', step='review_deposit', language='en')['steps']
        assert len(step) == 1 and step[0]['order'] == 2 and 'approve_order' in step[0]['mcp_tools']
        assert call('get_crm_guide', step='unknown')['isError']
        listed = set(tools)
        assert all(set(row['mcp_tools']) <= listed for row in guide['steps'] + guide['references'])

        staff = post('auth/login', {'username': 'dylan', 'password': os.getenv('VERA_DEMO_PASSWORD', 'vera-demo')})
        staff_headers = {'Authorization': 'Bearer ' + staff['token']}
        assert rpc('tools/list', Authorization=staff_headers['Authorization']).status_code == 401
        post('users', {'username': 'mcp-staff', 'name': 'MCP staff', 'password': 'test-password', 'role': 'staff'}, staff_headers)
        with patch.dict(os.environ, VERA_MCP_USERNAME='mcp-staff'):
            assert call('get_pricing_knowledge')['isError']
        with patch.dict(os.environ, VERA_MCP_USERNAME='missing'):
            assert rpc('tools/list').status_code == 403

        post('operations/customers', dict(company='MCP Test Company', contact_name='Test contact',
             email='mcp@example.invalid', phone='123', company_address='Test', username='mcp-client',
             password='test-password', customer_type='wholesale', customer_code='MCP'), staff_headers)
        client.headers.update(staff_headers)
        publish_fixture_knowledge(client, fixture(), 'test.xlsm')
        client.headers.clear()
        assert payload('get_pricing_knowledge')['active']
        assert payload('list_customers', query='mcp test')['total'] == 1

        portal = post('portal/login', {'username': 'mcp-client', 'password': 'test-password'})
        portal_headers = {'Authorization': 'Bearer ' + portal['token']}
        assert rpc('tools/list', Authorization=portal_headers['Authorization']).status_code == 401
        catalog = client.get('/api/portal/catalog', headers=portal_headers).json()
        product = next(p for p in catalog['products'] if p['source_code'] == 'Shutters_PVC')
        order = post('portal/orders', dict(project_name='MCP test order', site_address='', submission_key='mcp-test-1',
                     lines=[dict(window_name='Window', product_id=product['id'], width_mm='1000', height_mm='1000',
                                 quantity=1, panel_count=2, options={'colour': 'White TEST', 'fitting': 'In Fit'})]),
                     portal_headers)
        oid = order['id']
        summary = payload('search_orders', query='mcp test order', status='pending_review')['items'][0]
        assert summary['id'] == oid
        assert payload('get_order', reference=summary['order_number'])['id'] == oid
        assert call('record_supplier_order', order_id=oid)['isError']
        with patch.dict(os.environ, VERA_MCP_USERNAME='mcp-staff'):
            assert call('approve_order', order_id=oid)['isError']
        assert payload('approve_order', order_id=oid, details={'confirm_order_number': True})['status'] == 'accepted'
        assert payload('record_order_deposit', order_id=oid)['payment_status'] == 'deposit_received'
        assert payload('record_supplier_order', order_id=oid)['status'] == 'supplier_ordered'
        batch = {'order_ids': [oid], 'operation_key': 'mcp-test-transit'}
        transit = payload('mark_orders_in_transit', batch=batch)
        assert transit['results'][0]['status'] == 'success'
        assert payload('mark_orders_in_transit', batch=batch) == transit
        final = payload('get_order', reference=oid)
        assert final['status'] == 'in_transit'
        assert final['history'][-1]['actor'] == 'dylan'
        for kind, expected in [('arrival', 'ready'), ('delivery', 'complete')]:
            details = {'order_id': oid, 'kind': kind, 'operation_key': 'mcp-test-' + kind,
                       'lines': [{'line_id': line['id'], 'quantity': line['quantity']} for line in final['lines']]}
            recorded = payload('record_order_fulfilment', details=details)
            assert recorded['order']['status'] == expected
            replay = payload('record_order_fulfilment', details=details)
            assert replay['id'] == recorded['id'] and replay['order'] == recorded['order']
            assert len([entry for entry in replay['order']['history'] if entry['action'] == kind]) == 1
        assert client.get('/api/operations/orders', headers=staff_headers).json()[0]['status'] == 'complete'
        print('PASS CRM MCP transport, authentication, published knowledge and order workflow')


if __name__ == '__main__':
    with TemporaryDirectory() as folder:
        main(folder)
