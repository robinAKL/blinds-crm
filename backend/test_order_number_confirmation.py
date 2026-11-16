"""Regression checks for generated, visible, editable, and globally unique order numbers."""
import os
import re
import tempfile

with tempfile.TemporaryDirectory() as folder:
    os.environ['VERA_DB_BACKEND'] = 'sqlite'
    os.environ['VERA_STORAGE_BACKEND'] = 'local'
    os.environ['VERA_DB'] = os.path.join(folder, 'order-numbers.db')
    from service import app
    from fastapi.testclient import TestClient

    staff, wholesale, retail, other = TestClient(app), TestClient(app), TestClient(app), TestClient(app)

    def call(client, method, path, body=None, expected=200):
        response = client.get(f'/api/{path}') if method == 'get' else client.post(f'/api/{path}', json=body)
        assert response.status_code == expected, (path, response.status_code, response.text)
        return response.json() if response.content else None

    admin = call(staff, 'post', 'auth/login', {'username':'dylan','password':os.getenv('VERA_DEMO_PASSWORD','vera-demo')})
    staff.headers['Authorization'] = 'Bearer '+admin['token']
    customers = []
    for client, kind, username, code in [(wholesale,'wholesale','wholesale-test','TEST'),(retail,'retail','retail-test',None),
                                         (other,'wholesale','other-test','test')]:
        customer = call(staff,'post','operations/customers',{
            'company':username,'contact_name':'Test User','email':username+'@example.invalid','phone':'12345',
            'company_address':'Test address','username':username,'password':'test-password',
            'customer_type':kind,'customer_code':code})
        customers.append(customer)
        session = call(client,'post','portal/login',{'username':username,'password':'test-password'})
        client.headers['Authorization'] = 'Bearer '+session['token']

    price = {'evidence':'TEST ONLY','currency':'NZD','tax_basis':'test','rate_per_m2':'100','minimum_area':'1',
             'dimension_step_mm':1,'max_width_mm':3000,'max_height_mm':3000,'options':{},
             'formula':'area_fixed_percent_installation','deposit_basis':'order_total'}
    call(staff,'post','operations/pricing/1',price)
    order_body = {'project_name':'Test Job','site_address':'Test Site','submission_key':'submission-0001',
                  'lines':[{'window_name':'Window 1','product_id':1,'width_mm':1000,'height_mm':1000,'quantity':1,'options':{}}]}

    # The number is generated and shown to the customer as soon as the order is submitted.
    wholesale_pending = call(wholesale,'post','portal/orders',order_body)
    assert wholesale_pending['order_number']=='TEST-Test Job' and 'order_number_confirmed' not in wholesale_pending
    assert call(wholesale,'get','portal/orders')[0]['order_number']=='TEST-Test Job'
    assert call(wholesale,'post',f"operations/orders/{wholesale_pending['id']}/order-number",{'order_number':'x'},401)

    retail_pending = call(retail,'post','portal/orders',{**order_body,'project_name':'Retail Job','submission_key':'submission-0002'})
    assert re.fullmatch(r'R\d{6}\d{2}A',retail_pending['order_number']), retail_pending['order_number']
    assert call(retail,'get','portal/orders')[0]['order_number']==retail_pending['order_number']

    # Unique across every customer, ignoring case: another customer whose code differs only in case cannot reuse it.
    call(other,'post','portal/orders',{**order_body,'submission_key':'submission-0003'},409)

    edited_number = 'TEST-Edited Job'
    saved = call(staff,'post',f"operations/orders/{wholesale_pending['id']}/order-number",{'order_number':edited_number})
    assert saved['order_number']==edited_number
    assert call(wholesale,'get','portal/orders')[0]['order_number']==edited_number
    call(staff,'post',f"operations/orders/{retail_pending['id']}/order-number",{'order_number':edited_number.upper()},409)
    accepted = call(staff,'post',f"operations/orders/{wholesale_pending['id']}/review",{})
    assert accepted['status']=='accepted' and accepted['order_number']==edited_number
    call(staff,'post',f"operations/orders/{wholesale_pending['id']}/order-number",{'order_number':'after-accept'},409)
    print('PASS order number flow: customer-type generation, visible on submission, admin edit, global case-insensitive uniqueness, no confirmation step')
