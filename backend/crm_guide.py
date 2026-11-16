"""Staff operating guide for the VERA CRM, shared with MCP clients.

Keep the step wording in sync with frontend/src/components/CrmGuide.vue.
"""
from copy import deepcopy

LANGUAGES = ('zh', 'en')


def _t(zh, en):
    return {'zh': zh, 'en': en}


STEPS = [
    {
        'id': 'customer_order',
        'name': _t('客户下单', 'Customer order'),
        'workspace': '/crm/projects',
        'points': [
            _t('客户在门户选系列，逐扇配置窗户（尺寸为毫米），价格随选项实时显示。',
               'The customer picks a series and configures each window (millimetres). The price updates as options change.'),
            _t('提交后订单状态是“待审核”：还没收款，也没向供应商下单。',
               'A submitted order is “awaiting review”: nothing is paid and nothing is ordered from the supplier yet.'),
        ],
        'note': _t('缺少必填项时页面会列出具体字段，补齐后才能进入下一扇窗。',
                   'Missing required fields are listed by name; complete them to continue.'),
        'mcp_tools': ['search_orders', 'get_order'],
        'ui_only': [_t('订单由客户在门户创建，MCP 不能代客下单。', 'Orders are created by customers in the portal; MCP cannot place them.')],
    },
    {
        'id': 'review_deposit',
        'name': _t('审核与定金', 'Review & deposit'),
        'workspace': '/crm/projects',
        'points': [
            _t('选中订单，在“计价与审核”核对价格版本和配置（尺寸超限、扇数不对等技术问题在这里拦截）。',
               'Select the order and check price version and configuration under Pricing & review (out-of-spec sizes and wrong panel counts are caught here).'),
            _t('点“确认接收”生成 60% 定金发票草稿（向上取整到分）。审核后价格冻结。',
               'Accepting creates a 60% deposit invoice draft, rounded up to the cent. Prices are frozen after review.'),
            _t('“定金已收”是单独的记录动作，核实到账后再点；发送发票也是单独一步。',
               '“Deposit received” is a separate record, clicked only after the money is confirmed; sending the invoice is another separate step.'),
        ],
        'note': _t('系统不会扣款或转账，只记录你确认的结果。',
                   'The system never charges or transfers money; it only records what you confirm.'),
        'mcp_tools': ['get_order', 'approve_order', 'record_order_deposit'],
        'ui_only': [_t('接收前需确认订单号：approve_order 传 details.confirm_order_number=true。',
                       'The order number must be confirmed on acceptance: pass details.confirm_order_number=true to approve_order.'),
                    _t('发送发票邮件只能在后台操作。', 'Sending the invoice email is done in the CRM UI.')],
    },
    {
        'id': 'supplier_order',
        'name': _t('供应商下单', 'Supplier order'),
        'workspace': '/crm/providers',
        'points': [
            _t('到“供应商与导出”核对自动带出的供应商和模板，点“下载供应商订单 Excel”，分配同时被保存。',
               'Under Supplier & files, check the preselected supplier and template, then download the supplier Excel; the assignment is saved at the same time.'),
            _t('定金确认后下载供应商订单，再点“标为已下单”。订单号就是客户订单号，不用另填供应商号。',
               "After the deposit is confirmed, download the supplier order, then click Mark as ordered. The order number is the customer's; no separate supplier number."),
        ],
        'note': _t('没有正式工厂模板时导出的只是通用草稿，需要人工核对；导出本身不会发邮件。',
                   'Without a confirmed factory template the export is a generic draft to be checked by hand; exporting never sends email.'),
        'mcp_tools': ['list_suppliers', 'get_order_suppliers', 'assign_order_supplier', 'record_supplier_order'],
        'ui_only': [_t('供应商 Excel 下载只能在后台操作。', 'Downloading the supplier Excel is done in the CRM UI.')],
    },
    {
        'id': 'transit_delivery',
        'name': _t('在途·到货·交付', 'Transit, arrival, delivery'),
        'workspace': '/crm/projects',
        'points': [
            _t('供应商发货后，在订单列表勾选订单，批量标记“在途”。',
               'After the supplier ships, tick the orders in the list and mark them in transit in one action.'),
            _t('运输批次标记为到仓后，批次内订单会自动更新为可提货；无需逐个订单录入到货件数。',
               'When a shipment batch is marked arrived at the warehouse, its orders automatically become ready for collection; arrival quantities do not need to be entered order by order.'),
            _t('订单交付仍在订单明细中单独记录。',
               'Record collection or installation completion separately in the order details.'),
        ],
        'note': _t('尾款开票以运输批次到仓和定金已收为准。',
                   'Balance invoicing requires the shipment batch to be at the warehouse and the deposit to be received.'),
        'mcp_tools': ['mark_orders_in_transit', 'list_shipments', 'get_shipment', 'update_shipment_eta',
                      'record_shipment_arrival', 'record_order_fulfilment', 'get_order_lead_time'],
        'ui_only': [],
    },
    {
        'id': 'balance_invoice',
        'name': _t('尾款发票', 'Balance invoice'),
        'workspace': '/crm/finance',
        'points': [
            _t('在“账款与返利”勾选同一公司、同币种、批次已到仓且定金已收的订单，点“生成尾款草稿”。',
               'Under Accounts & rebates, tick orders of one company and currency whose shipment has arrived and whose deposit is received, then click Create balance draft.'),
            _t('金额 = 所选订单总额 − 已存定金 − 本次明确选择的可用返利；每条返利抵扣会列在发票上。“规则说明”按所选订单自动生成，可以修改。',
               'Amount = selected order totals − stored deposits − rebates explicitly selected for this invoice. Each rebate credit is listed on the invoice. The rule note is generated from the selected orders and can be edited.'),
            _t('草稿检查无误后再单独发送，收到款项后点“确认尾款收款”。',
               'Review the draft, send it as a separate step, and click Confirm balance receipt once the money has arrived.'),
        ],
        'note': _t('生成草稿不会发给客户。', 'Creating the draft sends nothing to the customer.'),
        'mcp_tools': ['list_invoices'],
        'ui_only': [_t('生成、发送尾款发票及确认收款只能在后台操作。',
                       'Creating, sending and confirming balance invoices is done in the CRM UI.')],
    },
    {
        'id': 'rebate',
        'name': _t('返利', 'Rebate'),
        'workspace': '/crm/finance',
        'points': [
            _t('在“返利”页填年月、金额、来源订单和确认依据。创建尾款账单时，手动选择要抵扣的返利；用过的金额会显示关联账单。',
               'On the Rebates tab enter the month, amount, source orders and evidence. Select rebates explicitly when creating a balance invoice; used amounts show the linked invoice.'),
            _t('同一来源订单不能重复计入；页面显示已用和余额。',
               'A source order cannot be counted twice; used and remaining amounts are shown.'),
        ],
        'note': _t('原始 Excel 里没有返利公式，所以系统不会自动算阶梯。需要的参数见 docs/REBATE-RULE-INPUTS.md。',
                   'The source Excel has no rebate formula, so tiers are not calculated automatically. Required inputs are listed in docs/REBATE-RULE-INPUTS.md.'),
        'mcp_tools': [],
        'ui_only': [_t('返利录入只能在后台操作。', 'Rebates are recorded in the CRM UI.')],
    },
]

ORDER_STATUSES = [
    ('draft', _t('草稿', 'Draft')),
    ('pending_review', _t('待审核', 'Awaiting review')),
    ('accepted', _t('已接收', 'Accepted')),
    ('supplier_ordered', _t('已向供应商下单', 'Ordered from supplier')),
    ('in_transit', _t('在途', 'In transit')),
    ('ready', _t('可提货', 'Ready for collection')),
    ('complete', _t('已完成', 'Complete')),
]

PAYMENT_STATUSES = [
    ('deposit_unpaid', _t('定金未付', 'Deposit unpaid')),
    ('deposit_received', _t('定金已收', 'Deposit received')),
    ('paid', _t('已付清', 'Paid in full')),
]

REFERENCES = [
    {'name': _t('定价知识库（产品价格与计算）', 'Pricing knowledge (Product pricing & calculation)'),
     'workspace': '/crm/products',
     'detail': _t('在“产品”页切到“产品价格与计算”：产品价格、共享规则（最低面积、税率、定金、安装费、附加项、折扣）、来源与版本。仅管理员可编辑。',
                  'Under Product, open Product pricing & calculation: product rates, shared rules (minimum area, tax, deposit, installation, add-ons, discounts), sources and versions. Admins only.'),
     'mcp_tools': ['get_pricing_knowledge']},
    {'name': _t('客户资料', 'Customers'), 'workspace': '/crm/customers',
     'detail': _t('客户类型、批发代码和门户账号。', 'Customer type, wholesale code and portal accounts.'),
     'mcp_tools': ['list_customers']},
    {'name': _t('产品目录', 'Product catalogue'), 'workspace': '/crm/products',
     'detail': _t('产品展示信息、尺寸范围、颜色与控制方式。', 'Product listing, size ranges, colours and controls.'),
     'mcp_tools': []},
]


def _localize(value, language):
    if isinstance(value, dict) and set(value) == set(LANGUAGES):
        return value[language]
    if isinstance(value, dict):
        return {key: _localize(item, language) for key, item in value.items()}
    if isinstance(value, list):
        return [_localize(item, language) for item in value]
    return value


def crm_guide(step='', language='zh'):
    """Return the operating guide, optionally narrowed to one step."""
    language = language if language in LANGUAGES else 'zh'
    steps = [{**deepcopy(row), 'order': index} for index, row in enumerate(STEPS, 1)]
    if step:
        steps = [row for row in steps if row['id'] == step]
        if not steps:
            raise KeyError(step)
    guide = {
        'title': _t('后台操作指南', 'CRM operating guide'),
        'summary': _t('按业务顺序：客户下单 → 审核与定金 → 供应商下单 → 在途·到货·交付 → 尾款发票 → 返利。',
                      'Workflow order: customer order → review & deposit → supplier order → transit, arrival, delivery → balance invoice → rebate.'),
        'steps': steps,
        'step_ids': [row['id'] for row in STEPS],
    }
    if not step:
        guide['order_statuses'] = [{'value': value, 'label': label} for value, label in ORDER_STATUSES]
        guide['payment_statuses'] = [{'value': value, 'label': label} for value, label in PAYMENT_STATUSES]
        guide['references'] = REFERENCES
    return _localize(guide, language)
