"""Remote CRM tools using the MCP Streamable HTTP transport."""
import hmac
import logging
import os
from contextlib import asynccontextmanager
from contextvars import ContextVar
from functools import wraps
from typing import Annotated, Any

from fastapi import HTTPException
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import Field
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.routing import Route

from operations import Batch, Fulfilment, OrderProviderAssignment, OrderReview, ShipmentEta, Supplier

from crm_mcp_oauth import KNOWLEDGE, MCP_PATH, METADATA_PATH, READ, SCOPES, WRITE, Principal, configured_oauth

LOGGER = logging.getLogger(__name__)
CURRENT_PRINCIPAL = ContextVar('crm_mcp_principal')


def actor():
    return CURRENT_PRINCIPAL.get().username

Limit = Annotated[int, Field(ge=1, le=100)]
Offset = Annotated[int, Field(ge=0)]


class AuthenticatedTransport:
    def __init__(self, transport, crm, oauth):
        self.transport = transport
        self.crm = crm
        self.oauth = oauth

    async def authenticate(self, headers):
        scheme, _, supplied = headers.get('authorization', '').partition(' ')
        bearer = supplied if scheme.lower() == 'bearer' else ''
        if self.oauth:
            if not bearer:
                raise HTTPException(401, 'MCP access token required',
                                    headers={'WWW-Authenticate': self.oauth.challenge()})
            principal = await run_in_threadpool(self.oauth.authenticate, bearer)
        else:
            token = os.getenv('VERA_MCP_TOKEN', '')
            username = os.getenv('VERA_MCP_USERNAME', '')
            if len(token) < 32 or not username:
                raise HTTPException(404, 'MCP is disabled')
            if not hmac.compare_digest(bearer.encode(), token.encode()):
                raise HTTPException(401, 'MCP credentials required', headers={'WWW-Authenticate': 'Bearer'})
            principal = Principal(username, frozenset(SCOPES))
        try:
            await run_in_threadpool(self.crm.me, principal.username)
        except HTTPException:
            raise HTTPException(403, 'MCP account is inactive') from None
        return principal

    async def __call__(self, scope, receive, send):
        headers = Headers(scope=scope)
        allowed_origins = {origin.strip() for origin in os.getenv('VERA_MCP_ALLOWED_ORIGINS', '').split(',')}
        origin = headers.get('origin')
        try:
            if origin is not None and (not origin or origin not in allowed_origins):
                raise HTTPException(403, 'Origin not allowed')
            principal = await self.authenticate(headers)
        except HTTPException as error:
            response = JSONResponse({'detail': error.detail}, status_code=error.status_code, headers=error.headers)
            await response(scope, receive, send)
            return
        context = CURRENT_PRINCIPAL.set(principal)
        try:
            await self.transport(scope, receive, send)
        finally:
            CURRENT_PRINCIPAL.reset(context)


def register_crm_mcp(app, crm, **operations):
    try:
        oauth = configured_oauth()
    except ValueError:
        LOGGER.error('MCP is disabled because its OAuth configuration is incomplete or invalid')
        return
    server = FastMCP(
        'VERA CRM',
        instructions='Use search_orders to find an order and get_order to inspect its current state and line IDs.',
        stateless_http=True,
        json_response=True,
        streamable_http_path=MCP_PATH,
        # The outer transport validates Origin and requires a private bearer credential.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    def scoped_tool(required_scope, *, read_only=False, open_world=False):
        annotations = ToolAnnotations(readOnlyHint=read_only, destructiveHint=False, openWorldHint=open_world)
        meta = {'securitySchemes': [{'type': 'oauth2', 'scopes': [required_scope]}]} if oauth else None

        def register(fn):
            @wraps(fn)
            async def guarded(*args, **kwargs):
                if required_scope not in CURRENT_PRINCIPAL.get().scopes:
                    message = f'Missing OAuth scope: {required_scope}'
                    return CallToolResult(isError=True, structuredContent={},
                                          content=[TextContent(type='text', text=message)],
                                          _meta={'mcp/www_authenticate': [
                                              oauth.challenge(required_scope, error='insufficient_scope')
                                          ]})
                return await fn(*args, **kwargs)

            return server.tool(annotations=annotations, meta=meta)(guarded)

        return register

    read = scoped_tool(READ, read_only=True)
    write = scoped_tool(WRITE)

    async def invoke(action, *args, admin=False, **kwargs):
        username = actor()

        def execute():
            if admin:
                crm.require_admin(username)
            return operations[action](*args, **kwargs)

        try:
            return await run_in_threadpool(execute)
        except HTTPException as error:
            if error.status_code < 500:
                raise ToolError(f'{error.status_code}: {error.detail}') from None
            raise ToolError(f'{error.status_code}: CRM service unavailable') from None
        except Exception:
            LOGGER.exception('CRM MCP operation failed: %s', action)
            raise ToolError('CRM operation failed') from None

    def page(items, limit, offset):
        return {'items': items[offset:offset + limit], 'total': len(items)}

    @read
    async def search_orders(query: str = '', status: str = '', customer_id: int | None = None,
                            limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
        """Find orders by number, project, company or internal ID. Filter by CRM status or customer."""
        return await invoke('search_orders', query.strip().casefold(), status.strip().casefold(),
                            customer_id, limit, offset)

    @read
    async def get_order(reference: str) -> dict[str, Any]:
        """Get CRM order details, lines, event history and linked invoices by order number or internal ID."""
        return await invoke('get_order', reference.strip())

    @read
    async def get_order_lead_time(order_id: str) -> dict[str, Any]:
        """Read the lead-time rules for an accepted order. Use get_order for its estimated arrival."""
        return await invoke('lead_time', order_id, actor=actor())

    @scoped_tool(KNOWLEDGE, read_only=True)
    async def get_pricing_knowledge() -> dict[str, Any]:
        """Read the published pricing rules, variable bindings and source references. Requires a CRM administrator."""
        return await invoke('current_knowledge', admin=True)

    @read
    async def list_customers(query: str = '', limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
        """List CRM customer profiles, optionally filtering by company name."""
        customers = await invoke('customers', actor=actor())
        term = query.strip().casefold()
        return page([item for item in customers if term in str(item.get('company') or '').casefold()], limit, offset)

    @read
    async def list_invoices(customer_id: int | None = None, limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
        """List invoices, optionally filtering by CRM customer ID."""
        invoices = await invoke('invoices', actor=actor())
        return page([item for item in invoices if customer_id is None or item['customer_id'] == customer_id],
                    limit, offset)

    @read
    async def list_shipments(limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
        """List shipment batches and their CRM statuses."""
        return page(await invoke('shipments', actor=actor()), limit, offset)

    @read
    async def get_shipment(shipment_id: str) -> dict[str, Any]:
        """Get one shipment batch and its linked orders."""
        return await invoke('shipment_detail', shipment_id, actor=actor())

    @read
    async def list_suppliers(limit: Limit = 20, offset: Offset = 0) -> dict[str, Any]:
        """List CRM supplier records."""
        return page(await invoke('providers', actor=actor()), limit, offset)

    @read
    async def get_order_suppliers(order_id: str) -> dict[str, Any]:
        """Read supplier assignments for an internal order ID."""
        return {'items': await invoke('order_providers', order_id, actor=actor())}

    @scoped_tool(WRITE, open_world=True)
    async def approve_order(order_id: str, details: OrderReview | None = None) -> dict[str, Any]:
        """Approve technical review and create the deposit invoice. CRM email settings apply. Administrator required. Confirm the order number in details when CRM requires it."""
        return await invoke('review', order_id, details, actor=actor(), admin=True)

    @write
    async def record_order_deposit(order_id: str) -> dict[str, Any]:
        """Record an already-received deposit and start the order lead time. Does not collect payment."""
        return await invoke('received', order_id, actor=actor())

    @write
    async def record_supplier_order(order_id: str, details: Supplier | None = None) -> dict[str, Any]:
        """Record that a deposit-paid order was placed with a supplier."""
        return await invoke('supplier_order', order_id, details, actor=actor())

    @write
    async def mark_orders_in_transit(batch: Batch) -> dict[str, Any]:
        """Move supplier-ordered orders to in_transit. Reuse the operation key on retries. Inspect per-order results."""
        return await invoke('transit', batch, actor=actor())

    @scoped_tool(WRITE, open_world=True)
    async def record_order_fulfilment(details: Fulfilment) -> dict[str, Any]:
        """Record whole-order arrival or delivery using all outstanding line quantities. CRM email settings apply."""
        return await invoke('fulfilment', details, actor=actor())

    @write
    async def update_shipment_eta(shipment_id: str, details: ShipmentEta) -> dict[str, Any]:
        """Set a shipment ETA using an ISO calendar date."""
        return await invoke('shipment_eta', shipment_id, details, actor=actor())

    @scoped_tool(WRITE, open_world=True)
    async def record_shipment_arrival(shipment_id: str) -> dict[str, Any]:
        """Record arrival for a shipment batch and its linked orders. CRM email settings apply."""
        return await invoke('shipment_arrive', shipment_id, actor=actor())

    @write
    async def assign_order_supplier(order_id: str, details: OrderProviderAssignment) -> dict[str, Any]:
        """Assign an active supplier and optional template to an order."""
        return await invoke('assign_provider', order_id, details, actor=actor())

    transport = server.streamable_http_app()
    previous_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application):
        async with previous_lifespan(application) as state, server.session_manager.run():
            yield state

    app.router.lifespan_context = lifespan
    app.router.routes.append(Route(MCP_PATH, AuthenticatedTransport(transport, crm, oauth)))
    if oauth:
        app.get(METADATA_PATH, include_in_schema=False)(oauth.metadata)
