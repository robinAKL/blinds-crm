# VERA API

The current API is documented in [OPERATIONS.md](OPERATIONS.md).

Retained domains: staff auth/users, products/media, `/api/portal/*` and `/api/operations/*`. The previous inquiry, quotation, manual-order, follow-up, communication, AI and mail-sync APIs have been removed and return 404.

Create a new schema with `python backend/init_database.py`. Add current tables to an existing schema with `python backend/migrate_operations.py`.

Physical retired-data cleanup is explicit: `python backend/cleanup_legacy.py` prints a count-only plan. `--apply --backup <private-new-archive.json>` archives retired rows, drops only fixed legacy tables without CASCADE, removes unlinked legacy customers and verifies current records unchanged in one transaction. Use a provider snapshot for complete rollback. No live cleanup is performed by preparing this change.

## Remote CRM MCP

Use Streamable HTTP at `https://<CRM-host>/api/mcp`. Deploy with OAuth 2.1 for
per-user sign-in. A fixed integration credential is also supported when the four
OAuth settings below are unset. Configure the backend environment and redeploy.

### OAuth 2.1 with existing VERA staff accounts

Set the following backend environment variables and deploy:

```env
VERA_MCP_OAUTH_MODE=staff
VERA_MCP_OAUTH_RESOURCE=https://blinds-crm.vercel.app/api/mcp
```

Add the resource URL to the MCP client and select OAuth with dynamic client
registration. The client redirects to VERA's consent page where the employee
signs in using the regular CRM username and password. Each tool call is attributed
to that account. The staff mode uses CRM-backed, resource-bound opaque access
tokens. An access token lasts up to 15 minutes, and a rotating refresh token lasts
at most as long as the current CRM authorization session. Disabling the account
or changing its password invalidates its MCP access.

The default approved callbacks are
`https://chatgpt.com/connector_platform_oauth_redirect` and
`https://claude.ai/api/mcp/auth_callback`. If the MCP client displays a different
callback, set `VERA_MCP_OAUTH_CALLBACKS` to the exact displayed HTTPS URL
(additional entries can be comma-separated), then redeploy. The allowlist is
applied to dynamic registrations. The backend creates the OAuth storage table on
first use with its existing database credentials.

The external issuer, JWKS and subject map settings below apply to external
OAuth mode. Staff mode derives the issuer from the resource and binds each token
directly to the authorized CRM account.

### OAuth 2.1 with an external identity provider

| Variable | Purpose |
| --- | --- |
| `VERA_MCP_OAUTH_RESOURCE` | The exact HTTPS MCP endpoint, for example `https://crm.example.com/api/mcp`. Use this as the authorization server's resource indicator and access-token audience. |
| `VERA_MCP_OAUTH_ISSUER` | The provider's exact issuer URL as published in its metadata and tokens. Include its trailing slash if the provider does. |
| `VERA_MCP_OAUTH_JWKS_URL` | The provider's trusted HTTPS signing-key endpoint. |
| `VERA_MCP_OAUTH_SUBJECT_MAP` | JSON map from immutable provider subjects to active CRM usernames, e.g. `{"provider-subject-1":"crm-staff"}`. Keep it in backend configuration. |

Configure the provider to publish OAuth or OIDC discovery, handle user sign-in
and consent, and support the authorization-code flow with S256 PKCE. Configure
client registration using the method supported by the target MCP client and
provider (Client ID Metadata Document, dynamic registration, or a preregistered
client), including their exact callback URLs. Issue short-lived, RS256-signed
RFC 9068 JWT access tokens for the configured resource. FastAPI validates the
signature, issuer, audience, expiry, token type and scope, then uses the mapped
CRM staff account for authorization and audit events.

The public discovery endpoint is
`/.well-known/oauth-protected-resource/api/mcp`. An unauthenticated request to the
MCP endpoint returns a 401 challenge that advertises this URL. Configure these
scopes at the identity provider and grant them only to the relevant users.

| Scope | Access |
| --- | --- |
| `crm:read` | Read orders, customers, invoices, shipments and suppliers. |
| `crm:orders:write` | Run order, shipment and supplier workflow actions. CRM role checks also apply. |
| `crm:knowledge:read` | Read active pricing knowledge. The mapped account must also be a CRM administrator. |

Set all four OAuth variables together. When OAuth is enabled, the shared bearer
token is disabled. Each mapped account can access the same CRM records its
staff role can access through the REST API.

### Fixed bearer token and shared settings

| Variable | Purpose |
| --- | --- |
| `VERA_MCP_TOKEN` | Private random token of at least 32 characters. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. |
| `VERA_MCP_USERNAME` | Existing active CRM staff username used for permissions and audit events. Access covers the CRM records available to that account. |
| `VERA_MCP_ALLOWED_ORIGINS` | Optional comma-separated exact origins for clients that send an Origin header. |

For fixed-token mode, store the token in server and client secret settings and
send it as `Authorization: Bearer <token>` over HTTPS. This mode attributes
all requests to the configured integration account.

| Capability | Tools |
| --- | --- |
| CRM operating guide (workflow steps, statuses, UI-only actions) | `get_crm_guide` (optional `step`, `language` zh/en) |
| Orders | `search_orders`, `get_order`, `get_order_lead_time` |
| Published pricing knowledge and source references | `get_pricing_knowledge` (CRM administrator) |
| Customers, invoices, shipments and suppliers | `list_customers`, `list_invoices`, `list_shipments`, `get_shipment`, `list_suppliers`, `get_order_suppliers` |
| Order review, payment and fulfilment | `approve_order` (CRM administrator), `record_order_deposit`, `record_supplier_order`, `mark_orders_in_transit`, `record_order_fulfilment` |
| Shipment and supplier changes | `update_shipment_eta`, `record_shipment_arrival`, `assign_order_supplier` |

Use `search_orders` and `get_order` to resolve a business order number to the
internal order ID before making a change. CRM workflow rules apply, including
invoice creation and configured notifications. Reuse the same operation key and
arguments when retrying transit or fulfilment. Transit reports individual order
outcomes in `results`. MCP clients should inspect both `isError` and those outcomes.

Run `python test_crm_mcp.py`, `python test_crm_mcp_oauth.py` and `python test_crm_mcp_staff_oauth.py` from the backend directory for local integration checks.
