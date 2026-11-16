"""Renderer for the staff OAuth consent and recovery pages."""
import base64
import hashlib
from html import escape
from urllib.parse import quote, urlsplit

from starlette.responses import HTMLResponse


PAGE_HEADERS = {
    'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
}
CONSENT_STYLE = """
  :root {
    color-scheme: light;
    font: 16px/1.5 "Figtree", "Segoe UI", system-ui, sans-serif;
    color: #28343a;
    background: #edf1f1;
    --muted: #51636c;
    --border: #d5dfe1;
    --action: #354552;
  }
  *, *::before, *::after { box-sizing: border-box; }
  body { margin: 0; }
  main { width: min(100% - 2rem, 34rem); margin: clamp(1rem, 6vh, 4rem) auto; }
  .card {
    padding: clamp(1.25rem, 5vw, 2.25rem);
    border: 1px solid var(--border);
    border-radius: 1.25rem;
    background: #fff;
    box-shadow: 0 18px 56px -30px rgb(35 54 63 / 35%);
  }
  .brand { display: flex; align-items: center; gap: .65rem; margin-bottom: 1.4rem; font-weight: 700; }
  .brand-mark { display: grid; place-items: center; width: 2rem; height: 2rem; color: #fff;
    background: var(--action); border-radius: .55rem; font: bold 1.15rem Georgia, serif; }
  h1, h2, p { margin: 0; }
  h1 { font: 600 clamp(1.65rem, 5vw, 2.25rem)/1.2 Georgia, serif; letter-spacing: -.035em; }
  h2 { font-size: .94rem; }
  .intro { margin-top: .65rem; color: var(--muted); }
  .permissions { margin: 1.25rem 0; padding: .9rem 1rem; background: #f4f7f7;
    border: 1px solid #e2e9e9; border-radius: .75rem; }
  .permissions ul { margin: .35rem 0 0; padding-left: 1.15rem; font-size: .9rem; }
  .permissions li + li { margin-top: .25rem; }
  .destination { display: block; margin-top: .55rem; color: var(--muted); font-size: .78rem; overflow-wrap: anywhere; }
  form { display: grid; gap: .8rem; }
  label { display: grid; gap: .25rem; font-weight: 650; font-size: .9rem; }
  input { width: 100%; min-height: 2.8rem; border: 1px solid #aebdc3; padding: .55rem .7rem;
    background: #fff; border-radius: .55rem; color: inherit;
    font-family: inherit; font-size: 1rem; font-weight: 400; }
  .actions { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .35rem; }
  button, .action {
    display: inline-flex; align-items: center; justify-content: center; min-height: 44px;
    padding: .55rem 1rem; border-radius: .55rem; border: 1px solid var(--action);
    font: inherit; font-weight: 650; font-size: .9rem; cursor: pointer; text-decoration: none;
    color: #fff; background: var(--action);
  }
  .primary { flex: 1; }
  .secondary { color: var(--action); background: #fff; border-color: var(--border); }
  .primary:hover, .action:hover { background: #243740; }
  .secondary:hover { background: #edf1f1; }
  .notice { margin: 1rem 0; padding: .65rem .8rem; background: #fff4ef; color: #7c352f;
    border: 1px solid #f0cfc4; border-radius: .55rem; font-size: .9rem; }
  .notice a { color: inherit; }
  :focus-visible { outline: 2px solid #245d6a; outline-offset: 2px; }
  @media (max-width: 24rem) {
    .actions > * { width: 100%; flex: auto; }
  }
"""
STYLE_HASH = base64.b64encode(hashlib.sha256(CONSENT_STYLE.encode()).digest()).decode()
PERMISSIONS = {
    'crm:read': 'Read CRM records and the operating guide',
    'crm:orders:write': 'Update orders, shipments and supplier assignments',
    'crm:knowledge:read': 'Read pricing knowledge (CRM administrators only)',
}


def document(content, status=200, callback=None):
    # Chromium applies form-action to the OAuth redirect after submission.
    targets = "'self'"
    if callback:
        url = urlsplit(callback)
        path = quote(url.path or '/', safe='/%-._~')
        targets += f' {url.scheme}://{url.netloc}{path}'
    csp = (f"default-src 'none'; style-src 'sha256-{STYLE_HASH}'; "
           f"form-action {targets}; frame-ancestors 'none'; base-uri 'none'")
    return HTMLResponse(f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect VERA CRM</title><style>{CONSENT_STYLE}</style></head>
<body><main><section class="card" aria-labelledby="consent-title">
<div class="brand"><span class="brand-mark" aria-hidden="true">V</span>VERA CRM</div>
{content}
</section></main></body></html>""", status_code=status,
                        headers={**PAGE_HEADERS, 'Content-Security-Policy': csp})


def consent_form(action, ticket, csrf, scopes, callback, app_name, username='', error='', status=200):
    permissions = ''.join(f'<li>{escape(PERMISSIONS[scope])}</li>' for scope in scopes)
    host = escape(urlsplit(callback).netloc)
    notice = f'<p class="notice" role="alert">{escape(error)}</p>' if error else ''
    return document(f"""
<h1 id="consent-title">Connect VERA CRM</h1>
<p class="intro">Sign in with your CRM staff account to connect to <strong>{escape(app_name)}</strong>.</p>
<section class="permissions" aria-labelledby="permission-heading">
<h2 id="permission-heading">Requested access</h2><ul>{permissions}</ul>
<small class="destination">{host}</small>
</section>
{notice}
<form method="post" action="{escape(action)}">
<input type="hidden" name="ticket" value="{escape(ticket)}">
<input type="hidden" name="csrf" value="{escape(csrf)}">
<label>CRM username <input name="username" value="{escape(username)}" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="200" required></label>
<label>CRM password <input name="password" type="password" autocomplete="current-password" maxlength="200" required></label>
<div class="actions">
<button class="primary" name="decision" value="allow">Sign in and authorize</button>
<button class="secondary" name="decision" value="deny" formnovalidate>Cancel</button>
</div>
</form>
""", status=status, callback=callback)


def consent_error(message, status, resume=None):
    link = f'<div class="actions"><a class="action" href="{escape(resume)}">Reload authorization</a></div>' if resume else ''
    return document(f"""
<h1 id="consent-title">Reconnect VERA CRM</h1>
<p class="notice" role="alert">{escape(message)}</p>
{link}
""", status=status)
