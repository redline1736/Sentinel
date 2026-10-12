#!/usr/bin/env python3
"""
XSSLab — a Flask app that reflects user input under progressively
stricter WAF rules.  Designed as a scanner training target.

Routes:
    /                  index with links
    /level/0           no filtering at all (baseline)
    /level/1           HTML-entity output escaping (broken reflexively)
    /level/2           WAF: blocks literal '<script', 'onerror=', etc.
    /level/3           WAF: decodes entities + url before matching
    /level/4           WAF: whitelist-based (only safe tags allowed)
    /level/5           WAF: CSP + strict blacklist + rate limiting
"""
from flask import Flask, request, render_template_string, abort, make_response
from functools import wraps
import html
import re
import time
import urllib.parse
from collections import defaultdict

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Level metadata (drives the index page)
# ---------------------------------------------------------------------------
LEVELS = {
    0: "No filtering — raw reflection. Baseline sanity check.",
    1: "HTML-escaped reflection. Entities are inserted verbatim.",
    2: "WAF: naive blacklist on raw query string.",
    3: "WAF: blacklist applied AFTER url-decode + entity-decode.",
    4: "WAF: tag whitelist — only <b>, <i>, <u>, <p> survive.",
    5: "WAF: strict blacklist + CSP + per-IP rate limit.",
}

# ---------------------------------------------------------------------------
# Rate limiting (per IP, per level)
# ---------------------------------------------------------------------------
RATE_LIMIT_WINDOW = 10       # seconds
RATE_LIMIT_MAX    = 30       # requests per window
_hits = defaultdict(list)

def rate_limited(ip: str, key: str = "global") -> bool:
    now = time.time()
    bucket = _hits[(ip, key)]
    bucket[:] = [t for t in bucket if now - t < RATE_LIMIT_WINDOW]
    if len(bucket) >= RATE_LIMIT_MAX:
        return True
    bucket.append(now)
    return False

# ---------------------------------------------------------------------------
# WAF rules — ordered by strictness
# ---------------------------------------------------------------------------

# Level 2: naive blacklist.  Case-insensitive, applied to the raw value.
NAIVE_BLACKLIST = [
    r"<script",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"<img",
    r"<svg",
    r"<iframe",
    r"alert\s*\(",
]

# Level 3: after canonicalization, block anything that smells like XSS.
# Broader than level 2 — we strip tags entirely if they contain an event
# handler or a javascript: URL anywhere inside.
CANONICAL_TAG_RE = re.compile(r"<\s*([a-zA-Z0-9]+)([^>]*)>", re.S)
EVENT_HANDLER_RE = re.compile(r"\bon[a-z]+\s*=", re.I)
JS_URL_RE = re.compile(r"(?:java|vb|data)\s*script\s*:", re.I)
PROTOCOL_URL_RE = re.compile(r"\b(?:javascript|data|vbscript)\s*:", re.I)

# Level 4: only these tags survive, and only bare tags (no attributes).
SAFE_TAGS = {"b", "i", "u", "p", "br", "em", "strong"}

# Level 5: aggressive multi-layer blacklist.
LEVEL5_PATTERNS = [
    re.compile(r"<", re.I),
    re.compile(r">", re.I),
    re.compile(r"&(?:#x?[0-9a-f]+|[a-z]+);", re.I),  # any entity
    re.compile(r"\\x[0-9a-f]{2}", re.I),             # hex escapes
    re.compile(r"\\u[0-9a-f]{4}", re.I),             # unicode escapes
    re.compile(r"eval\s*\(", re.I),
    re.compile(r"expression\s*\(", re.I),
    re.compile(r"document\.", re.I),
    re.compile(r"window\.", re.I),
    re.compile(r"cookie", re.I),
    re.compile(r"location", re.I),
    re.compile(r"srcdoc", re.I),
    re.compile(r"formaction", re.I),
]

# ---------------------------------------------------------------------------
# WAF implementation
# ---------------------------------------------------------------------------

def waf_level2(value: str) -> tuple[bool, str]:
    lowered = value.lower()
    for pat in NAIVE_BLACKLIST:
        if re.search(pat, lowered, re.I):
            return False, f"blocked by WAF rule: {pat}"
    return True, value

def _canonicalize(value: str) -> str:
    """Decode entities and url-escapes, repeatedly, to catch obfuscation."""
    prev = None
    cur = value
    for _ in range(5):
        if cur == prev:
            break
        prev = cur
        cur = html.unescape(cur)
        cur = urllib.parse.unquote_plus(cur)
    return cur

def waf_level3(value: str) -> tuple[bool, str]:
    canon = _canonicalize(value)

    # Block any tag that carries an event handler or a JS/protocol URL.
    for m in CANONICAL_TAG_RE.finditer(canon):
        attrs = m.group(2) or ""
        if EVENT_HANDLER_RE.search(attrs):
            return False, "event handler in tag attributes"
        if PROTOCOL_URL_RE.search(attrs):
            return False, "script protocol in tag attributes"
    if JS_URL_RE.search(canon):
        return False, "javascript: scheme"

    # Strip <script> outright.
    if re.search(r"<\s*script", canon, re.I):
        return False, "<script> tag"

    return True, value

def waf_level4(value: str) -> tuple[bool, str]:
    """
    Whitelist: any tag not in SAFE_TAGS is removed; every attribute is
    dropped.  Anything that survives must be a bare formatting tag.
    """
    canon = _canonicalize(value)

    def repl(m):
        tag = m.group(1).lower()
        if tag in SAFE_TAGS:
            return f"<{tag}>"
        return ""   # drop unknown tags entirely

    filtered = CANONICAL_TAG_RE.sub(repl, canon)

    # Final check: no attribute-like or event-like residue.
    if EVENT_HANDLER_RE.search(filtered):
        return False, "event handler survived filtering"
    if PROTOCOL_URL_RE.search(filtered):
        return False, "script protocol survived filtering"

    return True, filtered

def waf_level5(value: str) -> tuple[bool, str]:
    canon = _canonicalize(value)
    for pat in LEVEL5_PATTERNS:
        if pat.search(canon):
            return False, f"blocked by rule: {pat.pattern}"
    # Additional structural check: reject anything starting with a '<'
    if canon.lstrip().startswith("<"):
        return False, "leading '<' rejected"
    return True, value

WAFS = {
    2: waf_level2,
    3: waf_level3,
    4: waf_level4,
    5: waf_level5,
}

# ---------------------------------------------------------------------------
# Shared layout
# ---------------------------------------------------------------------------
LAYOUT = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>XSSLab — level {{ level }}</title>
  <style>
    body   { font: 14px/1.5 system-ui, sans-serif; max-width: 780px;
             margin: 2rem auto; padding: 0 1rem; }
    h1     { margin-bottom: .2rem; }
    .meta  { color: #666; margin-bottom: 1rem; }
    .box   { border: 1px solid #ccc; padding: 1rem; border-radius: 6px;
             background: #fafafa; margin: 1rem 0; }
    code   { background: #eee; padding: 1px 4px; border-radius: 3px; }
    a      { color: #06c; }
    .block { color: #b00; font-weight: 600; }
    .pass  { color: #070; font-weight: 600; }
  </style>
</head>
<body>
  <h1>XSSLab — level {{ level }}</h1>
  <p class="meta">{{ description }}</p>
  <form method="get" action="">
    <input type="text" name="q" value="{{ q_raw }}" size="50"
           autocomplete="off" autofocus>
    <button type="submit">Go</button>
  </form>

  {% if blocked %}
    <div class="box block">🛑 {{ blocked }}</div>
  {% endif %}

  {% if q_raw %}
    <div class="box">
      <div><strong>Canonical form:</strong> <code>{{ q_canon }}</code></div>
      <div style="margin-top:.5rem"><strong>Rendered:</strong></div>
      <div>{{ rendered|safe }}</div>
    </div>
  {% endif %}

  <p><a href="/">← all levels</a></p>
</body>
</html>"""

INDEX = """<!doctype html>
<html><head><meta charset="utf-8"><title>XSSLab</title>
<style>
  body { font: 14px/1.6 system-ui, sans-serif; max-width: 720px;
         margin: 2rem auto; padding: 0 1rem; }
  h1   { margin-bottom: .2rem; }
  li   { margin-bottom: .4rem; }
  code { background: #eee; padding: 1px 4px; border-radius: 3px; }
</style></head><body>
<h1>XSSLab</h1>
<p>Reflected-XSS targets with progressive defenses. Test each level:</p>
<ul>
{% for n, desc in levels.items() %}
  <li><a href="/level/{{ n }}"><code>/level/{{ n }}</code></a> — {{ desc }}</li>
{% endfor %}
</ul>
<p>Submit with <code>?q=...</code>, e.g. <code>/level/0?q=&lt;b&gt;hi&lt;/b&gt;</code>.</p>
</body></html>"""

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template_string(INDEX, levels=LEVELS)

@app.route("/level/<int:n>")
def level(n: int):
    if n not in LEVELS:
        abort(404)

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?")

    # Level 5 rate limit
    if n == 5 and rate_limited(ip, key="level5"):
        return make_response("Too Many Requests", 429)

    q_raw = request.args.get("q", "")

    # Canonical form is always shown (informational — this is a lab).
    q_canon = _canonicalize(q_raw)

    blocked = None
    value = q_raw

    # Apply WAF if the level has one.
    if n in WAFS:
        ok, result = WAFS[n](q_raw)
        if not ok:
            blocked = result
            value = ""

    # -----------------------------------------------------------------
    # Reflection strategies per level
    # -----------------------------------------------------------------
    if n == 0:
        rendered = value                       # raw reflection
    elif n == 1:
        rendered = html.escape(value)          # entities inserted verbatim
    elif n == 2:
        rendered = value                       # passthrough after naive WAF
    elif n == 3:
        rendered = value                       # passthrough after canonical WAF
    elif n == 4:
        rendered = value                       # already whitelisted
    elif n == 5:
        rendered = value                       # passthrough after strict WAF
    else:
        rendered = value

    # Level 5 also sets a strict CSP.
    resp = make_response(render_template_string(
        LAYOUT,
        level=n,
        description=LEVELS[n],
        q_raw=q_raw,
        q_canon=q_canon,
        rendered=rendered,
        blocked=blocked,
    ))
    if n == 5:
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "script-src 'none'; "
            "style-src 'unsafe-inline'; "
            "img-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'none'; "
            "form-action 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
    return resp

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)