#!/usr/bin/env python3
"""
Public gateway — the only service bound to 0.0.0.0.

    /search?q=...        forwards to products-api  (SQLi rides through)
    /render?tmpl=...     fetches URL, injects body as HTML (SSRF → XSS)
    /products/<id>       clean lookup, no injection surface
"""
import requests
from flask import Flask, request, Response

PRODUCTS_API = "http://127.0.0.1:8081"
SANDBOX      = "http://127.0.0.1:8082"

app = Flask(__name__)


@app.route("/")
def index():
    return (
        "<h1>Aero Store</h1>"
        "<form action='/search'>"
        "<input name='q' placeholder='search products'>"
        "<button>Search</button>"
        "</form>"
        "<p><a href='/render?tmpl=http://127.0.0.1:8082/templates'>"
        "Show templates</a></p>"
    )


# ---------------------------------------------------------------------------
# 1. Legitimate search.  Forwards q to products-api unchanged.
#    Any SQLi in the products API is reachable through this hop.
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    try:
        r = requests.get(f"{PRODUCTS_API}/products",
                         params={"q": q}, timeout=5)
    except requests.RequestException as e:
        return Response(f"upstream error: {e}\n", status=502,
                        mimetype="text/plain")
    return Response(r.content, status=r.status_code,
                    mimetype=r.headers.get("Content-Type", "application/json"))


# ---------------------------------------------------------------------------
# 2. SSRF.  Fetches an arbitrary URL.  Reaches the sandbox, and through
#    the sandbox, any other internal service.  The fetched body is
#    injected as HTML — the XSS sink.
# ---------------------------------------------------------------------------
@app.route("/render")
def render():
    tmpl = request.args.get("tmpl", "")
    if not tmpl:
        return Response("usage: /render?tmpl=http://...\n",
                        status=400, mimetype="text/plain")
    try:
        r = requests.get(tmpl, timeout=5)
    except requests.RequestException as e:
        return Response(f"fetch failed: {e}\n", status=502,
                        mimetype="text/plain")

    page = (
        "<!doctype html><html><head><title>Aero Store</title></head><body>"
        "<header><a href='/'>Aero Store</a></header>"
        f"<main>{r.text}</main>"
        "<footer>© Aero Store</footer>"
        "</body></html>"
    )
    return Response(page, mimetype="text/html")


# ---------------------------------------------------------------------------
# 3. Clean lookup.  id is an int — no injection surface.
# ---------------------------------------------------------------------------
@app.route("/products/<int:pid>")
def product(pid):
    try:
        r = requests.get(f"{PRODUCTS_API}/product/{pid}", timeout=5)
    except requests.RequestException as e:
        return Response(f"upstream error: {e}\n", status=502,
                        mimetype="text/plain")
    return Response(r.content, status=r.status_code,
                    mimetype=r.headers.get("Content-Type", "application/json"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)