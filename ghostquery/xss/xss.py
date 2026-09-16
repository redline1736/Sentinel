#!/usr/bin/env python3
"""
ghostquery/xss/main.py — JS route harvester + XSS scanner.

Usage:
    python3 ghostquery/xss/main.py <target-url> <output-dir> [--gobuster <file>]

Arguments:
    <target-url>     Full URL or bare hostname. Examples:
                        https://example.com/greet
                        https://example.com/search?q=test
                        example.com
    <output-dir>     Directory to write routes.txt / urls.txt / *.txt results.

Options:
    --gobuster PATH  Explicit path to a gobuster.txt file. If omitted, the
                     script auto-detects <output-dir>/gobuster.txt.

Pipeline:
    1. Normalize the target into (base_url, seed_url).
    2. Load gobuster.txt (explicit path or <output-dir>/gobuster.txt).
       * gobuster paths are joined against base_url.
    3. Crawl the seed URL + all gobuster URLs (same-origin, bounded) for JS.
    4. Extract routes & query params from JS bundles.
    5. Union of {seed_url, gobuster_urls, JS-extracted routes}.
    6. Keep only URLs with query params → urls.txt.
    7. Run Dalfox + XSStrike on those URLs.

Requires: dalfox, XSStrike, playwright (chromium), requests.
Gobuster is NOT run here — it must be produced upstream.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import urljoin, urlparse, parse_qs, urlsplit, urlunsplit

import requests
from playwright.sync_api import sync_playwright

# --------------------------------------------------------------------------- #
# Globals (populated in main())
# --------------------------------------------------------------------------- #
ROUTES = set()
VISITED_JS = set()

OUT_DIR = None
GOBUSTER_FILE = None
BASE_URL = None
SEED_URL = None

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

XSSTRIKE_PATHS = [
    "/opt/XSStrike/xsstrike.py",
    "/usr/share/XSStrike/xsstrike.py",
    os.path.join(os.getcwd(), "XSStrike", "xsstrike.py"),
]

NON_ROUTE_EXT = {
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".webm", ".avi",
    ".pdf", ".zip", ".gz", ".tar", ".7z", ".exe", ".msi", ".map", ".txt", ".xml",
    ".json", ".webmanifest",
}

TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term",
                   "utm_content", "_ga", "_gl", "fbclid", "gclid"}

MAX_CRAWL_PAGES = 12   # seed + up to (N-1) gobuster paths


# --------------------------------------------------------------------------- #
# URL helpers
# --------------------------------------------------------------------------- #
def normalize(base, path):
    """Resolve a possibly-relative URL against base. Returns None for junk."""
    if not path:
        return None
    path = path.strip().strip("\"'`")
    if not path:
        return None

    if path.startswith(("http://", "https://")):
        url = path
    elif path.startswith("//"):
        scheme = urlsplit(base).scheme or "http"
        url = f"{scheme}:{path}"
    elif path.startswith("/"):
        p = urlsplit(base)
        url = urlunsplit((p.scheme or "http", p.netloc, path, "", ""))
    else:
        url = urljoin(base, path)

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return None
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def clean_template(s):
    """Turn `/api/users/${id}` into `/api/users/` so it can be normalized."""
    return re.sub(r"\$\{[^}]*\}", "", s).strip()


def is_asset(url):
    path = urlsplit(url).path.lower()
    if any(path.endswith(ext) for ext in NON_ROUTE_EXT):
        return True
    return "/static/" in path or "/assets/" in path


def is_js_url(url):
    return urlsplit(url).path.lower().endswith((".js", ".mjs"))


def is_injectable(url):
    try:
        params = parse_qs(urlparse(url).query)
        params = {k: v for k, v in params.items()
                  if k.lower() not in TRACKING_PARAMS}
        return len(params) > 0
    except Exception:
        return False


def parse_target(raw):
    """
    Accept hostname OR full URL. Return (base_url, seed_url).
        "example.com"                    -> ("https://example.com", "https://example.com")
        "https://example.com/a/b"        -> ("https://example.com", "https://example.com/a/b")
        "https://example.com/x?y=1"      -> ("https://example.com", "https://example.com/x?y=1")
    """
    raw = raw.strip()
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw

    p = urlsplit(raw)
    scheme = p.scheme or "https"
    netloc = p.netloc
    path = p.path or "/"
    query = p.query

    base = urlunsplit((scheme, netloc, "", "", ""))
    seed = urlunsplit((scheme, netloc, path, query, ""))
    return base, seed


# --------------------------------------------------------------------------- #
# Phase 1: gobuster.txt loader
# --------------------------------------------------------------------------- #
def parse_gobuster_line(line):
    """
    Gobuster dir output looks like:
        /admin                (Status: 301) [Size: 0]
        /index.html           (Status: 200) [Size: 1234]
    Return the leading path if valid, else None.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    # First whitespace-delimited token is the path.
    token = line.split()[0]
    if not token.startswith("/"):
        return None
    # strip trailing junk that isn't part of a URL path
    token = token.rstrip(",;:")
    return token or None


def load_gobuster(base):
    """
    Read gobuster.txt. Returns a set of absolute URLs (paths joined to base).
    Missing file is non-fatal.
    """
    if not GOBUSTER_FILE or not os.path.exists(GOBUSTER_FILE):
        print(f"[!] gobuster file not found: {GOBUSTER_FILE}")
        return set()

    discovered = set()
    try:
        with open(GOBUSTER_FILE, encoding="utf-8", errors="ignore") as f:
            for raw in f:
                path = parse_gobuster_line(raw)
                if not path:
                    continue
                url = normalize(base, path)
                if url and not is_asset(url):
                    discovered.add(url)
    except OSError as e:
        print(f"[!] Could not read {GOBUSTER_FILE}: {e}")
        return set()

    print(f"[*] Loaded {len(discovered)} paths from {GOBUSTER_FILE}")
    return discovered


# --------------------------------------------------------------------------- #
# Phase 2: JS crawl
# --------------------------------------------------------------------------- #
def download_js(base_url, js_url):
    try:
        r = requests.get(js_url, timeout=15,
                         headers={"User-Agent": USER_AGENT},
                         allow_redirects=True)
        if r.status_code != 200:
            return
        ctype = r.headers.get("Content-Type", "").lower()
        if "javascript" in ctype or urlsplit(r.url).path.lower().endswith((".js", ".mjs")):
            extract(base_url, r.text)
    except requests.RequestException:
        pass


def crawl(seed, extra_urls):
    """
    Crawl the seed URL first, then up to MAX_CRAWL_PAGES-1 same-origin
    URLs from extra_urls. Collect JS bundle URLs and parse them.
    """
    js_files = set()

    seed_origin = urlsplit(seed).netloc

    # Deduplicate + same-origin filter for extras
    seen_extras = set()
    same_origin = []
    for u in extra_urls:
        if u in seen_extras or u == seed:
            continue
        seen_extras.add(u)
        if urlsplit(u).netloc == seed_origin and not is_asset(u):
            same_origin.append(u)

    queue = [seed] + same_origin[: MAX_CRAWL_PAGES - 1]
    visited = set()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(user_agent=USER_AGENT)
            page = context.new_page()

            def handler(response):
                if is_js_url(response.url):
                    js_files.add(response.url)

            page.on("response", handler)

            for u in queue:
                if u in visited:
                    continue
                visited.add(u)
                print(f"[*] Crawling {u}")
                try:
                    page.goto(u, timeout=30000, wait_until="domcontentloaded")
                    page.wait_for_timeout(4000)
                except Exception as e:  # noqa: BLE001
                    print(f"[!] Failed to load {u}: {e}")
                    continue

            context.close()
            browser.close()
    except Exception as e:  # noqa: BLE001
        print(f"[!] Playwright error: {e}")
        return js_files

    for js in sorted(js_files):
        if js in VISITED_JS:
            continue
        VISITED_JS.add(js)
        print(f"[JS] {js}")
        download_js(seed, js)

    return js_files


# --------------------------------------------------------------------------- #
# Phase 3: JS route extraction
# --------------------------------------------------------------------------- #
def add_route(base, raw):
    url = normalize(base, clean_template(raw))
    if url and not is_asset(url):
        ROUTES.add(url)


def extract(base_url, js):
    # fetch("...")
    for m in re.finditer(r'fetch\s*\(\s*["\'`]([^"\'`]+)["\'`]', js):
        add_route(base_url, m.group(1))

    # axios.get/post/put/delete/patch("...")
    for m in re.finditer(
        r'axios\.(?:get|post|put|delete|patch)\s*\(\s*["\'`]([^"\'`]+)["\'`]', js
    ):
        add_route(base_url, m.group(1))

    # router.push("/x") | router.replace("/x") | router.push({ path: "/x" })
    for m in re.finditer(
        r'router\.(?:push|replace)\s*\(\s*(?:\{\s*path\s*:\s*)?["\'`]([^"\'`]+)["\'`]', js
    ):
        add_route(base_url, m.group(1))

    # history.pushState(state, title, "/x")
    for m in re.finditer(
        r'pushState\s*\([^)]*?,\s*["\'`][^"\'`]*["\'`]\s*,\s*["\'`]([^"\'`]+)["\'`]', js
    ):
        add_route(base_url, m.group(1))

    # location.href = "/x" | window.open("/x") | navigate("/x")
    for m in re.finditer(
        r'(?:location\.href\s*=|window\.open\s*\(|navigate\s*\()\s*["\'`]([^"\'`]+)["\'`]', js
    ):
        add_route(base_url, m.group(1))

    # quoted path-like strings
    for m in re.finditer(r'["\'`](/[A-Za-z0-9_./?=&%:@#+${}-]{2,120})["\'`]', js):
        add_route(base_url, m.group(1))

    # new URLSearchParams().set("q", ...)
    for m in re.finditer(r'\.set\s*\(\s*["\'`]([A-Za-z0-9_\-\[\]]+)["\'`]\s*,', js):
        ROUTES.add(urljoin(base_url, f"/?{m.group(1)}="))

    # new URLSearchParams({ q: ..., r: ... })
    for m in re.finditer(r'URLSearchParams\s*\(\s*\{(.*?)\}\s*\)', js, re.S):
        for k in re.finditer(r'([A-Za-z0-9_\-\[\]]+)\s*:', m.group(1)):
            ROUTES.add(urljoin(base_url, f"/?{k.group(1)}="))


# --------------------------------------------------------------------------- #
# Phase 4: filter + scan
# --------------------------------------------------------------------------- #
def save_routes():
    path = os.path.join(OUT_DIR, "routes.txt")
    with open(path, "w", encoding="utf-8") as f:
        for r in sorted(ROUTES):
            f.write(r + "\n")
    print(f"[*] Wrote {len(ROUTES)} routes -> {path}")


def build_injectable():
    injectable = sorted({u for u in ROUTES if is_injectable(u)})
    path = os.path.join(OUT_DIR, "urls.txt")
    with open(path, "w", encoding="utf-8") as f:
        for u in injectable:
            f.write(u + "\n")
    print(f"[*] Wrote {len(injectable)} injectable URLs -> {path}")
    return injectable


def run_dalfox():
    if not shutil.which("dalfox"):
        print("[!] dalfox not found in PATH - skipping")
        return

    urls_path = os.path.join(OUT_DIR, "urls.txt")
    if not (os.path.exists(urls_path) and os.path.getsize(urls_path) > 0):
        print("[!] urls.txt empty - skipping dalfox")
        return

    dalfox_out = os.path.join(OUT_DIR, "dalfox.txt")
    if os.path.exists(dalfox_out):
        os.remove(dalfox_out)

    print("[*] Running Dalfox...")
    try:
        subprocess.run(
            ["dalfox", "file", urls_path,
             "--worker", "10", "--skip-bav",
             "--silence", "-o", dalfox_out],
            check=False,
        )
    except Exception as e:  # noqa: BLE001
        print(f"[!] dalfox failed: {e}")


def find_xsstrike():
    for p in XSSTRIKE_PATHS:
        if os.path.isfile(p):
            return p
    return None


def run_xsstrike():
    xsstrike = find_xsstrike()
    if not xsstrike:
        print(f"[!] XSStrike not found (tried: {', '.join(XSSTRIKE_PATHS)}) - skipping")
        return

    urls_path = os.path.join(OUT_DIR, "urls.txt")
    if not (os.path.exists(urls_path) and os.path.getsize(urls_path) > 0):
        print("[!] urls.txt empty - skipping XSStrike")
        return

    with open(urls_path, encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    out_file = os.path.join(OUT_DIR, "xsstrike.txt")
    print(f"[*] Running XSStrike on {len(urls)} URLs...")

    with open(out_file, "a", encoding="utf-8") as fh:
        for i, url in enumerate(urls, 1):
            print(f"[XSStrike {i}/{len(urls)}] {url}")
            try:
                subprocess.run(
                    ["python3", xsstrike, "-u", url, "--skip-dom"],
                    check=False,
                    timeout=300,
                    stdout=fh,
                    stderr=subprocess.STDOUT,
                )
            except subprocess.TimeoutExpired:
                print(f"[!] Timeout after 300s: {url}")
            except Exception as e:  # noqa: BLE001
                print(f"[!] XSStrike error on {url}: {e}")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv):
    p = argparse.ArgumentParser(
        description="JS route harvester + XSS scanner (target URL + gobuster.txt).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target",
                   help="Target hostname or full URL (e.g. https://host/greet?x=1)")
    p.add_argument("output_dir",
                   help="Output directory for routes.txt / urls.txt / results")
    p.add_argument("--gobuster", dest="gobuster_file", default=None,
                   help="Explicit path to gobuster.txt. If omitted, "
                        "auto-detects <output_dir>/gobuster.txt")
    return p.parse_args(argv)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    global OUT_DIR, GOBUSTER_FILE, BASE_URL, SEED_URL

    args = parse_args(sys.argv[1:])

    OUT_DIR = args.output_dir
    os.makedirs(OUT_DIR, exist_ok=True)

    # Resolve gobuster path: explicit wins, else <OUT_DIR>/gobuster.txt
    if args.gobuster_file:
        GOBUSTER_FILE = args.gobuster_file
    else:
        GOBUSTER_FILE = os.path.join(OUT_DIR, "gobuster.txt")

    BASE_URL, SEED_URL = parse_target(args.target)

    print(f"[*] Target (raw) : {args.target}")
    print(f"[*] Base URL     : {BASE_URL}")
    print(f"[*] Seed URL     : {SEED_URL}")
    print(f"[*] Output dir   : {OUT_DIR}")
    print(f"[*] Gobuster     : {GOBUSTER_FILE} "
          f"({'present' if os.path.exists(GOBUSTER_FILE) else 'missing'})")

    # Seed the route set with the exact URL the user asked about.
    ROUTES.add(SEED_URL)

    # 1. Load gobuster URLs (paths joined against BASE_URL).
    gobuster_urls = load_gobuster(BASE_URL)
    ROUTES.update(gobuster_urls)

    # 2. Crawl seed + a bounded slice of gobuster URLs for JS.
    print("[*] Crawling JS...")
    crawl(SEED_URL, extra_urls=sorted(gobuster_urls))

    # 3. Persist everything we've found.
    save_routes()

    # 4. Filter to injectable URLs.
    injectable = build_injectable()

    # 5. Scan.
    run_dalfox()
    run_xsstrike()

    print("[*] Done")
    print("    - routes.txt   (seed + gobuster + JS-extracted routes)")
    print("    - urls.txt     (injectable URLs fed to scanners)")
    print("    - dalfox.txt")
    print("    - xsstrike.txt")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)