#!/usr/bin/env python3
"""
JS route harvester + XSS scanner.

Usage:
    python3 ghostquery/xss/main.py <target-host> <output-dir>

Pipeline:
    1. read gobuster.txt produced upstream by the C pipeline (scan.c)
    2. headless-Chromium crawl (homepage + a bounded set of discovered pages) to collect JS
    3. extract candidate routes/parameters from JS
    4. run Dalfox + XSStrike on injectable URLs (those with query params)

Requires: dalfox, XSStrike, playwright (chromium), seclists wordlist.
Gobuster is NOT run here — the C pipeline runs it once and writes
gobuster.txt into the same directory we read from.
"""

import os
import re
import sys
import shutil
import subprocess
from urllib.parse import urljoin, urlparse, parse_qs, urlsplit, urlunsplit

import requests
from playwright.sync_api import sync_playwright

ROUTES = set()
VISITED_JS = set()

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# Populated in main() once argv is validated.
OUT_DIR = None
GOBUSTER_OUT = None

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

MAX_CRAWL_PAGES = 8


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
    # drop fragments, keep query
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def clean_template(s):
    """Turn `/api/users/${id}` into `/api/users/` so it can be normalized."""
    return re.sub(r"\$\{[^}]*\}", "", s).strip()


def is_asset(url):
    """Heuristic: skip URLs that look like static assets rather than routes."""
    path = urlsplit(url).path.lower()
    if any(path.endswith(ext) for ext in NON_ROUTE_EXT):
        return True
    return "/static/" in path or "/assets/" in path


def is_js_url(url):
    return urlsplit(url).path.lower().endswith((".js", ".mjs"))


def is_injectable(url):
    try:
        params = parse_qs(urlparse(url).query)
        # drop pure tracking params; if nothing meaningful remains, not injectable
        params = {k: v for k, v in params.items() if k.lower() not in TRACKING_PARAMS}
        return len(params) > 0
    except Exception:
        return False


def normalize_target(target):
    target = target.strip()
    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target
    return target.rstrip("/")


# --------------------------------------------------------------------------- #
# Phase 1: load gobuster output produced by the C pipeline
# --------------------------------------------------------------------------- #
def load_gobuster(domain):
    """Read the gobuster.txt the C pipeline wrote into OUT_DIR.

    No subprocess call here — gobuster runs once from scan.c so nuclei
    and this crawler share a single discovery pass. Missing file just
    means zero crawl seeds, not a fatal error.
    """
    if not os.path.exists(GOBUSTER_OUT):
        print(f"[!] {GOBUSTER_OUT} not found — no gobuster results to load")
        return set()

    discovered = set()
    try:
        with open(GOBUSTER_OUT, encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split()
                if not parts:
                    continue
                path = parts[0]
                # skip comment/progress/error lines; keep only "/path" entries
                if not path.startswith("/"):
                    continue
                url = normalize(domain, path)
                if url:
                    discovered.add(url)
    except OSError as e:
        print(f"[!] Could not read {GOBUSTER_OUT}: {e}")
        return set()

    print(f"[*] Gobuster (pre-run) found: {len(discovered)}")
    return discovered


# --------------------------------------------------------------------------- #
# Phase 2: JS collection
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


def crawl(target, extra_urls=None):
    js_files = set()

    same_origin = [u for u in (extra_urls or [])
                   if urlsplit(u).netloc == urlsplit(target).netloc
                   and not is_asset(u)][: MAX_CRAWL_PAGES - 1]

    queue = [target] + same_origin
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
        download_js(target, js)

    return js_files


# --------------------------------------------------------------------------- #
# Phase 3: route extraction from JS
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
    for m in re.finditer(r'axios\.(?:get|post|put|delete|patch)\s*\(\s*["\'`]([^"\'`]+)["\'`]', js):
        add_route(base_url, m.group(1))

    # router.push("/x") | router.replace("/x") | router.push({ path: "/x" })
    for m in re.finditer(
        r'router\.(?:push|replace)\s*\(\s*(?:\{\s*path\s*:\s*)?["\'`]([^"\'`]+)["\'`]', js
    ):
        add_route(base_url, m.group(1))

    # history.pushState(state, title, "/x")  -> URL is the 3rd string arg
    for m in re.finditer(
        r'pushState\s*\([^)]*?,\s*["\'`][^"\'`]*["\'`]\s*,\s*["\'`]([^"\'`]+)["\'`]', js
    ):
        add_route(base_url, m.group(1))

    # location.href = "/x" | window.open("/x") | navigate("/x")
    for m in re.finditer(
        r'(?:location\.href\s*=|window\.open\s*\(|navigate\s*\()\s*["\'`]([^"\'`]+)["\'`]', js
    ):
        add_route(base_url, m.group(1))

    # quoted path-like strings (bounded length to limit bundle noise)
    for m in re.finditer(r'["\'`](/[A-Za-z0-9_./?=&%:@#+${}-]{2,120})["\'`]', js):
        add_route(base_url, m.group(1))

    # new URLSearchParams().set("q", ...)  (require 2 args to cut Map/Set noise)
    for m in re.finditer(r'\.set\s*\(\s*["\'`]([A-Za-z0-9_\-\[\]]+)["\'`]\s*,', js):
        ROUTES.add(urljoin(base_url, f"/?{m.group(1)}="))

    # new URLSearchParams({ q: ..., r: ... })
    for m in re.finditer(r'URLSearchParams\s*\(\s*\{(.*?)\}\s*\)', js, re.S):
        for k in re.finditer(r'([A-Za-z0-9_\-\[\]]+)\s*:', m.group(1)):
            ROUTES.add(urljoin(base_url, f"/?{k.group(1)}="))


# --------------------------------------------------------------------------- #
# Phase 4: filtering + scanning
# --------------------------------------------------------------------------- #
def save_routes():
    with open(os.path.join(OUT_DIR, "routes.txt"), "w", encoding="utf-8") as f:
        for r in sorted(ROUTES):
            f.write(r + "\n")


def build_injectable():
    injectable = sorted({u for u in ROUTES if is_injectable(u)})
    with open(os.path.join(OUT_DIR, "urls.txt"), "w", encoding="utf-8") as f:
        for u in injectable:
            f.write(u + "\n")
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

    # Append each run's stdout+stderr to xsstrike.txt. subprocess.run with a
    # list does NOT invoke a shell, so ">" has to be handled here, not in argv.
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
# Main
# --------------------------------------------------------------------------- #
def main():
    global OUT_DIR, GOBUSTER_OUT

    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    target = normalize_target(sys.argv[1])
    OUT_DIR = sys.argv[2]
    GOBUSTER_OUT = os.path.join(OUT_DIR, "gobuster.txt")

    print(f"[*] Target: {target}")
    print(f"[*] Output: {OUT_DIR}")

    # 1. Load the gobuster results the C pipeline already produced.
    gobuster_urls = load_gobuster(target)
    ROUTES.update(gobuster_urls)

    # 2. Crawl for JS
    print("[*] Crawling JS...")
    crawl(target, extra_urls=list(gobuster_urls))

    # 3. Persist all routes (crash-safe: written here, not only inside crawl)
    save_routes()
    print(f"[*] Total routes: {len(ROUTES)}")

    # 4. Keep only URLs with query parameters
    injectable = build_injectable()
    print(f"[*] Injectable URLs: {len(injectable)}")

    # 5. Scan
    run_dalfox()
    run_xsstrike()

    print("[*] Done")
    print("    - routes.txt   (all extracted routes)")
    print("    - urls.txt     (injectable URLs fed to scanners)")
    print("    - dalfox.txt")
    print("    - xsstrike.txt")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(130)