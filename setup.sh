#!/usr/bin/env bash
# setup.sh — Kali equivalent of .github/workflows/sentinel-ci.yml
#
# Usage:
#   ./setup.sh [TARGET_URL]
#
# Default TARGET_URL is http://192.168.8.156:5000/ .
#
# Env knobs:
#   SKIP_INSTALL=1     skip apt/go/pip/gem installs
#   SKIP_BUILD=1       skip `make`
#   SKIP_TESTS=1       stop after build + install
#   HOSTNAME_OVERRIDE  override hostname passed to ./sentinel

set -euo pipefail

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
TARGET_URL="${1:-http://192.168.8.156:5000/}"
TARGET_HOST="${HOSTNAME_OVERRIDE:-$(printf '%s' "$TARGET_URL" \
    | sed -E 's#^[a-z]+://##; s#[:/].*$##')}"
TARGET_PORT="$(printf '%s' "$TARGET_URL" \
    | sed -nE 's#^[a-z]+://[^:/]+:([0-9]+).*#\1#p')"
[ -z "$TARGET_PORT" ] && TARGET_PORT=80

GO_VERSION="${GO_VERSION:-1.24.2}"
GOPATH="${GOPATH:-$HOME/go}"
GOBIN="${GOBIN:-$HOME/go/bin}"
SECLISTS="${SECLISTS:-/usr/share/seclists}"
export GOPATH GOBIN

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
if [ -t 1 ]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'
    C_BLUE=$'\033[34m'; C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'
else
    C_RESET=; C_BOLD=; C_BLUE=; C_GREEN=; C_YELLOW=; C_RED=
fi
step() { printf '\n%s==>%s %s%s%s\n' "$C_BLUE" "$C_RESET" "$C_BOLD" "$*" "$C_RESET"; }
ok()   { printf '%s[ ok ]%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
fail() { printf '%s[fail]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; exit 1; }

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
apt_run() {
    if [ "$(id -u)" -eq 0 ]; then
        DEBIAN_FRONTEND=noninteractive apt-get "$@"
    else
        command -v sudo >/dev/null 2>&1 || fail "need root or sudo"
        sudo env DEBIAN_FRONTEND=noninteractive apt-get "$@"
    fi
}
sys() {
    if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}
have() { command -v "$1" >/dev/null 2>&1; }

# --------------------------------------------------------------------------
# 0. Preflight
# --------------------------------------------------------------------------
step "Preflight: $TARGET_URL"
if have curl; then
    code="$(curl -sS -o /dev/null -m 5 -w '%{http_code}' "$TARGET_URL" || true)"
    if printf '%s' "$code" | grep -Eq '^[12345][0-9][0-9]$'; then
        ok "target reachable (HTTP $code)"
    else
        warn "target not responding cleanly — continuing anyway"
    fi
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "${ID:-}" != "kali" ]; then
        warn "tuned for Kali; detected: ${PRETTY_NAME:-unknown}"
    else
        ok "Kali detected: ${PRETTY_NAME:-unknown}"
    fi
fi

# --------------------------------------------------------------------------
# 1. System packages (matches YAML's apt list, Kali-adjusted)
#    'chromium-browser' is Ubuntu-only; Kali ships 'chromium'.
# --------------------------------------------------------------------------
if [ "${SKIP_INSTALL:-0}" != "1" ]; then
    step "Installing system packages (apt)"

    apt_run update -qq
    apt_run install -y --no-install-recommends \
        ca-certificates curl git gcc g++ make pkg-config \
        libcurl4-openssl-dev python3 python3-pip python3-venv python3-full \
        chromium libcjson-dev ruby ruby-dev zlib1g-dev \
        procps file tor proxychains4 nikto dnsutils \
        perl libnet-ssleay-perl libwww-perl \
        libssl-dev build-essential jq unzip

    ok "system packages installed"
else
    warn "SKIP_INSTALL=1 — skipping apt"
fi

# --------------------------------------------------------------------------
# 2. Go toolchain (needed for all eight go install lines from the YAML)
# --------------------------------------------------------------------------
if [ "${SKIP_INSTALL:-0}" != "1" ]; then
    step "Ensuring Go $GO_VERSION"

    need_go=1
    if have go; then
        have_ver="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
        if [ "$have_ver" = "$GO_VERSION" ]; then
            need_go=0
            ok "go $have_ver present"
        fi
    fi

    if [ "$need_go" -eq 1 ]; then
        arch="$(uname -m)"
        case "$arch" in
            x86_64)         goarch=amd64 ;;
            aarch64|arm64)  goarch=arm64 ;;
            *) fail "unsupported arch: $arch" ;;
        esac
        url="https://go.dev/dl/go${GO_VERSION}.linux-${goarch}.tar.gz"
        printf '  downloading %s\n' "$url"
        tmp="$(mktemp -d)"
        if curl -fsSL "$url" -o "$tmp/go.tgz" 2>/dev/null; then
            sys rm -rf /usr/local/go
            sys tar -C /usr/local -xzf "$tmp/go.tgz"
            rm -rf "$tmp"
            ok "go ${GO_VERSION} installed to /usr/local/go"
        else
            rm -rf "$tmp"
            warn "go ${GO_VERSION} tarball not available — trying apt"
            apt_run install -y --no-install-recommends golang-go
            ok "go installed from apt ($(go version 2>/dev/null || echo '?'))"
        fi
    fi

    export PATH="/usr/local/go/bin:/usr/lib/go/bin:$GOPATH/bin:$PATH"
fi

# --------------------------------------------------------------------------
# 3. Build sentinel
# --------------------------------------------------------------------------
if [ "${SKIP_BUILD:-0}" != "1" ]; then
    step "Building sentinel"
    if [ -f Makefile ]; then
        make clean all
    else
        mapfile -t SRC < <(find . -name '*.c' -not -path './.git/*')
        [ "${#SRC[@]}" -gt 0 ] || fail "no .c files and no Makefile"
        cc -O2 -Wall -Wextra -o sentinel "${SRC[@]}" \
            $(pkg-config --cflags --libs libcurl) -lcjson -lpthread
    fi
    [ -x ./sentinel ] || fail "sentinel not produced"
    ok "binary ready: $(pwd)/sentinel"
else
    warn "SKIP_BUILD=1 — reusing existing ./sentinel"
fi

# --------------------------------------------------------------------------
# 4. Install Go tools — exactly the YAML list
# --------------------------------------------------------------------------
if [ "${SKIP_INSTALL:-0}" != "1" ]; then
    step "Installing Go tools"
    export PATH="/usr/local/go/bin:/usr/lib/go/bin:$GOPATH/bin:$PATH"

    GO_TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/hahwul/dalfox/v2@latest"
        "github.com/PentestPad/subzy@latest"
        "github.com/haccer/subjack@latest"
        "github.com/OJ/gobuster/v3@latest"
    )

    for pkg in "${GO_TOOLS[@]}"; do
        printf '  -> %s\n' "$pkg"
        go install -v "$pkg" 2>&1 || warn "go install failed: $pkg"
    done

    # Inventory
    for t in subfinder assetfinder httpx nuclei dalfox subzy subjack gobuster; do
        if have "$t"; then
            ok "$t -> $(command -v "$t")"
        else
            warn "$t missing after install"
        fi
    done
fi

# --------------------------------------------------------------------------
# 5. wpscan via gem (YAML does the same)
# --------------------------------------------------------------------------
if [ "${SKIP_INSTALL:-0}" != "1" ]; then
    step "Installing wpscan (gem)"
    if have wpscan; then
        ok "wpscan already present"
    else
        gem install --user-install wpscan 2>&1 || warn "wpscan install failed"
        GEM_BIN="$(ruby -e 'puts Gem.user_dir' 2>/dev/null)/bin"
        [ -d "$GEM_BIN" ] && export PATH="$GEM_BIN:$PATH" && ok "wpscan path: $GEM_BIN"
    fi
fi

# --------------------------------------------------------------------------
# 6. XSStrike
# --------------------------------------------------------------------------
if [ "${SKIP_INSTALL:-0}" != "1" ]; then
    step "Setting up XSStrike"
    if [ ! -d /opt/XSStrike ]; then
        sys git clone --depth 1 https://github.com/s0md3v/XSStrike /opt/XSStrike
    fi
    sys python3 -m venv /opt/xsenv 2>/dev/null || true
    sys /opt/xsenv/bin/pip install --upgrade pip -q
    sys /opt/xsenv/bin/pip install -r /opt/XSStrike/requirements.txt -q
    ok "XSStrike ready at /opt/XSStrike/xsstrike.py"
fi

# --------------------------------------------------------------------------
# 7. SecLists + Playwright (YAML does both)
# --------------------------------------------------------------------------
if [ "${SKIP_INSTALL:-0}" != "1" ]; then
    step "Fetching SecLists subset"
    sys mkdir -p \
        "${SECLISTS}/Discovery/DNS" \
        "${SECLISTS}/Discovery/Web-Content"
    sys curl -fsSL \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
        -o "${SECLISTS}/Discovery/DNS/subdomains-top1million-5000.txt"
    sys curl -fsSL \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
        -o "${SECLISTS}/Discovery/Web-Content/common.txt"
    if ! grep -qx 'greet' "${SECLISTS}/Discovery/Web-Content/common.txt" 2>/dev/null; then
        echo "greet" | sys tee -a \
            "${SECLISTS}/Discovery/Web-Content/common.txt" >/dev/null
    fi
    ok "SecLists ready"

    step "Installing Playwright + Chromium (venv for PEP 668)"
    PW_VENV="$HOME/.cache/sentinel-playwright"
    python3 -m venv "$PW_VENV" 2>/dev/null || true
    "$PW_VENV/bin/pip" install --upgrade pip -q
    "$PW_VENV/bin/pip" install -q playwright || warn "pip playwright failed"
    if [ -x "$PW_VENV/bin/playwright" ]; then
        "$PW_VENV/bin/playwright" install chromium || \
            warn "playwright chromium install failed"
    fi
    if [ ! -e /usr/local/bin/playwright ] && [ -x "$PW_VENV/bin/playwright" ]; then
        sys ln -sf "$PW_VENV/bin/playwright" /usr/local/bin/playwright
    fi
    ok "Playwright ready"
fi

# --------------------------------------------------------------------------
# 8. PATH for test phase — ~/go/bin FIRST so go-installed tools win over
#    any apt package (python3-httpx, etc.)
# --------------------------------------------------------------------------
export PATH="$GOPATH/bin:/usr/local/go/bin:/usr/lib/go/bin:$HOME/.local/bin:$PATH"
if have ruby; then
    GEM_BIN="$(ruby -e 'puts Gem.user_dir' 2>/dev/null)/bin"
    [ -d "$GEM_BIN" ] && export PATH="$GEM_BIN:$PATH"
fi

if [ "${SKIP_TESTS:-0}" = "1" ]; then
    step "SKIP_TESTS=1 — finished after build/install"
    exit 0
fi

# --------------------------------------------------------------------------
# 9. Test matrix
# --------------------------------------------------------------------------
TEST_ROOT="$(pwd)"

run_test() {
    local label="$1"; shift
    local outdir="$1"; shift
    printf '\n%s--- %s ---%s\n' "$C_BOLD" "$label" "$C_RESET"
    mkdir -p "$outdir"
    if ./sentinel "$@" ; then
        ok "$label completed"
    else
        warn "$label exited non-zero (continuing)"
    fi
}

SCAN_ROOT="${TARGET_URL%/}"
SCAN_HOST="$TARGET_HOST"
if [ -n "$TARGET_PORT" ] && [ "$TARGET_PORT" != "80" ] && \
   [ "$TARGET_PORT" != "443" ]; then
    SCAN_HOST="${TARGET_HOST}:${TARGET_PORT}"
fi

run_test "Subdomain test" test_sub \
    "$SCAN_HOST" test_sub -sub

run_test "Scan URL: /echo"    testscanurlecho    "$SCAN_HOST" testscanurlecho    --scan-url "${SCAN_ROOT}/echo"
run_test "Scan URL: /preview" testscanurlpreview "$SCAN_HOST" testscanurlpreview --scan-url "${SCAN_ROOT}/preview"
run_test "Scan URL: /search"  testscanurlsearch  "$SCAN_HOST" testscanurlsearch  --scan-url "${SCAN_ROOT}/search"
run_test "Scan URL: /user"    testscanurluser    "$SCAN_HOST" testscanurluser    --scan-url "${SCAN_ROOT}/user"

run_test "Scan Site" testscansite \
    "$SCAN_HOST" testscansite --scan-site "${SCAN_ROOT}/"

run_test "XSS: /xss"         testxss        "$SCAN_HOST" testxss        --scan-url "${SCAN_ROOT}/xss"
run_test "XSS: /nuclei-xss"  testnucleixss  "$SCAN_HOST" testnucleixss  --scan-url "${SCAN_ROOT}/nuclei-xss"

# --------------------------------------------------------------------------
# 10. Summary
# --------------------------------------------------------------------------
step "Summary"
for d in test_sub testscanurlecho testscanurlpreview testscanurlsearch \
         testscanurluser testscansite testxss testnucleixss ghostquery; do
    if [ -d "$d" ]; then
        n="$(find "$d" -type f 2>/dev/null | wc -l | tr -d ' ')"
        printf '  %-24s %s files\n' "$d/" "$n"
    else
        printf '  %-24s (missing)\n' "$d/"
    fi
done

printf '\n%sAll done.%s Results are in %s/test*/\n' \
    "$C_GREEN" "$C_RESET" "$TEST_ROOT"