#!/usr/bin/env bash
#
# Sentinel CI — local equivalent of .github/workflows/sentinel-ci.yml
#
# Runs the full build + test pipeline that the GitHub Actions workflow
# performs on ubuntu-24.04. Intended to be executed from the repo root
# on a fresh Ubuntu 24.04 host (or CI runner) with sudo available.
#
# Usage:
#   ./sentinel-ci.sh
#
# Environment overrides:
#   GO_VERSION  (default 1.24.2)
#   GOPATH      (default $PWD/go)
#   GOBIN       (default $GOPATH/bin)  -- workflow uses /usr/local/bin, but
#                                        that requires root; $GOPATH/bin is
#                                        the safest local default.
#   SECLISTS    (default /usr/share/seclists)
#   CHROME_BIN  (default /usr/bin/chromium)
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
GO_VERSION="${GO_VERSION:-1.24.2}"
GOPATH="${GOPATH:-$PWD/go}"
GOBIN="${GOBIN:-$GOPATH/bin}"
SECLISTS="${SECLISTS:-/usr/share/seclists}"
CHROME_BIN="${CHROME_BIN:-/usr/bin/chromium}"
DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"

export GO_VERSION GOPATH GOBIN SECLISTS CHROME_BIN DEBIAN_FRONTEND
export PATH="$GOPATH/bin:$GOBIN:/usr/local/go/bin:$PATH"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

SUMMARY_FILE="$REPO_ROOT/ci-test-summary.md"
ARTIFACTS_DIR="$REPO_ROOT/ci-artifacts"
: > "$SUMMARY_FILE"

# Use sudo only if we aren't already root.
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  SUDO="sudo"
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[WARN] %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m[ERROR] %s\033[0m\n' "$*" >&2; exit 1; }

record_pass() { echo "$1=pass" >> "$SUMMARY_FILE"; }
record_fail() { echo "$1=fail" >> "$SUMMARY_FILE"; }

# ---------------------------------------------------------------------------
# System packages
#
# Union of the build-job and test-job package lists. SDL packages are
# intentionally omitted (see workflow comment): the Makefile only links
# -lcurl -lpthread -lcjson -lm.
# ---------------------------------------------------------------------------
install_system_packages() {
  log "Installing system packages"
  $SUDO apt-get update -qq
  $SUDO apt-get install -y --no-install-recommends \
    ca-certificates curl git gcc make pkg-config \
    libcurl4-openssl-dev python3 python3-pip python3-venv \
    chromium libcjson-dev ruby ruby-dev zlib1g-dev \
    procps file tor proxychains4 nikto dnsutils \
    perl libnet-ssleay-perl libwww-perl \
    libssl-dev build-essential
}

# ---------------------------------------------------------------------------
# Go toolchain
# ---------------------------------------------------------------------------
setup_go() {
  local want="go${GO_VERSION}"
  if command -v go >/dev/null 2>&1; then
    local have
    have="$(go env GOVERSION 2>/dev/null || true)"
    if [ "$have" = "$want" ]; then
      log "Go $have already installed"
      return
    fi
  fi

  log "Installing Go $GO_VERSION"
  local arch tarball
  arch="$(uname -m)"
  case "$arch" in
    x86_64)        arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) die "Unsupported architecture: $arch" ;;
  esac
  tarball="go${GO_VERSION}.linux-${arch}.tar.gz"
  curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
  $SUDO rm -rf /usr/local/go
  $SUDO tar -C /usr/local -xzf "/tmp/${tarball}"
  rm -f "/tmp/${tarball}"
  export PATH="/usr/local/go/bin:$PATH"
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
build_sentinel() {
  log "Building sentinel"
  make clean all
  [ -x ./sentinel ] || die "sentinel binary was not produced"
  echo "✅ binary OK"
}

# ---------------------------------------------------------------------------
# Test-job setup
# ---------------------------------------------------------------------------
install_go_tools() {
  log "Installing Go tools (subfinder, assetfinder, httpx, nuclei, dalfox, subzy, subjack, gobuster)"
  mkdir -p "$GOBIN"
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install github.com/tomnomnom/assetfinder@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  go install github.com/hahwul/dalfox/v2@latest
  go install -v github.com/PentestPad/subzy@latest
  go install -mod=mod github.com/haccer/subjack@latest
  go install github.com/OJ/gobuster/v3@latest
}

setup_playwright() {
  log "Installing Playwright + managed Chromium"
  # Ubuntu 24.04 blocks system-wide pip installs (PEP 668); use a venv.
  local venv="$REPO_ROOT/.ci-venv"
  python3 -m venv "$venv"
  "$venv/bin/pip" install --upgrade pip -q
  "$venv/bin/pip" install -q playwright
  "$venv/bin/playwright" install --with-deps chromium
  export PATH="$venv/bin:$PATH"
}

setup_wpscan() {
  log "Installing wpscan"
  if ! gem install --user-install wpscan 2>&1; then
    warn "wpscan install failed (continuing)"
  fi
  local gem_bin
  gem_bin="$(ruby -e 'puts Gem.user_dir')/bin"
  export PATH="$gem_bin:$PATH"
}

setup_xsstrike() {
  log "Setting up XSStrike"
  if [ ! -d /opt/XSStrike ]; then
    $SUDO git clone --depth 1 https://github.com/s0md3v/XSStrike /opt/XSStrike
  fi
  $SUDO python3 -m venv /opt/xsenv 2>/dev/null || true
  $SUDO /opt/xsenv/bin/pip install --upgrade pip -q
  $SUDO /opt/xsenv/bin/pip install -r /opt/XSStrike/requirements.txt -q
}

setup_seclists() {
  log "Downloading SecLists wordlists"
  $SUDO mkdir -p "${SECLISTS}/Discovery/DNS" "${SECLISTS}/Discovery/Web-Content"
  $SUDO curl -fsSL \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
    -o "${SECLISTS}/Discovery/DNS/subdomains-top1million-5000.txt"
  $SUDO curl -fsSL \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
    -o "${SECLISTS}/Discovery/Web-Content/common.txt"
  echo "greet" | $SUDO tee -a "${SECLISTS}/Discovery/Web-Content/common.txt" >/dev/null
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  log "Sentinel CI starting (repo: $REPO_ROOT)"

  install_system_packages
  setup_go
  build_sentinel

  install_go_tools
  setup_playwright
  setup_wpscan
  setup_xsstrike
  setup_seclists


}

main "$@"