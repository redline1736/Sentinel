#!/bin/bash
set -euo pipefail

# ======================== Configuration ==========================
GO_VERSION="1.24.2"
GOBIN="/usr/local/bin"
GOPATH="${HOME}/go"
SECLISTS="/usr/share/seclists"
DEBIAN_FRONTEND="noninteractive"

# Add Go and user Go bins to PATH
export PATH="/usr/local/go/bin:${GOBIN}:${GOPATH}/bin:${PATH}"

# ======================= Helper Functions ========================
sudo_cmd() {
    if command -v sudo &>/dev/null; then
        sudo "$@"
    else
        "$@"
    fi
}

install_system_packages() {
    echo ">>> Installing system packages..."
    sudo_cmd apt-get update -qq
    sudo_cmd apt-get install -y --no-install-recommends \
        ca-certificates curl git gcc make pkg-config \
        libcurl4-openssl-dev python3 python3-pip python3-venv \
        chromium libcjson-dev ruby ruby-dev zlib1g-dev \
        procps file tor proxychains4 nikto tar
}

install_go() {
    echo ">>> Setting up Go ${GO_VERSION}..."
    if [ -x /usr/local/go/bin/go ] && [ "$(/usr/local/go/bin/go version | awk '{print $3}' | sed 's/go//')" = "${GO_VERSION}" ]; then
        echo "Go ${GO_VERSION} already installed."
        return
    fi
    echo "Downloading and installing Go ${GO_VERSION}..."
    curl -fsSL "https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz" | sudo_cmd tar -C /usr/local -xz
}

install_go_tools() {
    echo ">>> Installing Go tools (subfinder, assetfinder, httpx, nuclei, dalfox, subzy, subjack)..."
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install github.com/tomnomnom/assetfinder@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install github.com/hahwul/dalfox/v2@latest
    go install -v github.com/PentestPad/subzy@latest
    go install -mod=mod github.com/haccer/subjack@latest
    hash -r
}

install_wpscan() {
    echo ">>> Installing wpscan via gem..."
    gem install wpscan 2>&1 || echo "[WARN] wpscan install failed"
}

setup_xsstrike() {
    echo ">>> Setting up XSStrike in /opt/XSStrike..."
    if [ ! -d /opt/XSStrike ]; then
        sudo_cmd git clone --depth 1 https://github.com/s0md3v/XSStrike /opt/XSStrike
    fi
    # Create virtual environment if not exists
    if [ ! -d /opt/xsenv ]; then
        sudo_cmd python3 -m venv /opt/xsenv
    fi
    sudo_cmd /opt/xsenv/bin/pip install --upgrade pip -q
    sudo_cmd /opt/xsenv/bin/pip install -r /opt/XSStrike/requirements.txt -q
}

download_seclists() {
    echo ">>> Downloading SecLists (subdomains and common.txt)..."
    sudo_cmd mkdir -p "${SECLISTS}/Discovery/DNS" "${SECLISTS}/Discovery/Web-Content"
    sudo_cmd curl -fsSL \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
        -o "${SECLISTS}/Discovery/DNS/subdomains-top1million-5000.txt"
    sudo_cmd curl -fsSL \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
        -o "${SECLISTS}/Discovery/Web-Content/common.txt"
}

build_sentinel() {
    echo ">>> Building Sentinel..."
    make clean all
    echo ">>> Verifying binary and dependencies..."
    test -x ./sentinel && echo "binary OK"
    for t in subfinder assetfinder httpx nuclei dalfox wpscan; do
        if command -v "$t" &>/dev/null; then
            echo "  $t OK"
        else
            echo "  MISSING: $t"
        fi
    done
    if [ -f "${SECLISTS}/Discovery/Web-Content/common.txt" ]; then
        echo "SecLists common.txt OK"
    else
        echo "SecLists common.txt MISSING"
    fi
    echo "Build complete."
}

run_tests() {
    echo ">>> Running integration tests..."
    echo "--- Test 1: subfinder ---"
    ./sentinel example.com test_sub -sub || echo "Test 1 failed (non-fatal)"
    echo "--- Test 2: scan-url ---"
    ./sentinel thegod.pythonanywhere.com testscanurl --scan-url https://thegod.pythonanywhere.com/ || echo "Test 2 failed (non-fatal)"
    echo "--- Test 3: xss low ---"
    ./sentinel thegod.pythonanywhere.com testxsslow test-new-feature https://thegod.pythonanywhere.com/vulnerabilities/xss_r/low || echo "Test 3 failed (non-fatal)"
    echo "--- Test 4: xss medium ---"
    ./sentinel thegod.pythonanywhere.com testxssmedium test-new-feature https://thegod.pythonanywhere.com/vulnerabilities/xss_r/medium || echo "Test 4 failed (non-fatal)"
    echo "--- Test 5: xss high ---"
    ./sentinel thegod.pythonanywhere.com testxsshigh test-new-feature https://thegod.pythonanywhere.com/vulnerabilities/xss_r/high || echo "Test 5 failed (non-fatal)"
    echo "--- Test 6: xss impossible ---"
    ./sentinel thegod.pythonanywhere.com testxssimpossible test-new-feature https://thegod.pythonanywhere.com/vulnerabilities/xss_r/impossible || echo "Test 6 failed (non-fatal)"
    echo "All tests finished."
}

# ======================= Main Execution ==========================
main() {
    echo "=== Sentinel CI Local Test Runner ==="
    echo "This script will install dependencies and run the full CI pipeline."
    echo "It requires sudo privileges for package installation and writing to /opt and /usr/local."
    echo "Press Ctrl+C to cancel, or wait 5 seconds to continue..."
    sleep 5

    install_system_packages
    install_go
    install_go_tools
    install_wpscan
    setup_xsstrike
    download_seclists
    build_sentinel
    run_tests

    echo "=== All steps completed ==="
}

# Run main only if script is executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
fi