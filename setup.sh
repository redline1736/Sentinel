#!/usr/bin/env bash
#
# setup.sh — build and install Sentinel.
#
# Steps:
#   1. Check prerequisites (gcc, make, libcurl-dev, cjson, python3, chromium)
#   2. Build the C binary
#   3. Install binary to /usr/bin/sentinel
#   4. Install runtime data to /usr/share/sentinel/
#   5. Smoke-test that sentinel can find its data from any CWD
#
# Usage:
#   sudo ./setup.sh              # install to /usr
#   sudo ./setup.sh --prefix /usr/local
#   ./setup.sh --build-only      # skip install steps
#   ./setup.sh --uninstall

set -euo pipefail

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
PREFIX="${PREFIX:-/usr}"
BINDIR="${PREFIX}/bin"
DATADIR="${PREFIX}/share/sentinel"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Runtime data directories that must accompany the binary
DATA_DIRS=(
    "ghostquery"
    "deepblue"
    "darkshield"
    "glassworm"
)

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
MODE="install"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            PREFIX="$2"
            BINDIR="${PREFIX}/bin"
            DATADIR="${PREFIX}/share/sentinel"
            shift 2
            ;;
        --build-only)
            MODE="build-only"
            shift
            ;;
        --uninstall)
            MODE="uninstall"
            shift
            ;;
        -h|--help)
            sed -n '3,18p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Colors (only if stdout is a terminal)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_HDR=$'\033[1;36m'; C_RST=$'\033[0m'
else
    C_OK=""; C_ERR=""; C_HDR=""; C_RST=""
fi

hdr()  { printf '%s==>%s %s\n' "${C_HDR}" "${C_RST}" "$*"; }
ok()   { printf '%s  ✓%s %s\n' "${C_OK}" "${C_RST}" "$*"; }
err()  { printf '%s  ✗%s %s\n' "${C_ERR}" "${C_RST}" "$*" >&2; }

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
if [[ "${MODE}" == "uninstall" ]]; then
    hdr "Uninstalling Sentinel"
    [[ -f "${BINDIR}/sentinel" ]] && { rm -f "${BINDIR}/sentinel"; ok "removed ${BINDIR}/sentinel"; } \
        || ok "${BINDIR}/sentinel not present"
    [[ -d "${DATADIR}" ]] && { rm -rf "${DATADIR}"; ok "removed ${DATADIR}"; } \
        || ok "${DATADIR} not present"
    exit 0
fi

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
hdr "Checking prerequisites"

need_pkg_config() {
    local pkg="$1" name="$2"
    if pkg-config --exists "${pkg}" 2>/dev/null; then
        ok "${name}"
    else
        err "${name} missing — install ${pkg}-dev"
        return 1
    fi
}

need_cmd() {
    local cmd="$1" name="${2:-$1}"
    if command -v "${cmd}" >/dev/null 2>&1; then
        ok "${name} ($(command -v "${cmd}"))"
    else
        err "${name} missing"
        return 1
    fi
}

MISSING=0
need_cmd gcc        || MISSING=1
need_cmd make       || MISSING=1
need_cmd python3    || MISSING=1
need_pkg_config libcurl  "libcurl"  || MISSING=1
need_pkg_config libcjson "libcjson" || MISSING=1

# chromium is only needed for headless XSS confirmation; warn but don't fail
if command -v chromium >/dev/null 2>&1 \
   || command -v chromium-browser >/dev/null 2>&1 \
   || command -v google-chrome >/dev/null 2>&1; then
    ok "chromium"
else
    printf '%s  !%s chromium not found — XSS verification will fall back to HTTP-only\n' \
        "$( [[ -t 1 ]] && echo $'\033[33m' || echo "" )" "${C_RST}"
fi

if [[ "${MISSING}" -ne 0 ]]; then
    echo ""
    echo "Install missing packages with:" >&2
    echo "    sudo apt install build-essential libcurl4-openssl-dev libcjson-dev python3 chromium" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
hdr "Building"
make clean all

if [[ ! -x "${SCRIPT_DIR}/sentinel" ]]; then
    err "build succeeded but ./sentinel is missing"
    exit 1
fi
ok "built ${SCRIPT_DIR}/sentinel"

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
if [[ "${MODE}" == "install" ]]; then
    if [[ "${EUID}" -ne 0 ]]; then
        err "installation requires root (run with sudo, or use --build-only)"
        exit 1
    fi

    hdr "Installing binary to ${BINDIR}/sentinel"
    install -d "${BINDIR}"
    install -m 0755 "${SCRIPT_DIR}/sentinel" "${BINDIR}/sentinel"
    ok "${BINDIR}/sentinel"

    hdr "Installing runtime data to ${DATADIR}"
    install -d "${DATADIR}"

    for d in "${DATA_DIRS[@]}"; do
        if [[ -d "${SCRIPT_DIR}/${d}" ]]; then
            # Use cp -r (not install -r) so permissions inside the tree are preserved.
            rm -rf "${DATADIR:?}/${d}"
            cp -r "${SCRIPT_DIR}/${d}" "${DATADIR}/${d}"
            ok "${DATADIR}/${d}"
        else
            printf '  - %s (not present, skipping)\n' "${d}"
        fi
    done

    # Make absolutely sure the two files find_param_reflecting and xss_run
    # need most are actually there before declaring victory.
    hdr "Verifying critical data files"
    for f in \
        "ghostquery/params.txt" \
        "ghostquery/xss/custom.txt" \
        "deepblue/module.dvr"
    do
        if [[ -f "${DATADIR}/${f}" ]]; then
            ok "${DATADIR}/${f}"
        else
            err "${DATADIR}/${f} missing"
            printf '    Sentinel will not find this file at runtime.\n' >&2
        fi
    done
fi

# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
if [[ "${MODE}" == "install" ]]; then
    hdr "Smoke test (running from /tmp)"
    pushd /tmp >/dev/null
    # 'sentinel -h' must exit 0 and print the usage banner
    if command -v sentinel >/dev/null 2>&1; then
        if sentinel -h >/dev/null 2>&1; then
            ok "sentinel -h works from /tmp"
        else
            err "sentinel -h failed from /tmp"
        fi
    else
        err "sentinel not on PATH after install"
    fi
    popd >/dev/null
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
printf '%s────────────────────────────────────────────────────────────%s\n' \
    "${C_HDR}" "${C_RST}"
if [[ "${MODE}" == "install" ]]; then
    printf '  Installed:\n'
    printf '    binary : %s/sentinel\n' "${BINDIR}"
    printf '    data   : %s/\n' "${DATADIR}"
    printf '\n'
    printf '  Try:\n'
    printf '    cd /tmp\n'
    printf '    sentinel -h\n'
    printf '    sentinel /tmp/xsslab --xss-only http://TARGET/level/0\n'
else
    printf '  Built (not installed): %s/sentinel\n' "${SCRIPT_DIR}"
fi
printf '%s────────────────────────────────────────────────────────────%s\n' \
    "${C_HDR}" "${C_RST}"