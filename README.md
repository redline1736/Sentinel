# Sentinel — Automated Pentest Scanner

> A modular, pipeline-driven security assessment toolkit built in C with Python-based XSS analysis, SQL injection detection, headless browser verification, and pre-built exploit modules for Lighttpd and Nginx. Designed for authorized penetration testing engagements.

[![Pipeline](https://gitlab.com/mind-loom/sentinel/badges/main/pipeline.svg)](https://gitlab.com/mind-loom/sentinel/-/pipelines)
[![C](https://img.shields.io/badge/language-C-555555?logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Python](https://img.shields.io/badge/language-Python-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tor](https://img.shields.io/badge/proxy-Tor-7D4698?logo=tor&logoColor=white)](https://www.torproject.org/)

---

## Table of Contents

- [Architecture](#architecture)
- [Subdomain Enumeration](#subdomain-enumeration--sub-mode)
- [Full Scan Pipeline](#full-scan-pipeline--scan-mode)
- [Proxy Infrastructure](#proxy-infrastructure)
- [XSS Analysis Engine](#xss-analysis-engine)
- [GhostQuery — Injection Detection](#ghostquery--injection-detection)
- [DeepBlue — Exploit Modules](#deepblue--exploit-modules)
- [Chrome — Headless Browser Verification](#chrome--headless-browser-verification)
- [Glassworm — Module Analysis Engine](#glassworm--module-analysis-engine)
- [DarkShield — Custom Proxy Lists](#darkshield--custom-proxy-lists)
- [CLI Reference](#cli-reference)
- [CI/CD Pipeline](#cicd-pipeline)
- [Quick Start](#quick-start)

---

## Architecture

```
Sentinel/
│
├── src/                                    # C core engine
│   ├── main.c                              # Entry point, CLI argument parsing, mode dispatch
│   ├── global.h                            # Shared global state struct, configuration
│   │
│   ├── scan/                               # Subdomain enumeration & vulnerability scanning
│   │   ├── scan.c                          # Passive/active enum, pipeline orchestration, analysis
│   │   └── scan.h                          # Scan module API
│   │
│   ├── prox/                               # Tor proxy pool management
│   │   ├── prox.c                          # Multi-instance pool, burn/rotate, health checks
│   │   └── prox.h                          # Proxy module API
│   │
│   ├── util/                               # HTTP & file utilities
│   │   ├── util.c                          # libcurl wrapper, file I/O, string helpers
│   │   └── util.h                          # Utility API
│   │
│   ├── chrome/                             # Headless Chromium XSS verification
│   │   ├── chrome.c                        # Browser launch, page eval, screenshot capture
│   │   └── chrome.h                        # Chrome integration API
│   │
│   ├── deepblue/                           # Exploit module dispatcher (C engine)
│   │   ├── deepblue.c                      # Module loading, CVE routing, execution
│   │   └── deepblue.h                      # DeepBlue module API
│   │
│   ├── ghostquery/                         # Injection analysis engine
│   │   ├── gq.c                            # Parameter fuzzing, payload injection, response analysis
│   │   └── gq.h                            # GhostQuery API
│   │
│   └── glassworm/                          # DVR/module analysis engine
│       ├── gw.c                            # Glassworm entry point, DVR dispatch
│       ├── gw.h                            # Glassworm API
│       ├── dvr/                            # DVR firmware analysis routines
│       ├── file/                           # File format analysis helpers
│       └── http/                           # HTTP traffic analysis helpers
│
├── xss/                                    # XSS analysis module (Python)
│   ├── main.py                             # JS route extraction, gobuster wrapper, dalfox/XSStrike runner
│   ├── xss.py                              # Parametric XSS payload generator
│   └── xss.json                            # Tag × event × function × encoding definitions
│
├── deepblue/                               # Exploit module scripts & metadata
│   ├── model.dvr                           # Module registry / DVR index
│   ├── module.json                         # Full CVE metadata, versions, config requirements, usage
│   ├── modules/
│   │   ├── lighttpd/
│   │   │   ├── CVE-2014-2323.sh            # SQLi → RCE via mod_mysql_vhost
│   │   │   ├── CVE-2014-2324.sh            # Directory traversal via mod_evhost
│   │   │   ├── CVE-2018-19052.sh           # Path traversal via mod_alias
│   │   │   ├── CVE-2019-11072.py           # DoS via burl_normalize underflow
│   │   │   └── CVE-2022-30780.py           # DoS via excessive URL length
│   │   └── nginx/
│   │       ├── CVE-2013-2028.sh            # Stack overflow RCE in rewrite module
│   │       ├── CVE-2023-44487.py           # HTTP/2 rapid reset DoS
│   │       └── CVE-2026-42945/             # NGINX Rift — heap buffer overflow RCE
│   │           ├── helper.py               # Full recon & heap feng shui spray
│   │           └── htb.py                  # Exploit trigger & command execution
│   └── tools/
│       └── scanner.py                      # Auxiliary port/service scanner
│
├── darkshield/                             # Custom proxy infrastructure
│   └── proxy/custom/
│       └── proxy.txt                       # SOCKS5/HTTP proxy list (one per line)
│
├── ghostquery/                             # Injection detection payloads (Python)
│   ├── params.txt                          # Web parameter name list for fuzzing
│   ├── sql/
│   │   └── sql.json                        # SQLi payload definitions (time-based, error-based, union, blind)
│   └── xss/
│       ├── main.py                         # GhostQuery XSS scanner runner
│       ├── xss.py                          # Advanced multi-encoding payload generator
│       ├── xss.json                        # Tag × event × function definitions
│       └── custom.txt                      # Custom/curated XSS payload list
│
├── glassworm/                              # Glassworm ML model definitions & tests
│
├── .gitlab-ci.yml                          # CI/CD pipeline (build + test stages)
├── Makefile                                # Build system
├── LICENSE                                 # MIT license
└── README.md                               # This file
```

---

## Subdomain Enumeration (`-sub` mode)

Discovers subdomains using a combination of passive and active techniques, then validates live hosts and checks for subdomain takeover.

### Passive Sources

| Tool | Purpose |
|------|---------|
| **Subfinder** | Aggregates from 30+ sources (Certificates, DNSDumpster, Shodan, AlienVault, etc.) |
| **Assetfinder** | OSINT-based subdomain discovery via various sources |
| **WaybackURLs** | Extracts historical URLs from Wayback Machine for subdomain discovery |
| **Gau** (GetAllUrls) | Fetches URLs from AlienVault, WayBack, CommonCrawl, URLScan |

### Active Enumeration

| Tool | Purpose |
|------|---------|
| **Gobuster (DNS)** | DNS subdomain brute-force using SecLists top 5000 |
| **Gobuster (dir)** | Directory/file brute-force on discovered hosts |

### Subdomain Takeover Detection

| Tool | Purpose |
|------|---------|
| **Subjack** | Checks for dangling DNS/CNAME records pointing to unclaimed cloud services |
| **Subzy** | Passive takeover detection with high accuracy |

### Health Validation

| Tool | Purpose |
|------|---------|
| **Httpx** | Probes all discovered subdomains — filters live hosts, captures status codes, titles, tech stack |

### Anonymity

All enumeration traffic routes through the **Tor proxy pool** (configurable instance count, default 3). Each proxy instance is health-checked before use, and burned/rotated on detection (HTTP 429/503).

---

## Full Scan Pipeline (`-scan` mode)

Orchestrates a complete vulnerability assessment pipeline across all discovered live subdomains.

```
Phase 0: Tor Proxy Pool
  └─ Start N Tor instances (configurable)
  └─ Health-check ports
  └─ Enable auto burn/rotate

Phase 1: Subdomain Discovery
  └─ Subfinder (passive)
  └─ Assetfinder (passive)
  └─ WaybackURLs + Gau (historical)
  └─ Gobuster DNS (active brute-force)
  └─ Aggregate + deduplicate

Phase 2: Vulnerability Scanning
  └─ Nuclei — template-based scanning (1000s of CVE templates)
  └─ Nikto — web server scanner (misconfigurations, outdated software, dangerous files)

Phase 3: WordPress Audit (conditional)
  └─ WPScan — detects WordPress installations, enumerates plugins/themes/users,
       checks for vulnerable versions, weak passwords

Phase 4: XSS Scanning
  └─ Dalfox — DOM/reflected/stored XSS detection with payload reflection
  └─ XSStrike — context-aware XSS scanner with WAF bypass
  └─ Custom parametric payloads from xss.json

Phase 5: Internal Analysis
  └─ Severity filtering
  └─ Deduplication
  └─ Vulnerability report generation
```

---

## Proxy Infrastructure

### Tor Proxy Pool

- **Multi-instance** — spawns N Tor instances (default 3, configurable at runtime)
- **Auto burn/rotate** — monitors for HTTP 429 (rate-limited) and 503 (service unavailable); automatically kills and replaces burned proxies
- **Health monitoring** — periodic TCP port connectivity checks before routing traffic
- **Proxychains integration** — all external tools (subfinder, nuclei, dalfox, etc.) transparently proxied through the pool via system proxychains configuration

### DarkShield Custom Proxies

Alternative proxy list support via `darkshield/proxy/custom/proxy.txt`. Each line should contain one proxy in the format:

```
socks5://127.0.0.1:9050
http://proxy.example.com:8080
socks5://user:pass@proxy.example.com:1080
```

Used as fallback or primary when Tor is unavailable or undesirable.

---

## XSS Analysis Engine

Located in `xss/` with a companion C integration in `src/xss/` and headless verification in `src/chrome/`.

### Parametric Payload Generator (`xss.py` + `xss.json`)

Generates unique, deduplicated XSS payloads from a cross-product definition:

**Tags** (15):
`img`, `svg`, `script`, `iframe`, `a`, `form`, `object`, `embed`, `body`, `input`, `video`, `audio`, `marquee`

**Events** (50+):
- **Standard**: `onload`, `onerror`, `onclick`, `onmouseover`, `onfocus`, `onblur`, `onsubmit`, `onchange`, `onreset`, `onselect`, `onscroll`
- **Extended**: `onpointerover`, `ontouchstart`, `ondrag`, `ondrop`, `oncopy`, `oncut`, `onpaste`, `onwheel`, `onauxclick`
- **Media**: `onplay`, `onpause`, `onended`, `onvolumechange`, `onseeking`
- **Document**: `onreadystatechange`, `onpageshow`, `onpopstate`, `onhashchange`
- **SVG**: `onbegin`, `onrepeat`, `onend`, `onactivate`, `onzoom`
- **Animation**: `onanimationstart`, `onanimationend`, `onanimationiteration`, `ontransitionend`

**Functions**: `alert(1)`, `confirm(2)`, `prompt(3)`

**Encodings**:
- Raw
- HTML entities (decimal): `&#x6C;&#x6F;&#x63;&#x61;&#x74;&#x69;&#x6F;&#x6E;`
- HTML entities (hex): `&#108;&#111;&#99;&#97;&#116;&#105;&#111;&#110;`
- URL-encoded (single): `%61%6C%65%72%74%28%31%29`
- URL-encoded (double): `%2561%256C%2565%2572%2574%2528%2531%2529`
- Base64 eval(atob()): `eval(atob('YWxlcnQoMSk='))`
- JS hex escapes: `\x61\x6C\x65\x72\x74\x28\x31\x29`
- JS unicode escapes: `\u0061\u006C\u0065\u0072\u0074\u0028\u0031\u0029`
- Mixed case: `AlErT(1)`
- Tab/newline/null-byte injection: `%09`, `%0a`, `%00`

**Output**: ~1,200+ unique, deduplicated payloads with no duplicates across encoding variants.

### Chrome Headless Verification (`src/chrome/`)

After payload generation and injection, launches headless Chromium to:
- Render the target page with injected payload
- Capture triggered JavaScript alerts/confirms/prompts
- Screenshot the DOM for manual review
- Confirm execution with DOM mutation detection

### Pipeline Integration

The `xss/main.py` script:
1. Extracts JavaScript routes from the target via gobuster/wayback
2. Feeds routes to dalfox and XSStrike for automated scanning
3. Runs the custom parametric payload generator against discovered parameters
4. Routes all traffic through the Tor proxy pool

---

## GhostQuery — Injection Detection

A dual-module detection engine that targets both SQL injection and cross-site scripting, with a C-powered high-performance fuzzer and Python-based advanced analysis.

### SQL Injection Detection (`ghostquery/sql/`)

**Payload definitions** (`sql.json`) organized by detection technique:

| Technique | Description |
|-----------|-------------|
| **Error-based** | Triggers SQL errors to extract DBMS info (MySQL `extractvalue`, PostgreSQL `cast`, MSSQL `convert`) |
| **Time-based blind** | Conditional time delays for blind inference (MySQL `SLEEP(5)`, PostgreSQL `PG_SLEEP(5)`, MSSQL `WAITFOR DELAY`) |
| **Boolean-based blind** | True/false condition responses for blind enumeration |
| **UNION-based** | Column count detection + data extraction via UNION SELECT |
| **Stacked queries** | Multi-statement execution for DB manipulation |
| **Out-of-band** | DNS/HTTP exfiltration via `LOAD_FILE`, `xp_cmdshell`, `UTL_HTTP` |

**Database targets**: MySQL, MariaDB, PostgreSQL, MSSQL, Oracle, SQLite

**C integration** (`src/ghostquery/gq.c`):
- High-speed parameter fuzzing engine
- Automatically rotates payload classes on false negatives
- Response time analysis for time-based blind detection
- Pattern matching for error-based DBMS fingerprinting
- Tor proxy pool integration

### XSS Detection (`ghostquery/xss/`)

Standalone XSS scanner complementing the main `xss/` module:

- **`main.py`** — route discovery (gobuster), payload delivery, response analysis
- **`xss.py`** — alternative payload generator with different encoding emphasis
- **`xss.json`** — tag/event/function definitions (tuned for GhostQuery's approach)
- **`custom.txt`** — hand-curated payloads for edge cases and WAF bypass

### Parameter Fuzzing (`params.txt`)

Pre-loaded with common web parameters for injection point discovery:
`q`, `s`, `search`, `query`, `id`, `page`, `name`, `user`, `pass`, `email`, `url`, `redirect`, `next`, `file`, `dir`, `cmd`, `exec`, `debug`, `test`, `view`, `action`, `do`, `ajax`, `callback`, `jsonp`, `format`, `type`, `sort`, `order`, `limit`, `offset`, `filter`, `lang`, `theme`

---

## DeepBlue — Exploit Modules

A registry-driven exploit framework with pre-built, ready-to-use scripts organized by target service.

### Module Registry

- **`deepblue/model.dvr`** — master registry indexing all available modules
- **`deepblue/module.json`** — structured metadata including:
  - Affected service & version ranges
  - CVE identifier & CVSS score
  - Vulnerability type (RCE, traversal, DoS, SQLi)
  - Required configuration/modules
  - Usage examples
  - Mitigation/remediation guidance

### Lighttpd Exploits

| CVE | Type | Affected Versions | Required Config | Script |
|-----|------|-------------------|-----------------|--------|
| **CVE-2014-2323** | SQLi → RCE | < 1.4.35 | `mod_mysql_vhost` enabled | `CVE-2014-2323.sh` |
| **CVE-2014-2324** | Directory Traversal | < 1.4.35 | `mod_evhost` or `mod_simple_vhost` | `CVE-2014-2324.sh` |
| **CVE-2018-19052** | Path Traversal | 1.4.40–1.4.50 | `mod_dirlisting` enabled | `CVE-2018-19052.sh` |
| **CVE-2019-11072** | Denial of Service | 1.4.0–1.4.53 | Default (any config) | `CVE-2019-11072.py` |
| **CVE-2022-30780** | Denial of Service | < 1.4.56 | Default (any config) | `CVE-2022-30780.py` |

#### CVE-2014-2323 — SQL Injection to RCE

- **Vector**: `mod_mysql_vhost` fails to sanitize virtual-host query parameters
- **Exploitation**: Injects SQL to write a PHP backdoor to the web root via `SELECT ... INTO OUTFILE`
- **Usage**: `./CVE-2014-2323.sh -u http://target.com -p /path/to/writeable`

#### CVE-2014-2324 — Directory Traversal

- **Vector**: Host header not sanitized before filesystem operations
- **Exploitation**: Sends crafted Host header with `../` sequences to read arbitrary files
- **Usage**: `./CVE-2014-2324.sh -u http://target.com -f /etc/passwd`

#### CVE-2018-19052 — URL-Encoded Path Traversal

- **Vector**: `mod_dirlisting` fails to decode `%2f` sequences in URL
- **Exploitation**: Uses `..%2f` to traverse directories outside web root
- **Usage**: `./CVE-2018-19052.sh -u http://target.com:80 -d /etc`

#### CVE-2019-11072 — burl_normalize DoS

- **Vector**: Integer underflow in `burl_normalize_2F_to_slash_fix()`
- **Exploitation**: Sends a crafted URI causing infinite loop / crash
- **Usage**: `./CVE-2019-11072.py -u http://target.com`

#### CVE-2022-30780 — URL Length DoS

- **Vector**: Excessive URL length causes stack exhaustion
- **Exploitation**: Dichotomic search for crash threshold, then flood
- **Usage**: `./CVE-2022-30780.py -u http://target.com`

### Nginx Exploits

| CVE | Type | Affected Versions | Required Config | CVSS | Script(s) |
|-----|------|-------------------|-----------------|------|-----------|
| **CVE-2013-2028** | Remote Code Execution | 1.3.9–1.4.0 | `ngx_http_rewrite_module` enabled | 7.5 | `CVE-2013-2028.sh` |
| **CVE-2023-44487** | Denial of Service | 1.0.0–1.25.x (HTTP/2) | `http2` enabled | 7.5 | `CVE-2023-44487.py` |
| **CVE-2026-42945** | Remote Code Execution | 0.6.27–1.30.0 | Rewrite with unnamed PCRE captures + `?` | 9.2 (CVSS 4.0) | `helper.py` + `htb.py` |

#### CVE-2013-2028 — Stack Overflow RCE

- **Vector**: `ngx_http_parse_unsafe_uri()` copies user-supplied URI into a fixed 1024-byte stack buffer without bounds checking
- **Exploitation**: URI > 1024 bytes overwrites saved EBP and return address; shellcode executes `execve("/bin/sh", NULL, NULL)`
- **Usage**: `./CVE-2013-2028.sh http://target.com:8080/ "cat /etc/passwd"`

#### CVE-2023-44487 — HTTP/2 Rapid Reset

- **Vector**: HTTP/2 stream multiplexing allows rapid open+reset cycles, exhausting server resources
- **Exploitation**: Opens 100,000+ streams that are immediately reset, starving legitimate connections
- **Usage**: `python3 CVE-2023-44487.py target.com`

#### CVE-2026-42945 — NGINX Rift (Heap Buffer Overflow RCE)

- **Vector**: Two-pass script engine in rewrite module computes undersized buffer when `?` appears in replacement string alongside unnamed PCRE captures (`$1`, `$2`). The length pass sees `is_args=0`, the copy pass sees `is_args=1`, causing heap overflow during URI escape expansion.
- **Exploitation**:
  1. **Recon phase** (`helper.py --target <IP> --all`) — checks vulnerability, identifies config patterns, performs heap feng shui via POST body sprays
  2. **Exploit phase** (`htb.py --target <IP> --cmd "id"`) — triggers overflow, redirects `ngx_pool_t cleanup` pointer to invoke `system()`
- **CVSS 4.0 Score**: 9.2 (Critical)
- **Active in wild**: Confirmed May 18, 2026
- **Mitigation**: Upgrade to Nginx 1.30.1+/NGINX Plus R36 P4. Replace unnamed captures with named captures. Ensure ASLR enabled.
- **Usage**:
  ```bash
  # Check vulnerability
  python3 CVE-2026-42945/helper.py --target 10.0.0.1 --all

  # Exploit
  python3 CVE-2026-42945/htb.py --target 10.0.0.1 --cmd "id"
  python3 CVE-2026-42945/htb.py --target 10.0.0.1 --cmd "cat /etc/shadow"
  ```

---

## Chrome — Headless Browser Verification

Located in `src/chrome/`, this module provides browser-based confirmation of XSS payload execution.

### Capabilities

- Launches headless Chromium via CDP (Chrome DevTools Protocol)
- Injects XSS payloads into target pages
- Listens for `alert()`, `confirm()`, and `prompt()` JavaScript dialogs
- Captures full-page screenshots after injection
- Detects DOM mutations caused by payload execution
- Reports execution success/failure with evidence

### Configuration

Requires `chromium` or `google-chrome` installed on the system. Configurable via environment variables:

- `CHROME_BIN` — path to Chromium executable (default: `/usr/bin/chromium`)
- `CHROME_HEADLESS` — force headless mode (default: `true`)
- `CHROME_TIMEOUT` — page load timeout in seconds (default: `15`)

---

## Glassworm — Module Analysis Engine

Located in `src/glassworm/` with sub-modules for multi-purpose analysis.

### Sub-Modules

| Module | Purpose |
|--------|---------|
| `dvr/` | DVR firmware analysis — inspects firmware images for hardcoded credentials, backdoors, and vulnerable configurations |
| `file/` | File format analysis — signature detection, magic byte parsing, entropy analysis |
| `http/` | HTTP traffic analysis — request/response inspection, header analysis, cookie auditing |

### Testing

```bash
# Run DVR analysis test
./sentinel example.com test_dvr --test-dvr glassworm/hello.ml
```

---

## DarkShield — Custom Proxy Lists

Provides alternative proxy infrastructure when Tor is not suitable.

### Format (`darkshield/proxy/custom/proxy.txt`)

```
socks5://127.0.0.1:9050
socks5://127.0.0.1:9051
http://proxy.example.com:8080
socks5://user:pass@proxy.example.com:1080
```

### Behavior

- Proxies are loaded at startup when Tor pool is unavailable
- Each proxy is health-checked before routing
- Failed proxies are removed from the pool
- Supports SOCKS4, SOCKS5, and HTTP/S proxies
- Used as fallback or primary depending on runtime configuration

---

## CLI Reference

### Global Syntax

```bash
./sentinel <target_domain> <engagement_name> [mode] [options]
```

### Modes

| Flag | Description |
|------|-------------|
| `-sub` | Subdomain enumeration only |
| `-scan` | Full scan pipeline |
| `--scan-url <url>` | Scan a specific URL (bypasses subdomain discovery) |
| `--test-dvr <file>` | Test a DVR analysis file (Glassworm) |

### Example Commands

```bash
# Subdomain enumeration
./sentinel example.com engagement1 -sub

# Full scan pipeline against a domain
./sentinel example.com full_audit -scan

# Scan a specific URL
./sentinel example.com url_scan --scan-url https://target.com/

# XSS testing at specific difficulty levels
./sentinel thegod.pythonanywhere.com xss_low --scan-url https://thegod.pythonanywhere.com/vulnerabilities/xss_r/low
./sentinel thegod.pythonanywhere.com xss_medium --scan-url https://thegod.pythonanywhere.com/vulnerabilities/xss_r/medium
./sentinel thegod.pythonanywhere.com xss_high --scan-url https://thegod.pythonanywhere.com/vulnerabilities/xss_r/high
./sentinel thegod.pythonanywhere.com xss_impossible --scan-url https://thegod.pythonanywhere.com/vulnerabilities/xss_r/impossible

# DVR analysis
./sentinel example.com dvr_test --test-dvr glassworm/hello.ml
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GO_VERSION` | `1.24.2` | Go toolchain version |
| `GOBIN` | `/usr/local/bin` | Go binary install path |
| `SECLISTS` | `/usr/share/seclists` | SecLists base path |
| `TOR_COUNT` | `3` | Number of Tor instances in proxy pool |
| `CHROME_BIN` | `/usr/bin/chromium` | Chromium executable path |
| `CHROME_TIMEOUT` | `15` | Page load timeout (seconds) |

---

## CI/CD Pipeline

The `.gitlab-ci.yml` defines two stages:

### Build Stage

1. Configures Debian repositories with `non-free` components
2. Installs system dependencies: `gcc`, `libcurl4-openssl-dev`, `make`, `tor`, `python3`, `chromium`, `ruby`, `nikto`, `proxychains4`
3. Downloads and installs Go 1.24.2
4. Installs Go tools:
   - `subfinder`, `assetfinder`, `httpx`, `nuclei`, `dalfox`, `subzy`, `subjack`
5. Installs Ruby gems: `wpscan`
6. Clones XSStrike to `/opt/XSStrike` and installs Python dependencies in a virtual environment
7. Downloads SecLists (DNS subdomains top 5000, web content common.txt)
8. Builds the C binary: `make clean all`
9. Verifies binary and all dependency tools are present

### Test Stage

Runs the compiled binary against test targets:

```bash
./sentinel example.com test_sub -sub
./sentinel thegod.pythonanywhere.com test_scan_url --scan-url https://thegod.pythonanywhere.com/
./sentinel thegod.pythonanywhere.com test_xss_low --scan-url https://thegod.pythonanywhere.com/vulnerabilities/xss_r/low
./sentinel thegod.pythonanywhere.com test_xss_medium --scan-url https://thegod.pythonanywhere.com/vulnerabilities/xss_r/medium
./sentinel thegod.pythonanywhere.com test_xss_high --scan-url https://thegod.pythonanywhere.com/vulnerabilities/xss_r/high
./sentinel thegod.pythonanywhere.com test_xss_impossible --scan-url https://thegod.pythonanywhere.com/vulnerabilities/xss_r/impossible
./sentinel example.com test_dvr --test-dvr glassworm/hello.ml
```

The test stage uses `allow_failure: true` to prevent pipeline blocking on expected test target fluctuations.

---

## Quick Start

### Prerequisites

```bash
# System dependencies
apt install -y gcc libcurl4-openssl-dev make tor pkg-config python3 python3-pip chromium

# Go (required for Go-based tooling)
curl -fsSL https://dl.google.com/go/go1.24.2.linux-amd64.tar.gz | tar -C /usr/local -xz
export PATH=$PATH:/usr/local/go/bin
```

### Build

```bash
git clone https://gitlab.com/mind-loom/sentinel.git
cd sentinel
make clean all
```

### Verify Build

```bash
./sentinel --help
```

### Basic Usage

```bash
# Enumerate subdomains
./sentinel example.com my_engagement -sub

# Full vulnerability scan
./sentinel example.com pentest_2026 -scan

# Test a specific URL
./sentinel example.com quick_test --scan-url https://target.com/

# Run exploit module (standalone)
cd deepblue/modules/lighttpd
./CVE-2018-19052.sh -u http://target.com -d /etc
```

### Full CI Environment Setup

For a complete environment matching CI:

```bash
# Install all Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/PentestPad/subzy@latest
go install github.com/haccer/subjack@latest

# Install WPScan
gem install wpscan

# Install XSStrike
git clone https://github.com/s0md3v/XSStrike /opt/XSStrike
python3 -m venv /opt/xsenv
/opt/xsenv/bin/pip install -r /opt/XSStrike/requirements.txt

# Download SecLists
mkdir -p /usr/share/seclists/Discovery/{DNS,Web-Content}
curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
  -o /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
  -o /usr/share/seclists/Discovery/Web-Content/common.txt
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## Disclaimer

Sentinel is a security assessment tool designed for authorized penetration testing engagements. Users are responsible for complying with all applicable laws and obtaining explicit written authorization before testing any target systems. The developers assume no liability for misuse or damage caused by this tool.