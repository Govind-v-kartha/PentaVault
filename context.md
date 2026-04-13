# PentaVault — Complete Project Context

> **This document provides exhaustive technical context for the PentaVault project.
> It covers every module, architecture decision, data flow, API surface, configuration
> parameter, integration detail, and implementation nuance.
> Last updated: 2026.**

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Technology Stack](#2-technology-stack)
3. [Project Structure](#3-project-structure)
4. [7-Stage Scan Pipeline](#4-7-stage-scan-pipeline)
5. [Core Modules](#5-core-modules)
6. [Vulnerability Modules](#6-vulnerability-modules)
7. [Utility Modules](#7-utility-modules)
8. [Web Dashboard & REST API](#8-web-dashboard--rest-api)
9. [MITRE ATT&CK v16.1 Integration](#9-mitre-attck-v161-integration)
10. [OWASP 2025 Top 10 Integration](#10-owasp-2025-top-10-integration)
11. [CVSS v3.1 Scoring](#11-cvss-v31-scoring)
12. [Selenium Browser Engine](#12-selenium-browser-engine)
13. [Configuration & Limits](#13-configuration--limits)
14. [Data Flow & Finding Model](#14-data-flow--finding-model)
15. [Report Generation](#15-report-generation)
16. [Logging System](#16-logging-system)
17. [Concurrency & Threading](#17-concurrency--threading)
18. [Timeout & Hang Prevention](#18-timeout--hang-prevention)
19. [Deduplication](#19-deduplication)
20. [CLI Interface](#20-cli-interface)
21. [Web Dashboard UI Details](#21-web-dashboard-ui-details)
22. [REST API Endpoint Reference](#22-rest-api-endpoint-reference)
23. [File-by-File Reference](#23-file-by-file-reference)
24. [Dependencies](#24-dependencies)
25. [Known Considerations](#25-known-considerations)
26. [Author & License](#26-author--license)

---

## 1. Project Overview

**PentaVault** is a professional-grade **Automated Vulnerability Assessment and Penetration Testing (VAPT)** security suite. It automates the full security scanning lifecycle from target reconnaissance through vulnerability testing to scored report generation.

- **Version**: 1.2.0
- **Language**: Python 3.13
- **Platform**: Windows (primary), cross-compatible
- **Interfaces**: CLI + Web Dashboard (FastAPI)
- **Author**: © 2026 Govind V Kartha
- **License**: Proprietary — All rights reserved

### What It Does

1. Takes a target URL or IP address
2. Performs DNS reconnaissance, subdomain enumeration, port scanning, and service detection
3. Fingerprints the technology stack, detects WAFs, analyses SSL/TLS certificates
4. Crawls web applications to discover endpoints, forms, parameters, and API routes
5. Runs 23+ vulnerability testing modules concurrently (SQLi, XSS, Headers, SSRF, IDOR, Open Redirect, Command Injection, XXE, LFI, Sensitive Files, NoSQLi, SSTI, GraphQL Abuse, JWT Checks, Host Header Injection, CORS Misconfiguration, HPP, CRLF Injection, Request Smuggling, Mass Assignment/BOLA, Insecure Deserialization, Prototype Pollution, CSV/Formula Injection)
6. Optionally uses Selenium Chrome for JS-rendered apps (SPA, AJAX, dynamic forms)
7. Scores all findings with CVSS v3.1, maps to OWASP 2025 Top 10 and MITRE ATT&CK v16.1
8. Generates standard, executive, and technical JSON reports
9. Provides a real-time web dashboard with live progress, timer, findings, and analytics

---

## 2. Technology Stack

| Component | Technology | Version | Purpose |
|---|---|---|---|
| Language | Python | 3.13 | Core runtime |
| Web Framework | FastAPI | 0.111+ | REST API backend |
| ASGI Server | Uvicorn | 0.29+ | HTTP server for FastAPI |
| HTTP Client | httpx, requests | Latest | Making HTTP requests to targets |
| HTML Parser | BeautifulSoup4 | 4.12+ | Parsing HTML for crawling/forms |
| DNS | dnspython | 2.6+ | DNS lookups, subdomain enumeration |
| Port Scanner | python-nmap | 0.7.1+ | Nmap wrapper for port/service scanning |
| Network | scapy | 2.5+ | Low-level network analysis |
| WHOIS | python-whois | 0.9.4+ | Domain WHOIS lookups |
| CVSS | cvss | 3.1+ | CVSS v3.1 scoring library |
| Browser | Selenium | 4.20+ | Headless/headed Chrome automation |
| WebDriver | webdriver-manager | 4.0+ | Automatic ChromeDriver management |
| Frontend | HTML/CSS/JS | Vanilla | Dark-themed SPA dashboard |

### External Tool Dependencies

- **Nmap**: Optional but recommended; scans continue with a warning when unavailable
- **Google Chrome / Chromium / Edge**: Required only for Selenium browser mode
- **ChromeDriver / EdgeDriver**: Required for Selenium browser mode
- **Node.js**: Required for DOCX report export

---

## 3. Project Structure

```
c:\Project 1\
├── .venv/                           # Python virtual environment
├── README.md                        # Project documentation
├── context.md                       # This file — full project context
├── scanner/
│   ├── __init__.py                  # Package marker
│   ├── main.py                      # CLI entry point (argparse)
│   ├── requirements.txt             # pip dependencies
│   │
│   ├── core/                        # Pipeline stage engines
│   │   ├── __init__.py
│   │   ├── recon.py                 # DNS, subdomain enumeration, WHOIS
│   │   ├── port_scanner.py          # Nmap port/service/OS detection
│   │   ├── fingerprint.py           # Tech stack, WAF, SSL/TLS
│   │   ├── crawler.py               # Static HTTP web crawler
│   │   ├── selenium_crawler.py      # Browser-based crawler (JS/SPA)
│   │   ├── scorer.py                # CVSS v3.1 scoring engine
│   │   └── browser.py               # Shared Selenium browser utilities
│   │
│   ├── modules/                     # Vulnerability testing modules
│   │   ├── __init__.py
│   │   ├── sqli.py                  # SQL Injection — error, time-blind, boolean-blind
│   │   ├── xss.py                   # XSS — reflected, DOM, stored, template injection
│   │   ├── headers.py               # Security header analysis (CSP, HSTS, etc.)
│   │   ├── ssrf.py                  # Server-Side Request Forgery
│   │   ├── idor.py                  # Insecure Direct Object Reference
│   │   ├── open_redirect.py         # Open Redirect detection (7 payload variants)
│   │   ├── command_injection.py     # OS command injection detection
│   │   ├── xxe.py                   # XML External Entity detection
│   │   ├── prototype_pollution.py   # Prototype pollution heuristic checks
│   │   ├── csv_formula_injection.py # CSV/formula injection heuristic checks
│   │   ├── sqli_selenium.py         # Browser-based SQLi with screenshot evidence
│   │   └── xss_selenium.py          # Browser-based XSS with alert() hooking
│   │
│   ├── utils/                       # Support/utility modules
│   │   ├── __init__.py
│   │   ├── logger.py                # Centralized file + console logging
│   │   ├── report_exporter.py       # JSON report generation (3 variants)
│   │   ├── mitre_mapping.py         # MITRE ATT&CK v16.1 mapping engine
│   │   ├── ai_engine.py             # Gemini AI threat intelligence (stateful key-pool rotation/cooldown + model failover)
│   │   └── pdf_report.py            # Professional PDF/DOCX report generation
│   │
│   ├── web/                         # Web Dashboard (FastAPI)
│   │   ├── app.py                   # FastAPI application + REST API
│   │   └── static/                  # Frontend assets
│   │       ├── index.html           # Dashboard HTML (single-page app)
│   │       ├── style.css            # SOC Obsidian design system CSS (glass panels, responsive rail/stage layout)
│   │       └── app.js               # Interaction engine (scan lifecycle, AI actions, D3 + Three.js visual controllers)
│   │
│   ├── reports/                     # Auto-created: JSON report output
│   ├── data/                        # Auto-created: persistent scan history
│   ├── evidence/                    # Auto-created: screenshot PNGs
│   └── logs/                        # Auto-created: timestamped log files
```

---

## 4. 7-Stage Scan Pipeline

The scan pipeline executes sequentially through 7 stages. Each stage updates progress in real-time (both CLI and web UI).

### Stage 1: Target Input (5% progress)
- Normalises the target: adds `http://` if bare IP/hostname
- Extracts hostname via `urllib.parse.urlparse`
- Determines if target is a URL or bare IP

### Stage 2: Reconnaissance (10% progress)
- **Runs only for**: `full`, `network-only` modes
- DNS lookup (A, AAAA, MX, NS, TXT, SOA records) via dnspython
- Subdomain enumeration (brute-force with built-in wordlist)
- WHOIS lookups for domain registration info
- Nmap port scanning: top 1000 ports, service detection, OS fingerprinting
- Output: `recon_data` dict with `ip`, `open_ports`, `services`, `os_guess`, `dns_records`, `subdomains`, `whois`

### Stage 3: Fingerprinting (20% progress)
- **Runs only for**: `full`, `web-only`, `quick` modes (URL targets only)
- Technology stack detection via HTTP response headers and body signatures
- WAF detection (Cloudflare, AWS WAF, ModSecurity, etc.)
- SSL/TLS certificate analysis (issuer, validity, algorithms)
- Output: `fingerprint_data` dict with `server`, `technologies`, `waf`, `ssl_info`

### Stage 4: Web Crawling (30% progress)
- **Runs only for**: `full`, `web-only`, `quick` modes (URL targets only)
- Two crawlers: static HTTP (`crawler.py`) or Selenium (`selenium_crawler.py`)
- Crawl strategy supports `auto`, `httpx`, `selenium`, and `hybrid` (httpx first with Selenium fallback on low coverage)
- Discovers: endpoints (URLs), forms (with fields + actions), parameters, JS API routes
- `CrawlResult` class stores: `endpoints`, `forms`, `parameters`, `api_endpoints`
- Crawl depth/pages: 2/50 (quick) or 3/200 (full)
- `summary()` method returns counts for reporting
- Selenium crawler: renders JavaScript, discovers dynamically loaded links, AJAX endpoints, SPA routes

### Stage 5: Vulnerability Testing (50→80% progress)
- Modules run concurrently via `ThreadPoolExecutor(max_workers=threads)`
- HTTP modules run in parallel; Selenium modules run sequentially (due to browser resources)
- Each module receives: endpoints, forms, cookie, timeout, mode flags
- Progress increments per completed module
- Live `findings_count` updates during execution
- Module timeout: 300s default, 120s/180s for browser modules

**Modules executed:**
1. **SQLi** (`sqli.py` or `sqli_selenium.py`) — Error-based, time-based blind, boolean-based blind injection
2. **XSS** (`xss.py` or `xss_selenium.py`) — Reflected, DOM-based, stored XSS with template injection canary
3. **Headers** (`headers.py`) — Missing/misconfigured security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, CORS, Referrer-Policy, Permissions-Policy)
4. **SSRF** (`ssrf.py`) — Injects internal/cloud-metadata URLs (localhost, 127.0.0.1, 169.254.169.254, Redis, Elasticsearch)
5. **IDOR** (`idor.py`) — Extracts numeric IDs from URLs, attempts access to adjacent objects
6. **Open Redirect** (`open_redirect.py`) — 7 payload variants (protocol bypass, path traversal, URL encoding, etc.)
7. **Command Injection** (`command_injection.py`) — Separator-based payloads with output-marker confirmation (`expr`, `set /a`, canary echoes)
8. **XXE** (`xxe.py`) — XML external entity payloads with local-file disclosure marker detection
9. **LFI** (`lfi.py`) — Path traversal and local file disclosure checks for file-like parameters
10. **Sensitive Files** (`sensitive_files.py`) — Probes common exposed backup/config/admin artifacts
11. **NoSQLi** (`nosqli.py`) — Boolean and error-based NoSQL injection heuristics
12. **SSTI** (`ssti.py`) — Server-side template expression evaluation probes
13. **GraphQL Abuse** (`graphql_abuse.py`) — Introspection exposure and query-depth control checks
14. **JWT Checks** (`jwt_checks.py`) — Static JWT weakness checks (`alg=none`, suspicious `kid`, missing `exp`)
15. **Host Header Injection** (`host_header.py`) — Host/X-Forwarded-Host reflection and poisoning indicators
16. **CORS Misconfiguration** (`cors_misconfig.py`) — Overly permissive origin/credential policy detection
17. **HTTP Parameter Pollution** (`hpp.py`) — Duplicate parameter ambiguity checks
18. **CRLF Injection** (`crlf_injection.py`) — Response splitting/header injection probes
19. **Request Smuggling** (`request_smuggling.py`) — TE/CL framing discrepancy heuristic probes
20. **Mass Assignment/BOLA** (`mass_assignment.py`) — Privileged field injection and object-reference authorization drift checks
21. **Insecure Deserialization** (`insecure_deserialization.py`) — Serialized payload error/behavioral probes for unsafe deserialization paths
22. **Prototype Pollution** (`prototype_pollution.py`) — Prototype-key probes (`__proto__`, `constructor.prototype`) with baseline/follow-up drift checks
23. **CSV/Formula Injection** (`csv_formula_injection.py`) — Formula-prefixed value probes (`=`, `+`, `-`, `@`) against export/report surfaces

### Stage 6: CVSS Scoring (85% progress)
- `enrich_findings()` in `scorer.py` computes CVSS v3.1 scores
- Assigns severity: Critical (9.0–10.0), High (7.0–8.9), Medium (4.0–6.9), Low (0.1–3.9)
- Sorts findings by severity (Critical first)
- Maps to OWASP 2025 categories
- Maps to MITRE ATT&CK techniques (with confidence scoring)

### Stage 7: Report Generation (90→100% progress)
- `export_json()` generates 3 JSON files:
  - `findings.json` — Full structured report with all metadata
  - `findings_executive.json` — Executive summary with counts, risk rating, top issues
  - `findings_technical.json` — Grouped by OWASP category with detailed evidence
- Stores results in in-memory scan store (web) or writes to disk (CLI)
- Final status: `completed`, `failed`, or `cancelled`

---

## 5. Core Modules

### `scanner/core/recon.py`
- **Purpose**: DNS reconnaissance and domain intelligence
- **Functions**: `dns_lookup(domain)` performs A/AAAA/MX/NS/TXT/SOA lookups, `run_recon(hostname)` orchestrates full recon including WHOIS
- **Subdomain Enumeration**: Brute-force with built-in wordlist against the target domain
- **Dependencies**: dnspython, python-whois

### `scanner/core/port_scanner.py`
- **Purpose**: Network port and service discovery
- **Function**: `scan_ports(target, ports, arguments)` wraps Nmap
- **Output**: `{ open_ports: [...], services: {...}, os_guess: str }`
- **Dependencies**: python-nmap (requires Nmap installed)

### `scanner/core/fingerprint.py`
- **Purpose**: Technology stack identification
- **Detection Methods**: HTTP response headers, HTML body content signatures, SSL/TLS certificate analysis
- **WAF Detection**: Signature-based identification of common WAFs
- **Output**: `{ server, technologies: [...], waf: str|None, ssl_info: {...} }`

### `scanner/core/crawler.py`
- **Purpose**: Static HTTP web crawler
- **Output**: `CrawlResult` dataclass with `.endpoints`, `.forms`, `.parameters`, `.api_endpoints`
- **Form Extraction**: Parses `<form>` elements with field names, types, and actions
- **API Route Detection**: Finds `/api/`, REST-like patterns in HTML/JS
- **Respects**: robots.txt (advisory), URL depth/page limits
- **Cancellation**: Supports cooperative stop via optional `should_stop` callback

### `scanner/core/selenium_crawler.py`
- **Purpose**: JavaScript-aware browser-based crawler
- **Advantages**: Renders SPAs, discovers dynamically loaded links, intercepts AJAX/XHR endpoints
- **Detection**: Regex on page source for API endpoints, event listener-bound URLs
- **Reuses**: Same `CrawlResult` class as static crawler
- **Browser**: Headless Chrome via Selenium WebDriver
- **Cancellation**: Supports cooperative stop via optional `should_stop` callback

### `scanner/core/scorer.py`
- **Purpose**: CVSS v3.1 scoring and severity enrichment
- **Function**: `enrich_findings(findings)` — adds `cvss_score`, `cvss_vector`, `severity`, `owasp_category`, `mitre_attack` to each finding
- **Self-contained**: Zero hard dependencies on external scoring services
- **MITRE integration**: Calls `enrich_findings_mitre()` from mitre_mapping.py

### `scanner/core/browser.py`
- **Purpose**: Shared Selenium browser setup utilities
- **Provides**: Chrome options configuration, WebDriver initialization, common browser operations

---

## 6. Vulnerability Modules

### `scanner/modules/sqli.py` — SQL Injection
- **Techniques**: Error-based, time-based blind, boolean-based blind
- **Payloads**: Predefined error patterns (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- **Tests**: All discovered endpoints + form parameters
- **Output**: Finding dict with `type: "sqli"`, `detail`, `payload`, `parameter`, `url`

### `scanner/modules/xss.py` — Cross-Site Scripting
- **Techniques**: Reflected, DOM-based, stored detection, template injection canary
- **Payloads**: Standard + encoded (HTML entity, URL-encoded, Unicode)
- **Output**: Finding with `type: "xss"`, subtype (reflected/dom/stored)

### `scanner/modules/headers.py` — Security Headers
- **Checks**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, CORS, Referrer-Policy, Permissions-Policy
- **Severity Mapping**: Each missing header has a pre-assigned severity level and CVSS vector
- **Output**: Finding per missing/misconfigured header

### `scanner/modules/ssrf.py` — Server-Side Request Forgery
- **Payloads**: localhost, 127.0.0.1, internal IPs, cloud metadata (169.254.169.254), Redis, Elasticsearch
- **Detection**: Checks response for access indicators (status codes, body content)
- **Output**: Finding with `type: "ssrf"`

### `scanner/modules/idor.py` — Insecure Direct Object Reference
- **Detection**: `_ID_PATTERN` regex finds paths like `/api/user/1001`
- **Method**: Attempts access to adjacent object IDs (±1, +100)
- **Output**: Finding when unauthorized access succeeds

### `scanner/modules/open_redirect.py` — Open Redirect
- **Payloads**: 7 variants — protocol bypass, path traversal, URL encoding, double encoding, data: URI, javascript: URI, backslash tricks
- **Detection**: Follows redirects and checks final destination
- **Output**: Finding with `type: "open_redirect"`

### `scanner/modules/command_injection.py` — OS Command Injection
- **Techniques**: Command separator payloads (`;`, `|`, `&&`) across URL and POST form parameters
- **Evidence model**: Requires response markers not present in baseline (numeric command outputs and command canaries)
- **Safety posture**: Uses non-destructive arithmetic/echo probes for confirmation
- **Output**: Finding with `title: OS Command Injection ...`, OWASP A05 mapping

### `scanner/modules/xxe.py` — XML External Entity (XXE)
- **Techniques**: XML `<!DOCTYPE ... <!ENTITY ... SYSTEM ...>>` payloads targeting common local file paths
- **Parameter targeting**: XML-like parameter names/values only (`xml`, `payload`, `import`, etc.)
- **Evidence model**: Requires file disclosure markers that differ from baseline response
- **Output**: Finding with `title: XXE ...`, OWASP A05 mapping

### `scanner/modules/lfi.py` — Local File Inclusion / Path Traversal
- **Techniques**: Query/form parameter replacement with traversal and absolute path payloads
- **Evidence model**: OS file markers (`root:x:0:0:`, `[fonts]`, `PATH=`) that are absent from baseline
- **Output**: High-severity finding with OWASP A01 mapping

### `scanner/modules/sensitive_files.py` — Sensitive File Exposure
- **Techniques**: Direct probing of common sensitive paths (`/.env`, `/.git/config`, `/backup.zip`, `/actuator/env`, etc.)
- **Evidence model**: HTTP 200 on sensitive paths and secret/config markers in response body
- **Output**: High-severity misconfiguration finding with OWASP A02 mapping

### `scanner/modules/nosqli.py` — NoSQL Injection
- **Techniques**: Boolean differential probes and error-marker probes for NoSQL backends
- **Heuristics**: Baseline/true/false similarity and size differentials to reduce noise
- **Output**: High-severity injection finding with OWASP A05 mapping

### `scanner/modules/ssti.py` — Server-Side Template Injection
- **Techniques**: Template expression payloads across likely rendered parameters
- **Evidence model**: Arithmetic/string marker evaluation visible in responses and absent from baseline
- **Output**: High-severity injection finding with OWASP A05 mapping

### `scanner/modules/graphql_abuse.py` — GraphQL Abuse Checks
- **Techniques**: Introspection query probing and nested/deep query control checks
- **Coverage**: Candidate endpoint detection from default paths + crawled endpoints
- **Output**: Medium/Low findings for exposed introspection or missing complexity controls (OWASP A06)

### `scanner/modules/jwt_checks.py` — JWT Static Security Checks
- **Techniques**: Token discovery from cookie/query/form inputs and offline header/claim inspection
- **Checks**: `alg=none`, suspicious `kid` path/URL patterns, missing `exp`
- **Output**: Auth-related findings with OWASP A07 mapping

### `scanner/modules/host_header.py` — Host Header Injection
- **Techniques**: Modified `Host` and `X-Forwarded-Host` probes against baseline response
- **Evidence model**: Payload reflection in body or redirect `Location`
- **Output**: Medium finding with OWASP A05 mapping

### `scanner/modules/cors_misconfig.py` — CORS Misconfiguration
- **Techniques**: Crafted `Origin` preflight checks
- **Evidence model**: Arbitrary-origin reflection and wildcard+credentials combinations
- **Output**: Medium/High misconfiguration findings with OWASP A02 mapping

### `scanner/modules/hpp.py` — HTTP Parameter Pollution
- **Techniques**: Duplicate parameter injection with behavioral comparison to baseline
- **Evidence model**: Status-code or response-size deltas under duplicated parameters
- **Output**: Medium injection finding with OWASP A05 mapping

### `scanner/modules/crlf_injection.py` — CRLF Injection
- **Techniques**: URL-encoded CRLF payload injection in query parameters
- **Evidence model**: Presence of injected/sentinel response headers
- **Output**: Medium injection finding with OWASP A05 mapping

### `scanner/modules/request_smuggling.py` — HTTP Request Smuggling (Heuristic)
- **Techniques**: Ambiguous `Content-Length` + `Transfer-Encoding` request framing probe
- **Evidence model**: Differential status behavior on TE/CL ambiguity requests
- **Output**: Medium injection finding with OWASP A05 mapping

### `scanner/modules/mass_assignment.py` — Mass Assignment / BOLA
- **Techniques**: Privileged-field injection into update forms plus object-ID mutation on query parameters
- **Evidence model**: Access/status/response-shape drift when sensitive fields or object references are manipulated
- **Output**: Medium/High access-control findings with OWASP A01 mapping

### `scanner/modules/insecure_deserialization.py` — Insecure Deserialization
- **Techniques**: Serialized payload probes (Java/PHP/Python/.NET style) against likely serialized parameters
- **Evidence model**: Deserializer-specific error markers or baseline→5xx transitions
- **Output**: High-severity integrity finding with OWASP A08 mapping

### `scanner/modules/sqli_selenium.py` — Browser-Based SQL Injection
- **Advantage**: Handles JS-rendered forms, CSRF tokens, client-side form validation
- **Evidence**: Auto-captures PNG screenshots of confirmed SQL injections
- **WAF Bypass**: Works through client-side WAF protections
- **Output**: Same as sqli.py plus `screenshot` field

### `scanner/modules/xss_selenium.py` — Browser-Based XSS
- **Technique**: Hooks `window.alert()` and `window.confirm()` via CDP to detect actual JS execution
- **DOM XSS**: Detects DOM-based XSS via real execution observation
- **Evidence**: Screenshots of confirmed XSS
- **Quick Mode**: Respects `quick` parameter to limit payload count
- **Output**: Same as xss.py plus `screenshot` field

---

## 7. Utility Modules

### `scanner/utils/logger.py`
- **Purpose**: Centralized logging with file + console output
- **Functions**: `setup_logger(log_dir)` creates timestamped log file, `get_logger(name)` returns named logger
- **Log Levels**: DEBUG to file, INFO to console
- **Output**: `scanner/logs/scan_YYYYMMDD_HHMMSS.log`

### `scanner/utils/report_exporter.py`
- **Purpose**: Generate structured JSON reports
- **Exports 3 files**:
  1. `findings.json` — Complete report with all stages, findings, metadata
  2. `findings_executive.json` — Summary: counts, risk rating, top issues, OWASP breakdown
  3. `findings_technical.json` — Grouped by OWASP category with detailed evidence per finding
- **OWASP 2025 Map**: Contains the full `OWASP_2025` dict (A01–A10)
- **Functions**: `export_json()`, `_build_summary()`, `_build_owasp_breakdown()`, `_build_affected_endpoints()`, `_assign_ids()`
- **Scanner Version**: Embedded as constant `SCANNER_VERSION = "1.2.0"`

### `scanner/utils/ai_engine.py`
- **Purpose**: Gemini AI threat intelligence with centralized prompt composition and key/model failover
- **Config Sources**: `PENTAVAULT_GEMINI_API_KEYS` (CSV), `GEMINI_API_KEY` (single fallback), `PENTAVAULT_GEMINI_MODELS` (CSV override)
- **Behavior**: Rotates across keys and models on recoverable API failures (429/503/404/401/403 and transient request errors)
- **Prompt Architecture**: Shared `_compose_prompt()` enforces common output rules (HTML-only, scan-anchored, non-generic) across threat analysis, remediation, MITRE explain, and executive summary generation

### `scanner/utils/mitre_mapping.py`
- **Purpose**: MITRE ATT&CK Enterprise v16.1 professional threat intelligence mapping
- **Coverage**: 47+ techniques across all 14 Enterprise tactics
- **Data Model**: Python dataclasses with enums (`Confidence`, `Platform`, `KillChainPhase`)
- **Per Technique**: ID, name, description, tactic, URL, detection guidance, mitigations (M-codes), platforms, data sources, kill-chain phases, severity weight, is_subtechnique flag
- **Mapping Rules**: 75+ vulnerability → technique rules with 3 confidence levels
- **Public API**:
  - `MITRE_TECHNIQUES` — Full technique database (dict)
  - `build_mitre_breakdown(findings)` — Group detected techniques by tactic with counts
  - `enrich_findings_mitre(findings)` — Add `mitre_attack` list to each finding
  - `build_attack_paths(findings)` — Construct kill-chain progression from correlated findings
  - `compute_matrix_coverage(findings)` — Calculate coverage statistics per tactic
  - `get_all_tactics()` — Return ordered list of all 14 ATT&CK tactics
- **Alignment**: STIX 2.1 object model

---

## 8. Web Dashboard & REST API

### Backend: `scanner/web/app.py`
- **Framework**: FastAPI with CORS middleware (allow all origins)
- **Static Files**: Mounted at `/static/` from `scanner/web/static/`
- **Scan Store**: In-memory dictionary `scans: dict[str, dict[str, Any]]` with file-backed persistence to `scanner/data/scan_history.json`
- **Persistence**: `_load_history()` on startup, `_save_history()` after each state change — atomic writes via temp file + `os.replace()` to prevent corruption
- **Background Execution**: `_run_scan()` runs in a daemon thread per scan
- **Models**:
  - `ScanRequest` (Pydantic): target, mode, cookie, threads (1–10), timeout (1–60), use_browser, crawl_mode (`auto|httpx|selenium|hybrid`)
  - `ScanStatus`: scan_id, status, target, mode, progress, current_stage, stages, started_at, elapsed, findings_count

### Frontend: Single-Page Application
- **Technology**: Vanilla HTML/CSS/JS (no frameworks)
- **Theme**: SOC Obsidian command-center theme with command rail + stage workspace
- **4 Tabs**: New Scan, History, OWASP 2025, MITRE ATT&CK
- **Live Timer**: Client-side interval timer (250ms tick) independent of API polling
- **Poll Interval**: 1 second during active scan
- **Total Time Display**: Prominent banner after scan completion showing status + duration
- **Mapping rendering resilience**: Request-token guards prevent stale async responses from overwriting newer MITRE/OWASP views during rapid tab/scan switches
- **Frontend mapping cache**: In-memory cache for OWASP reference, MITRE reference, and per-scan MITRE breakdown payloads to reduce redundant fetches
- **AI error UX contract**: Frontend AI calls use shared parsing compatible with both legacy string errors and structured backend `detail` objects; provider/config internals are sanitized from user-facing messages.
- **MITRE chart fallback strategy**: Primary renderer uses Three.js matrix scenes + interactive tactic strip/filtering. If 3D or motion is unavailable, UI falls back to readable static/empty-state components.

---

## 9. MITRE ATT&CK v16.1 Integration

### Architecture
- **Data Source**: Static database in `mitre_mapping.py` (no external API calls)
- **14 Enterprise Tactics**: TA0043 (Reconnaissance) through TA0040 (Impact)
- **47+ Techniques** with full metadata per technique
- **Confidence Scoring**: HIGH / MEDIUM / LOW per vulnerability→technique mapping
- **Kill Chain Mapping**: Each technique maps to Lockheed Martin phases

### Tactic Coverage

| ID | Tactic | Description |
|---|---|---|
| TA0043 | Reconnaissance | Gathering information for targeting |
| TA0042 | Resource Development | Establishing resources for operations |
| TA0001 | Initial Access | Getting into the network |
| TA0002 | Execution | Running attacker-controlled code |
| TA0003 | Persistence | Maintaining foothold |
| TA0004 | Privilege Escalation | Gaining higher-level permissions |
| TA0005 | Defense Evasion | Avoiding detection |
| TA0006 | Credential Access | Stealing credentials |
| TA0007 | Discovery | Exploring the environment |
| TA0008 | Lateral Movement | Moving through the network |
| TA0009 | Collection | Gathering data of interest |
| TA0011 | Command and Control | Communicating with compromised systems |
| TA0010 | Exfiltration | Stealing data |
| TA0040 | Impact | Manipulation, disruption, destruction |

### Web UI Components
- **Matrix Coverage Scene + Strip**: Primary MITRE coverage view uses an interactive Three.js tactic matrix scene synchronized with a clickable tactic strip (counts + coverage). If 3D is unavailable, mapping feedback and static fallback messaging remain available.
- **Technique Breakdown Bars**: Grouped by tactic, bar chart with confidence dots + interactive filters (tactic, confidence, search, clear)
- **Attack Path Visualization**: Responsive, collapsible vertical timeline of kill-chain phases with severity markers, per-phase finding lists, and progression connectors.
- **Technique Reference Panel**: Expandable cards with search + expand/collapse-all controls and keyboard-accessible card toggles
- **Modal Detail**: Full MITRE metadata per finding in click-to-expand modal
- **Mapping UX states**: Explicit loading, error, and empty-state UI for MITRE/OWASP sections with retry affordances

---

## 10. OWASP 2025 Top 10 Integration

### Category Map (from `report_exporter.py`)

| ID | Category |
|---|---|
| A01:2025 | Broken Access Control |
| A02:2025 | Security Misconfiguration |
| A03:2025 | Software Supply Chain Failures |
| A04:2025 | Cryptographic Failures |
| A05:2025 | Injection |
| A06:2025 | Insecure Design |
| A07:2025 | Authentication Failures |
| A08:2025 | Software & Data Integrity Failures |
| A09:2025 | Security Logging & Alerting Failures |
| A10:2025 | Mishandling of Exceptional Conditions |

### Integration Points
- Each finding gets `owasp_category` assigned during CVSS scoring
- Web UI shows OWASP breakdown horizontal bar chart per scan
- Reference panel tab shows all categories
- Executive report groups findings by OWASP category
- API endpoint: `GET /api/owasp` returns the full map

---

## 11. CVSS v3.1 Scoring

- **Engine**: `scanner/core/scorer.py`
- **Function**: `enrich_findings(findings)` processes all findings
- **Assignment**: Each finding gets `cvss_score` (float), `cvss_vector` (string), `severity` (string)
- **Severity Classification**:
  - Critical: 9.0 – 10.0
  - High: 7.0 – 8.9
  - Medium: 4.0 – 6.9
  - Low: 0.1 – 3.9
  - None: 0.0
- **Sorting**: Findings sorted Critical → High → Medium → Low → None
- **Enrichment Chain**: CVSS → OWASP category → MITRE ATT&CK mapping

---

## 12. Selenium Browser Engine

### When Used
- Web dashboard: "Use Selenium Browser Engine" toggle
- CLI: `--browser` flag (headless) or `--headed` flag (visible)

### Architecture
- `selenium_crawler.py` — Replaces static crawler for JavaScript-rendered pages
- `sqli_selenium.py` — Replaces sqli.py for more accurate form testing
- `xss_selenium.py` — Replaces xss.py with alert() hook detection
- `browser.py` — Shared Chrome options and WebDriver setup
- `dependency_check.py` — Runtime preflight checks for nmap/browser/node capabilities

### Features
- **Headless Chrome** via ChromeDriver (auto-managed by webdriver-manager)
- **CDP Protocol**: Chrome DevTools Protocol for `alert()`/`confirm()` hooking
- **Screenshot Evidence**: Auto-captures PNG evidence for confirmed vulnerabilities (stored in `scanner/evidence/`)
- **CSRF Token Handling**: Browser can handle dynamic CSRF tokens in forms
- **SPA Support**: Crawls JavaScript-generated content
- **Resource Limits**: Reduced browser capabilities for stability (images disabled, etc.)
- **Sandbox Policy**: Chrome sandbox remains enabled by default; set `PENTAVAULT_ALLOW_NO_SANDBOX=1` only in constrained environments where sandbox startup fails

### Execution Model
- HTTP modules (`headers`, `ssrf`, `idor`, `open_redirect`) run concurrently in thread pool
- Browser modules (`sqli_selenium`, `xss_selenium`) run **sequentially** due to Chrome resource constraints
- Each browser module has a hard timeout (120s quick / 180s full)

---

## 13. Configuration & Limits

### Thread Limits
| Location | Max | Default | Enforcement |
|---|---|---|---|
| Web API (Pydantic) | 10 | 5 | `Field(ge=1, le=10)` — returns 422 if exceeded |
| Web UI (HTML) | 10 | 5 | `<input max="10">` — browser-side |
| Web UI (JS) | 10 | 5 | Clamped with alert on exceed |
| CLI | 10 | 5 | Clamped with warning log message |

### Timeout Limits
| Parameter | Range | Default | Purpose |
|---|---|---|---|
| Per-request timeout | 1–60s | 10s | HTTP request timeout |
| Module timeout | Fixed 300s | 300s | Per vulnerability module execution |
| Browser module timeout | Fixed 120/180s | 120s (quick) | Per Selenium module |

### Crawl Limits
| Parameter | Quick | Full |
|---|---|---|
| Max depth | 2 | 3 |
| Max pages | 50 | 200 |

---

## 14. Data Flow & Finding Model

### Finding Dictionary Structure
Each vulnerability finding is a Python dict with these fields:

```python
{
    "id": "PVAULT-001",               # Auto-assigned sequential ID
    "type": "sqli",                    # Module type (sqli, xss, headers, ssrf, idor, open_redirect)
    "module": "SQLi",                  # Human-readable module name
    "severity": "High",               # Critical / High / Medium / Low / None
    "cvss_score": 8.6,                # CVSS v3.1 numeric score
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    "url": "https://target.com/page", # Affected URL
    "path": "/page",                  # URL path
    "parameter": "id",                # Vulnerable parameter
    "payload": "' OR 1=1--",          # Attack payload used
    "detail": "Error-based SQL injection found",
    "evidence": "MySQL syntax error detected in response",
    "recommendation": "Use parameterized queries",
    "owasp_category": "A03:2025 - Injection",
    "mitre_attack": [                  # List of MITRE ATT&CK mappings
        {
            "technique": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "url": "https://attack.mitre.org/techniques/T1190/",
            "confidence": "high",
            "detection": "Monitor for unusual web traffic...",
            "mitigations": ["M1048 - Application Isolation", ...],
            "platforms": ["Linux", "Windows", "macOS"],
            "data_sources": ["Application Log", "Network Traffic"],
            "kill_chain": ["Delivery", "Exploitation"],
            "severity_weight": 9.0
        }
    ],
    "mitre_kill_chain": ["Delivery", "Exploitation"],
    "screenshot": "evidence/evidence_sqli_error__page_id.png"  # Optional, browser mode only
}
```

### Data Flow

```
Target URL/IP
    │
    ▼
[Recon Module] ───► recon_data dict
    │
    ▼
[Fingerprint Module] ───► fingerprint_data dict
    │
    ▼
[Crawler / Selenium Crawler] ───► CrawlResult (endpoints, forms, params)
    │
    ▼
[Vulnerability Modules x21] ───► raw findings[] (list of dicts)
    │
    ▼
[CVSS Scorer + Enrichment] ───► enriched findings[] (with severity, OWASP, MITRE)
    │
    ▼
[Report Exporter] ───► 3 JSON files (standard, executive, technical)
    │
    ▼
[Web API Response / CLI Output]
```

---

## 15. Report Generation

### Three Report Variants

1. **Standard Report** (`findings.json` / `scan_{id}.json`)
   - Full structured report with all scan metadata
   - All findings with complete detail
   - Recon data, fingerprint data, crawl summary
   - OWASP and MITRE breakdowns

2. **Executive Report** (`findings_executive.json` / `scan_{id}_executive.json`)
   - Summary counts by severity
   - Overall risk rating
   - Top issues list
   - OWASP category breakdown
   - Suitable for non-technical stakeholders

3. **Technical Report** (`findings_technical.json` / `scan_{id}_technical.json`)
   - Findings grouped by OWASP category
   - Detailed evidence per finding
   - Per-endpoint vulnerability view
   - Full payloads and reproduction steps

### Report Metadata
- Scanner version (1.2.0)
- Scan date/time
- Target URL
- Scan mode
- Total finding counts by severity

---

## 16. Logging System

- **Module**: `scanner/utils/logger.py`
- **Log Directory**: `scanner/logs/`
- **File Format**: `scan_YYYYMMDD_HHMMSS.log`
- **Console**: INFO level and above
- **File**: DEBUG level and above
- **Named Loggers**: Each module uses `get_logger("module_name")` for prefixed output

---

## 17. Concurrency & Threading

### CLI Mode
- `ThreadPoolExecutor(max_workers=threads)` in `main.py`
- In HTTP mode, all 23 vulnerability modules are submitted as futures
- `as_completed()` for progress tracking

### Web Mode
- Background scan thread: `threading.Thread(target=_run_scan, daemon=True)`
- HTTP modules: `ThreadPoolExecutor(max_workers=req.threads)` in parallel
- Browser modules: Sequential execution (due to Chrome resource constraints)
- Progress updates: Atomic dict writes (Python GIL protects simple assignments)
- Polling: Frontend polls `GET /api/scan/{id}` every 1 second

### Thread Safety
- `scans` dict: Shared between request handlers and background threads
- Simple dict assignments are atomic under GIL
- No explicit locks needed for progress updates

---

## 18. Timeout & Hang Prevention

### Problem Solved
Selenium browser modules could hang indefinitely, causing the scan to freeze at ~70%.

### Solution: `_run_module_with_timeout()`
- Wraps module execution in a **daemon thread**
- `thread.join(timeout=timeout_sec)` — waits up to the timeout
- If thread is still alive after timeout:
  - Logs warning
  - Forcefully kills `chromedriver.exe` and `chrome.exe` via `taskkill /F /IM ... /T`
  - Returns empty results (scan continues)
- Error container pattern: captures exceptions from the worker thread

### Timeout Values
- HTTP modules: No explicit timeout (rely on per-request timeout)
- Browser modules: 120s (quick mode) / 180s (full mode)
- Chrome kill: `subprocess.run(["taskkill", ...], capture_output=True, timeout=10)`

---

## 19. Deduplication

- Findings are deduplicated before scoring/export
- Dedup key: combination of `type`, `url`, `parameter`, `payload`
- Prevents duplicate findings from overlapping module tests

---

## 20. CLI Interface

### Entry Point: `scanner/main.py`
- Uses `argparse` for argument parsing
- Banner displayed on startup: ASCII art with version info
- Legal disclaimer: "For authorized VAPT engagements only"

### Arguments
| Argument | Type | Default | Choices | Description |
|---|---|---|---|---|
| `--target` | str | required | — | URL or IP to scan |
| `--mode` | str | `full` | quick, full, web-only, network-only | Scan mode |
| `--threads` | int | 5 | 1–10 (clamped) | Concurrent threads |
| `--timeout` | float | 10.0 | — | Per-request timeout |
| `--request-delay` | float | 0.0 | 0.0–2.0 | Delay between crawler requests/navigation |
| `--cookie` | str | None | — | Session cookie |
| `--browser` | flag | False | — | Headless Selenium |
| `--crawl-mode` | str | `auto` | auto, httpx, selenium, hybrid | Crawler strategy |
| `--headed` | flag | False | — | Visible browser (implies --browser) |
| `--output` | str | `findings.json` | — | Output JSON path |

### Exit: Prints summary with finding counts by severity and total execution time.

---

## 21. Web Dashboard UI Details

### Tab Structure
1. **New Scan** — Scan form + live progress + results dashboard
2. **History** — All past scans with view/cancel/delete actions
3. **OWASP 2025** — Reference panel showing all categories
4. **MITRE ATT&CK** — Reference panel with tactic overview cards and expandable technique cards

### Progress Card (visible during scan)
- Stage name indicator
- Percentage progress bar (animated gradient fill)
- **Live timer**: Client-side `setInterval` at 250ms, format `Xh XXm XXs` / `Xm XXs` / `Xs`
- Findings counter
- Stage timeline chips (completed stages with duration)
- **Total time display**: Appears after completion — color-coded by status (green=completed, red=failed, yellow=cancelled)

### Results Dashboard (shown after scan)
- **Mission Control**: Live stage feed + live finding stream + 3D progress engine with checkpoint pulse/audio cue toggle
- **Runtime Behavior Cards**: “Runtime Behavior” + “Execution Settings” blocks show effective mode, threads, timeout, request delay, crawl resolution, HTTP worker model, and browser timeout budget.
- **Severity Ring**: D3 radial severity visualization with animated counters
- **OWASP Treemap**: D3 treemap with click-to-filter behavior wired to findings table
- **MITRE ATT&CK Coverage**:
  - Matrix summary stats (tactics/techniques/coverage%)
  - Interactive Three.js tactic matrix scene synchronized with tactic strip filtering
  - Technique cloud pills and grouped breakdown rows with confidence markers
  - Resilient loading/error/empty states for mapping requests
- **Attack Path Analysis**: Three.js attack node graph + phase timeline controls with hover/highlight linking
- **AI Intelligence Cards**: Threat analysis, executive summary, modal remediation, and MITRE explainer panel with sanitized error UX
- **Export Buttons**: JSON / CSV / TXT + PDF + DOCX download
- **Findings Table**: Virtualized chunk rendering with text/severity filters and detail modal
- **Finding Modal**: CVSS gauge + MITRE cards + remediation generation in context
- **Scan Stages**: Timing bar chart per pipeline stage

### Design System
- **Theme**: SOC Obsidian command-center shell (command rail + stage workspace)
- **Visual language**: Glass cards, depth layers, neon signal accents, and motion-safe transitions
- **Typography**: Syne (display), DM Sans (body), JetBrains Mono (telemetry)
- **Severity Colors**: Critical (#ff1f4b), High (#ff6b35), Medium (#f5a623), Low (#00ff9d), Info (#4fa5ff)
- **Responsive**: Rail-and-panel layout adapts across desktop/tablet/mobile breakpoints
- **Reduced-motion support**: 3D scenes degrade to static fallback cards when motion reduction is requested

### History Panel
- Table: ID, Target, Mode, Status (badge), Findings count, Started At, Actions
- Actions: View (loads results), Cancel (if running), Delete
- View: Switches to Scan tab and loads results or starts polling if still running

---

## 22. REST API Endpoint Reference

### `POST /api/scan`
- **Body**: `ScanRequest` — `{ target, mode, threads, timeout, cookie, use_browser }`
- **Response**: `{ scan_id, status: "started" }`
- **Action**: Launches background scan thread

### `GET /api/scan/{scan_id}`
- **Response**: Full scan state including progress, current_stage, stages, elapsed, findings, summary, error, plus additive `runtime_config` and `execution_metadata`
- **Used For**: Polling during scan and showing effective runtime behavior settings in UI

### `GET /api/scan/{scan_id}/findings`
- **Response**: `{ findings: [...] }`

### `GET /api/scan/{scan_id}/mitre`
- **Response**: `{ target, threat_narrative, mitre_breakdown, attack_paths, matrix_coverage }`
- **Behavior**: Uses deterministic per-scan cache key derived from findings signature; recomputes only when findings change

### `GET /api/scans`
- **Response**: List of all scans (most recent first) with summary info

### `DELETE /api/scan/{scan_id}`
- **Response**: `{ deleted: true }`

### `POST /api/scan/{scan_id}/cancel`
- **Response**: `{ cancelled: true/false }`
- **Action**: Sets `_cancel` flag checked by `_run_scan()`

### `GET /api/owasp`
- **Response**: OWASP 2025 category map

### `GET /api/mitre`
- **Response**: Full MITRE technique database with metadata

### `GET /api/mitre/tactics`
- **Response**: Ordered list of 14 ATT&CK Enterprise tactics

### `GET /api/evidence/{filename}`
- **Response**: PNG screenshot file
- **Security**: Path traversal prevention via `Path(filename).name`

### `POST /api/ai/analyze`
- **Body**: `{ scan_id }`
- **Response (success)**: `{ analysis: "..." }`
- **Behavior**: Generates threat analysis from scan findings + MITRE coverage; uses deterministic per-scan cache key to avoid duplicate model calls for identical scan state
- **Error contract**: On failure returns structured FastAPI `detail` object `{ code, message, retryable }` with sanitized, user-safe messages

### `POST /api/ai/remediate`
- **Body**: `{ scan_id, finding_index }`
- **Response (success)**: `{ remediation: "..." }`
- **Behavior**: Generates per-finding remediation guidance; cache key includes finding index + finding payload signature
- **Error contract**: Uses the same structured/sanitized AI error `detail` object

### `POST /api/ai/executive-summary`
- **Body**: `{ scan_id }`
- **Response (success)**: `{ summary: "..." }`
- **Behavior**: Generates executive summary and caches it; also stores in `scan["_ai_executive_summary"]` for PDF/DOCX reuse
- **Error contract**: Uses the same structured/sanitized AI error `detail` object

### `POST /api/ai/mitre-explain`
- **Body**: `{ scan_id, technique_id, technique_name, tactic, question }`
- **Response (success)**: `{ explanation: "..." }`
- **Behavior**: Generates MITRE technique explainer in scan context; cache key includes normalized question text and findings signature
- **Error contract**: Uses the same structured/sanitized AI error `detail` object

---

## 23. File-by-File Reference

| File | Lines (approx) | Purpose |
|---|---|---|
| `scanner/__init__.py` | ~1 | Package marker |
| `scanner/main.py` | ~300 | CLI entry point with full pipeline |
| `scanner/requirements.txt` | ~17 | pip dependency list |
| `scanner/core/__init__.py` | ~1 | Package marker |
| `scanner/core/recon.py` | ~150 | DNS, subdomain, WHOIS |
| `scanner/core/port_scanner.py` | ~80 | Nmap wrapper |
| `scanner/core/fingerprint.py` | ~200 | Tech stack, WAF, SSL |
| `scanner/core/crawler.py` | ~250 | Static HTTP crawler |
| `scanner/core/selenium_crawler.py` | ~200 | Browser crawler |
| `scanner/core/scorer.py` | ~200 | CVSS scoring + enrichment |
| `scanner/core/browser.py` | ~80 | Shared Selenium utilities |
| `scanner/modules/__init__.py` | ~1 | Package marker |
| `scanner/modules/sqli.py` | ~200 | SQL injection detection |
| `scanner/modules/xss.py` | ~200 | XSS detection |
| `scanner/modules/headers.py` | ~100 | Security header analysis |
| `scanner/modules/ssrf.py` | ~120 | SSRF detection |
| `scanner/modules/idor.py` | ~100 | IDOR detection |
| `scanner/modules/open_redirect.py` | ~100 | Open redirect detection |
| `scanner/modules/command_injection.py` | ~210 | OS command injection detection |
| `scanner/modules/xxe.py` | ~200 | XXE detection |
| `scanner/modules/lfi.py` | ~190 | Local file inclusion/path traversal detection |
| `scanner/modules/sensitive_files.py` | ~110 | Sensitive file exposure detection |
| `scanner/modules/nosqli.py` | ~280 | NoSQL injection detection |
| `scanner/modules/ssti.py` | ~170 | SSTI detection |
| `scanner/modules/graphql_abuse.py` | ~110 | GraphQL abuse checks |
| `scanner/modules/jwt_checks.py` | ~140 | JWT static security checks |
| `scanner/modules/host_header.py` | ~90 | Host header injection checks |
| `scanner/modules/cors_misconfig.py` | ~90 | CORS misconfiguration checks |
| `scanner/modules/hpp.py` | ~110 | HTTP parameter pollution checks |
| `scanner/modules/crlf_injection.py` | ~90 | CRLF injection checks |
| `scanner/modules/request_smuggling.py` | ~80 | Request smuggling heuristic checks |
| `scanner/modules/mass_assignment.py` | ~260 | Mass assignment/BOLA heuristic checks |
| `scanner/modules/insecure_deserialization.py` | ~290 | Insecure deserialization heuristic checks |
| `scanner/modules/prototype_pollution.py` | ~250 | Prototype pollution heuristic checks |
| `scanner/modules/csv_formula_injection.py` | ~260 | CSV/formula injection heuristic checks |
| `scanner/modules/sqli_selenium.py` | ~250 | Browser SQLi with evidence |
| `scanner/modules/xss_selenium.py` | ~250 | Browser XSS with alert hooks |
| `scanner/utils/__init__.py` | ~1 | Package marker |
| `scanner/utils/logger.py` | ~50 | Logging setup |
| `scanner/utils/report_exporter.py` | ~200 | Report generation |
| `scanner/utils/mitre_mapping.py` | ~800 | MITRE ATT&CK mapping engine |
| `scanner/web/app.py` | ~515 | FastAPI backend |
| `scanner/web/static/index.html` | ~245 | Dashboard HTML |
| `scanner/web/static/style.css` | ~1900 | SOC Obsidian design system CSS (rail/stage layout, glass cards, responsive + motion fallback) |
| `scanner/web/static/app.js` | ~3000 | Frontend interaction engine (scan lifecycle, AI UX, D3 + Three.js scene controllers) |

---

## 24. Dependencies

### Python Packages (requirements.txt)

| Package | Version | Purpose |
|---|---|---|
| httpx | ≥0.27.0 | Async HTTP client |
| requests | ≥2.31.0 | HTTP client (sync) |
| beautifulsoup4 | ≥4.12.0 | HTML parsing |
| dnspython | ≥2.6.0 | DNS resolution |
| python-nmap | ≥0.7.1 | Nmap wrapper |
| scapy | ≥2.5.0 | Network analysis |
| python-whois | ≥0.9.4 | WHOIS lookups |
| cvss | ≥3.1 | CVSS scoring |
| selenium | ≥4.20.0 | Browser automation |
| webdriver-manager | ≥4.0.0 | ChromeDriver management |
| fastapi | ≥0.111.0 | Web framework |
| uvicorn[standard] | ≥0.29.0 | ASGI server |

### System Dependencies
- **Python 3.13+**: Required runtime
- **Nmap**: Optional but recommended; scans continue with warnings when unavailable
- **Google Chrome / Chromium / Edge**: Required for Selenium browser mode
- **ChromeDriver / EdgeDriver**: Required for Selenium browser mode
- **Node.js**: Required for DOCX report export

---

## 25. Known Considerations

1. **Scan Store**: In-memory dictionary backed by JSON file persistence (`scanner/data/scan_history.json`). Atomic writes prevent corruption.
2. **Single Instance**: Web dashboard runs on one port (8000) — no multi-instance/load balancing.
3. **Chrome Processes**: Browser mode may leave orphaned Chrome processes on crash — `_run_module_with_timeout` handles cleanup via taskkill.
4. **Windows-Specific**: `taskkill` command is Windows-only. Cross-platform would need `os.kill()` or `psutil`.
5. **Rate Limiting**: No built-in rate limiting to target — high thread counts may trigger target WAF/IDS.
6. **Scan Cancellation**: Uses `_cancel` stage checks plus module/crawler `should_stop` checkpoints for more responsive cancellation with partial-result returns.
7. **CORS**: API allows all origins (`allow_origins=["*"]`) — suitable for local development, not production deployment.
8. **Authentication**: No dashboard authentication — anyone with network access to port 8000 can run scans.
9. **Evidence Storage**: Screenshots stored on disk with no auto-cleanup.
10. **Legal**: Tool is for authorized security testing only. Unauthorized use is illegal.

---

## 26. Author & License

- **Author**: Govind V Kartha
- **Copyright**: © 2026 Govind V Kartha. All rights reserved.
- **License**: Proprietary
- **Project**: PentaVault — Automated VAPT Security Suite v1.2.0
- **Tagline**: PentaVault — Automated VAPT Security Suite

---

*This document is the single source of truth for the PentaVault project architecture, implementation details, and technical specifications.*
