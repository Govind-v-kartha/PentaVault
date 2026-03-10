<p align="center">
  <img src="https://img.shields.io/badge/Python-3.13-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.111+-009688?logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/Selenium-4.20+-43B02A?logo=selenium&logoColor=white" />
  <img src="https://img.shields.io/badge/License-Proprietary-red" />
</p>

# 🛡️ PentaVault — Automated VAPT Security Suite

**PentaVault** is a professional-grade **Vulnerability Assessment and Penetration Testing (VAPT)** tool that automates the full security scanning pipeline — from reconnaissance to report generation. It features a modern dark-themed web dashboard, MITRE ATT&CK v16.1 integration, OWASP 2025 Top 10 mapping, and optional Selenium-based browser engine for deep JS-rendered vulnerability testing.

> **© 2026 Govind V Kartha. All rights reserved.**

---

## ✨ Key Features

| Category | Details |
|---|---|
| **7-Stage Pipeline** | Target Input → Recon → Fingerprint → Crawl → Attack → CVSS Score → Export |
| **Scan Modes** | `quick`, `full`, `web-only`, `network-only` |
| **Web Vulnerability Modules** | SQL Injection, XSS, Security Headers, SSRF, IDOR, Open Redirect |
| **Browser Engine** | Optional Selenium headless/headed Chrome for JS-heavy apps |
| **MITRE ATT&CK v16.1** | 47 techniques across all 14 Enterprise tactics with confidence scoring, attack path analysis, and matrix coverage heatmap |
| **OWASP 2025 Top 10** | Full A01–A10 category mapping for every finding |
| **CVSS v3.1 Scoring** | Automatic severity scoring with vector strings |
| **Web Dashboard** | FastAPI-powered dark-themed single-page app with live progress, history, filters, modal details |
| **Export Formats** | JSON, CSV, TXT — standard, executive, and technical report variants |
| **Evidence Capture** | Screenshot-based proof for browser-detected vulnerabilities |

---

## 🏗️ Architecture

```
c:\Project 1\
├── scanner/
│   ├── main.py                  # CLI entry point
│   ├── requirements.txt         # Python dependencies
│   ├── __init__.py
│   │
│   ├── core/                    # Pipeline stage engines
│   │   ├── recon.py             # DNS lookup, subdomain enumeration, WHOIS
│   │   ├── port_scanner.py      # Nmap port/service discovery
│   │   ├── fingerprint.py       # Tech stack, WAF, SSL/TLS analysis
│   │   ├── crawler.py           # Static HTTP crawler
│   │   ├── selenium_crawler.py  # Browser-based crawler (SPA/JS support)
│   │   ├── scorer.py            # CVSS v3.1 severity scoring
│   │   └── browser.py           # Shared Selenium browser utilities
│   │
│   ├── modules/                 # Vulnerability testing modules
│   │   ├── sqli.py              # SQL Injection (error, time-blind, boolean)
│   │   ├── xss.py               # Cross-Site Scripting (reflected, DOM, stored)
│   │   ├── headers.py           # Security header analysis
│   │   ├── ssrf.py              # Server-Side Request Forgery
│   │   ├── idor.py              # Insecure Direct Object Reference
│   │   ├── open_redirect.py     # Open Redirect detection
│   │   ├── sqli_selenium.py     # Browser-based SQLi with screenshots
│   │   └── xss_selenium.py      # Browser-based XSS with alert() hook
│   │
│   ├── utils/                   # Support modules
│   │   ├── logger.py            # File + console logging
│   │   ├── report_exporter.py   # JSON/executive/technical report generation
│   │   └── mitre_mapping.py     # MITRE ATT&CK v16.1 mapping engine
│   │
│   ├── web/                     # Web Dashboard
│   │   ├── app.py               # FastAPI REST API backend
│   │   └── static/
│   │       ├── index.html       # Dashboard HTML
│   │       ├── style.css        # Dark theme CSS
│   │       └── app.js           # Dashboard JavaScript
│   │
│   ├── reports/                 # Generated JSON reports (auto-created)
│   ├── evidence/                # Screenshot evidence (auto-created)
│   └── logs/                    # Scan log files (auto-created)
│
└── README.md
```

---

## 🚀 Installation

### Prerequisites

- **Python 3.13+**
- **Nmap** — installed and in PATH ([https://nmap.org/download.html](https://nmap.org/download.html))
- **Google Chrome** — required only for Selenium browser mode

### Setup

```bash
# Clone the repository
cd "c:\Project 1"

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -r scanner/requirements.txt
```

---

## 📖 Usage

### Web Dashboard (Recommended)

```bash
python -m scanner.web.app
```

Open **http://127.0.0.1:8000** in a browser. The dashboard provides:
- Scan configuration form (target, mode, threads, timeout, cookies, browser toggle)
- Live progress bar with real-time timer
- Total elapsed time after scan completion
- Severity breakdown (Critical / High / Medium / Low / Info)
- OWASP 2025 category bars
- MITRE ATT&CK matrix heatmap, technique breakdown, attack path analysis
- Findings table with filtering, click-to-expand detail modal
- Export buttons (JSON / CSV / TXT)
- Scan history with view / cancel / delete

### CLI Mode

```bash
cd scanner

# Quick scan
python main.py --target https://example.com --mode quick

# Full scan with all stages
python main.py --target https://example.com --mode full --threads 5

# Web-only with Selenium browser engine
python main.py --target https://example.com --mode web-only --browser

# Network recon only
python main.py --target 192.168.1.1 --mode network-only

# Full options
python main.py \
  --target https://example.com \
  --mode full \
  --threads 5 \
  --timeout 10 \
  --cookie "session=abc123" \
  --browser \
  --output findings.json
```

### CLI Arguments

| Argument | Default | Description |
|---|---|---|
| `--target` | *(required)* | URL or IP address to scan |
| `--mode` | `full` | `quick`, `full`, `web-only`, `network-only` |
| `--threads` | `5` | Concurrent threads (max: 10) |
| `--timeout` | `10` | Per-request timeout in seconds |
| `--cookie` | `None` | Session cookie for authenticated scans |
| `--browser` | `off` | Use Selenium headless Chrome |
| `--headed` | `off` | Show browser window (implies `--browser`) |
| `--output` | `findings.json` | Output JSON report path |

---

## 🔒 Scan Pipeline

| Stage | Description |
|---|---|
| **1. Target Input** | URL/IP normalisation and validation |
| **2. Reconnaissance** | DNS lookup, subdomain enumeration, WHOIS, Nmap port/service scan, OS fingerprinting |
| **3. Fingerprinting** | Technology stack detection, WAF identification, SSL/TLS certificate analysis |
| **4. Web Crawling** | Endpoint discovery, form extraction, parameter collection, JS API route detection |
| **5. Vulnerability Testing** | Concurrent module execution: SQLi, XSS, Headers, SSRF, IDOR, Open Redirect |
| **6. CVSS Scoring** | CVSS v3.1 scoring, severity classification, OWASP 2025 + MITRE ATT&CK mapping |
| **7. Report Generation** | JSON reports (standard, executive, technical) with full metadata |

---

## 🗺️ MITRE ATT&CK Integration

PentaVault maps findings to **MITRE ATT&CK Enterprise v16.1** with:

- **47 techniques** across all **14 tactics** (Reconnaissance through Impact)
- **3 confidence levels**: High, Medium, Low
- Per-technique metadata: detection guidance, mitigations (M-codes), platforms, data sources, kill-chain phases
- **Attack path analysis**: Kill-chain progression from detected vulnerabilities
- **Matrix coverage heatmap**: Visual tactic/technique coverage overview
- Expandable technique reference cards with full detail

---

## 📊 OWASP 2025 Top 10

All findings are categorised against the **OWASP Top 10:2025** framework:

| ID | Category |
|---|---|
| A01:2025 | Broken Access Control |
| A02:2025 | Cryptographic Failures |
| A03:2025 | Injection |
| A04:2025 | Insecure Design |
| A05:2025 | Security Misconfiguration |
| A06:2025 | Vulnerable and Outdated Components |
| A07:2025 | Identification and Authentication Failures |
| A08:2025 | Software and Data Integrity Failures |
| A09:2025 | Security Logging and Monitoring Failures |
| A10:2025 | Server-Side Request Forgery (SSRF) |

---

## 🌐 REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Dashboard page |
| `POST` | `/api/scan` | Start a new scan |
| `GET` | `/api/scan/{id}` | Get scan status/results |
| `GET` | `/api/scan/{id}/findings` | Get findings only |
| `GET` | `/api/scan/{id}/mitre` | Get MITRE breakdown for scan |
| `GET` | `/api/scans` | List all scans |
| `DELETE` | `/api/scan/{id}` | Delete a scan |
| `POST` | `/api/scan/{id}/cancel` | Cancel a running scan |
| `GET` | `/api/owasp` | OWASP 2025 reference data |
| `GET` | `/api/mitre` | MITRE technique reference |
| `GET` | `/api/mitre/tactics` | All 14 ATT&CK tactics |
| `GET` | `/api/evidence/{filename}` | Serve screenshot evidence |

---

## ⚙️ Configuration & Limits

| Parameter | Limit | Reason |
|---|---|---|
| **Threads** | Max 10 | Prevents resource exhaustion and target overload |
| **Timeout** | 1–60s | Per-request timeout for stability |
| **Browser timeout** | 120s (quick) / 180s (full) | Per Selenium module; auto-kills Chrome on timeout |
| **Crawl depth** | 2 (quick) / 3 (full) | Balances coverage vs speed |
| **Crawl pages** | 50 (quick) / 200 (full) | Limits crawl scope |

---

## 🧰 Tech Stack

- **Python 3.13** — Core language
- **FastAPI** — REST API and web server
- **Uvicorn** — ASGI server
- **Selenium + Chrome** — Browser-based testing
- **Nmap (python-nmap)** — Port scanning
- **httpx / requests** — HTTP client
- **BeautifulSoup4** — HTML parsing
- **dnspython** — DNS resolution
- **python-whois** — WHOIS lookups
- **scapy** — Network analysis
- **cvss** — CVSS v3.1 scoring

---

## 📝 License

**Proprietary** — © 2026 Govind V Kartha. All rights reserved.

---

<p align="center">
  <strong>PentaVault</strong> — Automated VAPT Security Suite<br/>
  Built with ❤️ by Govind V Kartha
</p>
