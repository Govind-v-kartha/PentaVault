# 🛠️ Pentavault — Rework Code & Diagnostics Report

This document contains the exact test output, source file contents, and architecture diagnostics requested for **Priorities A, B, C, and D**.

---

## 1. Priority A — `test_payload_sets.py` Pytest Output & Analysis

### Executed Command
```bash
PYTHONPATH=. .venv/bin/pytest scanner/tests/test_payload_sets.py -vv
```

### Full Pytest Output
```text
============================= test session starts ==============================
platform linux -- Python 3.11.15, pytest-9.1.1, pluggy-1.6.0 -- /home/govind-v-kartha/Downloads/Pentavault/.venv/bin/python3
cachedir: .pytest_cache
rootdir: /home/govind-v-kartha/Downloads/Pentavault
configfile: pytest.ini
plugins: anyio-4.14.2
collected 22 items                                                             

scanner/tests/test_payload_sets.py::TestPayloadSets::test_command_injection_payload_sets_expanded PASSED [  4%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_cors_payload_sets_expanded PASSED [  9%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_crlf_payload_sets_expanded PASSED [ 13%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_csv_formula_payload_set_expanded PASSED [ 18%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_graphql_payload_sets_expanded PASSED [ 22%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_host_header_payload_sets_expanded PASSED [ 27%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_hpp_payload_sets_expanded PASSED [ 31%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_insecure_deserialization_payload_set_expanded PASSED [ 36%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_jwt_module_token_extractor_exists PASSED [ 40%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_lfi_payload_sets_expanded PASSED [ 45%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_mass_assignment_payload_set_expanded PASSED [ 50%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_nosqli_payload_sets_expanded PASSED [ 54%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_open_redirect_payload_sets_expanded FAILED [ 59%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_prototype_pollution_payload_set_expanded PASSED [ 63%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_request_smuggling_module_entrypoint_exists PASSED [ 68%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_sensitive_files_paths_expanded PASSED [ 72%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_sqli_payload_sets_expanded FAILED [ 77%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_sqli_selenium_payload_sets_expanded FAILED [ 81%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_ssrf_payload_sets_expanded FAILED [ 86%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_ssti_payload_sets_expanded PASSED [ 90%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_xss_payload_sets_expanded FAILED [ 95%]
scanner/tests/test_payload_sets.py::TestPayloadSets::test_xxe_payload_sets_expanded PASSED [100%]

=================================== FAILURES ===================================
___________ TestPayloadSets.test_open_redirect_payload_sets_expanded ___________

self = <test_payload_sets.TestPayloadSets testMethod=test_open_redirect_payload_sets_expanded>

    def test_open_redirect_payload_sets_expanded(self):
>       self.assertGreaterEqual(len(open_redirect._REDIRECT_PAYLOADS), 18)
E       AssertionError: 7 not greater than or equal to 18

scanner/tests/test_payload_sets.py:53: AssertionError
_______________ TestPayloadSets.test_sqli_payload_sets_expanded ________________

self = <test_payload_sets.TestPayloadSets testMethod=test_sqli_payload_sets_expanded>

    def test_sqli_payload_sets_expanded(self):
>       self.assertGreaterEqual(len(sqli.ERROR_PAYLOADS), 32)
E       AssertionError: 7 not greater than or equal to 32

scanner/tests/test_payload_sets.py:32: AssertionError
___________ TestPayloadSets.test_sqli_selenium_payload_sets_expanded ___________

self = <test_payload_sets.TestPayloadSets testMethod=test_sqli_selenium_payload_sets_expanded>

    def test_sqli_selenium_payload_sets_expanded(self):
>       self.assertGreaterEqual(len(sqli_selenium.PAYLOADS_QUICK), 8)
E       AssertionError: 5 not greater than or equal to 8

scanner/tests/test_payload_sets.py:39: AssertionError
_______________ TestPayloadSets.test_ssrf_payload_sets_expanded ________________

self = <test_payload_sets.TestPayloadSets testMethod=test_ssrf_payload_sets_expanded>

    def test_ssrf_payload_sets_expanded(self):
>       self.assertGreaterEqual(len(ssrf.INTERNAL_URLS), 24)
E       AssertionError: 8 not greater than or equal to 24

scanner/tests/test_payload_sets.py:49: AssertionError
________________ TestPayloadSets.test_xss_payload_sets_expanded ________________

self = <test_payload_sets.TestPayloadSets testMethod=test_xss_payload_sets_expanded>

    def test_xss_payload_sets_expanded(self):
>       self.assertGreaterEqual(len(xss.REFLECTED_PAYLOADS), 18)
E       AssertionError: 7 not greater than or equal to 18

scanner/tests/test_payload_sets.py:43: AssertionError
=========================== short test summary info ============================
FAILED scanner/tests/test_payload_sets.py::TestPayloadSets::test_open_redirect_payload_sets_expanded - AssertionError: 7 not greater than or equal to 18
FAILED scanner/tests/test_payload_sets.py::TestPayloadSets::test_sqli_payload_sets_expanded - AssertionError: 7 not greater than or equal to 32
FAILED scanner/tests/test_payload_sets.py::TestPayloadSets::test_sqli_selenium_payload_sets_expanded - AssertionError: 5 not greater than or equal to 8
FAILED scanner/tests/test_payload_sets.py::TestPayloadSets::test_ssrf_payload_sets_expanded - AssertionError: 8 not greater than or equal to 24
FAILED scanner/tests/test_payload_sets.py::TestPayloadSets::test_xss_payload_sets_expanded - AssertionError: 7 not greater than or equal to 18
========================= 5 failed, 17 passed in 0.14s =========================
```

### Full Contents of `scanner/tests/test_payload_sets.py`
```python
import unittest

from scanner.modules import (
    command_injection,
    cors_misconfig,
    crlf_injection,
    csv_formula_injection,
    graphql_abuse,
    host_header,
    hpp,
    jwt_checks,
    lfi,
    nosqli,
    open_redirect,
    prototype_pollution,
    request_smuggling,
    sensitive_files,
    mass_assignment,
    insecure_deserialization,
    sqli,
    sqli_selenium,
    ssrf,
    ssti,
    xss,
    xss_selenium,
    xxe,
)


class TestPayloadSets(unittest.TestCase):
    def test_sqli_payload_sets_expanded(self):
        self.assertGreaterEqual(len(sqli.ERROR_PAYLOADS), 32)
        self.assertGreaterEqual(len(sqli.ERROR_PAYLOADS_QUICK), 10)
        self.assertGreaterEqual(len(sqli.TIME_PAYLOADS), 20)
        self.assertGreaterEqual(len(sqli.BOOLEAN_PAYLOADS), 24)
        self.assertGreaterEqual(len(sqli.BOOLEAN_PAYLOADS_QUICK), 8)

    def test_sqli_selenium_payload_sets_expanded(self):
        self.assertGreaterEqual(len(sqli_selenium.PAYLOADS_QUICK), 8)
        self.assertGreaterEqual(len(sqli_selenium.PAYLOADS_FULL), 14)

    def test_xss_payload_sets_expanded(self):
        self.assertGreaterEqual(len(xss.REFLECTED_PAYLOADS), 18)
        self.assertGreaterEqual(len(xss.ENCODED_PAYLOADS), 10)
        self.assertGreaterEqual(len(xss_selenium.PAYLOADS), 16)
        self.assertGreaterEqual(len(xss_selenium.WAF_BYPASS_PAYLOADS), 10)

    def test_ssrf_payload_sets_expanded(self):
        self.assertGreaterEqual(len(ssrf.INTERNAL_URLS), 24)
        self.assertGreaterEqual(len(ssrf.CLOUD_METADATA_URLS), 14)

    def test_open_redirect_payload_sets_expanded(self):
        self.assertGreaterEqual(len(open_redirect._REDIRECT_PAYLOADS), 18)

    def test_command_injection_payload_sets_expanded(self):
        self.assertGreaterEqual(len(command_injection._PAYLOADS), 18)

    def test_xxe_payload_sets_expanded(self):
        self.assertGreaterEqual(len(xxe._XXE_PAYLOADS), 10)

    def test_lfi_payload_sets_expanded(self):
        self.assertGreaterEqual(len(lfi._PAYLOADS), 15)

    def test_sensitive_files_paths_expanded(self):
        self.assertGreaterEqual(len(sensitive_files._COMMON_PATHS), 12)

    def test_nosqli_payload_sets_expanded(self):
        self.assertGreaterEqual(len(nosqli._BOOLEAN_PAYLOADS), 6)
        self.assertGreaterEqual(len(nosqli._ERROR_PAYLOADS), 7)

    def test_ssti_payload_sets_expanded(self):
        self.assertGreaterEqual(len(ssti._PAYLOAD_MARKERS), 12)

    def test_graphql_payload_sets_expanded(self):
        self.assertGreaterEqual(len(graphql_abuse._GRAPHQL_PATHS), 3)

    def test_host_header_payload_sets_expanded(self):
        self.assertGreaterEqual(len(host_header._HOST_PAYLOADS), 3)

    def test_cors_payload_sets_expanded(self):
        self.assertGreaterEqual(len(cors_misconfig._ORIGIN_PAYLOADS), 3)

    def test_hpp_payload_sets_expanded(self):
        self.assertGreaterEqual(len(hpp._PAYLOADS), 3)

    def test_crlf_payload_sets_expanded(self):
        self.assertGreaterEqual(len(crlf_injection._PAYLOADS), 3)

    def test_jwt_module_token_extractor_exists(self):
        self.assertTrue(callable(jwt_checks._extract_jwt_candidates))

    def test_request_smuggling_module_entrypoint_exists(self):
        self.assertTrue(callable(request_smuggling.test_request_smuggling))

    def test_mass_assignment_payload_set_expanded(self):
        self.assertGreaterEqual(len(mass_assignment._SENSITIVE_FIELDS), 15)

    def test_insecure_deserialization_payload_set_expanded(self):
        self.assertGreaterEqual(len(insecure_deserialization._SERIALIZED_PAYLOADS), 4)

    def test_prototype_pollution_payload_set_expanded(self):
        self.assertGreaterEqual(len(prototype_pollution._QUERY_PROBES), 5)

    def test_csv_formula_payload_set_expanded(self):
        self.assertGreaterEqual(len(csv_formula_injection._FORMULA_PAYLOADS), 6)


if __name__ == "__main__":
    unittest.main()
```

---

## 2. Priority B — Render Static Serving & Dashboard Directory Layout

### Static Directory Layout (`scanner/web/static/`)
* `app.js` (50,591 bytes) — Dynamic React/JS Single Page Application.
* `index.html` (13,323 bytes) — Core application layout template.
* `style.css` (35,802 bytes) — Pentavault design system tokens and layout.

### FastAPI Mount Logic in `scanner/web/app.py`
```python
# Mounting static asset directory for GUI
_STATIC_DIR = Path(__file__).resolve().parent / "static"
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

@app.get("/", response_class=HTMLResponse)
def index():
    """Serve the single-page GUI dashboard."""
    index_file = _STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h1>PentaVault Scanner Server</h1><p>Dashboard build static asset directory missing.</p>")
```

---

## 3. Priority C — Full Contents of `scanner/core/recon.py`

```python
"""Reconnaissance module — DNS, subdomain enumeration, and WHOIS lookups."""

from __future__ import annotations

import socket
from typing import Any

import dns.resolver
import dns.exception

from scanner.utils.logger import get_logger

log = get_logger("recon")

# Compact built-in wordlist for subdomain brute-force.
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "portal", "blog", "shop", "store", "cdn", "media", "static",
    "app", "m", "mobile", "docs", "wiki", "support", "help",
    "status", "monitor", "git", "gitlab", "jenkins", "ci", "cd",
    "vpn", "remote", "intranet", "internal", "db", "database",
    "auth", "login", "sso", "oauth", "beta", "demo", "sandbox",
    "ns1", "ns2", "mx", "smtp", "pop", "imap", "webmail",
    "cpanel", "whm", "plesk", "backup", "old", "new", "v2",
]


def dns_lookup(domain: str) -> dict[str, Any]:
    """Resolve common DNS record types for *domain*."""
    results: dict[str, Any] = {}
    for rtype in ("A", "AAAA", "MX", "CNAME", "TXT", "NS"):
        try:
            answers = dns.resolver.resolve(domain, rtype)
            results[rtype] = [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            results[rtype] = []
    log.info("DNS lookup complete for %s — %d record types populated",
             domain, sum(1 for v in results.values() if v))
    return results


def enumerate_subdomains(
    domain: str,
    wordlist: list[str] | None = None,
    timeout: float = 2.0,
) -> list[str]:
    """Brute-force subdomains by resolving ``{word}.{domain}``."""
    words = wordlist or DEFAULT_SUBDOMAINS
    found: list[str] = []
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    for word in words:
        fqdn = f"{word}.{domain}"
        try:
            resolver.resolve(fqdn, "A")
            found.append(fqdn)
            log.debug("Subdomain found: %s", fqdn)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout,
                dns.exception.DNSException):
            continue

    log.info("Subdomain enumeration: %d found for %s", len(found), domain)
    return found


def whois_lookup(domain: str) -> dict[str, str]:
    """Perform a WHOIS query via the ``whois`` library (best-effort)."""
    try:
        import whois  # type: ignore[import-untyped]
        w = whois.whois(domain)
        return {
            "registrar": str(w.registrar or ""),
            "creation_date": str(w.creation_date or ""),
            "expiration_date": str(w.expiration_date or ""),
            "name_servers": str(w.name_servers or ""),
            "org": str(w.org or ""),
        }
    except Exception as exc:
        log.warning("WHOIS lookup failed for %s: %s", domain, exc)
        return {}


def resolve_ip(target: str) -> str | None:
    """Best-effort resolution of a hostname to its IPv4 address."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        log.warning("Could not resolve IP for %s", target)
        return None


def run_recon(domain: str) -> dict[str, Any]:
    """Execute the full recon stage and return aggregated data."""
    log.info("=== STAGE 02: Reconnaissance — %s ===", domain)
    ip = resolve_ip(domain)
    dns_records = dns_lookup(domain)
    subdomains = enumerate_subdomains(domain)
    whois_info = whois_lookup(domain)

    return {
        "ip": ip,
        "dns_records": dns_records,
        "subdomains": subdomains,
        "whois": whois_info,
    }
```

---

## 4. Priority D — Parity Audit & Module Imports Summary

Both `scanner/main.py` (CLI) and `scanner/web/app.py` (FastAPI) import and execute all **23 vulnerability scanning modules**:

```python
from scanner.modules.sqli import test_sqli
from scanner.modules.xss import test_xss
from scanner.modules.headers import test_headers
from scanner.modules.ssrf import test_ssrf
from scanner.modules.idor import test_idor
from scanner.modules.open_redirect import test_open_redirect
from scanner.modules.sqli_selenium import test_sqli_selenium
from scanner.modules.xss_selenium import test_xss_selenium
from scanner.modules.command_injection import test_command_injection
from scanner.modules.cors_misconfig import test_cors_misconfig
from scanner.modules.crlf_injection import test_crlf_injection
from scanner.modules.csv_formula_injection import test_csv_formula_injection
from scanner.modules.graphql_abuse import test_graphql_abuse
from scanner.modules.host_header import test_host_header_injection
from scanner.modules.hpp import test_hpp
from scanner.modules.insecure_deserialization import test_insecure_deserialization
from scanner.modules.jwt_checks import test_jwt_checks
from scanner.modules.lfi import test_lfi
from scanner.modules.mass_assignment import test_mass_assignment_bola
from scanner.modules.nosqli import test_nosqli
from scanner.modules.prototype_pollution import test_prototype_pollution
from scanner.modules.request_smuggling import test_request_smuggling
from scanner.modules.sensitive_files import test_sensitive_files
from scanner.modules.ssti import test_ssti
from scanner.modules.xxe import test_xxe
```
