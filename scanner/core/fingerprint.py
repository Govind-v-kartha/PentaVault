"""Fingerprinting module — tech stack detection, SSL/TLS analysis, WAF detection."""

from __future__ import annotations

import re
import ssl
import socket
from datetime import datetime, timezone
from typing import Any

import httpx

from scanner.utils.logger import get_logger

log = get_logger("fingerprint")

# Header / body signatures → technology label
_TECH_SIGNATURES: list[tuple[str, str, str]] = [
    # (where, pattern, label)
    ("header:X-Powered-By", r"PHP", "PHP"),
    ("header:X-Powered-By", r"ASP\.NET", "ASP.NET"),
    ("header:X-Powered-By", r"Express", "Express.js"),
    ("header:Server", r"Apache", "Apache"),
    ("header:Server", r"nginx", "Nginx"),
    ("header:Server", r"Microsoft-IIS", "IIS"),
    ("header:Server", r"LiteSpeed", "LiteSpeed"),
    ("header:Server", r"cloudflare", "Cloudflare"),
    ("body", r"wp-content|wp-includes", "WordPress"),
    ("body", r"Joomla!", "Joomla"),
    ("body", r"Drupal", "Drupal"),
    ("body", r"/static/admin/.*django", "Django"),
    ("body", r"laravel", "Laravel"),
    ("body", r"react", "React"),
    ("body", r"vue\.js|vuejs", "Vue.js"),
    ("body", r"angular", "Angular"),
    ("body", r"next\.js|nextjs|_next/", "Next.js"),
]

# WAF detection via response headers or body cues
_WAF_SIGNATURES: list[tuple[str, str, str]] = [
    ("header:Server", r"cloudflare", "Cloudflare WAF"),
    ("header:X-CDN", r"Incapsula", "Imperva/Incapsula"),
    ("header:X-Sucuri-ID", r".", "Sucuri WAF"),
    ("body", r"mod_security|NOYB", "ModSecurity"),
    ("header:X-Amz-Cf-Id", r".", "AWS CloudFront"),
    ("header:X-Azure-Ref", r".", "Azure Front Door"),
]


def _match_signatures(
    headers: dict[str, str],
    body: str,
    sigs: list[tuple[str, str, str]],
) -> list[str]:
    matches: list[str] = []
    for where, pattern, label in sigs:
        if where == "body":
            if re.search(pattern, body, re.IGNORECASE):
                if label not in matches:
                    matches.append(label)
        elif where.startswith("header:"):
            hdr_name = where.split(":", 1)[1]
            hdr_val = headers.get(hdr_name, "") or headers.get(hdr_name.lower(), "")
            if re.search(pattern, hdr_val, re.IGNORECASE):
                if label not in matches:
                    matches.append(label)
    return matches


def detect_tech_stack(url: str, timeout: float = 10.0) -> dict[str, Any]:
    """Fetch the target and fingerprint the technology stack."""
    try:
        with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url)
        headers = dict(resp.headers)
        body = resp.text
    except httpx.HTTPError as exc:
        log.warning("HTTP error during fingerprinting: %s", exc)
        return {"technologies": [], "waf": [], "headers_raw": {}}

    techs = _match_signatures(headers, body, _TECH_SIGNATURES)
    wafs = _match_signatures(headers, body, _WAF_SIGNATURES)

    log.info("Tech stack detected: %s", techs or ["unknown"])
    if wafs:
        log.info("WAF detected: %s", wafs)

    return {
        "technologies": techs,
        "waf": wafs,
        "headers_raw": headers,
    }


def check_ssl(hostname: str, port: int = 443) -> dict[str, Any]:
    """Examine the TLS certificate and cipher suite for *hostname*."""
    result: dict[str, Any] = {
        "valid": False,
        "issuer": "",
        "subject": "",
        "expires": "",
        "days_remaining": -1,
        "protocol": "",
        "cipher": "",
        "weak_cipher": False,
    }

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()  # (name, protocol, bits)

                if cert:
                    result["valid"] = True
                    result["issuer"] = str(dict(x[0] for x in cert.get("issuer", [])))
                    result["subject"] = str(dict(x[0] for x in cert.get("subject", [])))
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=timezone.utc
                        )
                        result["expires"] = expiry.isoformat()
                        result["days_remaining"] = (expiry - datetime.now(timezone.utc)).days

                if cipher_info:
                    result["cipher"] = cipher_info[0]
                    result["protocol"] = cipher_info[1]
                    bits = cipher_info[2]
                    # Flag weak ciphers (< 128-bit) or known weak suites
                    weak_patterns = ("RC4", "DES", "3DES", "NULL", "EXPORT", "anon")
                    result["weak_cipher"] = (
                        bits < 128 or any(w in cipher_info[0] for w in weak_patterns)
                    )
    except (ssl.SSLError, socket.error, OSError) as exc:
        log.warning("SSL check failed for %s:%d — %s", hostname, port, exc)

    log.info("SSL check for %s — valid=%s, expires=%s, cipher=%s",
             hostname, result["valid"], result["expires"], result["cipher"])
    return result


def run_fingerprint(url: str, hostname: str) -> dict[str, Any]:
    """Execute the full fingerprinting stage."""
    log.info("=== STAGE 03: Fingerprinting — %s ===", url)
    tech = detect_tech_stack(url)
    ssl_info = check_ssl(hostname)
    return {
        "technologies": tech["technologies"],
        "waf": tech["waf"],
        "headers_raw": tech["headers_raw"],
        "ssl": ssl_info,
    }
