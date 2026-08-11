"""Reconnaissance module — DNS, subdomain enumeration, WHOIS lookups, and Subdomain Takeover detection."""

from __future__ import annotations

import socket
from typing import Any, Callable

import dns.exception
import dns.resolver
import httpx

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

# Vulnerable SaaS service CNAME patterns and unclaimed response body signatures.
TAKEOVER_FINGERPRINTS = [
    {
        "service": "GitHub Pages",
        "cname_pattern": "github.io",
        "fingerprint": "There isn't a GitHub Pages site here",
    },
    {
        "service": "Heroku",
        "cname_pattern": "herokuapp.com",
        "fingerprint": "No such app",
    },
    {
        "service": "AWS S3",
        "cname_pattern": "s3.amazonaws.com",
        "fingerprint": "NoSuchBucket",
    },
    {
        "service": "Shopify",
        "cname_pattern": "myshopify.com",
        "fingerprint": "Sorry, this shop is currently unavailable",
    },
    {
        "service": "Fastly",
        "cname_pattern": "fastly.net",
        "fingerprint": "Fastly error: unknown domain",
    },
    {
        "service": "Unbounce",
        "cname_pattern": "unbouncepages.com",
        "fingerprint": "The requested URL was not found on this server",
    },
    {
        "service": "WordPress.com",
        "cname_pattern": "wordpress.com",
        "fingerprint": "Do you want to register",
    },
    {
        "service": "Zendesk",
        "cname_pattern": "zendesk.com",
        "fingerprint": "Help Center Closed",
    },
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


def check_subdomain_takeover(
    subdomains: list[str],
    timeout: float = 5.0,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Check list of subdomains for dangling CNAME records pointing to unclaimed SaaS services."""
    findings: list[dict[str, Any]] = []

    for sub in subdomains:
        if should_stop and should_stop():
            log.info("Subdomain takeover check cancelled mid-execution")
            break

        cname_target: str | None = None
        try:
            answers = dns.resolver.resolve(sub, "CNAME")
            for rdata in answers:
                cname_target = rdata.to_text().rstrip(".")
                break
        except Exception:
            continue

        if not cname_target:
            continue

        # Match CNAME against known vulnerable patterns
        matched_service: dict[str, str] | None = None
        for fp in TAKEOVER_FINGERPRINTS:
            if fp["cname_pattern"] in cname_target.lower():
                matched_service = fp
                break

        if not matched_service:
            continue

        # Confirmation step: HTTP request to check for unclaimed fingerprint string
        service_name = matched_service["service"]
        fingerprint_text = matched_service["fingerprint"]
        target_url = f"http://{sub}"

        try:
            with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as client:
                resp = client.get(target_url)
                body = resp.text
                if fingerprint_text.lower() in body.lower():
                    findings.append({
                        "title": f"Subdomain Takeover Vulnerability on {sub}",
                        "severity": "High",
                        "cvss_score": 7.5,
                        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        "affected_url": target_url,
                        "parameter": "CNAME Record",
                        "payload": cname_target,
                        "evidence": f"Subdomain '{sub}' points via CNAME to '{cname_target}' ({service_name}) which returned unclaimed fingerprint: '{fingerprint_text}'",
                        "remediation": f"Remove the dangling CNAME record for '{sub}' or claim the target resource on {service_name}.",
                        "owasp_category": "A02:2025 - Security Misconfiguration",
                    })
                    log.warning("Subdomain takeover detected: %s -> %s (%s)", sub, cname_target, service_name)
        except httpx.HTTPError as exc:
            log.debug("HTTP request failed during subdomain takeover check for %s: %s", sub, exc)

    log.info("Subdomain takeover scan complete — %d findings", len(findings))
    return findings


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


def run_recon(
    domain: str,
    should_stop: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Execute the full recon stage and return aggregated data."""
    log.info("=== STAGE 02: Reconnaissance — %s ===", domain)
    ip = resolve_ip(domain)
    dns_records = dns_lookup(domain)
    subdomains = enumerate_subdomains(domain)
    whois_info = whois_lookup(domain)
    takeover_findings = check_subdomain_takeover(subdomains, should_stop=should_stop)

    return {
        "ip": ip,
        "dns_records": dns_records,
        "subdomains": subdomains,
        "whois": whois_info,
        "takeover_findings": takeover_findings,
    }
