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
