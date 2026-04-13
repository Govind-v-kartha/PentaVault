"""Sensitive file discovery module.

Probes common backup/config/admin artifacts and reports publicly exposed files.
"""

from __future__ import annotations

from typing import Callable
from urllib.parse import urljoin, urlparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("sensitive_files")

_COMMON_PATHS = [
    "/.env",
    "/.git/config",
    "/.svn/entries",
    "/backup.zip",
    "/db.sql",
    "/config.php.bak",
    "/phpinfo.php",
    "/server-status",
    "/actuator/env",
    "/actuator/heapdump",
    "/swagger.json",
    "/openapi.json",
    "/robots.txt",
    "/sitemap.xml",
    "/admin/",
    "/debug",
]

_INTERESTING_MARKERS = (
    "DB_PASSWORD",
    "DATABASE_URL",
    "AWS_SECRET_ACCESS_KEY",
    "BEGIN RSA PRIVATE KEY",
    "root:x:0:0:",
    "phpinfo()",
    "mongodb://",
)


def test_sensitive_files(
    base_url: str,
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict]:
    """Probe a target origin for sensitive file exposure."""
    findings: list[dict] = []
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    paths = _COMMON_PATHS[:8] if quick else _COMMON_PATHS
    base = urlparse(base_url)._replace(path="", query="", fragment="").geturl().rstrip("/")

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=False, headers=headers) as client:
        for path in paths:
            if should_stop and should_stop():
                log.info("Sensitive file scan cancelled")
                break

            target = urljoin(base + "/", path.lstrip("/"))
            try:
                resp = client.get(target)
            except httpx.HTTPError:
                continue

            if resp.status_code != 200:
                continue

            body = resp.text[:4000]
            marker = next((m for m in _INTERESTING_MARKERS if m in body), None)
            if marker or any(token in path.lower() for token in (".env", ".git", "backup", "db.sql", "heapdump")):
                evidence = f"HTTP 200 on sensitive path {path}"
                if marker:
                    evidence += f" with marker '{marker}'"
                findings.append(_to_finding(target, path, evidence))
                log.info("[Sensitive Files] %s exposed", path)

    log.info("Sensitive file scan complete — %d findings", len(findings))
    return findings


def _to_finding(url: str, path: str, evidence: str) -> dict:
    return {
        "title": f"Sensitive File Exposure on {path}",
        "severity": "High",
        "cvss_score": 7.5,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "affected_url": url,
        "parameter": "N/A",
        "payload": path,
        "evidence": evidence[:300],
        "remediation": "Remove sensitive artifacts from web root, deny direct access to configuration and backup files, and enforce strict server access controls.",
        "owasp_category": "A02:2025 - Security Misconfiguration",
    }
