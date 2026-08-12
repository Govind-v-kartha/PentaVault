"""Secrets Detection Module — identifies hardcoded API keys, tokens, and credentials in page source and JS bundles."""

from __future__ import annotations

import re
from typing import Any, Callable

import httpx

from scanner.core.crawler import CrawlResult
from scanner.utils.logger import get_logger

log = get_logger("secrets_detection")

# Table of secret patterns, labels, severities, CVSS vectors, and default confidence levels
SECRET_PATTERNS: list[dict[str, Any]] = [
    {
        "type": "AWS Access Key",
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "severity": "High",
        "confidence": "high",
        "cvss": 7.5,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    {
        "type": "AWS Secret Key",
        "pattern": re.compile(r"""(?i)(?:aws_secret|aws_secret_access_key|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?"""),
        "severity": "Critical",
        "confidence": "high",
        "cvss": 8.5,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    },
    {
        "type": "Google API Key",
        "pattern": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "severity": "High",
        "confidence": "high",
        "cvss": 7.5,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    {
        "type": "Generic Bearer Token",
        "pattern": re.compile(r"\bBearer\s+([A-Za-z0-9\-_\.=]{20,})\b"),
        "severity": "Medium",
        "confidence": "medium",
        "cvss": 5.3,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    {
        "type": "GitHub Personal Access Token",
        "pattern": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
        "severity": "High",
        "confidence": "high",
        "cvss": 7.5,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    {
        "type": "Slack Token",
        "pattern": re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
        "severity": "High",
        "confidence": "high",
        "cvss": 7.5,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    {
        "type": "Stripe API Key",
        "pattern": re.compile(r"\bsk_live_[0-9a-zA-Z]{24}\b"),
        "severity": "High",
        "confidence": "high",
        "cvss": 7.5,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    },
    {
        "type": "Generic Private Key Header",
        "pattern": re.compile(r"-----BEGIN (?:RSA|EC|DSA)? ?PRIVATE KEY-----"),
        "severity": "Critical",
        "confidence": "high",
        "cvss": 9.0,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    },
    {
        "type": "JWT Token",
        "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        "severity": "Medium",
        "confidence": "medium",
        "cvss": 5.3,
        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
    {
        "type": "Generic Password Assignment",
        "pattern": re.compile(r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{6,})['"]"""),
        "severity": "Low",
        "confidence": "low",
        "cvss": 3.1,
        "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    },
]


def redact_secret(secret_str: str) -> str:
    """Partially redact sensitive string to prevent exposing raw credentials in reports.

    Example:
        'AKIAIOSFODNN7EXAMPLE' -> 'AKIAIO...MPLE'
        'ghp_1234567890abcdef' -> 'ghp_12...cdef'
    """
    length = len(secret_str)
    if length <= 8:
        return "*" * length
    if length >= 12:
        return f"{secret_str[:6]}...{secret_str[-4:]}"
    return f"{secret_str[:2]}...{secret_str[-2:]}"


def test_secrets_detection(
    crawl_result: CrawlResult | None = None,
    base_url: str = "",
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Scan crawled HTML page sources and linked JS files for exposed hardcoded secrets."""
    log.info("=== Vulnerability Testing: Secrets Detection ===")
    findings: list[dict[str, Any]] = []
    if not crawl_result:
        log.info("No crawl result provided — skipping secrets detection.")
        return findings

    seen_secrets: set[tuple[str, str]] = set()

    def _scan_text(text: str, source_url: str) -> None:
        for rule in SECRET_PATTERNS:
            secret_type = rule["type"]
            pattern: re.Pattern = rule["pattern"]
            for match in pattern.finditer(text):
                matched_val = match.group(1) if match.groups() else match.group(0)
                if not matched_val or len(matched_val.strip()) < 4:
                    continue

                dedup_key = (secret_type, matched_val)
                if dedup_key in seen_secrets:
                    continue
                seen_secrets.add(dedup_key)

                redacted = redact_secret(matched_val)
                finding = {
                    "type": "secrets_detection",
                    "title": f"Exposed {secret_type} in Client Code",
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "affected_url": source_url,
                    "parameter": "N/A",
                    "owasp_category": "A02:2025 - Security Misconfiguration",
                    "cvss_score": rule["cvss"],
                    "cvss_vector": rule["vector"],
                    "description": (
                        f"A hardcoded {secret_type} was discovered exposed in client-accessible content at {source_url}."
                    ),
                    "remediation": (
                        "Revoke and rotate the exposed credential immediately. Store all API keys, "
                        "tokens, and credentials securely on the backend server or secret manager, "
                        "and access third-party services via backend proxy endpoints rather than client-side scripts."
                    ),
                    "evidence": f"Exposed {secret_type} detected: {redacted}",
                    "payload": redacted,
                    "mitre_attack": [
                        {
                            "technique": "T1552.001",
                            "name": "Unsecured Credentials: Credentials In Files",
                            "tactic": "Credential Access",
                            "tactic_id": "TA0006",
                            "url": "https://attack.mitre.org/techniques/T1552/001/",
                        }
                    ],
                }
                findings.append(finding)
                log.warning("Discovered %s at %s (Redacted: %s)", secret_type, source_url, redacted)

    # 1. Scan crawled HTML page sources
    for page_url, html_source in crawl_result.page_sources.items():
        if should_stop and should_stop():
            log.info("Secrets detection cancelled during page source scanning.")
            return findings
        _scan_text(html_source, page_url)

    # 2. Fetch and scan external JS files unless quick mode is active
    if not quick and crawl_result.js_files:
        headers: dict[str, str] = {}
        if cookie:
            headers["Cookie"] = cookie

        with httpx.Client(verify=False, timeout=timeout, headers=headers, follow_redirects=True) as client:
            for js_url in crawl_result.js_files:
                if should_stop and should_stop():
                    log.info("Secrets detection cancelled during JS file scanning.")
                    return findings
                try:
                    resp = client.get(js_url)
                    if resp.status_code == 200:
                        _scan_text(resp.text, js_url)
                except httpx.HTTPError as exc:
                    log.debug("Failed to fetch JS file %s for secrets scanning: %s", js_url, exc)

    log.info("Secrets detection complete — %d finding(s) discovered.", len(findings))
    return findings


test_secrets_detection.__test__ = False
