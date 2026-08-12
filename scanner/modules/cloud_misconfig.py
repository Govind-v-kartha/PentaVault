"""Cloud Misconfiguration Module — checks for public cloud storage buckets and leaked cloud metadata."""

from __future__ import annotations

import re
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from scanner.core.crawler import CrawlResult
from scanner.modules.ssrf import CLOUD_METADATA_URLS  # Reused from ssrf.py
from scanner.utils.logger import get_logger

log = get_logger("cloud_misconfig")

# Patterns indicating directory listing content in bucket responses
_BUCKET_LISTING_PATTERNS = [
    re.compile(r"<ListBucketResult", re.IGNORECASE),
    re.compile(r"<ListAllMyBucketsResult", re.IGNORECASE),
    re.compile(r"<EnumerationResults", re.IGNORECASE),
    re.compile(r"<Contents>", re.IGNORECASE),
    re.compile(r"<Key>", re.IGNORECASE),
    re.compile(r"<Blob>", re.IGNORECASE),
]

# Patterns indicating Access Denied / bucket existence
_BUCKET_DENIED_PATTERNS = [
    re.compile(r"AccessDenied", re.IGNORECASE),
    re.compile(r"AuthenticationFailed", re.IGNORECASE),
    re.compile(r"AllAccessDisabled", re.IGNORECASE),
]

# Patterns indicating leaked cloud metadata in response content
_METADATA_LEAK_PATTERNS = [
    (re.compile(r"\bami-[0-9a-f]{8,17}\b"), "AWS AMI ID"),
    (re.compile(r"\binstance-id\b[\s\:\"]+[i]-[0-9a-f]{8,17}"), "AWS Instance ID"),
    (re.compile(r'iam/security-credentials/[^"]+'), "AWS IAM Security Credentials Path"),
    (re.compile(r"\bcomputeMetadata/v1/\b"), "GCP Metadata API Reference"),
    (re.compile(r"\bAZURE_CLIENT_SECRET\b"), "Azure Identity Credential"),
]



def _derive_bucket_candidates(base_url: str, quick: bool = False) -> list[str]:
    """Generate candidate bucket names from the target domain."""
    hostname = urlparse(base_url).hostname or base_url
    parts = hostname.lower().split(".")
    
    # Extract main domain label (e.g. example from example.com or sub.example.co.uk)
    domain_label = parts[0] if parts else "target"
    if domain_label == "www" and len(parts) > 1:
        domain_label = parts[1]

    domain_dash = hostname.lower().replace(".", "-")
    domain_dot = hostname.lower()

    candidates = [domain_label, domain_dash, domain_dot]
    
    if not quick:
        candidates.extend([
            f"{domain_label}-assets",
            f"{domain_label}-backup",
            f"{domain_label}-dev",
            f"{domain_label}-staging",
            f"{domain_label}-media",
            f"{domain_label}-public",
        ])

    # Deduplicate maintaining order
    return list(dict.fromkeys(candidates))


def test_cloud_misconfig(
    base_url: str,
    crawl_result: CrawlResult | None = None,
    should_stop: Callable[[], bool] | None = None,
    timeout: float = 10.0,
    quick: bool = False,
) -> list[dict[str, Any]]:
    """Scan for publicly exposed cloud storage buckets and leaked cloud instance metadata."""
    log.info("=== Vulnerability Testing: Cloud Misconfiguration ===")
    findings: list[dict[str, Any]] = []

    # ────────────────────────────────────────────────────────────────
    # Part A: Passive Cloud Bucket / Storage Exposure
    # ────────────────────────────────────────────────────────────────
    candidates = _derive_bucket_candidates(base_url, quick=quick)
    seen_urls: set[str] = set()

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as client:
        for name in candidates:
            if should_stop and should_stop():
                log.info("Cloud misconfig scan cancelled during bucket checks.")
                return findings

            bucket_urls = [
                f"https://{name}.s3.amazonaws.com",
                f"https://s3.amazonaws.com/{name}",
                f"https://storage.googleapis.com/{name}",
                f"https://{name}.blob.core.windows.net",
            ]

            for b_url in bucket_urls:
                if b_url in seen_urls:
                    continue
                seen_urls.add(b_url)

                if should_stop and should_stop():
                    log.info("Cloud misconfig scan cancelled during bucket checks.")
                    return findings

                try:
                    resp = client.get(b_url)
                    body = resp.text

                    # 1. Check for HTTP 200 + directory listing content
                    if resp.status_code == 200 and any(p.search(body) for p in _BUCKET_LISTING_PATTERNS):
                        findings.append({
                            "type": "cloud_misconfig",
                            "title": "Publicly Readable Cloud Storage Bucket",
                            "severity": "High",
                            "confidence": "high",
                            "affected_url": b_url,
                            "parameter": "N/A",
                            "owasp_category": "A02:2025 - Security Misconfiguration",
                            "cvss_score": 7.5,
                            "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            "description": (
                                f"A publicly accessible cloud storage bucket with directory listing enabled was discovered at {b_url}."
                            ),
                            "remediation": (
                                "Disable public read/list permissions on the bucket policies and ACLs. "
                                "Enforce block public access settings across cloud storage resources."
                            ),
                            "evidence": f"Bucket listing accessible at {b_url} (HTTP 200)",
                            "payload": b_url,
                            "mitre_attack": [
                                {
                                    "technique": "T1530",
                                    "name": "Data from Cloud Storage",
                                    "tactic": "Collection",
                                    "tactic_id": "TA0009",
                                    "url": "https://attack.mitre.org/techniques/T1530/",
                                }
                            ],
                        })
                        log.warning("Discovered publicly readable cloud bucket: %s", b_url)

                    # 2. Check for HTTP 403 Access Denied (Bucket exists but list access denied)
                    elif resp.status_code == 403 and any(p.search(body) for p in _BUCKET_DENIED_PATTERNS):
                        findings.append({
                            "type": "cloud_misconfig",
                            "title": "Existing Cloud Storage Bucket (Access Denied)",
                            "severity": "Low",
                            "confidence": "high",
                            "affected_url": b_url,
                            "parameter": "N/A",
                            "owasp_category": "A02:2025 - Security Misconfiguration",
                            "cvss_score": 2.0,
                            "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                            "description": (
                                f"An existing cloud storage bucket associated with the target domain was identified at {b_url}. "
                                "Public list access is denied, but bucket existence is confirmed."
                            ),
                            "remediation": (
                                "Ensure bucket names do not leak sensitive infrastructure naming conventions. "
                                "Verify that object-level ACLs remain strictly private."
                            ),
                            "evidence": f"Bucket exists at {b_url} but returns HTTP 403 AccessDenied",
                            "payload": b_url,
                            "mitre_attack": [
                                {
                                    "technique": "T1530",
                                    "name": "Data from Cloud Storage",
                                    "tactic": "Collection",
                                    "tactic_id": "TA0009",
                                    "url": "https://attack.mitre.org/techniques/T1530/",
                                }
                            ],
                        })
                        log.info("Discovered protected cloud bucket: %s (HTTP 403)", b_url)

                except httpx.HTTPError:
                    continue

    # ────────────────────────────────────────────────────────────────
    # Part B: Leaked Cloud Metadata in Crawled Response Content
    # ────────────────────────────────────────────────────────────────
    if crawl_result and crawl_result.page_sources:
        seen_leaks: set[str] = set()
        for page_url, html_source in crawl_result.page_sources.items():
            if should_stop and should_stop():
                log.info("Cloud misconfig scan cancelled during metadata leak checks.")
                return findings

            for pattern, label in _METADATA_LEAK_PATTERNS:
                match = pattern.search(html_source)
                if match:
                    leak_key = f"{page_url}:{label}"
                    if leak_key in seen_leaks:
                        continue
                    seen_leaks.add(leak_key)

                    evidence_str = match.group(0)
                    findings.append({
                        "type": "cloud_misconfig",
                        "title": f"Leaked Cloud Instance Metadata ({label}) in Response",
                        "severity": "Critical",
                        "confidence": "high",
                        "affected_url": page_url,
                        "parameter": "N/A",
                        "owasp_category": "A02:2025 - Security Misconfiguration",
                        "cvss_score": 9.0,
                        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                        "description": (
                            f"Cloud instance metadata marker '{label}' was exposed in application response content at {page_url}."
                        ),
                        "remediation": (
                            "Restrict access to Instance Metadata Services (IMDS) from application containers/processes, "
                            "enforce IMDSv2 (token-based header auth), and sanitize debug/error pages to prevent data leakage."
                        ),
                        "evidence": f"Leaked metadata indicator ({label}): {evidence_str[:50]}",
                        "payload": evidence_str[:50],
                        "mitre_attack": [
                            {
                                "technique": "T1552.005",
                                "name": "Unsecured Credentials: Cloud Instance Metadata API",
                                "tactic": "Credential Access",
                                "tactic_id": "TA0006",
                                "url": "https://attack.mitre.org/techniques/T1552/005/",
                            }
                        ],
                    })
                    log.warning("Discovered cloud metadata leak (%s) at %s", label, page_url)

    log.info("Cloud misconfiguration scan complete — %d finding(s) discovered.", len(findings))
    return findings


test_cloud_misconfig.__test__ = False
