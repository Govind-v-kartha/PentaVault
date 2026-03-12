"""Server-Side Request Forgery (SSRF) detection module.

Injects internal/cloud-metadata URLs into parameters that accept URL-like values
and checks for indicators of successful internal access.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("ssrf")

# ── SSRF Payloads ───────────────────────────────────────────────────
INTERNAL_URLS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:6379/",  # Redis
    "http://127.0.0.1:9200/",  # Elasticsearch
]

CLOUD_METADATA_URLS = [
    "http://169.254.169.254/latest/meta-data/",       # AWS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
]

# Patterns in response body that indicate successful internal access
_SSRF_EVIDENCE = re.compile(
    r"(ami-id|instance-id|local-ipv4|iam/security-credentials|"
    r"computeMetadata|internal server|root:x:0:|"
    r"redis_version|elasticsearch|ERR wrong number of arguments)",
    re.IGNORECASE,
)

# Heuristic: parameters whose names suggest they accept URLs
_URL_PARAM_NAMES = re.compile(
    r"(url|uri|link|redirect|next|dest|target|path|page|file|load|fetch|proxy|callback|return)",
    re.IGNORECASE,
)


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _looks_like_url_param(name: str, value: str) -> bool:
    """Heuristic: does the parameter seem to take URL/path values?"""
    if _URL_PARAM_NAMES.search(name):
        return True
    if value.startswith(("http://", "https://", "//", "/")):
        return True
    return False


def test_ssrf(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
) -> list[dict[str, Any]]:
    """Run SSRF tests on endpoints whose parameters look URL-like.

    Returns a list of confirmed finding dicts.
    """
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    # In quick mode: fewer payloads and fewer endpoints
    if quick:
        all_payloads = INTERNAL_URLS[:3] + CLOUD_METADATA_URLS[:1]
        endpoints = endpoints[:15]
        forms = forms[:5]
    else:
        all_payloads = INTERNAL_URLS + CLOUD_METADATA_URLS

    with httpx.Client(
        verify=False, timeout=timeout, follow_redirects=False, headers=headers
    ) as client:
        # ── GET parameters ──────────────────────────────────────────
        for url in endpoints:
            qs = parse_qs(urlparse(url).query, keep_blank_values=True)
            for param, values in qs.items():
                if not _looks_like_url_param(param, values[0] if values else ""):
                    continue
                sig = (urlparse(url).path, param)
                if sig in seen:
                    continue
                seen.add(sig)
                for payload in all_payloads:
                    target = _inject_param(url, param, payload)
                    try:
                        resp = client.get(target)
                    except httpx.HTTPError:
                        continue
                    match = _SSRF_EVIDENCE.search(resp.text)
                    if match:
                        log.info("[SSRF] %s param=%s payload=%s", url, param, payload)
                        findings.append(_to_finding(url, param, payload, match.group(0)))
                        break  # one confirmation per param is enough

        # ── POST form parameters ────────────────────────────────────
        for form in forms:
            if form["method"] != "POST":
                continue
            for inp in form["inputs"]:
                name = inp["name"]
                if not name or not _looks_like_url_param(name, inp["value"]):
                    continue
                for payload in all_payloads:
                    data = {i["name"]: i["value"] for i in form["inputs"] if i["name"]}
                    data[name] = payload
                    try:
                        resp = client.post(form["action"], data=data)
                    except httpx.HTTPError:
                        continue
                    match = _SSRF_EVIDENCE.search(resp.text)
                    if match:
                        log.info("[SSRF] POST %s param=%s", form["action"], name)
                        findings.append(
                            _to_finding(form["action"], name, payload, match.group(0))
                        )
                        break

    log.info("SSRF scan complete — %d findings", len(findings))
    return findings


def _to_finding(url: str, param: str, payload: str, evidence: str) -> dict[str, Any]:
    is_cloud = "169.254.169.254" in payload or "metadata" in payload.lower()
    return {
        "title": f"SSRF on {urlparse(url).path} ({'Cloud Metadata' if is_cloud else 'Internal'})",
        "severity": "High" if is_cloud else "Medium",
        "cvss_score": 9.1 if is_cloud else 6.5,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        if is_cloud
        else "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "affected_url": url,
        "parameter": param,
        "payload": payload,
        "evidence": evidence[:300],
        "remediation": "Validate and allowlist all user-supplied URLs server-side. "
                       "Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, "
                       "169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16) and link-local addresses.",
        "owasp_category": "A01:2025 - Broken Access Control",
    }
