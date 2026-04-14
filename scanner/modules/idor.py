"""Insecure Direct Object Reference (IDOR) detection module.

Identifies numeric IDs in URLs and attempts to access adjacent objects
to detect unauthorized data exposure using semantic evidence rather
than simple response-size comparison.
"""

from __future__ import annotations

import json
import re
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("idor")

# Matches paths like /api/user/1001 or /order/42
_ID_PATTERN = re.compile(r"(/[a-zA-Z_-]+/)(\d+)(/|$|\?)")

# Patterns that indicate user-specific identifiers in responses
_IDENTITY_KEYS = re.compile(
    r'"(?:user_?id|userId|account_?id|owner_?id|email|username|user_?name'
    r'|full_?name|display_?name|login|member_?id|profile_?id)"\s*:\s*"?([^",}\s]+)',
    re.IGNORECASE,
)


def _find_id_in_url(url: str) -> list[tuple[str, str, int]]:
    """Return a list of (prefix, suffix, id_value) tuples found in the URL path."""
    path = urlparse(url).path
    results: list[tuple[str, str, int]] = []
    for m in _ID_PATTERN.finditer(path):
        prefix = m.group(1)
        id_val = int(m.group(2))
        suffix = m.group(3)
        results.append((prefix, suffix, id_val))
    return results


def _replace_id(url: str, prefix: str, suffix: str, old_id: int, new_id: int) -> str:
    """Return *url* with the numeric ID segment replaced."""
    parsed = urlparse(url)
    new_path = parsed.path.replace(f"{prefix}{old_id}{suffix}", f"{prefix}{new_id}{suffix}", 1)
    return parsed._replace(path=new_path).geturl()


def _extract_identifiers(text: str) -> set[str]:
    """Extract user-identifying values from a response body."""
    identifiers: set[str] = set()
    for match in _IDENTITY_KEYS.finditer(text):
        val = match.group(1).strip().strip('"')
        if val and len(val) >= 2:
            identifiers.add(val.lower())
    return identifiers


def _is_json_response(text: str) -> bool:
    """Check if the response body looks like JSON."""
    stripped = text.strip()
    return stripped.startswith("{") or stripped.startswith("[")


def _is_stable_endpoint(client: httpx.Client, url: str) -> bool:
    """Fetch the same URL twice and check if responses are stable.
    
    If two fetches of the same URL differ significantly, the endpoint
    has dynamic content (ads, timestamps, etc.) and is unsuitable for
    IDOR diffing.
    """
    try:
        r1 = client.get(url)
        r2 = client.get(url)
    except httpx.HTTPError:
        return False

    if r1.status_code != r2.status_code:
        return False

    # For JSON, compare structure
    if _is_json_response(r1.text) and _is_json_response(r2.text):
        try:
            j1 = json.loads(r1.text)
            j2 = json.loads(r2.text)
            return json.dumps(j1, sort_keys=True) == json.dumps(j2, sort_keys=True)
        except (json.JSONDecodeError, TypeError):
            pass

    # For HTML, allow up to 2% length variance (timestamps, CSRF tokens)
    len_diff = abs(len(r1.text) - len(r2.text))
    max_len = max(len(r1.text), 1)
    return (len_diff / max_len) < 0.02


def _is_idor_evidence(
    baseline: httpx.Response,
    alt_resp: httpx.Response,
    baseline_text: str,
    alt_text: str,
) -> str | None:
    """Determine if an adjacent-ID response proves IDOR using semantic checks.
    
    Returns evidence string if IDOR is confirmed, None otherwise.
    """
    # 1. Status-based: 401/403→200 is strong evidence (authz bypass)
    if baseline.status_code in (401, 403) and alt_resp.status_code == 200:
        return f"Authorization bypass: original returned {baseline.status_code}, adjacent ID returned 200"

    # Both must be 200 for content-based checks
    if alt_resp.status_code != 200:
        return None

    # 2. JSON identity comparison: different user identifiers = IDOR
    if _is_json_response(baseline_text) and _is_json_response(alt_text):
        baseline_ids = _extract_identifiers(baseline_text)
        alt_ids = _extract_identifiers(alt_text)

        if baseline_ids and alt_ids and baseline_ids != alt_ids:
            changed = alt_ids - baseline_ids
            if changed:
                return (
                    f"Different user identity in response: "
                    f"original IDs {baseline_ids}, adjacent IDs include {changed}"
                )

        # JSON structural diff: same keys but different values for ID fields
        try:
            j_base = json.loads(baseline_text)
            j_alt = json.loads(alt_text)
            if isinstance(j_base, dict) and isinstance(j_alt, dict):
                id_keys = [k for k in j_base if any(
                    x in k.lower() for x in ("id", "user", "email", "name", "owner", "account")
                )]
                for key in id_keys:
                    if key in j_alt and j_base[key] != j_alt[key]:
                        return (
                            f"Different value for '{key}': "
                            f"original={j_base[key]!r}, adjacent={j_alt[key]!r}"
                        )
        except (json.JSONDecodeError, TypeError):
            pass

    # 3. HTML: look for different identifiers in non-JSON responses
    baseline_ids = _extract_identifiers(baseline_text)
    alt_ids = _extract_identifiers(alt_text)
    if baseline_ids and alt_ids and baseline_ids != alt_ids:
        changed = alt_ids - baseline_ids
        if changed:
            return f"Different user identity observed: new identifiers {changed}"

    return None


def test_idor(
    endpoints: list[str],
    cookie: str | None = None,
    timeout: float = 10.0,
    id_offset: int = 3,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Test for IDOR by incrementing/decrementing numeric IDs in endpoint paths.

    Uses semantic evidence (different user identifiers, authz bypass) rather
    than simple response-size comparison to minimize false positives.
    """
    findings: list[dict[str, Any]] = []
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    if quick:
        endpoints = endpoints[:15]
        id_offset = min(id_offset, 2)

    tested: set[str] = set()

    with httpx.Client(
        verify=False, timeout=timeout, follow_redirects=True, headers=headers
    ) as client:
        for url in endpoints:
            if should_stop and should_stop():
                log.info("IDOR scan cancelled during endpoint traversal")
                break
            id_matches = _find_id_in_url(url)
            if not id_matches:
                continue

            for prefix, suffix, original_id in id_matches:
                if should_stop and should_stop():
                    log.info("IDOR scan cancelled while testing %s", urlparse(url).path)
                    break
                sig = f"{prefix}|{suffix}"
                if sig in tested:
                    continue
                tested.add(sig)

                # Skip unstable endpoints (dynamic content defeats diffing)
                if not _is_stable_endpoint(client, url):
                    log.debug("[IDOR] Skipping unstable endpoint %s", url)
                    continue

                # Fetch original response as baseline
                try:
                    baseline = client.get(url)
                except httpx.HTTPError:
                    continue

                if baseline.status_code in (404,):
                    continue

                baseline_text = baseline.text

                # Try adjacent IDs
                for delta in range(1, id_offset + 1):
                    if should_stop and should_stop():
                        break
                    for new_id in (original_id + delta, original_id - delta):
                        if should_stop and should_stop():
                            break
                        if new_id < 0:
                            continue
                        alt_url = _replace_id(url, prefix, suffix, original_id, new_id)
                        try:
                            alt_resp = client.get(alt_url)
                        except httpx.HTTPError:
                            continue

                        evidence = _is_idor_evidence(
                            baseline, alt_resp, baseline_text, alt_resp.text
                        )
                        if evidence:
                            log.info(
                                "[IDOR] %s — ID %d→%d: %s",
                                url, original_id, new_id, evidence,
                            )
                            findings.append(_to_finding(url, original_id, new_id, prefix, evidence, bool(cookie)))
                            break  # one proof per ID position is enough
                    else:
                        continue
                    break

    log.info("IDOR scan complete — %d findings", len(findings))
    return findings


def _to_finding(url: str, orig_id: int, new_id: int, prefix: str, evidence: str, auth_required: bool) -> dict[str, Any]:
    from scanner.core.cvss_builder import build_finding_cvss
    vector, score, severity = build_finding_cvss("idor", context={"auth_required": auth_required})
    return {
        "title": f"IDOR on {urlparse(url).path} (ID {orig_id}→{new_id})",
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "affected_url": url,
        "parameter": f"path ID in {prefix}",
        "payload": f"Changed ID from {orig_id} to {new_id}",
        "evidence": evidence,
        "remediation": "Implement proper authorization checks on every object access. "
                       "Use indirect references (UUIDs) instead of sequential integers.",
        "owasp_category": "A01:2025 - Broken Access Control",
    }
