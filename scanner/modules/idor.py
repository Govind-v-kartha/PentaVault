"""Insecure Direct Object Reference (IDOR) detection module.

Identifies numeric IDs in URLs and attempts to access adjacent objects
to detect unauthorized data exposure.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("idor")

# Matches paths like /api/user/1001 or /order/42
_ID_PATTERN = re.compile(r"(/[a-zA-Z_-]+/)(\d+)(/|$|\?)")


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


def test_idor(
    endpoints: list[str],
    cookie: str | None = None,
    timeout: float = 10.0,
    id_offset: int = 5,
    quick: bool = False,
) -> list[dict[str, Any]]:
    """Test for IDOR by incrementing/decrementing numeric IDs in endpoint paths.

    Returns a list of confirmed finding dicts.
    """
    findings: list[dict[str, Any]] = []
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    # In quick mode, limit scope
    if quick:
        endpoints = endpoints[:15]
        id_offset = min(id_offset, 2)

    tested: set[str] = set()

    with httpx.Client(
        verify=False, timeout=timeout, follow_redirects=True, headers=headers
    ) as client:
        for url in endpoints:
            id_matches = _find_id_in_url(url)
            if not id_matches:
                continue

            for prefix, suffix, original_id in id_matches:
                sig = f"{prefix}|{suffix}"
                if sig in tested:
                    continue
                tested.add(sig)

                # Fetch original response as baseline
                try:
                    baseline = client.get(url)
                except httpx.HTTPError:
                    continue

                if baseline.status_code in (401, 403, 404):
                    continue

                # Try adjacent IDs
                for delta in range(1, id_offset + 1):
                    for new_id in (original_id + delta, original_id - delta):
                        if new_id < 0:
                            continue
                        alt_url = _replace_id(url, prefix, suffix, original_id, new_id)
                        try:
                            alt_resp = client.get(alt_url)
                        except httpx.HTTPError:
                            continue

                        if alt_resp.status_code == 200 and _responses_differ(
                            baseline.text, alt_resp.text
                        ):
                            log.info(
                                "[IDOR] %s — ID %d→%d returned different data",
                                url, original_id, new_id,
                            )
                            findings.append(_to_finding(url, original_id, new_id, prefix))
                            break  # one proof per ID position is enough
                    else:
                        continue
                    break

    log.info("IDOR scan complete — %d findings", len(findings))
    return findings


def _responses_differ(body_a: str, body_b: str) -> bool:
    """Heuristic: do the two responses contain meaningfully different data?"""
    if body_a == body_b:
        return False
    # Require at least 5 % length difference or >200 chars diff
    diff = abs(len(body_a) - len(body_b))
    if diff > 200:
        return True
    if len(body_a) > 0 and diff / len(body_a) > 0.05:
        return True
    return False


def _to_finding(url: str, orig_id: int, new_id: int, prefix: str) -> dict[str, Any]:
    return {
        "title": f"IDOR on {urlparse(url).path} (ID {orig_id}→{new_id})",
        "severity": "High",
        "cvss_score": 7.5,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "affected_url": url,
        "parameter": f"path ID in {prefix}",
        "payload": f"Changed ID from {orig_id} to {new_id}",
        "evidence": f"HTTP 200 with different response body for ID {new_id}",
        "remediation": "Implement proper authorization checks on every object access. "
                       "Use indirect references (UUIDs) instead of sequential integers.",
        "owasp_category": "A01:2025 - Broken Access Control",
    }
