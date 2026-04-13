"""JWT security checks module."""

from __future__ import annotations

import base64
import json
from typing import Callable
from urllib.parse import parse_qs, urlparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("jwt")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _extract_jwt_candidates(endpoints: list[str], forms: list[dict], cookie: str | None) -> list[str]:
    tokens: list[str] = []
    if cookie:
        for part in cookie.split(";"):
            if "=" not in part:
                continue
            _, value = part.split("=", 1)
            value = value.strip()
            if value.count(".") == 2:
                tokens.append(value)

    for url in endpoints[:40]:
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        for k, vals in qs.items():
            if "jwt" in k.lower() or "token" in k.lower() or "auth" in k.lower():
                for v in vals:
                    if v.count(".") == 2:
                        tokens.append(v)

    for form in forms[:20]:
        for inp in form.get("inputs", []):
            name = (inp.get("name") or "").lower()
            value = inp.get("value") or ""
            if ("jwt" in name or "token" in name or "auth" in name) and value.count(".") == 2:
                tokens.append(value)

    return list(dict.fromkeys(tokens))


def test_jwt_checks(
    endpoints: list[str],
    forms: list[dict],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict]:
    """Inspect discovered JWTs for weak header/claim properties."""
    findings: list[dict] = []
    tokens = _extract_jwt_candidates(endpoints, forms, cookie)
    if quick:
        tokens = tokens[:5]

    for token in tokens:
        if should_stop and should_stop():
            log.info("JWT checks cancelled")
            break

        parts = token.split(".")
        if len(parts) != 3:
            continue

        try:
            header = json.loads(_b64url_decode(parts[0]).decode("utf-8", errors="ignore") or "{}")
        except Exception:
            continue

        try:
            payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", errors="ignore") or "{}")
        except Exception:
            payload = {}

        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            findings.append(_to_finding(
                token,
                "JWT uses 'none' algorithm",
                "Header contains alg=none",
                "High",
                8.1,
            ))

        if "kid" in header and isinstance(header["kid"], str):
            kid = header["kid"]
            if any(x in kid for x in ("../", "..\\", "/", "\\", "http://", "https://")):
                findings.append(_to_finding(
                    token,
                    "Potentially unsafe JWT kid header value",
                    f"Suspicious kid value: {kid}",
                    "Medium",
                    6.5,
                ))

        if payload and "exp" not in payload:
            findings.append(_to_finding(
                token,
                "JWT missing exp claim",
                "Token payload does not include expiry",
                "Medium",
                5.9,
            ))

    return findings


def _to_finding(token: str, title: str, evidence: str, severity: str, score: float) -> dict:
    return {
        "title": f"JWT: {title}",
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" if severity == "High" else "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "affected_url": "N/A",
        "parameter": "JWT token",
        "payload": token[:120] + ("..." if len(token) > 120 else ""),
        "evidence": evidence,
        "remediation": "Enforce strong JWT validation: disallow alg=none, validate issuer/audience/expiry, and strictly sanitize kid usage.",
        "owasp_category": "A07:2025 - Authentication Failures",
    }
