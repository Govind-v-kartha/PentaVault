"""Insecure deserialization probe module (heuristic, non-destructive)."""

from __future__ import annotations

import base64
import re
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from scanner.utils.logger import get_logger

log = get_logger("insecure_deserialization")

_SERIALIZED_PAYLOADS: list[tuple[str, str, str]] = [
    (
        "java-base64",
        base64.b64encode(b"rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAAAAAAAAAABAwACSQAHdGhpc1NpemVMAAR0YWJsZXQAEkxqYXZhL3V0aWwvTWFwO3hwAAAAAXQABnBlbnRhdmF1bHQ=").decode("ascii"),
        "java",
    ),
    (
        "php-object",
        'O:8:"stdClass":1:{s:4:"user";s:5:"admin";}',
        "php",
    ),
    (
        "python-pickle-b64",
        base64.b64encode(b"\x80\x04\x95\x1d\x00\x00\x00\x00\x00\x00\x00}\x94\x8c\x04role\x94\x8c\x05admin\x94s.").decode("ascii"),
        "python",
    ),
    (
        "json-type-confusion",
        '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"ToString"}',
        "dotnet",
    ),
]

_PARAM_HINT = re.compile(
    r"(data|payload|object|serialized|token|state|session|profile|prefs|remember|cache)",
    re.IGNORECASE,
)

_ERROR_MARKERS = [
    re.compile(r"java\.io\.StreamCorruptedException", re.IGNORECASE),
    re.compile(r"InvalidClassException", re.IGNORECASE),
    re.compile(r"ObjectInputStream", re.IGNORECASE),
    re.compile(r"unserialize\(\)", re.IGNORECASE),
    re.compile(r"__wakeup", re.IGNORECASE),
    re.compile(r"pickle", re.IGNORECASE),
    re.compile(r"yaml\.load", re.IGNORECASE),
    re.compile(r"SerializationException", re.IGNORECASE),
    re.compile(r"JsonSerializationException", re.IGNORECASE),
]


def _inject_query(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _looks_serialized(name: str, value: str) -> bool:
    if _PARAM_HINT.search(name):
        return True

    v = (value or "").strip()
    if not v:
        return False

    if v.startswith(("rO0", "gAS", "O:", "a:", "{")):
        return True

    if len(v) > 24:
        try:
            decoded = base64.b64decode(v + "===", validate=False)
            if decoded.startswith((b"\x80\x04", b"rO0", b"{", b"[")):
                return True
        except Exception:
            pass

    return False


def _extract_error_marker(text: str, baseline: str) -> str | None:
    for pattern in _ERROR_MARKERS:
        match = pattern.search(text)
        if match and not pattern.search(baseline):
            return match.group(0)
    return None


def _submit_form(client: httpx.Client, method: str, action: str, data: dict[str, str]) -> httpx.Response:
    normalized = method.upper()
    if normalized == "POST":
        return client.post(action, data=data)
    if normalized == "PUT":
        return client.put(action, data=data)
    if normalized == "PATCH":
        return client.patch(action, data=data)
    if normalized == "GET":
        return client.get(action, params=data)
    return client.post(action, data=data)


def test_insecure_deserialization(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    cookie: str | None = None,
    timeout: float = 10.0,
    quick: bool = False,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Probe endpoints/forms for unsafe deserialization behavior."""
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    headers: dict[str, str] = {}
    if cookie:
        headers["Cookie"] = cookie

    payloads = _SERIALIZED_PAYLOADS[:2] if quick else _SERIALIZED_PAYLOADS
    test_endpoints = endpoints[:15] if quick else endpoints
    test_forms = forms[:8] if quick else forms

    with httpx.Client(verify=False, timeout=timeout, follow_redirects=True, headers=headers) as client:
        for url in test_endpoints:
            if should_stop and should_stop():
                log.info("Deserialization scan cancelled during GET tests")
                break

            params = parse_qs(urlparse(url).query, keep_blank_values=True)
            if not params:
                continue

            try:
                baseline_resp = client.get(url)
                baseline_text = baseline_resp.text
                baseline_code = baseline_resp.status_code
            except httpx.HTTPError:
                baseline_text = ""
                baseline_code = 0

            for param, values in params.items():
                if should_stop and should_stop():
                    break
                original = values[0] if values else ""
                if not _looks_serialized(param, original):
                    continue

                sig = (urlparse(url).path, param)
                if sig in seen:
                    continue

                for payload_name, payload, family in payloads:
                    if should_stop and should_stop():
                        break

                    target = _inject_query(url, param, payload)
                    try:
                        resp = client.get(target)
                    except httpx.HTTPError:
                        continue

                    marker = _extract_error_marker(resp.text, baseline_text)
                    if marker:
                        findings.append(
                            _to_finding(
                                url,
                                param,
                                payload_name,
                                f"Deserializer error marker '{marker}' for {family} payload",
                            )
                        )
                        seen.add(sig)
                        break

                    if baseline_code and baseline_code < 500 and resp.status_code >= 500:
                        findings.append(
                            _to_finding(
                                url,
                                param,
                                payload_name,
                                f"Status changed from {baseline_code} to {resp.status_code} for {family} payload",
                            )
                        )
                        seen.add(sig)
                        break

        for form in test_forms:
            if should_stop and should_stop():
                log.info("Deserialization scan cancelled during form tests")
                break

            method = form.get("method", "GET").upper()
            if method not in {"POST", "PUT", "PATCH"}:
                continue

            action = form.get("action", "")
            base_data = {inp["name"]: inp.get("value", "") for inp in form.get("inputs", []) if inp.get("name")}
            if not action or not base_data:
                continue

            try:
                baseline_resp = _submit_form(client, method, action, base_data)
                baseline_text = baseline_resp.text
                baseline_code = baseline_resp.status_code
            except httpx.HTTPError:
                baseline_text = ""
                baseline_code = 0

            for name, value in base_data.items():
                if should_stop and should_stop():
                    break
                if not _looks_serialized(name, str(value)):
                    continue

                sig = (urlparse(action).path, name)
                if sig in seen:
                    continue

                for payload_name, payload, family in payloads:
                    if should_stop and should_stop():
                        break

                    candidate = dict(base_data)
                    candidate[name] = payload

                    try:
                        resp = _submit_form(client, method, action, candidate)
                    except httpx.HTTPError:
                        continue

                    marker = _extract_error_marker(resp.text, baseline_text)
                    if marker:
                        findings.append(
                            _to_finding(
                                action,
                                name,
                                payload_name,
                                f"Deserializer error marker '{marker}' for {family} payload",
                            )
                        )
                        seen.add(sig)
                        break

                    if baseline_code and baseline_code < 500 and resp.status_code >= 500:
                        findings.append(
                            _to_finding(
                                action,
                                name,
                                payload_name,
                                f"Status changed from {baseline_code} to {resp.status_code} for {family} payload",
                            )
                        )
                        seen.add(sig)
                        break

    return findings


def _to_finding(url: str, param: str, payload: str, evidence: str) -> dict[str, Any]:
    return {
        "title": f"Potential Insecure Deserialization on {urlparse(url).path or '/'}",
        "severity": "High",
        "cvss_score": 8.0,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_url": url,
        "parameter": param,
        "payload": payload,
        "evidence": evidence,
        "remediation": "Avoid native deserialization of untrusted data, enforce strict signed/typed formats, and use allowlisted classes only.",
        "owasp_category": "A08:2025 - Software & Data Integrity Failures",
    }
