"""Contextual CVSS v3.1 vector builder.

Constructs CVSS vectors dynamically based on vulnerability context rather
than using hardcoded constants.  The existing ``scorer.compute_score()``
function is used to derive the numeric score from the resulting vector.
"""

from __future__ import annotations

from typing import Any


# ── Default metric values per vulnerability class ──────────────────
# These are the *base* values; context modifiers adjust them.
_DEFAULTS: dict[str, dict[str, str]] = {
    "sqli": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    },
    "xss_reflected": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "C", "C": "L", "I": "L", "A": "N",
    },
    "xss_stored": {
        "AV": "N", "AC": "L", "PR": "L", "UI": "R",
        "S": "C", "C": "L", "I": "L", "A": "N",
    },
    "xss_dom": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "C", "C": "L", "I": "L", "A": "N",
    },
    "ssrf_internal": {
        "AV": "N", "AC": "L", "PR": "L", "UI": "N",
        "S": "U", "C": "H", "I": "N", "A": "N",
    },
    "ssrf_cloud": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "N",
    },
    "idor": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "N", "A": "N",
    },
    "command_injection": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    },
    "xxe": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "N", "A": "L",
    },
    "lfi": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "N", "A": "N",
    },
    "nosqli": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "L",
    },
    "ssti": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    },
    "open_redirect": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "C", "C": "L", "I": "L", "A": "N",
    },
    "jwt": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "N",
    },
    "cors": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "U", "C": "H", "I": "N", "A": "N",
    },
    "request_smuggling": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N",
        "S": "U", "C": "L", "I": "H", "A": "L",
    },
    "mass_assignment": {
        "AV": "N", "AC": "L", "PR": "L", "UI": "N",
        "S": "U", "C": "H", "I": "L", "A": "N",
    },
    "bola": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "N",
    },
    "header_missing": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "R",
        "S": "U", "C": "N", "I": "L", "A": "N",
    },
    "graphql": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "N", "A": "N",
    },
    "host_header": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "U", "C": "N", "I": "L", "A": "N",
    },
    "crlf": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "C", "C": "L", "I": "L", "A": "N",
    },
    "hpp": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "N", "I": "L", "A": "N",
    },
    "deserialization": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    },
    "prototype_pollution": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "L", "I": "L", "A": "N",
    },
    "csv_injection": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "U", "C": "L", "I": "L", "A": "N",
    },
    "sensitive_files": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "L", "I": "N", "A": "N",
    },
}

# Fallback for unknown types
_GENERIC = {
    "AV": "N", "AC": "L", "PR": "N", "UI": "N",
    "S": "U", "C": "L", "I": "L", "A": "N",
}


def build_vector(
    vuln_type: str,
    *,
    auth_required: bool = False,
    waf_bypass: bool = False,
    scope_change: bool | None = None,
    confidentiality: str | None = None,
    integrity: str | None = None,
    availability: str | None = None,
) -> str:
    """Build a CVSS v3.1 vector string from vulnerability context.

    Parameters
    ----------
    vuln_type:
        Key into _DEFAULTS (e.g. ``"sqli"``, ``"xss_reflected"``).
    auth_required:
        True if a session cookie was needed — bumps PR from N to L.
    waf_bypass:
        True if WAF evasion payloads were required — bumps AC to H.
    scope_change:
        Override the Scope metric (True=Changed, False=Unchanged).
    confidentiality, integrity, availability:
        Override individual CIA impact metrics (N/L/H).
    """
    base = dict(_DEFAULTS.get(vuln_type, _GENERIC))

    # ── Context modifiers ──────────────────────────────────────
    if auth_required and base["PR"] == "N":
        base["PR"] = "L"

    if waf_bypass:
        base["AC"] = "H"

    if scope_change is not None:
        base["S"] = "C" if scope_change else "U"

    if confidentiality and confidentiality in ("N", "L", "H"):
        base["C"] = confidentiality
    if integrity and integrity in ("N", "L", "H"):
        base["I"] = integrity
    if availability and availability in ("N", "L", "H"):
        base["A"] = availability

    return _format_vector(base)


def _format_vector(metrics: dict[str, str]) -> str:
    """Format metrics dict into ``AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``."""
    order = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    return "/".join(f"{k}:{metrics[k]}" for k in order)


def build_finding_cvss(
    vuln_type: str,
    context: dict[str, Any] | None = None,
) -> tuple[str, float, str]:
    """Convenience: return (vector, score, severity) for a vulnerability.

    ``context`` may contain keys: ``auth_required``, ``waf_bypass``,
    ``scope_change``, ``confidentiality``, ``integrity``, ``availability``.
    """
    from scanner.core.scorer import compute_score, severity_label

    ctx = context or {}
    vector = build_vector(
        vuln_type,
        auth_required=ctx.get("auth_required", False),
        waf_bypass=ctx.get("waf_bypass", False),
        scope_change=ctx.get("scope_change"),
        confidentiality=ctx.get("confidentiality"),
        integrity=ctx.get("integrity"),
        availability=ctx.get("availability"),
    )
    score = compute_score(vector)
    severity = severity_label(score)
    return vector, score, severity
