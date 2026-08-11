"""CVSS v3.1 scoring engine.

Parses CVSS vector strings and computes base scores following the
CVSS v3.1 specification.  Also provides severity classification.

If the ``cvss`` library is installed it will be used for validation;
otherwise a self-contained implementation is used so the scanner has
zero hard scoring dependencies.
"""

from __future__ import annotations

import math
from typing import Any

from scanner.utils.logger import get_logger

log = get_logger("scorer")

# ── CVSS v3.1 metric value weights ─────────────────────────────────
_METRICS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {  # values depend on Scope; handled in _pr_weight()
        "N": 0.85, "L": 0.62, "H": 0.27,
    },
    "PR_CHANGED": {
        "N": 0.85, "L": 0.68, "H": 0.50,
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S":  {"U": 0, "C": 1},  # 0 = Unchanged, 1 = Changed
    "C":  {"N": 0.00, "L": 0.22, "H": 0.56},
    "I":  {"N": 0.00, "L": 0.22, "H": 0.56},
    "A":  {"N": 0.00, "L": 0.22, "H": 0.56},
}


def _parse_vector(vector: str) -> dict[str, str]:
    """Parse ``CVSS:3.1/AV:N/AC:L/...`` into a dict."""
    parts = vector.replace("CVSS:3.1/", "").replace("CVSS:3.0/", "").split("/")
    parsed: dict[str, str] = {}
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            parsed[k.upper()] = v.upper()
    return parsed


def compute_score(vector: str) -> float:
    """Compute the CVSS v3.1 base score from a vector string.

    Returns a float rounded to one decimal place.
    """
    try:
        # Prefer the ``cvss`` library when available
        from cvss import CVSS3  # type: ignore[import-untyped]
        c = CVSS3(vector)
        return float(c.base_score)
    except Exception:
        pass

    # Fallback: self-contained scoring
    m = _parse_vector(vector)
    scope_changed = m.get("S") == "C"

    av = _METRICS["AV"].get(m.get("AV", "N"), 0.85)
    ac = _METRICS["AC"].get(m.get("AC", "L"), 0.77)
    pr_table = _METRICS["PR_CHANGED"] if scope_changed else _METRICS["PR"]
    pr = pr_table.get(m.get("PR", "N"), 0.85)
    ui = _METRICS["UI"].get(m.get("UI", "N"), 0.85)

    c_val = _METRICS["C"].get(m.get("C", "N"), 0.0)
    i_val = _METRICS["I"].get(m.get("I", "N"), 0.0)
    a_val = _METRICS["A"].get(m.get("A", "N"), 0.0)

    # ISS (Impact Sub Score)
    iss = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))

    if iss <= 0:
        return 0.0

    # Impact
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope_changed:
        score = min(1.08 * (impact + exploitability), 10.0)
    else:
        score = min(impact + exploitability, 10.0)

    return math.ceil(score * 10) / 10


def severity_label(score: float) -> str:
    """Map a CVSS score to its textual severity."""
    if score == 0.0:
        return "None"
    if score <= 3.9:
        return "Low"
    if score <= 6.9:
        return "Medium"
    if score <= 8.9:
        return "High"
    return "Critical"


def enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Recompute or attach CVSS score and severity label to a finding dict."""
    vector = finding.get("cvss_vector", "")
    if vector:
        score = compute_score(vector)
        finding["cvss_score"] = score
        finding["severity"] = severity_label(score)
    return finding


def enrich_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Batch-enrich all findings with CVSS scores and MITRE ATT&CK mappings."""
    from scanner.utils.mitre_mapping import enrich_findings_mitre

    for f in findings:
        enrich_finding(f)
    enrich_findings_mitre(findings)
    return findings
