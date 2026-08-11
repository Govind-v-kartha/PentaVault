"""PentaVault report exporter — bridges scanner output to the VAPT Reporting Tool.

Generates three report files:
  1. findings.json          — full structured report (all stages + findings)
  2. findings_executive.json — executive summary (counts, risk rating, top issues)
  3. findings_technical.json — grouped by OWASP category with detailed evidence
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import date, datetime
from typing import Any

from scanner.utils.logger import get_logger
from scanner.utils.mitre_mapping import build_mitre_breakdown

log = get_logger("report_exporter")

SCANNER_VERSION = "1.1.0"

# OWASP Top 10:2025 reference map (updated)
OWASP_2025 = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software & Data Integrity Failures",
    "A09:2025": "Security Logging & Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}


def _build_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    for f in findings:
        sev = f.get("severity", "Low").lower()
        if sev in counts:
            counts[sev] += 1

    # Overall risk rating
    if counts["critical"] > 0:
        risk = "Critical"
    elif counts["high"] > 0:
        risk = "High"
    elif counts["medium"] > 0:
        risk = "Medium"
    elif counts["low"] > 0:
        risk = "Low"
    else:
        risk = "Informational"

    return {
        "total_findings": len(findings),
        "risk_rating": risk,
        **counts,
    }


def _build_owasp_breakdown(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group findings by OWASP category and return counts + finding IDs."""
    groups: dict[str, list[str]] = defaultdict(list)
    for f in findings:
        cat = f.get("owasp_category", "Uncategorized")
        groups[cat].append(f.get("id", ""))

    breakdown = []
    for cat, ids in sorted(groups.items()):
        breakdown.append({
            "category": cat,
            "count": len(ids),
            "finding_ids": ids,
        })
    return breakdown


def _build_affected_endpoints(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build a per-endpoint view showing which vulns affect it."""
    ep_map: dict[str, list[dict[str, str]]] = defaultdict(list)
    for f in findings:
        url = f.get("affected_url", "")
        ep_map[url].append({
            "id": f.get("id", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
        })

    result = []
    for url, issues in sorted(ep_map.items()):
        result.append({"url": url, "issues": issues, "issue_count": len(issues)})
    result.sort(key=lambda x: x["issue_count"], reverse=True)
    return result


def _assign_ids(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for idx, f in enumerate(findings, start=1):
        f["id"] = f"F{idx:03d}"
    return findings


# ────────────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────────────

def export_json(
    target: str,
    findings: list[dict[str, Any]],
    output_path: str,
    recon_data: dict[str, Any] | None = None,
    fingerprint_data: dict[str, Any] | None = None,
    crawl_summary: dict[str, int] | None = None,
) -> str:
    """Write all three JSON reports and return the main report's absolute path."""
    findings = _assign_ids(findings)
    summary = _build_summary(findings)
    owasp_breakdown = _build_owasp_breakdown(findings)
    affected_endpoints = _build_affected_endpoints(findings)
    mitre_breakdown = build_mitre_breakdown(findings)

    # ── 1. Full report ──────────────────────────────────────────────
    report: dict[str, Any] = {
        "meta": {
            "report_type": "PentaVault — VAPT Scan Report",
            "target": target,
            "scan_date": date.today().isoformat(),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "scanner_version": SCANNER_VERSION,
            "owasp_reference": "OWASP Top 10:2025",
            "mitre_reference": "MITRE ATT&CK v15",
        },
        "summary": summary,
        "owasp_breakdown": owasp_breakdown,
        "mitre_attack_breakdown": mitre_breakdown,
        "affected_endpoints": affected_endpoints,
        "findings": findings,
    }

    if recon_data:
        report["recon"] = recon_data
    if fingerprint_data:
        report["fingerprint"] = fingerprint_data
    if crawl_summary:
        report["crawl_summary"] = crawl_summary

    base_dir = os.path.dirname(output_path) or "."
    os.makedirs(base_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(output_path))[0]

    main_path = output_path
    exec_path = os.path.join(base_dir, f"{base_name}_executive.json")
    tech_path = os.path.join(base_dir, f"{base_name}_technical.json")

    with open(main_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)

    # ── 2. Executive summary ────────────────────────────────────────
    top_issues = [
        {"id": f["id"], "title": f["title"], "severity": f["severity"],
         "cvss_score": f.get("cvss_score", 0)}
        for f in findings[:10]
    ]
    executive: dict[str, Any] = {
        "meta": report["meta"],
        "summary": summary,
        "risk_rating": summary["risk_rating"],
        "owasp_breakdown": owasp_breakdown,
        "mitre_attack_breakdown": mitre_breakdown,
        "top_issues": top_issues,
    }
    with open(exec_path, "w", encoding="utf-8") as fh:
        json.dump(executive, fh, indent=2, default=str)

    # ── 3. Technical detail (grouped by OWASP) ─────────────────────
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for f in findings:
        cat = f.get("owasp_category", "Uncategorized")
        grouped[cat].append(f)

    technical: dict[str, Any] = {
        "meta": report["meta"],
        "mitre_attack_breakdown": mitre_breakdown,
        "categories": [],
    }
    for cat in sorted(grouped):
        cat_findings = grouped[cat]
        technical["categories"].append({
            "owasp_category": cat,
            "finding_count": len(cat_findings),
            "max_severity": max(
                cat_findings,
                key=lambda x: {"Critical": 4, "High": 3, "Medium": 2,
                                "Low": 1, "None": 0}.get(x.get("severity", "Low"), 0)
            ).get("severity", "Low"),
            "findings": cat_findings,
        })
    with open(tech_path, "w", encoding="utf-8") as fh:
        json.dump(technical, fh, indent=2, default=str)

    log.info("Reports exported:")
    log.info("  Full      → %s (%d findings)", main_path, len(findings))
    log.info("  Executive → %s", exec_path)
    log.info("  Technical → %s", tech_path)
    return os.path.abspath(main_path)
