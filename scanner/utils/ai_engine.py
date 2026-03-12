"""PentaVault AI Engine — Google Gemini integration for threat intelligence.

Provides:
  - Deep threat analysis (MITRE-aware, target-specific)
  - Per-finding remediation guidance (tech-stack-aware)
  - Executive summary generation (non-technical, management-ready)

Multiple API keys are supported with automatic failover on rate limits.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

_GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
_GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.0-flash"]


def _call_gemini(api_key: str | list[str], prompt: str, max_tokens: int = 4096) -> str:
    """Call Gemini API with automatic key + model rotation on rate limits."""
    keys = api_key if isinstance(api_key, list) else [api_key]
    last_error = None
    for key in keys:
        for model in _GEMINI_MODELS:
            url = f"{_GEMINI_BASE}/{model}:generateContent"
            try:
                resp = httpx.post(
                    url,
                    params={"key": key},
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {
                            "maxOutputTokens": max_tokens,
                            "temperature": 0.3,
                        },
                    },
                    timeout=60,
                )
                if resp.status_code == 429:
                    last_error = f"Rate limited (key ...{key[-6:]}, model {model})"
                    continue
                resp.raise_for_status()
                data = resp.json()
                candidates = data.get("candidates", [])
                if not candidates:
                    return "No response from AI model."
                parts = candidates[0].get("content", {}).get("parts", [])
                return parts[0].get("text", "") if parts else ""
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 429:
                    last_error = f"Rate limited (key ...{key[-6:]}, model {model})"
                    continue
                raise
    raise RuntimeError(f"All API keys/models exhausted: {last_error}")


def _summarise_findings(findings: list[dict[str, Any]], limit: int = 30) -> str:
    """Build a compact text summary of findings for the AI prompt.

    Only sends vulnerability metadata — never raw target URLs for privacy.
    """
    lines = []
    for i, f in enumerate(findings[:limit], 1):
        sev = f.get("severity", "Unknown")
        vuln_type = f.get("type", f.get("module", "Unknown"))
        owasp = f.get("owasp_category", "N/A")
        cvss = f.get("cvss_score", "N/A")
        detail = (f.get("detail", "") or "")[:150]
        param = f.get("parameter", f.get("param", ""))
        mitre = ", ".join(mt.get("technique", "") for mt in f.get("mitre_attack", []))
        recommendation = (f.get("recommendation", "") or "")[:100]
        lines.append(
            f"{i}. [{sev}] {vuln_type} | OWASP: {owasp} | CVSS: {cvss} | "
            f"MITRE: {mitre} | Param: {param} | Detail: {detail} | Rec: {recommendation}"
        )
    if len(findings) > limit:
        lines.append(f"... and {len(findings) - limit} more findings")
    return "\n".join(lines)


def _build_context(scan_data: dict[str, Any]) -> str:
    """Build scan context string for AI prompts."""
    target = scan_data.get("target", "unknown")
    mode = scan_data.get("mode", "unknown")
    fingerprint = scan_data.get("fingerprint_data") or {}
    tech_stack = fingerprint.get("technologies", [])
    waf = fingerprint.get("waf", "Unknown")
    ssl_info = fingerprint.get("ssl", {})
    recon = scan_data.get("recon_data") or {}

    parts = [
        f"Target: {target}",
        f"Scan mode: {mode}",
    ]
    if tech_stack:
        parts.append(f"Tech stack: {', '.join(str(t) for t in tech_stack[:10])}")
    if waf and waf != "Unknown":
        parts.append(f"WAF: {waf}")
    if ssl_info:
        parts.append(f"SSL/TLS: {json.dumps(ssl_info, default=str)[:200]}")
    if recon:
        dns = recon.get("dns", {})
        if dns:
            parts.append(f"DNS: {json.dumps(dns, default=str)[:200]}")

    return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════
#  PUBLIC API
# ═══════════════════════════════════════════════════════════════════

def ai_threat_analysis(
    api_key: str,
    scan_data: dict[str, Any],
    findings: list[dict[str, Any]],
    mitre_breakdown: list[dict[str, Any]],
    coverage: dict[str, Any],
) -> str:
    """Generate a deep, target-specific AI threat analysis."""
    context = _build_context(scan_data)
    findings_summary = _summarise_findings(findings)

    tactics_hit = coverage.get("tactics_with_hits", 0)
    total_tactics = coverage.get("total_tactics", 14)
    tech_hits = coverage.get("total_technique_hits", 0)

    tactic_list = ", ".join(
        f"{tg['tactic']} ({tg['technique_count']} techniques)"
        for tg in mitre_breakdown
    )

    prompt = f"""You are a senior penetration tester and threat intelligence analyst.

SCAN CONTEXT:
{context}

FINDINGS SUMMARY ({len(findings)} total):
{findings_summary}

MITRE ATT&CK COVERAGE: {tech_hits} techniques across {tactics_hit}/{total_tactics} tactics
Tactics detected: {tactic_list}

Provide a PROFESSIONAL threat intelligence analysis in this exact structure.
Use HTML formatting (<strong>, <em>, <ul><li>, <br>).
Make it understandable for BOTH beginners and security professionals.

Structure:
1. **Risk Overview** (2-3 sentences) — Overall risk posture of this specific target.
2. **Attack Chain Analysis** (paragraph) — How an attacker could CHAIN these specific vulnerabilities together step by step. Be very specific about the target.
3. **Critical Findings** (bullet list) — Top 3-5 most dangerous findings and WHY they matter.
4. **MITRE ATT&CK Implications** (paragraph) — What the tactic/technique coverage means in real-world adversary behavior.
5. **Priority Remediation** (numbered list) — What to fix FIRST and WHY, in order of urgency. Include specific actions.
6. **Business Impact** (2-3 sentences) — What could happen to the organisation if these are exploited, in non-technical language.

Be concise but thorough. Reference specific vulnerability types, parameters, and MITRE technique IDs found in the scan.
Do NOT use markdown headers (##). Use <strong> tags for section titles.
Do NOT include generic advice — everything must be specific to THIS scan's findings."""

    return _call_gemini(api_key, prompt, max_tokens=4096)


def ai_remediation(
    api_key: str,
    finding: dict[str, Any],
    scan_data: dict[str, Any],
) -> str:
    """Generate specific remediation guidance for a single finding."""
    context = _build_context(scan_data)
    vuln_type = finding.get("type", finding.get("module", "Unknown"))
    severity = finding.get("severity", "Unknown")
    detail = finding.get("detail", "") or ""
    param = finding.get("parameter", finding.get("param", ""))
    payload = finding.get("payload", "")
    url = finding.get("url", finding.get("path", ""))
    owasp = finding.get("owasp_category", "")
    mitre = ", ".join(
        f"{mt.get('technique', '')} ({mt.get('name', '')})"
        for mt in finding.get("mitre_attack", [])
    )
    recommendation = finding.get("recommendation", "")

    prompt = f"""You are a senior application security engineer providing remediation guidance.

SCAN CONTEXT:
{context}

VULNERABILITY:
- Type: {vuln_type}
- Severity: {severity}
- URL/Path: {url}
- Parameter: {param}
- Detail: {detail[:300]}
- Payload used: {payload[:200] if payload else 'N/A'}
- OWASP: {owasp}
- MITRE ATT&CK: {mitre}
- Scanner recommendation: {recommendation[:200]}

Provide SPECIFIC remediation guidance in HTML format (<strong>, <code>, <pre>, <ul><li>, <br>).
Make it understandable for developers who may not be security experts.

Include:
1. **What's the risk?** — Explain in plain English what an attacker could do with this vulnerability.
2. **Quick Fix** — The fastest thing to do RIGHT NOW to mitigate the risk.
3. **Proper Fix** — The correct long-term solution with code examples where applicable.
   - If it's a header issue, provide the exact header configuration.
   - If it's XSS, show input sanitization code.
   - If it's SQLi, show parameterized query examples.
   - Tailor code to the detected tech stack if known.
4. **Verification** — How to verify the fix works.

Use <code> for inline code and <pre> for code blocks.
Do NOT use markdown formatting. Use HTML only.
Be specific to this vulnerability, not generic."""

    return _call_gemini(api_key, prompt, max_tokens=2048)


def ai_mitre_explain(
    api_key: str,
    technique_id: str,
    technique_name: str,
    tactic: str,
    scan_data: dict[str, Any],
    findings: list[dict[str, Any]],
    user_question: str | None = None,
) -> str:
    """Generate an AI explanation of a MITRE ATT&CK technique in context."""
    context = _build_context(scan_data)
    target = scan_data.get("target", "unknown")

    # Collect findings that map to this technique
    related = []
    for f in findings:
        for mt in f.get("mitre_attack", []):
            if mt.get("technique", "") == technique_id:
                related.append(f)
                break
    related_summary = ""
    if related:
        related_summary = _summarise_findings(related, limit=10)
    else:
        related_summary = "No findings directly mapped to this technique in this scan."

    question_section = ""
    if user_question and user_question.strip():
        question_section = f"""\n\nUSER'S SPECIFIC QUESTION:
{user_question.strip()}

Address the user's question directly as part of your response."""

    prompt = f"""You are a senior threat intelligence analyst and cybersecurity educator.

SCAN CONTEXT:
{context}

MITRE ATT&CK TECHNIQUE:
- Technique ID: {technique_id}
- Technique Name: {technique_name}
- Tactic: {tactic}

RELATED FINDINGS FROM THIS SCAN:
{related_summary}
{question_section}

Provide a COMPREHENSIVE, EASY-TO-UNDERSTAND explanation in HTML format.
Make it accessible for beginners while still being valuable for experts.

Structure your response as:

1. <strong>What is {technique_id} ({technique_name})?</strong>
   - Plain-English explanation (2-3 sentences). Explain like you're talking to someone who is NOT a security expert.
   - Include a real-world analogy if helpful.

2. <strong>How Does This Attack Work?</strong>
   - Step-by-step breakdown of how an attacker uses this technique.
   - Be specific to web applications and the target: {target}
   - Use numbered steps.

3. <strong>Why Was This Detected in Your Scan?</strong>
   - Explain which specific findings in this scan relate to this technique and why.
   - If no related findings, explain what conditions would trigger it.

4. <strong>Real-World Impact</strong>
   - What could actually happen if this technique is exploited?
   - Give concrete examples (data theft, account takeover, etc.).

5. <strong>How to Defend Against It</strong>
   - Specific, actionable defense measures.
   - Include code examples or configuration snippets where applicable.
   - Tailor to the detected tech stack if known.

6. <strong>Detection Tips</strong>
   - How security teams can detect this technique in their environment.
   - Mention specific logs, tools, or indicators to watch for.

Use HTML formatting: <strong>, <em>, <code>, <pre>, <ul><li>, <ol><li>, <br>.
Do NOT use markdown. Keep it professional but approachable.
Be specific to THIS scan and THIS target — not generic."""

    return _call_gemini(api_key, prompt, max_tokens=4096)


def ai_executive_summary(
    api_key: str,
    scan_data: dict[str, Any],
    findings: list[dict[str, Any]],
) -> str:
    """Generate a non-technical executive summary for management."""
    context = _build_context(scan_data)
    findings_summary = _summarise_findings(findings, limit=20)
    target = scan_data.get("target", "unknown")

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        if sev in sev_counts:
            sev_counts[sev] += 1

    prompt = f"""You are a cybersecurity consultant writing an executive summary for a C-suite audience.

TARGET: {target}
SCAN CONTEXT:
{context}

SEVERITY BREAKDOWN:
- Critical: {sev_counts['Critical']}
- High: {sev_counts['High']}
- Medium: {sev_counts['Medium']}
- Low: {sev_counts['Low']}
- Total: {len(findings)}

FINDINGS OVERVIEW:
{findings_summary}

Write a PROFESSIONAL executive summary in HTML format. This will be read by non-technical executives.

Structure:
1. <strong>Overall Security Posture</strong> — One paragraph rating the target's security (use terms like Critical Risk, High Risk, Moderate Risk, Low Risk). Explain what this means in business terms.

2. <strong>Key Risks</strong> — 3-5 bullet points describing the most important risks in PLAIN ENGLISH. No jargon. Example: "An attacker could steal user login credentials" not "XSS enables session hijacking via T1539".

3. <strong>Business Impact</strong> — What could happen if these vulnerabilities are exploited? Think: data breach, regulatory fines, reputation damage, service disruption.

4. <strong>Recommended Actions</strong> — 3-5 prioritized action items. Keep each to one sentence. Example: "Immediately implement security headers on all web pages."

5. <strong>Timeline</strong> — Suggested fix timeline: what to do this week, this month, this quarter.

Use HTML formatting (<strong>, <ul><li>, <br>, <em>).
No MITRE IDs, no CVSS vectors, no technical jargon.
Write for someone who understands business but NOT cybersecurity."""

    return _call_gemini(api_key, prompt, max_tokens=2048)
