"""PentaVault AI Engine — Google Gemini integration for threat intelligence.

Provides:
  - Deep threat analysis (MITRE-aware, target-specific)
  - Per-finding remediation guidance (tech-stack-aware)
  - Executive summary generation (non-technical, management-ready)

Multiple API keys are supported with automatic failover on rate limits.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx

_GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"
_DEFAULT_GEMINI_MODELS = ["gemini-2.0-flash", "gemini-1.5-flash"]

_RATE_LIMIT_STATUSES = {429}
_TRANSIENT_STATUSES = {408, 409, 500, 502, 503, 504}
_MODEL_RETRY_STATUSES = {400, 404}
_INVALID_KEY_STATUSES = {401}
_POTENTIALLY_QUOTA_STATUSES = {403}
_BASE_KEY_COOLDOWN_SECONDS = 15.0
_MAX_KEY_COOLDOWN_SECONDS = 300.0

_PROMPT_BASE_RULES = [
    "Use HTML fragments only (<strong>, <em>, <ul><li>, <ol><li>, <code>, <pre>, <br>, <p>, <div>, <span>).",
    "Do not use markdown syntax.",
    "Anchor every claim to the provided scan context and findings.",
    "Avoid generic advice and avoid role-play phrases.",
]


def _compose_prompt(role: str, context: str, body: str, extra_rules: list[str] | None = None) -> str:
    rules = _PROMPT_BASE_RULES + (extra_rules or [])
    rules_text = "\n".join(f"- {rule}" for rule in rules)
    return (
        f"Role: {role}\n\n"
        f"SCAN CONTEXT:\n{context}\n\n"
        f"OUTPUT RULES:\n{rules_text}\n\n"
        f"TASK:\n{body.strip()}"
    )


def load_gemini_api_keys() -> list[str]:
    """Load Gemini API keys from environment variables."""
    raw = os.environ.get("PENTAVAULT_GEMINI_API_KEYS", "")
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    if keys:
        return keys

    single_key = os.environ.get("GEMINI_API_KEY", "").strip()
    return [single_key] if single_key else []


def load_gemini_models() -> list[str]:
    """Load Gemini model list from environment with sane defaults."""
    raw = os.environ.get("PENTAVAULT_GEMINI_MODELS", "")
    models = [m.strip() for m in raw.split(",") if m.strip()]
    return models if models else _DEFAULT_GEMINI_MODELS


def _format_key_suffix(key: str) -> str:
    return f"...{key[-6:]}" if len(key) >= 6 else "(short-key)"


@dataclass
class _KeyState:
    key: str
    key_suffix: str
    cooldown_until: float = 0.0
    failures: int = 0
    disabled: bool = False

    def is_available(self, now: float) -> bool:
        return (not self.disabled) and now >= self.cooldown_until


class _GeminiKeyPool:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._states: list[_KeyState] = []
        self._next_index = 0

    def _sync_keys_locked(self, keys: list[str]) -> None:
        existing = {state.key: state for state in self._states}
        synced: list[_KeyState] = []
        for key in keys:
            state = existing.get(key)
            if state is None:
                state = _KeyState(key=key, key_suffix=_format_key_suffix(key))
            synced.append(state)
        self._states = synced
        if not self._states:
            self._next_index = 0
        else:
            self._next_index %= len(self._states)

    def configure_keys(self, keys: list[str]) -> None:
        with self._lock:
            self._sync_keys_locked(keys)

    def next_available_key(self, exclude_keys: set[str] | None = None) -> _KeyState | None:
        with self._lock:
            if not self._states:
                return None

            excluded = exclude_keys or set()
            now = time.time()
            total = len(self._states)
            earliest: _KeyState | None = None
            for offset in range(total):
                idx = (self._next_index + offset) % total
                state = self._states[idx]
                if state.disabled or state.key in excluded:
                    continue
                if earliest is None or state.cooldown_until < earliest.cooldown_until:
                    earliest = state
                if state.is_available(now):
                    self._next_index = (idx + 1) % total
                    return state
            if earliest and not earliest.disabled:
                self._next_index = (self._states.index(earliest) + 1) % total
                return earliest
            return None

    def mark_success(self, key: str) -> None:
        with self._lock:
            for state in self._states:
                if state.key == key:
                    state.failures = 0
                    state.cooldown_until = 0.0
                    return

    def mark_invalid_key(self, key: str) -> None:
        with self._lock:
            for state in self._states:
                if state.key == key:
                    state.disabled = True
                    state.cooldown_until = float("inf")
                    return

    def mark_quota_or_rate_limited(self, key: str) -> None:
        self._mark_with_backoff(key)

    def mark_transient_failure(self, key: str) -> None:
        self._mark_with_backoff(key)

    def _mark_with_backoff(self, key: str) -> None:
        with self._lock:
            now = time.time()
            for state in self._states:
                if state.key == key:
                    state.failures += 1
                    cooldown = min(
                        _BASE_KEY_COOLDOWN_SECONDS * (2 ** max(state.failures - 1, 0)),
                        _MAX_KEY_COOLDOWN_SECONDS,
                    )
                    state.cooldown_until = max(state.cooldown_until, now + cooldown)
                    return


_KEY_POOL = _GeminiKeyPool()


def _classify_403(exc: httpx.HTTPStatusError) -> str:
    body = ""
    try:
        body = exc.response.text or ""
    except Exception:
        body = ""
    lower = body.lower()
    if "quota" in lower or "rate" in lower or "exceeded" in lower or "resource exhausted" in lower:
        return "quota"
    return "invalid"


def _retry_model_only(status_code: int) -> bool:
    return status_code in _MODEL_RETRY_STATUSES


def _call_gemini(api_key: str | list[str], prompt: str, max_tokens: int = 4096) -> str:
    """Call Gemini API with key-pool rotation and model failover."""
    keys = [k for k in (api_key if isinstance(api_key, list) else [api_key]) if k]
    if not keys:
        raise RuntimeError("No Gemini API key configured")

    models = load_gemini_models()
    attempts: list[str] = []
    _KEY_POOL.configure_keys(keys)

    key_attempted: set[str] = set()
    while len(key_attempted) < len(keys):
        state = _KEY_POOL.next_available_key(exclude_keys=key_attempted)
        if state is None:
            break

        key = state.key
        key_suffix = state.key_suffix
        key_attempted.add(key)

        saw_quota_or_rate_limit = False
        saw_transient_failure = False

        for model in models:
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
                resp.raise_for_status()
                data = resp.json()
                candidates = data.get("candidates", [])
                _KEY_POOL.mark_success(key)
                if not candidates:
                    return "No response from AI model."
                parts = candidates[0].get("content", {}).get("parts", [])
                return parts[0].get("text", "") if parts else ""
            except httpx.HTTPStatusError as exc:
                status = exc.response.status_code
                attempts.append(f"HTTP {status} (key {key_suffix}, model {model})")

                if status in _RATE_LIMIT_STATUSES:
                    saw_quota_or_rate_limit = True
                    break
                if status in _TRANSIENT_STATUSES:
                    saw_transient_failure = True
                    continue
                if status in _INVALID_KEY_STATUSES:
                    _KEY_POOL.mark_invalid_key(key)
                    break
                if status in _POTENTIALLY_QUOTA_STATUSES:
                    if _classify_403(exc) == "quota":
                        saw_quota_or_rate_limit = True
                        break
                    _KEY_POOL.mark_invalid_key(key)
                    break

                if _retry_model_only(status):
                    continue
                raise
            except httpx.RequestError as exc:
                attempts.append(f"Request error {exc.__class__.__name__} (key {key_suffix}, model {model})")
                saw_transient_failure = True
                continue

        if saw_quota_or_rate_limit:
            _KEY_POOL.mark_quota_or_rate_limited(key)
        elif saw_transient_failure:
            _KEY_POOL.mark_transient_failure(key)

    attempts_text = "; ".join(attempts[-8:]) if attempts else "unknown error"
    raise RuntimeError(f"All API keys/models exhausted: {attempts_text}")


def _call_ollama(prompt: str, max_tokens: int = 4096) -> str:
    """Query a local Ollama server (http://localhost:11434)."""
    base_url = os.environ.get("PENTAVAULT_OLLAMA_URL") or os.environ.get("OLLAMA_HOST") or "http://localhost:11434"
    base_url = base_url.rstrip("/")
    if not base_url.startswith("http"):
        base_url = f"http://{base_url}"
    model = os.environ.get("PENTAVAULT_OLLAMA_MODEL") or os.environ.get("OLLAMA_MODEL") or "llama3.2"

    url = f"{base_url}/api/generate"
    try:
        resp = httpx.post(
            url,
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_predict": max_tokens,
                    "temperature": 0.3,
                },
            },
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("response", "")
    except Exception as exc:
        raise RuntimeError(f"Ollama local LLM request failed ({base_url}, model={model}): {exc}") from exc


def _call_openai_compatible(prompt: str, max_tokens: int = 4096) -> str:
    """Query a local OpenAI-compatible API (LM Studio, LocalAI, vLLM)."""
    base_url = os.environ.get("PENTAVAULT_OPENAI_LOCAL_URL") or os.environ.get("OPENAI_API_BASE") or "http://localhost:1234/v1"
    base_url = base_url.rstrip("/")
    model = os.environ.get("PENTAVAULT_OPENAI_LOCAL_MODEL") or os.environ.get("OPENAI_MODEL") or "local-model"
    api_key = os.environ.get("OPENAI_API_KEY", "not-needed")

    url = f"{base_url}/chat/completions"
    try:
        resp = httpx.post(
            url,
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "temperature": 0.3,
            },
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()
        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "")
        return ""
    except Exception as exc:
        raise RuntimeError(f"OpenAI-compatible local LLM request failed ({base_url}): {exc}") from exc


def _call_ai(api_key: str | list[str], prompt: str, max_tokens: int = 4096) -> str:
    """Unified AI dispatcher supporting Gemini cloud API with automatic Local LLM failover (Ollama / LocalAI)."""
    provider = (os.environ.get("PENTAVAULT_AI_PROVIDER") or os.environ.get("AI_PROVIDER") or "auto").lower().strip()

    if provider == "ollama":
        return _call_ollama(prompt, max_tokens=max_tokens)
    if provider in ("openai_local", "lmstudio", "vllm", "localai"):
        return _call_openai_compatible(prompt, max_tokens=max_tokens)
    if provider == "gemini":
        return _call_gemini(api_key, prompt, max_tokens=max_tokens)

    # Provider == "auto": Try Gemini first, fallback to Ollama then Local OpenAI if Gemini rate-limits or fails
    gemini_error = None
    try:
        keys = [k for k in (api_key if isinstance(api_key, list) else [api_key]) if k]
        if keys:
            return _call_gemini(keys, prompt, max_tokens=max_tokens)
    except Exception as exc:
        gemini_error = exc

    # Fallback attempt 1: Local Ollama
    try:
        return _call_ollama(prompt, max_tokens=max_tokens)
    except Exception:
        pass

    # Fallback attempt 2: Local OpenAI-compatible
    try:
        return _call_openai_compatible(prompt, max_tokens=max_tokens)
    except Exception:
        pass

    if gemini_error:
        raise gemini_error
    raise RuntimeError("No AI provider available (Gemini rate-limited/unconfigured and local LLM not reachable).")


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
    api_key: str | list[str],
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

    body = f"""
FINDINGS SUMMARY ({len(findings)} total):
{findings_summary}

MITRE ATT&CK COVERAGE: {tech_hits} techniques across {tactics_hit}/{total_tactics} tactics
Tactics detected: {tactic_list}

Provide a professional threat intelligence analysis with this exact structure:
1. Risk Overview (2-3 sentences) — overall risk posture of this specific target.
2. Attack Chain Analysis (paragraph) — how an attacker could chain these specific vulnerabilities together.
3. Critical Findings (bullet list) — top 3-5 most dangerous findings and why they matter.
4. MITRE ATT&CK Implications (paragraph) — what tactic/technique coverage implies about adversary behavior.
5. Priority Remediation (numbered list) — what to fix first and why.
6. Business Impact (2-3 sentences) — non-technical impact to the organisation.

Use <strong> tags for section titles.
"""
    prompt = _compose_prompt(
        role="Threat intelligence analyst for authorized penetration testing output.",
        context=context,
        body=body,
        extra_rules=[
            "Keep the analysis concise but thorough.",
            "Reference vulnerability types, parameters, and MITRE technique IDs from this scan when present.",
        ],
    )

    return _call_ai(api_key, prompt, max_tokens=4096)


def ai_remediation(
    api_key: str | list[str],
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

    body = f"""
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

Provide specific remediation guidance with this structure:
1. What's the risk? — explain in plain English what an attacker could do.
2. Quick Fix — fastest immediate mitigation.
3. Proper Fix — durable solution with concrete code/config examples.
4. Verification — practical steps to confirm the fix.

If relevant:
- for header issues, include exact header configuration;
- for XSS, include sanitization/encoding examples;
- for SQLi, include parameterized query examples;
- tailor examples to detected stack when context supports it.
"""
    prompt = _compose_prompt(
        role="Application security engineer producing remediation guidance.",
        context=context,
        body=body,
        extra_rules=[
            "Keep language understandable to developers who are not security specialists.",
            "Use <code> for inline code and <pre> for code blocks when examples are needed.",
            "Keep guidance specific to this vulnerability instance.",
        ],
    )

    return _call_ai(api_key, prompt, max_tokens=2048)


def ai_mitre_explain(
    api_key: str | list[str],
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

    body = f"""
MITRE ATT&CK TECHNIQUE:
- Technique ID: {technique_id}
- Technique Name: {technique_name}
- Tactic: {tactic}

RELATED FINDINGS FROM THIS SCAN:
{related_summary}
{question_section}

Provide a comprehensive explanation using this structure:
1. <strong>What is {technique_id} ({technique_name})?</strong>
   - Plain-English explanation (2-3 sentences).
2. <strong>How Does This Attack Work?</strong>
   - Step-by-step breakdown, specific to web applications and target: {target}.
3. <strong>Why Was This Detected in Your Scan?</strong>
   - Map to concrete findings, or explain likely trigger conditions if none map.
4. <strong>Real-World Impact</strong>
   - Concrete impact examples.
5. <strong>How to Defend Against It</strong>
   - Actionable defenses with code/config snippets where relevant.
6. <strong>Detection Tips</strong>
   - Logs, tools, and indicators defenders should monitor.
"""
    prompt = _compose_prompt(
        role="Threat intelligence analyst and cybersecurity educator.",
        context=context,
        body=body,
        extra_rules=[
            "Keep the explanation accessible to beginners and useful for experienced practitioners.",
            "Prefer concrete examples over abstract statements.",
        ],
    )

    return _call_ai(api_key, prompt, max_tokens=4096)


def ai_executive_summary(
    api_key: str | list[str],
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

    body = f"""
TARGET: {target}

SEVERITY BREAKDOWN:
- Critical: {sev_counts['Critical']}
- High: {sev_counts['High']}
- Medium: {sev_counts['Medium']}
- Low: {sev_counts['Low']}
- Total: {len(findings)}

FINDINGS OVERVIEW:
{findings_summary}

Write an executive summary for non-technical leaders with this structure:
1. <strong>Overall Security Posture</strong> — one paragraph with a clear risk rating and business interpretation.
2. <strong>Key Risks</strong> — 3-5 bullets in plain English.
3. <strong>Business Impact</strong> — practical consequences (breach, fines, reputation, downtime).
4. <strong>Recommended Actions</strong> — 3-5 prioritized, one-sentence actions.
5. <strong>Timeline</strong> — what to do this week, this month, this quarter.
"""
    prompt = _compose_prompt(
        role="Cybersecurity consultant writing for C-suite and business stakeholders.",
        context=context,
        body=body,
        extra_rules=[
            "Avoid MITRE IDs, CVSS vectors, and deep technical jargon.",
            "Use plain business language and concrete outcomes.",
        ],
    )

    return _call_ai(api_key, prompt, max_tokens=2048)

