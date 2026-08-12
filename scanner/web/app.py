"""FastAPI web application — GUI frontend for PentaVault.

Run with:
    python -m scanner.web.app
    # or
    cd scanner && python -m web.app

Opens at http://127.0.0.1:8000
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Ensure scanner package is importable
_WEB_DIR = Path(__file__).resolve().parent
_SCANNER_DIR = _WEB_DIR.parent
_PROJECT_DIR = _SCANNER_DIR.parent
if str(_PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(_PROJECT_DIR))

load_dotenv(_PROJECT_DIR / ".env")

from scanner.utils.logger import setup_logger, get_logger
from scanner.utils.report_exporter import export_json, _build_summary, OWASP_2025
from scanner.utils.mitre_mapping import (
    MITRE_TECHNIQUES, build_mitre_breakdown, build_attack_paths,
    compute_matrix_coverage, get_all_tactics, build_threat_narrative,
)
from scanner.utils.ai_engine import (
    ai_threat_analysis,
    ai_remediation,
    ai_executive_summary,
    ai_mitre_explain,
    load_gemini_api_keys,
)
from scanner.utils.pdf_report import generate_pdf, generate_docx
from scanner.core.recon import run_recon
from scanner.core.port_scanner import scan_ports
from scanner.core.fingerprint import run_fingerprint
from scanner.core.crawler import CrawlResult, crawl, merge_crawl_results

from scanner.core.dependency_check import check_dependencies
from scanner.core.scorer import enrich_findings
from scanner.modules.secrets_detection import test_secrets_detection
from scanner.modules.cloud_misconfig import test_cloud_misconfig
from scanner.modules.sqli import test_sqli


from scanner.modules.xss import test_xss
from scanner.modules.headers import test_headers
from scanner.modules.ssrf import test_ssrf
from scanner.modules.idor import test_idor
from scanner.modules.open_redirect import test_open_redirect
from scanner.modules.command_injection import test_command_injection
from scanner.modules.xxe import test_xxe
from scanner.modules.lfi import test_lfi
from scanner.modules.sensitive_files import test_sensitive_files
from scanner.modules.nosqli import test_nosqli
from scanner.modules.ssti import test_ssti
from scanner.modules.graphql_abuse import test_graphql_abuse
from scanner.modules.jwt_checks import test_jwt_checks
from scanner.modules.host_header import test_host_header_injection
from scanner.modules.cors_misconfig import test_cors_misconfig
from scanner.modules.hpp import test_hpp
from scanner.modules.crlf_injection import test_crlf_injection
from scanner.modules.request_smuggling import test_request_smuggling
from scanner.modules.mass_assignment import test_mass_assignment_bola
from scanner.modules.insecure_deserialization import test_insecure_deserialization
from scanner.modules.prototype_pollution import test_prototype_pollution
from scanner.modules.csv_formula_injection import test_csv_formula_injection
from scanner.modules.ssl_tls import test_ssl_tls


setup_logger(log_dir=os.environ.get("PENTAVAULT_LOGS_DIR", "logs"))
log = get_logger("web")

app = FastAPI(
    title="PentaVault",
    version="1.1.0",
    description="PentaVault — Automated VAPT Security Suite",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files (HTML/CSS/JS)
STATIC_DIR = _WEB_DIR / "static"
FRONTEND_DIR = _WEB_DIR / "frontend"
FRONTEND_DIST_DIR = FRONTEND_DIR / "dist"
FRONTEND_MODE = (os.environ.get("PENTAVAULT_FRONTEND_MODE", "legacy") or "legacy").strip().lower()
_FRONTEND_MODE_REACT = "react"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
_FRONTEND_ASSETS_DIR = FRONTEND_DIST_DIR / "assets"
if _FRONTEND_ASSETS_DIR.exists() and _FRONTEND_ASSETS_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=str(_FRONTEND_ASSETS_DIR)), name="frontend_assets")

# ── Vercel detection ────────────────────────────────────────────────
_IS_VERCEL = bool(os.environ.get("VERCEL"))

# ── Scan store with disk persistence ────────────────────────────────
DATA_DIR = Path(os.environ.get("PENTAVAULT_DATA_DIR", str(_SCANNER_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
_HISTORY_FILE = DATA_DIR / "scan_history.json"


def _load_history() -> dict[str, dict[str, Any]]:
    """Load persisted scan history from disk."""
    if _HISTORY_FILE.exists():
        try:
            with open(_HISTORY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            log.info("Loaded %d scans from history", len(data))
            return data
        except Exception as exc:
            log.warning("Failed to load scan history: %s", exc)
    return {}


def _save_history() -> None:
    """Persist completed/failed/cancelled scans to disk (atomic write)."""
    try:
        persistable = {}
        for sid, s in scans.items():
            if s.get("status") in ("completed", "failed", "cancelled"):
                # Shallow copy, drop non-serialisable transient keys
                entry = {k: v for k, v in s.items() if not k.startswith("_")}
                persistable[sid] = entry
        # Atomic write: write to temp file then rename to avoid corruption
        tmp_file = _HISTORY_FILE.with_suffix(".tmp")
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(persistable, f, default=str)
        tmp_file.replace(_HISTORY_FILE)
    except Exception as exc:
        log.warning("Failed to save scan history: %s", exc)


scans: dict[str, dict[str, Any]] = _load_history()


def _current_elapsed(scan: dict[str, Any]) -> float:
    started = datetime.fromisoformat(scan["started_at"])
    if scan.get("status") in ("completed", "failed", "cancelled") and scan.get("completed_at"):
        ended = datetime.fromisoformat(scan["completed_at"])
        return round((ended - started).total_seconds(), 1)
    return round((datetime.now() - started).total_seconds(), 1)


def _finalize_scan(
    scan: dict[str, Any],
    status: str,
    current_stage: str,
    *,
    error: str | None = None,
) -> None:
    scan["status"] = status
    scan["current_stage"] = current_stage
    scan["completed_at"] = datetime.now().isoformat(timespec="seconds")
    scan["elapsed"] = _current_elapsed(scan)
    if error is not None:
        scan["error"] = error
    _save_history()


def _ai_error_detail(code: str, message: str, retryable: bool) -> dict[str, Any]:
    return {"code": code, "message": message, "retryable": retryable}


def _raise_ai_config_error() -> None:
    raise HTTPException(
        status_code=400,
        detail=_ai_error_detail(
            "AI_CONFIG_MISSING",
            "AI service is not configured. Add API key settings in your environment and retry.",
            False,
        ),
    )


def _raise_ai_upstream_error(exc: Exception) -> None:
    log.error("AI upstream request failed: %s", exc, exc_info=True)
    raise HTTPException(
        status_code=502,
        detail=_ai_error_detail(
            "AI_UPSTREAM_UNAVAILABLE",
            "AI service is temporarily unavailable. Please retry in a moment.",
            True,
        ),
    )


def _raise_ai_internal_error(exc: Exception) -> None:
    log.error("AI internal error: %s", exc, exc_info=True)
    raise HTTPException(
        status_code=500,
        detail=_ai_error_detail(
            "AI_INTERNAL_ERROR",
            "AI request could not be completed due to an internal error.",
            True,
        ),
    )


def _raise_ai_endpoint_error(exc: Exception) -> None:
    if isinstance(exc, HTTPException):
        detail = exc.detail
        if isinstance(detail, dict) and {"code", "message", "retryable"}.issubset(detail.keys()):
            raise exc
        if exc.status_code == 400:
            _raise_ai_config_error()
        if exc.status_code in (502, 503, 504):
            _raise_ai_upstream_error(exc)
        _raise_ai_internal_error(exc)
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        _raise_ai_upstream_error(exc)
    _raise_ai_upstream_error(exc)


def _require_gemini_api_keys() -> list[str]:
    keys = load_gemini_api_keys()
    if not keys:
        # Retry after reloading .env in case keys were added after server start
        load_dotenv(_PROJECT_DIR / ".env", override=True)
        keys = load_gemini_api_keys()
    if not keys:
        _raise_ai_config_error()
    return keys


def _ai_findings_signature(findings: list[dict[str, Any]]) -> str:
    payload = []
    for finding in findings:
        payload.append({
            "type": finding.get("type"),
            "module": finding.get("module"),
            "severity": finding.get("severity"),
            "parameter": finding.get("parameter", finding.get("param")),
            "detail": finding.get("detail"),
            "payload": finding.get("payload"),
            "mitre_attack": finding.get("mitre_attack", []),
            "owasp_category": finding.get("owasp_category"),
            "cvss_score": finding.get("cvss_score"),
        })
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _ai_cache_key(name: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"v1:{name}:{digest}"


def _ai_cache_get(scan: dict[str, Any], key: str) -> str | None:
    cache = scan.get("_ai_cache")
    if not isinstance(cache, dict):
        return None
    value = cache.get(key)
    return value if isinstance(value, str) else None


def _ai_cache_set(scan: dict[str, Any], key: str, value: str) -> None:
    cache = scan.get("_ai_cache")
    if not isinstance(cache, dict):
        cache = {}
        scan["_ai_cache"] = cache
    cache[key] = value


def _mitre_cache_key(scan_id: str, findings: list[dict[str, Any]]) -> str:
    canonical = _ai_findings_signature(findings)
    return _ai_cache_key("scan_mitre", {"scan_id": scan_id, "findings_sig": canonical})


def _mitre_cache_get(scan: dict[str, Any], key: str) -> dict[str, Any] | None:
    cache = scan.get("_mitre_cache")
    if not isinstance(cache, dict):
        return None
    value = cache.get(key)
    return value if isinstance(value, dict) else None


def _mitre_cache_set(scan: dict[str, Any], key: str, value: dict[str, Any]) -> None:
    cache = scan.get("_mitre_cache")
    if not isinstance(cache, dict):
        cache = {}
        scan["_mitre_cache"] = cache
    cache[key] = value


# ── Pydantic models ────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target: str
    mode: str = Field(default="quick", pattern="^(quick|full|web-only|network-only)$")
    cookie: str | None = None
    threads: int = Field(default=5, ge=1, le=10)
    timeout: float = Field(default=10.0, ge=1.0, le=60.0)
    request_delay: float = Field(default=0.0, ge=0.0, le=2.0)
    use_browser: bool = False
    crawl_mode: str = Field(default="auto", pattern="^(auto|httpx|selenium|hybrid)$")


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    target: str
    mode: str
    progress: int
    current_stage: str
    stages: list[dict[str, Any]]
    started_at: str
    elapsed: float
    findings_count: int


# ── Helper: normalise target ───────────────────────────────────────
def _normalise_target(raw: str) -> tuple[str, str, bool]:
    from urllib.parse import urlparse
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        return raw.rstrip("/"), parsed.hostname or raw, True
    host = raw.split(":")[0]
    return f"http://{raw.rstrip('/')}", host, False




def _ensure_scan_runtime_metadata(scan: dict[str, Any]) -> None:
    runtime = scan.get("runtime_config")
    if not isinstance(runtime, dict):
        runtime = {}
        scan["runtime_config"] = runtime

    threads = scan.get("threads")
    timeout = scan.get("timeout")
    request_delay = scan.get("request_delay")

    runtime.setdefault("mode", scan.get("mode", "quick"))
    runtime.setdefault("threads", threads if isinstance(threads, int) else 0)
    runtime.setdefault("timeout_seconds", float(timeout) if isinstance(timeout, (int, float)) else 0.0)
    runtime.setdefault("request_delay_seconds", float(request_delay) if isinstance(request_delay, (int, float)) else 0.0)
    runtime.setdefault("use_browser", bool(scan.get("use_browser", False)))
    runtime.setdefault("crawl_mode", scan.get("crawl_mode", "auto"))

    execution = scan.get("execution_metadata")
    if not isinstance(execution, dict):
        execution = {}
        scan["execution_metadata"] = execution

    execution.setdefault("http_parallelization", "threadpool")
    execution.setdefault("http_module_workers", runtime.get("threads", 0))
    execution.setdefault("resolved_crawl_mode", runtime.get("crawl_mode", "auto"))
    execution.setdefault("browser_module_execution", "disabled")
    execution.setdefault("browser_module_timeout_seconds", 0)
    execution.setdefault("http_module_count", 0)
    execution.setdefault("browser_module_count", 0)


# ── Background scan runner ─────────────────────────────────────────
def _run_scan(scan_id: str, req: ScanRequest) -> None:
    """Execute the full scan pipeline (runs in a background thread)."""
    scan = scans[scan_id]
    _ensure_scan_runtime_metadata(scan)
    url, hostname, is_url = _normalise_target(req.target)
    scan["url"] = url

    try:
        # ── Connectivity pre-check ──────────────────────────────
        if is_url:
            import httpx as _hx
            try:
                _hx.get(url, timeout=15, verify=False, follow_redirects=True)
            except Exception as exc:
                _finalize_scan(scan, "failed", f"Error: Target unreachable: {exc}", error=f"Target unreachable: {exc}")
                log.error("[%s] Target unreachable: %s", scan_id[:8], exc)
                return

        # ── Stage 1: Target Input ───────────────────────────────
        t0 = time.monotonic()
        scan["current_stage"] = "Target Input"

        scan["progress"] = 5
        log.info("[%s] Target: %s | Mode: %s | Threads: %d | Timeout: %.1fs | Delay: %.2fs | Browser: %s | Crawl mode: %s | Cookie: %s",
                 scan_id[:8], url, req.mode, req.threads, req.timeout, req.request_delay, req.use_browser, req.crawl_mode, bool(req.cookie))

        dep = check_dependencies(mode=req.mode, use_browser=req.use_browser)
        for warning in dep["warnings"]:
            log.warning("[%s] Preflight: %s", scan_id[:8], warning)
        if not dep["ok"]:
            _finalize_scan(scan, "failed", "Dependency check failed", error="; ".join(dep["errors"]))
            return

        scan["dependency_warnings"] = dep["warnings"]
        scan["dependency_capabilities"] = dep["capabilities"]

        recon_data: dict[str, Any] = {}
        fingerprint_data: dict[str, Any] = {}

        # ── Stage 2: Recon ──────────────────────────────────────
        scan["runtime_config"]["mode"] = req.mode
        scan["runtime_config"]["threads"] = req.threads
        scan["runtime_config"]["timeout_seconds"] = req.timeout
        scan["runtime_config"]["request_delay_seconds"] = req.request_delay
        scan["execution_metadata"]["http_module_workers"] = req.threads

        if req.mode in ("full", "network-only"):
            if scan.get("_cancel"):
                _finalize_scan(scan, "cancelled", "Cancelled by user")
                return
            scan["current_stage"] = "Reconnaissance"
            scan["progress"] = 10
            t0 = time.monotonic()
            should_stop = lambda: bool(scan.get("_cancel"))

            recon_data = run_recon(hostname, should_stop=should_stop)
            if recon_data.get("takeover_findings"):
                scan["findings"].extend(recon_data["takeover_findings"])
            ip = recon_data.get("ip") or hostname

            port_data = scan_ports(ip)
            recon_data["open_ports"] = port_data["open_ports"]
            recon_data["services"] = port_data["services"]
            recon_data["os_guess"] = port_data["os_guess"]
            scan["stages"].append({"name": "Recon + Port Scan", "time": round(time.monotonic() - t0, 1)})
            scan["recon_data"] = recon_data

        # ── Stage 3: Fingerprinting ─────────────────────────────
        if req.mode in ("full", "web-only", "quick") and is_url:
            if scan.get("_cancel"):
                _finalize_scan(scan, "cancelled", "Cancelled by user")
                return
            scan["current_stage"] = "Fingerprinting"
            scan["progress"] = 20
            t0 = time.monotonic()
            fingerprint_data = run_fingerprint(url, hostname)
            scan["stages"].append({"name": "Fingerprinting", "time": round(time.monotonic() - t0, 1)})
            scan["fingerprint_data"] = fingerprint_data

        waf_detected = bool(fingerprint_data.get("waf"))

        # ── Stage 4: Crawling ───────────────────────────────────
        endpoints: list[str] = []
        forms: list[dict[str, Any]] = []
        crawl_summary: dict[str, int] | None = None

        if req.mode in ("full", "web-only", "quick") and is_url:
            if scan.get("_cancel"):
                _finalize_scan(scan, "cancelled", "Cancelled by user")
                return
            scan["current_stage"] = "Web Crawling"
            scan["progress"] = 30
            t0 = time.monotonic()

            use_browser = scan.get("use_browser", req.use_browser)
            crawl_mode = (req.crawl_mode or "auto")
            if crawl_mode == "auto":
                crawl_mode = "selenium" if use_browser else "httpx"
            scan["runtime_config"]["use_browser"] = bool(use_browser)
            scan["runtime_config"]["crawl_mode"] = crawl_mode
            scan["execution_metadata"]["resolved_crawl_mode"] = crawl_mode

            max_depth = 2 if req.mode == "quick" else 3
            max_pages = 50 if req.mode == "quick" else 200
            should_stop = lambda: bool(scan.get("_cancel"))

            if crawl_mode == "selenium":
                try:
                    from scanner.core.selenium_crawler import selenium_crawl

                    crawl_result = selenium_crawl(
                        url,
                        max_depth=max_depth,
                        max_pages=max_pages,
                        cookie=req.cookie,
                        headless=True,
                        should_stop=should_stop,
                        request_delay=req.request_delay,
                    )
                    crawler_label = "Selenium Crawler"
                except Exception as exc:
                    log.warning("[%s] Selenium crawl failed (%s), falling back to httpx crawler", scan_id[:8], exc)
                    crawl_result = crawl(
                        url,
                        max_depth=max_depth,
                        max_pages=max_pages,
                        cookie=req.cookie,
                        timeout=req.timeout,
                        respect_robots=(req.mode == "quick"),
                        should_stop=should_stop,
                        request_delay=req.request_delay,
                    )
                    crawler_label = "Crawler (Selenium fallback)"
            elif crawl_mode == "hybrid":
                from scanner.core.selenium_crawler import selenium_crawl

                primary = crawl(
                    url,
                    max_depth=max_depth,
                    max_pages=max_pages,
                    cookie=req.cookie,
                    timeout=req.timeout,
                    respect_robots=(req.mode == "quick"),
                    should_stop=should_stop,
                    request_delay=req.request_delay,
                )
                needs_fallback = len(primary.endpoints) < 5 or len(primary.forms) < 1
                if needs_fallback and not should_stop():
                    try:
                        fallback = selenium_crawl(
                            url,
                            max_depth=max_depth,
                            max_pages=max_pages,
                            cookie=req.cookie,
                            headless=True,
                            should_stop=should_stop,
                            request_delay=req.request_delay,
                        )
                        crawl_result = merge_crawl_results(primary, fallback)

                        crawler_label = "Hybrid Crawler"
                    except Exception as exc:
                        log.warning("[%s] Selenium fallback failed (%s), using httpx results only", scan_id[:8], exc)
                        crawl_result = primary
                        crawler_label = "Crawler (Hybrid/Selenium unavailable)"
                else:
                    crawl_result = primary
                    crawler_label = "Crawler"
            else:
                crawl_result = crawl(
                    url,
                    max_depth=max_depth,
                    max_pages=max_pages,
                    cookie=req.cookie,
                    timeout=req.timeout,
                    respect_robots=(req.mode == "quick"),
                    should_stop=should_stop,
                    request_delay=req.request_delay,
                )
                crawler_label = "Crawler"

            endpoints = crawl_result.endpoints
            forms = crawl_result.forms
            crawl_summary = crawl_result.summary()
            scan["stages"].append({"name": crawler_label, "time": round(time.monotonic() - t0, 1)})
            scan["crawl_summary"] = crawl_summary

        # ── Stage 5: Vulnerability Testing ──────────────────────
        all_findings: list[dict[str, Any]] = []
        is_quick = (req.mode == "quick")

        # Secrets Detection on crawled page sources and JS files
        if crawl_result:
            secrets_findings = test_secrets_detection(
                crawl_result=crawl_result,
                base_url=url,
                cookie=req.cookie,
                timeout=req.timeout,
                quick=is_quick,
                should_stop=should_stop,
            )
            if secrets_findings:
                all_findings.extend(secrets_findings)

        if req.mode != "network-only" and endpoints:
            if scan.get("_cancel"):
                _finalize_scan(scan, "cancelled", "Cancelled by user")
                return
            scan["current_stage"] = "Vulnerability Testing"
            scan["progress"] = 50
            t0 = time.monotonic()


            log.info("[%s] Starting vulnerability testing on %d endpoints | threads=%d | timeout=%.1fs | quick=%s",
                     scan_id[:8], len(endpoints), req.threads, req.timeout, is_quick)

            # Re-read mutable Selenium flag (may have been toggled mid-scan)
            use_browser_vuln = scan.get("use_browser", req.use_browser)
            scan["runtime_config"]["use_browser"] = bool(use_browser_vuln)

            should_stop = lambda: bool(scan.get("_cancel"))
            modules = [
                ("SQLi", lambda: test_sqli(endpoints, forms, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("XSS", lambda: test_xss(endpoints, forms, waf_detected=waf_detected, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("Headers", lambda: test_headers(url, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("SSRF", lambda: test_ssrf(endpoints, forms, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("IDOR", lambda: test_idor(endpoints, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("Open Redirect", lambda: test_open_redirect(endpoints, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("Command Injection", lambda: test_command_injection(endpoints, forms, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("XXE", lambda: test_xxe(endpoints, forms, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("LFI", lambda: test_lfi(endpoints, forms, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("Sensitive Files", lambda: test_sensitive_files(url, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("NoSQLi", lambda: test_nosqli(endpoints, forms, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("SSTI", lambda: test_ssti(endpoints, forms, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("GraphQL Abuse", lambda: test_graphql_abuse(url, endpoints, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("JWT Checks", lambda: test_jwt_checks(endpoints, forms, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("Host Header Injection", lambda: test_host_header_injection(url, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("CORS Misconfiguration", lambda: test_cors_misconfig(url, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("HTTP Parameter Pollution", lambda: test_hpp(endpoints, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("CRLF Injection", lambda: test_crlf_injection(endpoints, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("Request Smuggling", lambda: test_request_smuggling(url, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("Mass Assignment/BOLA", lambda: test_mass_assignment_bola(endpoints, forms, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("Insecure Deserialization", lambda: test_insecure_deserialization(endpoints, forms, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("Prototype Pollution", lambda: test_prototype_pollution(endpoints, forms, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("CSV/Formula Injection", lambda: test_csv_formula_injection(endpoints, forms, cookie=req.cookie, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("SSL/TLS Analysis", lambda: test_ssl_tls(url, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
                ("Cloud Misconfiguration", lambda: test_cloud_misconfig(url, crawl_result=crawl_result, timeout=req.timeout, quick=is_quick, should_stop=should_stop)),
            ]



            if use_browser_vuln:
                from scanner.modules.sqli_selenium import test_sqli_selenium
                from scanner.modules.xss_selenium import test_xss_selenium
                modules[0] = ("SQLi (Browser)", lambda: test_sqli_selenium(endpoints, forms, cookie=req.cookie, headless=True, quick=is_quick, evidence_dir="evidence", should_stop=should_stop))
                modules[1] = ("XSS (Browser)", lambda: test_xss_selenium(endpoints, forms, waf_detected=waf_detected, cookie=req.cookie, headless=True, quick=is_quick, evidence_dir="evidence", should_stop=should_stop))
                log.info("[%s] Using Selenium browser for SQLi and XSS tests (module timeout: %ds)", scan_id[:8], 120 if req.mode == "quick" else 180)
            else:
                log.info("[%s] Using standard HTTP modules for all vulnerability tests", scan_id[:8])

            from concurrent.futures import ThreadPoolExecutor, as_completed

            total_modules = len(modules)
            completed = 0
            browser_module_count = 2 if use_browser_vuln else 0
            http_module_count = total_modules - browser_module_count
            scan["execution_metadata"]["http_module_count"] = http_module_count
            scan["execution_metadata"]["browser_module_count"] = browser_module_count
            scan["execution_metadata"]["http_module_workers"] = req.threads

            def _run_module_with_timeout(name, fn, timeout_sec=300):
                """Run a module function with a hard timeout.

                Uses a daemon thread so the process can exit even if the
                module is still running, and forcefully kills any leftover
                Chrome/Selenium processes after timeout.
                """
                import threading

                result_container: list[list[dict[str, Any]]] = []
                error_container: list[Exception] = []

                def _worker():
                    try:
                        result_container.append(fn())
                    except Exception as exc:
                        error_container.append(exc)

                t = threading.Thread(target=_worker, daemon=True)
                t.start()
                t.join(timeout=timeout_sec)

                if t.is_alive():
                    log.warning("[%s] %s timed out after %ds — killing browser", scan_id[:8], name, timeout_sec)
                    # Kill leftover browser processes on Windows when available.
                    try:
                        import subprocess
                        if os.name == "nt":
                            subprocess.run(
                                ["taskkill", "/F", "/IM", "chromedriver.exe", "/T"],
                                capture_output=True, timeout=10,
                            )
                            subprocess.run(
                                ["taskkill", "/F", "/IM", "chrome.exe", "/T"],
                                capture_output=True, timeout=10,
                            )
                            subprocess.run(
                                ["taskkill", "/F", "/IM", "msedgedriver.exe", "/T"],
                                capture_output=True, timeout=10,
                            )
                            subprocess.run(
                                ["taskkill", "/F", "/IM", "msedge.exe", "/T"],
                                capture_output=True, timeout=10,
                            )
                    except Exception:
                        pass
                    return []

                if error_container:
                    raise error_container[0]
                return result_container[0] if result_container else []

            # Run non-browser modules concurrently, browser modules sequentially
            if use_browser_vuln:
                browser_modules = modules[:2]
                http_modules = modules[2:]
                scan["execution_metadata"]["browser_module_execution"] = "sequential"

                log.info("[%s] Selenium ON: running %d HTTP modules with %d threads, then %d browser modules sequentially",
                         scan_id[:8], len(http_modules), req.threads, len(browser_modules))

                with ThreadPoolExecutor(max_workers=req.threads) as pool:
                    futures = {pool.submit(fn): name for name, fn in http_modules}
                    for future in as_completed(futures):
                        name = futures[future]
                        try:
                            results = future.result()
                            all_findings.extend(results)
                            completed += 1
                            scan["progress"] = 50 + int(30 * completed / total_modules)
                            scan["module_results"][name] = len(results)
                            scan["findings_count"] = len(all_findings)
                            log.info("[%s] %s completed: %d findings (total: %d)", scan_id[:8], name, len(results), len(all_findings))
                        except Exception as exc:
                            log.error("[%s] %s failed: %s", scan_id[:8], name, exc)
                            completed += 1

                # Browser modules: run sequentially with per-module progress + timeout
                browser_timeout = 120 if req.mode == "quick" else 180
                scan["execution_metadata"]["browser_module_timeout_seconds"] = browser_timeout
                for name, fn in browser_modules:
                    if scan.get("_cancel"):
                        break
                    scan["current_stage"] = f"Vulnerability Testing — {name}"
                    try:
                        results = _run_module_with_timeout(name, fn, timeout_sec=browser_timeout)
                        all_findings.extend(results)
                        completed += 1
                        scan["progress"] = 50 + int(30 * completed / total_modules)
                        scan["module_results"][name] = len(results)
                        scan["findings_count"] = len(all_findings)
                        log.info("[%s] %s completed: %d findings (total: %d)", scan_id[:8], name, len(results), len(all_findings))
                    except Exception as exc:
                        log.error("[%s] %s failed: %s", scan_id[:8], name, exc)
                        completed += 1
            else:
                scan["execution_metadata"]["browser_module_execution"] = "disabled"
                scan["execution_metadata"]["browser_module_timeout_seconds"] = 0
                log.info("[%s] Selenium OFF: running all %d modules with %d threads",
                         scan_id[:8], len(modules), req.threads)
                with ThreadPoolExecutor(max_workers=req.threads) as pool:
                    futures = {pool.submit(fn): name for name, fn in modules}
                    for future in as_completed(futures):
                        name = futures[future]
                        try:
                            results = future.result()
                            all_findings.extend(results)
                            completed += 1
                            scan["progress"] = 50 + int(30 * completed / total_modules)
                            scan["module_results"][name] = len(results)
                            scan["findings_count"] = len(all_findings)
                            log.info("[%s] %s completed: %d findings (total: %d)", scan_id[:8], name, len(results), len(all_findings))
                        except Exception as exc:
                            log.error("[%s] %s failed: %s", scan_id[:8], name, exc)
                            completed += 1

            scan["stages"].append({"name": "Vulnerability Testing", "time": round(time.monotonic() - t0, 1)})

        # ── Stage 6: CVSS Scoring ───────────────────────────────
        if scan.get("_cancel"):
            _finalize_scan(scan, "cancelled", "Cancelled by user")
            return
        scan["current_stage"] = "CVSS Scoring"
        scan["progress"] = 85
        all_findings = enrich_findings(all_findings)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}
        all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "Low"), 4))

        # ── Stage 7: Report Generation ──────────────────────────
        scan["current_stage"] = "Report Generation"
        scan["progress"] = 90
        reports_dir = os.environ.get("PENTAVAULT_REPORTS_DIR", "reports")
        output_path = f"{reports_dir}/scan_{scan_id[:8]}.json"
        os.makedirs(reports_dir, exist_ok=True)
        export_json(
            target=url,
            findings=all_findings,
            output_path=output_path,
            recon_data=recon_data or None,
            fingerprint_data=fingerprint_data or None,
            crawl_summary=crawl_summary,
        )

        # Store results
        scan["findings"] = all_findings
        scan["summary"] = _build_summary(all_findings)
        scan["report_path"] = output_path
        scan["progress"] = 100
        scan["findings_count"] = len(all_findings)
        log.info("[%s] Scan complete — %d findings", scan_id[:8], len(all_findings))
        _finalize_scan(scan, "completed", "Complete")

    except Exception as exc:
        _finalize_scan(scan, "failed", f"Error: {exc}", error=str(exc))
        log.error("[%s] Scan failed: %s", scan_id[:8], exc, exc_info=True)


# ── API Endpoints ──────────────────────────────────────────────────

def _resolve_dashboard_index_path() -> Path:
    if FRONTEND_MODE == _FRONTEND_MODE_REACT:
        react_index = FRONTEND_DIST_DIR / "index.html"
        if react_index.exists() and react_index.is_file():
            return react_index
        log.warning("PENTAVAULT_FRONTEND_MODE=react but frontend dist not found; falling back to legacy static index")
    return STATIC_DIR / "index.html"


def _frontend_mode_state() -> dict[str, Any]:
    selected = FRONTEND_MODE if FRONTEND_MODE in {"legacy", _FRONTEND_MODE_REACT} else "legacy"
    available = ["legacy"]
    react_dist_ready = bool((FRONTEND_DIST_DIR / "index.html").exists() and (FRONTEND_DIST_DIR / "index.html").is_file())
    if react_dist_ready:
        available.append(_FRONTEND_MODE_REACT)
    active = _FRONTEND_MODE_REACT if (selected == _FRONTEND_MODE_REACT and react_dist_ready) else "legacy"
    return {
        "selected_mode": selected,
        "active_mode": active,
        "react_dist_ready": react_dist_ready,
        "available_modes": available,
    }


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main dashboard page."""
    return FileResponse(str(_resolve_dashboard_index_path()))


@app.get("/api/frontend/mode")
async def frontend_mode_info():
    """Expose selected/active dashboard frontend mode for runtime diagnostics."""
    return _frontend_mode_state()


@app.post("/api/scan", response_model=dict)
async def start_scan(req: ScanRequest):
    """Launch a new vulnerability scan."""
    if _IS_VERCEL:
        raise HTTPException(
            status_code=503,
            detail="Live scanning is unavailable on the Vercel deployment. "
                   "Run PentaVault locally for active scanning.",
        )
    preflight = check_dependencies(mode=req.mode, use_browser=req.use_browser)
    if not preflight["ok"]:
        raise HTTPException(status_code=400, detail={"errors": preflight["errors"], "warnings": preflight["warnings"]})

    req.request_delay = min(max(req.request_delay, 0.0), 2.0)

    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "target": req.target,
        "url": "",
        "mode": req.mode,
        "threads": req.threads,
        "timeout": req.timeout,
        "use_browser": req.use_browser,
        "crawl_mode": req.crawl_mode,
        "request_delay": req.request_delay,
        "progress": 0,
        "current_stage": "Initialising",
        "stages": [],
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "completed_at": None,
        "elapsed": 0,
        "findings": [],
        "findings_count": 0,
        "summary": {},
        "module_results": {},
        "crawl_summary": None,
        "fingerprint_data": None,
        "recon_data": None,
        "report_path": None,
        "error": None,
        "runtime_config": {
            "mode": req.mode,
            "threads": req.threads,
            "timeout_seconds": req.timeout,
            "request_delay_seconds": req.request_delay,
            "use_browser": req.use_browser,
            "crawl_mode": req.crawl_mode,
        },
        "execution_metadata": {
            "http_parallelization": "threadpool",
            "http_module_workers": req.threads,
            "resolved_crawl_mode": req.crawl_mode,
            "browser_module_execution": "disabled",
            "browser_module_timeout_seconds": 0,
            "http_module_count": 0,
            "browser_module_count": 0,
        },
        "dependency_warnings": preflight["warnings"],
        "dependency_capabilities": preflight["capabilities"],
    }

    # Run scan in background thread
    import threading
    thread = threading.Thread(target=_run_scan, args=(scan_id, req), daemon=True)
    thread.start()

    return {"scan_id": scan_id, "status": "started"}


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get the current status and results of a scan."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = scans[scan_id]
    _ensure_scan_runtime_metadata(scan)
    scan["elapsed"] = _current_elapsed(scan)
    return scan


@app.get("/api/scan/{scan_id}/findings")
async def get_findings(scan_id: str):
    """Get detailed findings for a completed scan."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"findings": scans[scan_id].get("findings", [])}


@app.get("/api/scan/{scan_id}/stream")
async def scan_progress_stream(scan_id: str):
    """SSE stream for real-time scan progress updates."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def _progress_events():
        last_progress = -1
        last_findings_count = 0
        last_stage_count = 0
        while True:
            if scan_id not in scans:
                break
            scan = scans[scan_id]
            progress = scan.get("progress", 0)
            findings = scan.get("findings", [])
            stages = scan.get("stages", [])
            status = scan.get("status", "running")

            # Send progress update if changed
            if progress != last_progress or len(findings) != last_findings_count:
                evt_data = {
                    "event": "progress",
                    "progress": progress,
                    "current_stage": scan.get("current_stage", ""),
                    "findings_count": len(findings),
                    "elapsed": _current_elapsed(scan),
                    "status": status,
                    "stages": stages,
                    "module_results": scan.get("module_results", {}),
                }
                yield f"data: {json.dumps(evt_data, default=str)}\n\n"
                last_progress = progress

            # Send new findings
            if len(findings) > last_findings_count:
                for f in findings[last_findings_count:]:
                    fd = {"event": "finding", "finding": f}
                    yield f"data: {json.dumps(fd, default=str)}\n\n"
                last_findings_count = len(findings)

            # Send new completed stages
            if len(stages) > last_stage_count:
                for st in stages[last_stage_count:]:
                    sd = {"event": "stage_complete", "stage": st}
                    yield f"data: {json.dumps(sd, default=str)}\n\n"
                last_stage_count = len(stages)

            # Terminal states
            if status in ("completed", "failed", "cancelled"):
                done_evt = {
                    "event": "complete" if status == "completed" else status,
                    "status": status,
                    "elapsed": _current_elapsed(scan),
                    "findings_count": len(findings),
                }
                yield f"data: {json.dumps(done_evt, default=str)}\n\n"
                break

            await asyncio.sleep(0.8)

    return StreamingResponse(
        _progress_events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@app.get("/api/scans")
async def list_scans():
    """List all scans (recent first)."""
    result = []
    for sid, s in sorted(scans.items(), key=lambda x: x[1]["started_at"], reverse=True):
        # Build severity counts
        sev_counts = {}
        for f in s.get("findings", []):
            sev = f.get("severity", "Info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        result.append({
            "scan_id": sid,
            "target": s["target"],
            "mode": s["mode"],
            "status": s["status"],
            "progress": s["progress"],
            "findings_count": s.get("findings_count", 0),
            "started_at": s["started_at"],
            "elapsed": s.get("elapsed", _current_elapsed(s)),
            "severity_counts": sev_counts,
            "summary": s.get("summary", {}),
        })
    return result


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Remove a scan from memory."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    del scans[scan_id]
    _save_history()
    return {"deleted": True}


@app.patch("/api/scan/{scan_id}")
async def update_scan_config(scan_id: str, body: dict):
    """Update mutable scan options (e.g. use_browser) while running."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]
    _ensure_scan_runtime_metadata(scan)
    if "use_browser" in body:
        scan["use_browser"] = bool(body["use_browser"])
        scan["runtime_config"]["use_browser"] = scan["use_browser"]
        log.info("[%s] Selenium toggled to %s mid-scan", scan_id[:8], scan["use_browser"])
    return {"updated": True}


@app.post("/api/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Force-stop a running scan by marking it as cancelled."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]
    if scan["status"] != "running":
        return {"cancelled": False, "reason": "Scan is not running"}
    # Signal the background thread; terminal state is finalized by worker.
    scan["_cancel"] = True
    scan["current_stage"] = "Cancellation requested"
    log.info("[%s] Scan cancellation requested by user", scan_id[:8])
    return {"cancelled": True}


@app.get("/api/owasp")
async def get_owasp_map():
    """Return the OWASP Top 10:2025 category reference."""
    return OWASP_2025


@app.get("/api/mitre")
async def get_mitre_map():
    """Return the full MITRE ATT&CK technique reference with metadata."""
    return MITRE_TECHNIQUES


@app.get("/api/mitre/tactics")
async def get_mitre_tactics():
    """Return ordered list of all 14 ATT&CK Enterprise tactics."""
    return get_all_tactics()


@app.get("/api/scan/{scan_id}/mitre")
async def get_mitre_breakdown(scan_id: str):
    """Return the MITRE ATT&CK breakdown for a scan."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]
    findings = scan.get("findings", [])
    target = scan.get("target", "")

    cache_key = _mitre_cache_key(scan_id, findings)
    cached = _mitre_cache_get(scan, cache_key)
    if cached is not None:
        return cached

    breakdown = build_mitre_breakdown(findings)
    attack_paths = build_attack_paths(findings)
    coverage = compute_matrix_coverage(findings)
    narrative = build_threat_narrative(target, findings, breakdown, coverage)

    payload = {
        "target": target,
        "threat_narrative": narrative,
        "mitre_breakdown": breakdown,
        "attack_paths": attack_paths,
        "matrix_coverage": coverage,
    }
    _mitre_cache_set(scan, cache_key, payload)
    return payload


@app.get("/api/evidence/{filename}")
async def get_evidence(filename: str):
    """Serve a screenshot evidence file."""
    # Sanitize filename to prevent path traversal
    safe_name = Path(filename).name
    evidence_path = _SCANNER_DIR / "evidence" / safe_name
    if not evidence_path.exists() or not evidence_path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file not found")
    return FileResponse(str(evidence_path), media_type="image/png")


# ── AI Endpoints ───────────────────────────────────────────────────

class AIRequest(BaseModel):
    scan_id: str
    finding_index: int | None = None  # for per-finding remediation


class MitreExplainRequest(BaseModel):
    scan_id: str
    technique_id: str
    technique_name: str = ""
    tactic: str = ""
    question: str = ""


def _stream_error_detail(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, HTTPException):
        detail = exc.detail
        if isinstance(detail, dict) and {"code", "message", "retryable"}.issubset(detail.keys()):
            return {
                "code": str(detail.get("code", "AI_UPSTREAM_UNAVAILABLE")),
                "message": str(detail.get("message", "AI request failed.")),
                "retryable": bool(detail.get("retryable", True)),
            }

        if exc.status_code == 404:
            return _ai_error_detail("SCAN_NOT_FOUND", "Scan not found.", False)

        if exc.status_code == 400:
            if isinstance(detail, dict):
                errors = detail.get("errors")
                if isinstance(errors, list) and errors:
                    message = str(errors[0])
                else:
                    message = "Invalid AI request."
            elif isinstance(detail, str) and detail.strip():
                message = detail.strip()
            else:
                message = "Invalid AI request."
            return _ai_error_detail("AI_REQUEST_INVALID", message, False)

        return _ai_error_detail("AI_REQUEST_FAILED", "AI request failed.", exc.status_code >= 500)

    try:
        _raise_ai_endpoint_error(exc)
    except HTTPException as mapped:
        mapped_detail = mapped.detail
        if isinstance(mapped_detail, dict) and {"code", "message", "retryable"}.issubset(mapped_detail.keys()):
            return {
                "code": str(mapped_detail["code"]),
                "message": str(mapped_detail["message"]),
                "retryable": bool(mapped_detail["retryable"]),
            }

    return _ai_error_detail(
        "AI_UPSTREAM_UNAVAILABLE",
        "AI service is temporarily unavailable. Please retry in a moment.",
        True,
    )


def _sse_event(event: str, data: dict[str, Any]) -> str:
    payload = json.dumps(data, ensure_ascii=False, default=str)
    return f"event: {event}\ndata: {payload}\n\n"


def _chunk_text(text: str, chunk_size: int = 320) -> list[str]:
    if not text:
        return []

    chunks: list[str] = []
    start = 0
    total_len = len(text)
    while start < total_len:
        end = min(start + chunk_size, total_len)
        if end < total_len:
            split_at = text.rfind(" ", start, end)
            if split_at > start + 40:
                end = split_at

        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        start = end
        while start < total_len and text[start].isspace():
            start += 1

    return chunks


def _ai_streaming_response(
    *,
    endpoint: str,
    result_key: str,
    compute: Callable[[], Any],
) -> StreamingResponse:
    async def _event_stream():
        yield _sse_event(
            "start",
            {
                "endpoint": endpoint,
                "started_at": datetime.now().isoformat(timespec="seconds"),
            },
        )

        try:
            payload = await compute()
            if not isinstance(payload, dict):
                payload = {result_key: str(payload)}

            text_value = payload.get(result_key, "")
            if not isinstance(text_value, str):
                text_value = str(text_value)

            chunks = _chunk_text(text_value)
            if chunks:
                for idx, chunk in enumerate(chunks, start=1):
                    yield _sse_event("delta", {"chunk": chunk, "index": idx, "total": len(chunks)})
                    await asyncio.sleep(0)
            else:
                yield _sse_event("delta", {"chunk": "", "index": 1, "total": 1})

            yield _sse_event("final", payload)
        except Exception as exc:
            yield _sse_event("error", _stream_error_detail(exc))

        yield _sse_event(
            "done",
            {
                "endpoint": endpoint,
                "finished_at": datetime.now().isoformat(timespec="seconds"),
            },
        )

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/ai/analyze")
async def ai_analyze(req: AIRequest):
    """Generate AI threat analysis for a completed scan."""
    if req.scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[req.scan_id]
    findings = scan.get("findings", [])
    if not findings:
        raise HTTPException(status_code=400, detail="No findings to analyse")

    findings_sig = _ai_findings_signature(findings)
    cache_key = _ai_cache_key("analyze", {"scan_id": req.scan_id, "findings_sig": findings_sig})
    cached = _ai_cache_get(scan, cache_key)
    if cached is not None:
        return {"analysis": cached}

    breakdown = build_mitre_breakdown(findings)
    coverage = compute_matrix_coverage(findings)
    gemini_api_keys = _require_gemini_api_keys()
    try:
        result = ai_threat_analysis(gemini_api_keys, scan, findings, breakdown, coverage)
    except Exception as exc:
        _raise_ai_endpoint_error(exc)

    _ai_cache_set(scan, cache_key, result)
    return {"analysis": result}


@app.post("/api/ai/analyze/stream")
async def ai_analyze_stream(req: AIRequest):
    """Stream AI threat analysis in SSE format with sanitized error events."""

    async def _compute() -> dict[str, Any]:
        return await ai_analyze(req)

    return _ai_streaming_response(endpoint="analyze", result_key="analysis", compute=_compute)


@app.post("/api/ai/remediate")
async def ai_remediate(req: AIRequest):
    """Generate AI remediation guidance for a specific finding."""
    if req.scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[req.scan_id]
    findings = scan.get("findings", [])
    idx = req.finding_index
    if idx is None or idx < 0 or idx >= len(findings):
        raise HTTPException(status_code=400, detail="Invalid finding index")

    finding = findings[idx]
    findings_sig = _ai_findings_signature(findings)
    cache_key = _ai_cache_key(
        "remediate",
        {
            "scan_id": req.scan_id,
            "finding_index": idx,
            "finding": finding,
            "findings_sig": findings_sig,
        },
    )
    cached = _ai_cache_get(scan, cache_key)
    if cached is not None:
        return {"remediation": cached}

    gemini_api_keys = _require_gemini_api_keys()
    try:
        result = ai_remediation(gemini_api_keys, finding, scan)
    except Exception as exc:
        _raise_ai_endpoint_error(exc)

    _ai_cache_set(scan, cache_key, result)
    return {"remediation": result}


@app.post("/api/ai/remediate/stream")
async def ai_remediate_stream(req: AIRequest):
    """Stream AI remediation guidance in SSE format with sanitized error events."""

    async def _compute() -> dict[str, Any]:
        return await ai_remediate(req)

    return _ai_streaming_response(endpoint="remediate", result_key="remediation", compute=_compute)


@app.post("/api/ai/executive-summary")
async def ai_exec_summary(req: AIRequest):
    """Generate an AI-powered executive summary."""
    if req.scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[req.scan_id]
    findings = scan.get("findings", [])

    findings_sig = _ai_findings_signature(findings)
    cache_key = _ai_cache_key("executive_summary", {"scan_id": req.scan_id, "findings_sig": findings_sig})
    cached = _ai_cache_get(scan, cache_key)
    if cached is not None:
        scan["_ai_executive_summary"] = cached
        return {"summary": cached}

    gemini_api_keys = _require_gemini_api_keys()
    try:
        result = ai_executive_summary(gemini_api_keys, scan, findings)
    except Exception as exc:
        _raise_ai_endpoint_error(exc)

    _ai_cache_set(scan, cache_key, result)
    scan["_ai_executive_summary"] = result
    return {"summary": result}


@app.post("/api/ai/executive-summary/stream")
async def ai_exec_summary_stream(req: AIRequest):
    """Stream AI executive summary in SSE format with sanitized error events."""

    async def _compute() -> dict[str, Any]:
        return await ai_exec_summary(req)

    return _ai_streaming_response(endpoint="executive-summary", result_key="summary", compute=_compute)


@app.post("/api/ai/mitre-explain")
async def ai_mitre_explain_endpoint(req: MitreExplainRequest):
    """Generate AI explanation of a MITRE ATT&CK technique in scan context."""
    if req.scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[req.scan_id]
    findings = scan.get("findings", [])

    findings_sig = _ai_findings_signature(findings)
    cache_key = _ai_cache_key(
        "mitre_explain",
        {
            "scan_id": req.scan_id,
            "technique_id": req.technique_id,
            "technique_name": req.technique_name,
            "tactic": req.tactic,
            "question": (req.question or "").strip(),
            "findings_sig": findings_sig,
        },
    )
    cached = _ai_cache_get(scan, cache_key)
    if cached is not None:
        return {"explanation": cached}

    gemini_api_keys = _require_gemini_api_keys()
    try:
        result = ai_mitre_explain(
            gemini_api_keys,
            req.technique_id,
            req.technique_name,
            req.tactic,
            scan,
            findings,
            req.question or None,
        )
    except Exception as exc:
        _raise_ai_endpoint_error(exc)

    _ai_cache_set(scan, cache_key, result)
    return {"explanation": result}


@app.post("/api/ai/mitre-explain/stream")
async def ai_mitre_explain_stream(req: MitreExplainRequest):
    """Stream AI MITRE explanation in SSE format with sanitized error events."""

    async def _compute() -> dict[str, Any]:
        return await ai_mitre_explain_endpoint(req)

    return _ai_streaming_response(endpoint="mitre-explain", result_key="explanation", compute=_compute)


# ── Report Download Endpoints ──────────────────────────────────────

@app.get("/api/scan/{scan_id}/report/pdf")
async def download_pdf(scan_id: str):
    """Download professional PDF report."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]
    findings = scan.get("findings", [])
    target = scan.get("target", "Unknown")
    # Build MITRE data
    mitre_data = None
    if findings:
        breakdown = build_mitre_breakdown(findings)
        attack_paths = build_attack_paths(findings)
        coverage = compute_matrix_coverage(findings)
        narrative = build_threat_narrative(target, findings, breakdown, coverage)
        mitre_data = {
            "mitre_breakdown": breakdown,
            "attack_paths": attack_paths,
            "matrix_coverage": coverage,
            "threat_narrative": narrative,
        }
    # Get AI summary if cached
    ai_summary = scan.get("_ai_executive_summary")
    try:
        pdf_bytes = bytes(generate_pdf(target, findings, scan, mitre_data, ai_summary))
    except Exception as exc:
        log.error("PDF generation failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")
    safe_target = "".join(c if c.isalnum() or c in "-_." else "_" for c in target[:30])
    filename = f"PentaVault_Report_{safe_target}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scan/{scan_id}/report/docx")
async def download_docx(scan_id: str):
    """Download professional DOCX report."""
    preflight = check_dependencies(mode="quick", use_browser=False, need_docx=True)
    if not preflight["ok"]:
        raise HTTPException(status_code=400, detail={"errors": preflight["errors"], "warnings": preflight["warnings"]})
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]
    findings = scan.get("findings", [])
    target = scan.get("target", "Unknown")
    mitre_data = None
    if findings:
        breakdown = build_mitre_breakdown(findings)
        attack_paths = build_attack_paths(findings)
        coverage = compute_matrix_coverage(findings)
        narrative = build_threat_narrative(target, findings, breakdown, coverage)
        mitre_data = {
            "mitre_breakdown": breakdown,
            "attack_paths": attack_paths,
            "matrix_coverage": coverage,
            "threat_narrative": narrative,
        }
    ai_summary = scan.get("_ai_executive_summary")
    try:
        docx_bytes = bytes(generate_docx(target, findings, scan, mitre_data, ai_summary))
    except Exception as exc:
        log.error("DOCX generation failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"DOCX generation failed: {exc}")
    safe_target = "".join(c if c.isalnum() or c in "-_." else "_" for c in target[:30])
    filename = f"PentaVault_Report_{safe_target}.docx"
    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scan/{scan_id}/report/json")
async def download_json(scan_id: str):
    """Download scan results as JSON."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]
    export_data = {
        "scan_id": scan_id,
        "target": scan.get("target"),
        "mode": scan.get("mode"),
        "status": scan.get("status"),
        "started_at": scan.get("started_at"),
        "elapsed": scan.get("elapsed"),
        "findings": scan.get("findings", []),
        "stages": scan.get("stages", []),
        "summary": scan.get("summary", {}),
    }
    content = json.dumps(export_data, indent=2, default=str, ensure_ascii=False)
    safe_target = "".join(c if c.isalnum() or c in "-_." else "_" for c in (scan.get("target", ""))[:30])
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="PentaVault_{safe_target}.json"'},
    )


# ── SPA catch-all for React Router ─────────────────────────────────
@app.get("/{full_path:path}", response_class=HTMLResponse)
async def spa_catch_all(full_path: str):
    """Serve the React SPA for all non-API routes (client-side routing support)."""
    # Don't catch API routes or static assets
    if full_path.startswith(("api/", "static/", "assets/")):
        raise HTTPException(status_code=404)
    return FileResponse(str(_resolve_dashboard_index_path()))


# ── Entry point ────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("PENTAVAULT_HOST", "127.0.0.1")
    port = int(os.environ.get("PENTAVAULT_PORT", os.environ.get("PORT", "8000")))

    banner = (
        "\n  ╔══════════════════════════════════════════════════╗\n"
        "  ║  PentaVault — Web Dashboard                      ║\n"
        f"  ║  Open: http://{host}:{port}                     ║\n"
        "  ╚══════════════════════════════════════════════════╝\n"
    )
    try:
        print(banner)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        print(banner.encode(encoding, errors="replace").decode(encoding, errors="replace"))

    uvicorn.run(app, host=host, port=port, log_level="info")
