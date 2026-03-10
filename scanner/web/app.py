"""FastAPI web application — GUI frontend for PentaVault.

Run with:
    python -m scanner.web.app
    # or
    cd scanner && python -m web.app

Opens at http://127.0.0.1:8000
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Ensure scanner package is importable
_WEB_DIR = Path(__file__).resolve().parent
_SCANNER_DIR = _WEB_DIR.parent
_PROJECT_DIR = _SCANNER_DIR.parent
if str(_PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(_PROJECT_DIR))

from scanner.utils.logger import setup_logger, get_logger
from scanner.utils.report_exporter import export_json, _build_summary, OWASP_2025
from scanner.utils.mitre_mapping import (
    MITRE_TECHNIQUES, build_mitre_breakdown, build_attack_paths,
    compute_matrix_coverage, get_all_tactics,
)
from scanner.core.recon import run_recon
from scanner.core.port_scanner import scan_ports
from scanner.core.fingerprint import run_fingerprint
from scanner.core.crawler import crawl
from scanner.core.scorer import enrich_findings
from scanner.modules.sqli import test_sqli
from scanner.modules.xss import test_xss
from scanner.modules.headers import test_headers
from scanner.modules.ssrf import test_ssrf
from scanner.modules.idor import test_idor
from scanner.modules.open_redirect import test_open_redirect

setup_logger()
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
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ── In-memory scan store ────────────────────────────────────────────
scans: dict[str, dict[str, Any]] = {}


# ── Pydantic models ────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target: str
    mode: str = Field(default="quick", pattern="^(quick|full|web-only|network-only)$")
    cookie: str | None = None
    threads: int = Field(default=5, ge=1, le=10)
    timeout: float = Field(default=10.0, ge=1.0, le=60.0)
    use_browser: bool = False


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


# ── Background scan runner ─────────────────────────────────────────
def _run_scan(scan_id: str, req: ScanRequest) -> None:
    """Execute the full scan pipeline (runs in a background thread)."""
    scan = scans[scan_id]
    url, hostname, is_url = _normalise_target(req.target)
    scan["url"] = url

    try:
        # ── Stage 1: Target Input ───────────────────────────────
        scan["current_stage"] = "Target Input"
        scan["progress"] = 5
        log.info("[%s] Target: %s | Mode: %s", scan_id[:8], url, req.mode)

        recon_data: dict[str, Any] = {}
        fingerprint_data: dict[str, Any] = {}

        # ── Stage 2: Recon ──────────────────────────────────────
        if req.mode in ("full", "network-only"):
            scan["current_stage"] = "Reconnaissance"
            scan["progress"] = 10
            t0 = time.monotonic()
            recon_data = run_recon(hostname)
            ip = recon_data.get("ip") or hostname
            port_data = scan_ports(ip)
            recon_data["open_ports"] = port_data["open_ports"]
            recon_data["services"] = port_data["services"]
            recon_data["os_guess"] = port_data["os_guess"]
            scan["stages"].append({"name": "Recon + Port Scan", "time": round(time.monotonic() - t0, 1)})
            scan["recon_data"] = recon_data

        # ── Stage 3: Fingerprinting ─────────────────────────────
        if req.mode in ("full", "web-only", "quick") and is_url:
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
                return
            scan["current_stage"] = "Web Crawling"
            scan["progress"] = 30
            t0 = time.monotonic()

            if req.use_browser:
                from scanner.core.selenium_crawler import selenium_crawl
                crawl_result = selenium_crawl(
                    url,
                    max_depth=2 if req.mode == "quick" else 3,
                    max_pages=50 if req.mode == "quick" else 200,
                    cookie=req.cookie,
                    headless=True,
                )
            else:
                crawl_result = crawl(
                    url,
                    max_depth=2 if req.mode == "quick" else 3,
                    max_pages=50 if req.mode == "quick" else 200,
                    cookie=req.cookie,
                    timeout=req.timeout,
                )
            endpoints = crawl_result.endpoints
            forms = crawl_result.forms
            crawl_summary = crawl_result.summary()
            crawler_label = "Selenium Crawler" if req.use_browser else "Crawler"
            scan["stages"].append({"name": crawler_label, "time": round(time.monotonic() - t0, 1)})
            scan["crawl_summary"] = crawl_summary

        # ── Stage 5: Vulnerability Testing ──────────────────────
        all_findings: list[dict[str, Any]] = []
        if req.mode != "network-only" and endpoints:
            if scan.get("_cancel"):
                return
            scan["current_stage"] = "Vulnerability Testing"
            scan["progress"] = 50
            t0 = time.monotonic()

            modules = [
                ("SQLi", lambda: test_sqli(endpoints, forms, cookie=req.cookie, timeout=req.timeout, quick=(req.mode == "quick"))),
                ("XSS", lambda: test_xss(endpoints, forms, waf_detected=waf_detected, cookie=req.cookie, timeout=req.timeout)),
                ("Headers", lambda: test_headers(url, cookie=req.cookie, timeout=req.timeout)),
                ("SSRF", lambda: test_ssrf(endpoints, forms, cookie=req.cookie, timeout=req.timeout)),
                ("IDOR", lambda: test_idor(endpoints, cookie=req.cookie, timeout=req.timeout)),
                ("Open Redirect", lambda: test_open_redirect(endpoints, cookie=req.cookie, timeout=req.timeout)),
            ]

            if req.use_browser:
                from scanner.modules.sqli_selenium import test_sqli_selenium
                from scanner.modules.xss_selenium import test_xss_selenium
                modules[0] = ("SQLi (Browser)", lambda: test_sqli_selenium(endpoints, forms, cookie=req.cookie, headless=True, quick=(req.mode == "quick"), evidence_dir="evidence"))
                modules[1] = ("XSS (Browser)", lambda: test_xss_selenium(endpoints, forms, waf_detected=waf_detected, cookie=req.cookie, headless=True, quick=(req.mode == "quick"), evidence_dir="evidence"))

            from concurrent.futures import ThreadPoolExecutor, as_completed

            total_modules = len(modules)
            completed = 0

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
                    # Kill any leftover Chrome processes spawned by Selenium
                    try:
                        import subprocess
                        subprocess.run(
                            ["taskkill", "/F", "/IM", "chromedriver.exe", "/T"],
                            capture_output=True, timeout=10,
                        )
                        subprocess.run(
                            ["taskkill", "/F", "/IM", "chrome.exe", "/T"],
                            capture_output=True, timeout=10,
                        )
                    except Exception:
                        pass
                    return []

                if error_container:
                    raise error_container[0]
                return result_container[0] if result_container else []

            # Run non-browser modules concurrently, browser modules sequentially
            if req.use_browser:
                browser_modules = modules[:2]
                http_modules = modules[2:]

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
                        except Exception as exc:
                            log.error("[%s] %s failed: %s", scan_id[:8], name, exc)
                            completed += 1

                # Browser modules: run sequentially with per-module progress + timeout
                browser_timeout = 120 if req.mode == "quick" else 180
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
                    except Exception as exc:
                        log.error("[%s] %s failed: %s", scan_id[:8], name, exc)
                        completed += 1
            else:
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
                        except Exception as exc:
                            log.error("[%s] %s failed: %s", scan_id[:8], name, exc)
                            completed += 1

            scan["stages"].append({"name": "Vulnerability Testing", "time": round(time.monotonic() - t0, 1)})

        # ── Stage 6: CVSS Scoring ───────────────────────────────
        scan["current_stage"] = "CVSS Scoring"
        scan["progress"] = 85
        all_findings = enrich_findings(all_findings)
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}
        all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "Low"), 4))

        # ── Stage 7: Report Generation ──────────────────────────
        scan["current_stage"] = "Report Generation"
        scan["progress"] = 90
        output_path = f"reports/scan_{scan_id[:8]}.json"
        os.makedirs("reports", exist_ok=True)
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
        scan["status"] = "completed"
        scan["progress"] = 100
        scan["current_stage"] = "Complete"
        scan["completed_at"] = datetime.now().isoformat(timespec="seconds")
        scan["findings_count"] = len(all_findings)
        log.info("[%s] Scan complete — %d findings", scan_id[:8], len(all_findings))

    except Exception as exc:
        scan["status"] = "failed"
        scan["current_stage"] = f"Error: {exc}"
        scan["error"] = str(exc)
        log.error("[%s] Scan failed: %s", scan_id[:8], exc, exc_info=True)


# ── API Endpoints ──────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main dashboard page."""
    index_path = STATIC_DIR / "index.html"
    return FileResponse(str(index_path))


@app.post("/api/scan", response_model=dict)
async def start_scan(req: ScanRequest):
    """Launch a new vulnerability scan."""
    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "target": req.target,
        "url": "",
        "mode": req.mode,
        "use_browser": req.use_browser,
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
    started = datetime.fromisoformat(scan["started_at"])
    elapsed = (datetime.now() - started).total_seconds()
    scan["elapsed"] = round(elapsed, 1)

    return scan


@app.get("/api/scan/{scan_id}/findings")
async def get_findings(scan_id: str):
    """Get detailed findings for a completed scan."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"findings": scans[scan_id].get("findings", [])}


@app.get("/api/scans")
async def list_scans():
    """List all scans (recent first)."""
    result = []
    for sid, s in sorted(scans.items(), key=lambda x: x[1]["started_at"], reverse=True):
        result.append({
            "scan_id": sid,
            "target": s["target"],
            "mode": s["mode"],
            "status": s["status"],
            "progress": s["progress"],
            "findings_count": s.get("findings_count", 0),
            "started_at": s["started_at"],
            "summary": s.get("summary", {}),
        })
    return result


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Remove a scan from memory."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    del scans[scan_id]
    return {"deleted": True}


@app.post("/api/scan/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Force-stop a running scan by marking it as cancelled."""
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]
    if scan["status"] != "running":
        return {"cancelled": False, "reason": "Scan is not running"}
    scan["status"] = "cancelled"
    scan["current_stage"] = "Cancelled by user"
    scan["completed_at"] = datetime.now().isoformat(timespec="seconds")
    # Mark as cancelled so _run_scan can check and exit early
    scan["_cancel"] = True
    log.info("[%s] Scan cancelled by user", scan_id[:8])
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
    findings = scans[scan_id].get("findings", [])
    return {
        "mitre_breakdown": build_mitre_breakdown(findings),
        "attack_paths": build_attack_paths(findings),
        "matrix_coverage": compute_matrix_coverage(findings),
    }


@app.get("/api/evidence/{filename}")
async def get_evidence(filename: str):
    """Serve a screenshot evidence file."""
    # Sanitize filename to prevent path traversal
    safe_name = Path(filename).name
    evidence_path = _SCANNER_DIR / "evidence" / safe_name
    if not evidence_path.exists() or not evidence_path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file not found")
    return FileResponse(str(evidence_path), media_type="image/png")


# ── Entry point ────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print("\n  ╔══════════════════════════════════════════════════╗")
    print("  ║  PentaVault — Web Dashboard                      ║")
    print("  ║  Open: http://127.0.0.1:8000                     ║")
    print("  ╚══════════════════════════════════════════════════╝\n")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
