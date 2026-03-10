#!/usr/bin/env python3
"""PentaVault — CLI entry point.

Usage examples:
    python main.py --target https://example.com --mode full --output findings.json
    python main.py --target 192.168.1.1 --mode network-only
    python main.py --target https://example.com --mode web-only --cookie "session=abc123"

This tool is intended **exclusively for authorized security testing**.
Unauthorized scanning of systems you do not own or have written permission
to test is illegal and unethical.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urlparse

# Ensure the parent directory of the scanner package is on sys.path so that
# ``python main.py`` works regardless of the working directory.
_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_PACKAGE_DIR)
if _PROJECT_DIR not in sys.path:
    sys.path.insert(0, _PROJECT_DIR)

from scanner.utils.logger import setup_logger, get_logger
from scanner.utils.report_exporter import export_json
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
from scanner.modules.sqli_selenium import test_sqli_selenium
from scanner.modules.xss_selenium import test_xss_selenium


BANNER = r"""
  ╔══════════════════════════════════════════════╗
  ║        PentaVault  v1.1.0                    ║
  ║   For authorized VAPT engagements only.      ║
  ║   --browser  →  Selenium-powered scanning    ║
  ╚══════════════════════════════════════════════╝
"""


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PentaVault — Automated VAPT Security Suite.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python main.py --target https://example.com --mode full --output findings.json",
    )
    parser.add_argument(
        "--target", required=True,
        help="URL or IP address to test (e.g. https://example.com or 192.168.1.1)",
    )
    parser.add_argument(
        "--mode", choices=["quick", "full", "web-only", "network-only"],
        default="full",
        help="Scan mode (default: full)",
    )
    parser.add_argument(
        "--output", default="findings.json",
        help="Output path for the JSON report (default: findings.json)",
    )
    parser.add_argument(
        "--cookie", default=None,
        help="Session cookie for authenticated scans (e.g. 'session=abc123')",
    )
    parser.add_argument(
        "--threads", type=int, default=5,
        help="Number of concurrent vulnerability-testing threads (default: 5, max: 10)",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0,
        help="Per-request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--browser", action="store_true", default=False,
        help="Use Selenium (headless Chrome) for crawling and vulnerability testing. "
             "More accurate — renders JS, confirms XSS via real alert(), captures screenshots.",
    )
    parser.add_argument(
        "--headed", action="store_true", default=False,
        help="Show the browser window (implies --browser). Useful for debugging.",
    )
    return parser.parse_args()


def _normalise_target(raw: str) -> tuple[str, str, bool]:
    """Return (url, hostname, is_url).

    If the user passes a bare IP / hostname, we default to ``http://``.
    """
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        return raw.rstrip("/"), parsed.hostname or raw, True

    # Bare IP or domain — treat as hostname
    host = raw.split(":")[0]
    return f"http://{raw.rstrip('/')}", host, False


# ── Scan pipeline ───────────────────────────────────────────────────

def _run_web_modules(
    endpoints: list[str],
    forms: list[dict[str, Any]],
    base_url: str,
    waf_detected: bool,
    cookie: str | None,
    timeout: float,
    threads: int,
    quick: bool = False,
    use_browser: bool = False,
    headless: bool = True,
) -> list[dict[str, Any]]:
    """Execute all web vulnerability modules concurrently."""
    log = get_logger("main")
    all_findings: list[dict[str, Any]] = []

    evidence_dir = "evidence" if use_browser else None

    def _sqli():
        if use_browser:
            return test_sqli_selenium(
                endpoints, forms, cookie=cookie,
                headless=headless, quick=quick, evidence_dir=evidence_dir,
            )
        return test_sqli(endpoints, forms, cookie=cookie, timeout=timeout, quick=quick)

    def _xss():
        if use_browser:
            return test_xss_selenium(
                endpoints, forms, waf_detected=waf_detected, cookie=cookie,
                headless=headless, evidence_dir=evidence_dir,
            )
        return test_xss(endpoints, forms, waf_detected=waf_detected, cookie=cookie, timeout=timeout)

    def _hdrs():
        return test_headers(base_url, cookie=cookie, timeout=timeout)

    def _ssrf():
        return test_ssrf(endpoints, forms, cookie=cookie, timeout=timeout)

    def _idor():
        return test_idor(endpoints, cookie=cookie, timeout=timeout)

    def _redirect():
        return test_open_redirect(endpoints, cookie=cookie, timeout=timeout)

    def _timed(name: str, fn):
        """Wrapper that times a module and logs duration."""
        t0 = time.monotonic()
        result = fn()
        elapsed = time.monotonic() - t0
        return name, result, elapsed

    tasks = {
        "SQLi": _sqli,
        "XSS": _xss,
        "Headers": _hdrs,
        "SSRF": _ssrf,
        "IDOR": _idor,
        "Open Redirect": _redirect,
    }

    if use_browser:
        # Selenium modules each open their own browser — run them sequentially
        # while httpx-based modules (headers, ssrf, idor, redirect) run in parallel.
        browser_tasks = {k: tasks.pop(k) for k in ["SQLi", "XSS"]}

        # Run httpx modules concurrently first
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_timed, name, fn): name for name, fn in tasks.items()}
            for future in as_completed(futures):
                try:
                    name, results, elapsed = future.result()
                    all_findings.extend(results)
                    log.info("[%s] finished — %d findings (%.1fs)", name, len(results), elapsed)
                except Exception as exc:
                    log.error("[%s] module failed: %s", futures[future], exc)

        # Run Selenium-based modules sequentially (each opens its own browser)
        for name, fn in browser_tasks.items():
            try:
                _, results, elapsed = _timed(name, fn)
                all_findings.extend(results)
                log.info("[%s] finished — %d findings (%.1fs, browser)", name, len(results), elapsed)
            except Exception as exc:
                log.error("[%s] module failed: %s", name, exc)
    else:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {pool.submit(_timed, name, fn): name for name, fn in tasks.items()}
            for future in as_completed(futures):
                try:
                    name, results, elapsed = future.result()
                    all_findings.extend(results)
                    log.info("[%s] finished — %d findings (%.1fs)", name, len(results), elapsed)
                except Exception as exc:
                    log.error("[%s] module failed: %s", futures[future], exc)

    return all_findings


def main() -> None:
    print(BANNER)
    args = _parse_args()
    setup_logger()
    log = get_logger("main")

    # Enforce thread limit
    if args.threads > 10:
        log.warning("Thread count %d exceeds max (10), clamping to 10", args.threads)
        args.threads = 10

    url, hostname, is_url = _normalise_target(args.target)
    use_browser = args.browser or args.headed
    headless = not args.headed
    log.info("Target: %s | Mode: %s | Threads: %d | Browser: %s",
             url, args.mode, args.threads, "headed" if args.headed else ("headless" if use_browser else "off"))
    start = time.monotonic()

    recon_data: dict[str, Any] = {}
    fingerprint_data: dict[str, Any] = {}
    all_findings: list[dict[str, Any]] = []
    stage_times: list[tuple[str, float]] = []

    # ── STAGE 01: Target Input (parsed above) ──────────────────────
    log.info("=== STAGE 01: Target Input ===")

    # ── STAGE 02: Recon ────────────────────────────────────────────
    t_stage = time.monotonic()
    if args.mode in ("full", "network-only"):
        recon_data = run_recon(hostname)
        ip = recon_data.get("ip") or hostname

        # ── Port scan ──────────────────────────────────────────────
        port_data = scan_ports(ip)
        recon_data["open_ports"] = port_data["open_ports"]
        recon_data["services"] = port_data["services"]
        recon_data["os_guess"] = port_data["os_guess"]
        stage_times.append(("Recon + Port Scan", time.monotonic() - t_stage))
    else:
        log.info("Skipping recon/network stages (mode=%s)", args.mode)

    # ── STAGE 03: Fingerprinting ───────────────────────────────────
    t_stage = time.monotonic()
    if args.mode in ("full", "web-only", "quick") and is_url:
        fingerprint_data = run_fingerprint(url, hostname)
        stage_times.append(("Fingerprinting", time.monotonic() - t_stage))
    else:
        log.info("Skipping fingerprinting (mode=%s)", args.mode)

    waf_detected = bool(fingerprint_data.get("waf"))

    # ── STAGE 04: Web Crawler ──────────────────────────────────────
    endpoints: list[str] = []
    forms: list[dict[str, Any]] = []
    crawl_summary: dict[str, int] | None = None

    t_stage = time.monotonic()
    if args.mode in ("full", "web-only", "quick") and is_url:
        max_depth = 2 if args.mode == "quick" else 3
        max_pages = 50 if args.mode == "quick" else 200
        if use_browser:
            from scanner.core.selenium_crawler import selenium_crawl
            crawl_result = selenium_crawl(
                url,
                max_depth=max_depth,
                max_pages=max_pages,
                cookie=args.cookie,
                headless=headless,
            )
        else:
            crawl_result = crawl(
                url,
                max_depth=max_depth,
                max_pages=max_pages,
                cookie=args.cookie,
                timeout=args.timeout,
                respect_robots=(args.mode == "quick"),
            )
        endpoints = crawl_result.endpoints
        forms = crawl_result.forms
        crawl_summary = crawl_result.summary()
        crawler_label = "Selenium Crawler" if use_browser else "Crawler"
        stage_times.append((crawler_label, time.monotonic() - t_stage))
    else:
        log.info("Skipping web crawl (mode=%s)", args.mode)

    # ── STAGE 05: Vulnerability Modules ────────────────────────────
    t_stage = time.monotonic()
    if args.mode != "network-only" and endpoints:
        log.info("=== STAGE 05: Vulnerability Testing (%d endpoints) ===", len(endpoints))
        all_findings = _run_web_modules(
            endpoints=endpoints,
            forms=forms,
            base_url=url,
            waf_detected=waf_detected,
            cookie=args.cookie,
            timeout=args.timeout,
            threads=args.threads,
            quick=(args.mode == "quick"),
            use_browser=use_browser,
            headless=headless,
        )
        stage_times.append(("Vulnerability Testing", time.monotonic() - t_stage))
    elif args.mode == "network-only":
        log.info("Skipping web vulnerability modules (mode=network-only)")
    else:
        log.info("No endpoints discovered — skipping vulnerability modules")

    # ── STAGE 06: CVSS Scoring ─────────────────────────────────────
    log.info("=== STAGE 06: CVSS Scoring ===")
    all_findings = enrich_findings(all_findings)

    # Sort: Critical → High → Medium → Low
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}
    all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "Low"), 4))

    # ── STAGE 07: JSON Export ──────────────────────────────────────
    log.info("=== STAGE 07: JSON Export ===")
    report_path = export_json(
        target=url,
        findings=all_findings,
        output_path=args.output,
        recon_data=recon_data or None,
        fingerprint_data=fingerprint_data or None,
        crawl_summary=crawl_summary,
    )

    elapsed = time.monotonic() - start
    base_name = os.path.splitext(os.path.basename(args.output))[0]
    base_dir = os.path.dirname(args.output) or "."
    exec_path = os.path.join(base_dir, f"{base_name}_executive.json")
    tech_path = os.path.join(base_dir, f"{base_name}_technical.json")

    log.info("Scan complete in %.1fs — %d findings written to %s",
             elapsed, len(all_findings), report_path)

    # Print summary to console
    from scanner.utils.report_exporter import _build_summary
    summary = _build_summary(all_findings)
    print(f"\n{'='*55}")
    print(f"  SCAN COMPLETE — {url}")
    print(f"  Risk Rating    : {summary['risk_rating']}")
    print(f"  Total findings : {summary['total_findings']}")
    print(f"  Critical: {summary['critical']}  |  High: {summary['high']}  |  "
          f"Medium: {summary['medium']}  |  Low: {summary['low']}")
    print(f"  {'─'*51}")
    print(f"  Stage Timings:")
    for stage_name, stage_elapsed in stage_times:
        print(f"    {stage_name:<30s} {stage_elapsed:>6.1f}s")
    print(f"    {'─'*37}")
    print(f"    {'Total':<30s} {elapsed:>6.1f}s")
    print(f"  {'─'*51}")
    print(f"  Reports:")
    print(f"    Full      → {os.path.abspath(report_path)}")
    print(f"    Executive → {os.path.abspath(exec_path)}")
    print(f"    Technical → {os.path.abspath(tech_path)}")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
