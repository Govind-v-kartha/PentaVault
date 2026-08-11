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
import signal
import sys
import threading
import time


from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urlparse

from dotenv import load_dotenv

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
from scanner.core.crawler import CrawlResult, crawl, merge_crawl_results

from scanner.core.dependency_check import check_dependencies
from scanner.core.scorer import enrich_findings
from scanner.modules.sqli import test_sqli
from scanner.modules.xss import test_xss
from scanner.modules.headers import test_headers
from scanner.modules.ssrf import test_ssrf
from scanner.modules.idor import test_idor
from scanner.modules.open_redirect import test_open_redirect
from scanner.modules.sqli_selenium import test_sqli_selenium
from scanner.modules.xss_selenium import test_xss_selenium
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
from scanner.modules.secrets_detection import test_secrets_detection




BANNER = r"""
  ╔══════════════════════════════════════════════╗
  ║        PentaVault  v1.1.0                    ║
  ║   For authorized VAPT engagements only.      ║
  ║   --browser  →  Playwright-powered scanning  ║
  ╚══════════════════════════════════════════════╝
"""


def _print_banner() -> None:
    try:
        print(BANNER)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        safe_banner = BANNER.encode(encoding, errors="replace").decode(encoding, errors="replace")
        print(safe_banner)


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
        "--request-delay", type=float, default=0.0,
        help="Delay in seconds between crawler requests/navigation (default: 0)",
    )
    parser.add_argument(
        "--browser", action="store_true", default=False,
        help="Use Playwright (headless Chromium) for crawling and vulnerability testing. "
             "More accurate — renders JS, confirms XSS via real alert(), captures screenshots.",
    )

    parser.add_argument(
        "--crawl-mode",
        choices=["auto", "httpx", "selenium", "hybrid"],
        default="auto",
        help="Crawler strategy: auto/httpx/selenium/hybrid (default: auto)",
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
    should_stop=None,
) -> list[dict[str, Any]]:
    """Execute all web vulnerability modules concurrently."""
    log = get_logger("main")
    all_findings: list[dict[str, Any]] = []

    evidence_dir = "evidence" if use_browser else None

    def _sqli():
        if use_browser:
            return test_sqli_selenium(
                endpoints,
                forms,
                cookie=cookie,
                headless=headless,
                quick=quick,
                evidence_dir=evidence_dir,
                should_stop=should_stop,
            )
        return test_sqli(
            endpoints,
            forms,
            cookie=cookie,
            timeout=timeout,
            quick=quick,
            should_stop=should_stop,
        )

    def _xss():
        if use_browser:
            return test_xss_selenium(
                endpoints,
                forms,
                waf_detected=waf_detected,
                cookie=cookie,
                headless=headless,
                quick=quick,
                evidence_dir=evidence_dir,
                should_stop=should_stop,
            )
        return test_xss(
            endpoints,
            forms,
            waf_detected=waf_detected,
            cookie=cookie,
            timeout=timeout,
            quick=quick,
            should_stop=should_stop,
        )

    def _hdrs():
        return test_headers(base_url, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _ssrf():
        return test_ssrf(endpoints, forms, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _idor():
        return test_idor(endpoints, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _redirect():
        return test_open_redirect(endpoints, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _cmdi():
        return test_command_injection(endpoints, forms, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _xxe():
        return test_xxe(endpoints, forms, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _lfi():
        return test_lfi(endpoints, forms, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _sensitive_files():
        return test_sensitive_files(base_url, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _nosqli():
        return test_nosqli(endpoints, forms, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _ssti():
        return test_ssti(endpoints, forms, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _graphql():
        return test_graphql_abuse(base_url, endpoints, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _jwt():
        return test_jwt_checks(endpoints, forms, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _host_header():
        return test_host_header_injection(base_url, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _cors():
        return test_cors_misconfig(base_url, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _hpp():
        return test_hpp(endpoints, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _crlf():
        return test_crlf_injection(endpoints, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _request_smuggling():
        return test_request_smuggling(base_url, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _mass_assignment_bola():
        return test_mass_assignment_bola(endpoints, forms, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _insecure_deserialization():
        return test_insecure_deserialization(endpoints, forms, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _prototype_pollution():
        return test_prototype_pollution(endpoints, forms, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _csv_formula_injection():
        return test_csv_formula_injection(endpoints, forms, cookie=cookie, timeout=timeout, quick=quick, should_stop=should_stop)

    def _ssl_tls():
        return test_ssl_tls(base_url, should_stop=should_stop, timeout=timeout, quick=quick)

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
        "Command Injection": _cmdi,
        "XXE": _xxe,
        "LFI": _lfi,
        "Sensitive Files": _sensitive_files,
        "NoSQLi": _nosqli,
        "SSTI": _ssti,
        "GraphQL Abuse": _graphql,
        "JWT Checks": _jwt,
        "Host Header Injection": _host_header,
        "CORS Misconfiguration": _cors,
        "HTTP Parameter Pollution": _hpp,
        "CRLF Injection": _crlf,
        "Request Smuggling": _request_smuggling,
        "Mass Assignment/BOLA": _mass_assignment_bola,
        "Insecure Deserialization": _insecure_deserialization,
        "Prototype Pollution": _prototype_pollution,
        "CSV/Formula Injection": _csv_formula_injection,
        "SSL/TLS Analysis": _ssl_tls,
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
    _print_banner()
    args = _parse_args()
    load_dotenv(os.path.join(_PROJECT_DIR, ".env"))
    setup_logger()
    log = get_logger("main")

    # Enforce thread limit
    if args.threads > 10:
        log.warning("Thread count %d exceeds max (10), clamping to 10", args.threads)
        args.threads = 10

    url, hostname, is_url = _normalise_target(args.target)
    use_browser = args.browser or args.headed
    headless = not args.headed
    args.request_delay = max(0.0, args.request_delay)

    if args.request_delay > 2.0:
        log.warning("Request delay %.2fs exceeds max (2.0), clamping to 2.0", args.request_delay)
        args.request_delay = 2.0

    dep = check_dependencies(mode=args.mode, use_browser=use_browser)
    for warning in dep["warnings"]:
        log.warning("Preflight: %s", warning)
    if not dep["ok"]:
        for err in dep["errors"]:
            log.error("Preflight: %s", err)
        raise SystemExit("Cannot start scan due to missing dependencies.")

    log.info("Target: %s | Mode: %s | Threads: %d | Browser: %s | Crawl mode: %s | Request delay: %.2fs",
             url, args.mode, args.threads, "headed" if args.headed else ("headless" if use_browser else "off"), args.crawl_mode, args.request_delay)
    start = time.monotonic()

    recon_data: dict[str, Any] = {}
    fingerprint_data: dict[str, Any] = {}
    all_findings: list[dict[str, Any]] = []
    stage_times: list[tuple[str, float]] = []

    cancel_event = threading.Event()

    def _sigint_handler(signum, frame):
        if not cancel_event.is_set():
            cancel_event.set()
            log.warning("Interrupt signal received (SIGINT) — initiating graceful shutdown...")

    try:
        signal.signal(signal.SIGINT, _sigint_handler)
    except (ValueError, AttributeError):
        pass

    _should_stop = lambda: cancel_event.is_set()


    # ── STAGE 01: Target Input (parsed above) ──────────────────────
    log.info("=== STAGE 01: Target Input ===")

    # ── STAGE 02: Recon ────────────────────────────────────────────
    t_stage = time.monotonic()
    if args.mode in ("full", "network-only"):
        recon_data = run_recon(hostname, should_stop=_should_stop)
        if recon_data.get("takeover_findings"):
            all_findings.extend(recon_data["takeover_findings"])
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
        crawler_mode = args.crawl_mode
        if crawler_mode == "auto":
            crawler_mode = "selenium" if use_browser else "httpx"

        crawl_result: CrawlResult
        crawler_label = "Crawler"

        if crawler_mode == "selenium":
            from scanner.core.selenium_crawler import selenium_crawl

            crawl_result = selenium_crawl(
                url,
                max_depth=max_depth,
                max_pages=max_pages,
                cookie=args.cookie,
                headless=headless,
                request_delay=args.request_delay,
            )
            crawler_label = "Selenium Crawler"
        elif crawler_mode == "hybrid":
            from scanner.core.selenium_crawler import selenium_crawl

            primary = crawl(
                url,
                max_depth=max_depth,
                max_pages=max_pages,
                cookie=args.cookie,
                timeout=args.timeout,
                respect_robots=(args.mode == "quick"),
                request_delay=args.request_delay,
            )
            needs_fallback = len(primary.endpoints) < 5 or len(primary.forms) < 1
            if needs_fallback:
                fallback = selenium_crawl(
                    url,
                    max_depth=max_depth,
                    max_pages=max_pages,
                    cookie=args.cookie,
                    headless=headless,
                    request_delay=args.request_delay,
                )
                crawl_result = merge_crawl_results(primary, fallback)

                crawler_label = "Hybrid Crawler"
            else:
                crawl_result = primary
                crawler_label = "Crawler"
        else:
            crawl_result = crawl(
                url,
                max_depth=max_depth,
                max_pages=max_pages,
                cookie=args.cookie,
                timeout=args.timeout,
                respect_robots=(args.mode == "quick"),
                request_delay=args.request_delay,
            )
            crawler_label = "Crawler"

        endpoints = crawl_result.endpoints
        forms = crawl_result.forms
        crawl_summary = crawl_result.summary()
        stage_times.append((crawler_label, time.monotonic() - t_stage))

        # Secrets Detection on crawled page sources and JS files
        secrets_findings = test_secrets_detection(
            crawl_result=crawl_result,
            base_url=url,
            cookie=args.cookie,
            timeout=args.timeout,
            quick=(args.mode == "quick"),
            should_stop=_should_stop,
        )
        if secrets_findings:
            all_findings.extend(secrets_findings)
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
            should_stop=_should_stop,
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

    try:
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
    except UnicodeEncodeError:
        print(f"\n{'='*55}")
        print(f"  SCAN COMPLETE - {url}")
        print(f"  Risk Rating    : {summary['risk_rating']}")
        print(f"  Total findings : {summary['total_findings']}")
        print(f"  Critical: {summary['critical']}  |  High: {summary['high']}  |  "
              f"Medium: {summary['medium']}  |  Low: {summary['low']}")
        print(f"  {'-'*51}")
        print(f"  Stage Timings:")
        for stage_name, stage_elapsed in stage_times:
            print(f"    {stage_name:<30s} {stage_elapsed:>6.1f}s")
        print(f"    {'-'*37}")
        print(f"    {'Total':<30s} {elapsed:>6.1f}s")
        print(f"  {'-'*51}")
        print(f"  Reports:")
        print(f"    Full      -> {os.path.abspath(report_path)}")
        print(f"    Executive -> {os.path.abspath(exec_path)}")
        print(f"    Technical -> {os.path.abspath(tech_path)}")
        print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
