"""Runtime dependency preflight checks for scanner features."""

from __future__ import annotations

import os
import shutil
from typing import Any


def _binary_available(candidates: list[str]) -> bool:
    return any(shutil.which(name) is not None for name in candidates)


def _known_windows_browser_available() -> bool:
    if os.name != "nt":
        return False
    candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    ]
    return any(os.path.exists(path) for path in candidates)


def check_dependencies(
    *,
    mode: str,
    use_browser: bool,
    need_docx: bool = False,
) -> dict[str, Any]:
    """Return dependency availability and user-facing warnings/errors."""
    warnings: list[str] = []
    errors: list[str] = []

    has_nmap = _binary_available(["nmap"])
    has_node = _binary_available(["node"])

    browser_env_hints = [
        "CHROME_PATH",
        "GOOGLE_CHROME_BIN",
        "PENTAVAULT_CHROME_BINARY",
        "EDGE_PATH",
        "PENTAVAULT_EDGE_BINARY",
    ]
    has_browser_hint = any(bool(os.environ.get(name)) for name in browser_env_hints)

    has_chrome = has_browser_hint or _binary_available([
        "chrome",
        "google-chrome",
        "chromium",
        "chromium-browser",
        "chrome.exe",
        "msedge",
        "msedge.exe",
    ]) or _known_windows_browser_available()
    has_chromedriver = _binary_available(["chromedriver", "chromedriver.exe", "msedgedriver", "msedgedriver.exe"])

    network_mode = mode in ("full", "network-only")
    web_mode = mode in ("full", "web-only", "quick")

    if network_mode and not has_nmap:
        warnings.append("nmap binary not found on PATH; recon port scanning will be skipped.")

    if use_browser and web_mode:
        if not has_chrome:
            errors.append("Chrome/Chromium binary not found on PATH; browser scan mode is unavailable.")
        if has_chrome and not has_chromedriver:
            warnings.append("chromedriver binary not found on PATH; Selenium manager will attempt automatic driver resolution.")

    if need_docx and not has_node:
        errors.append("Node.js binary not found on PATH; DOCX report export is unavailable.")

    return {
        "ok": len(errors) == 0,
        "warnings": warnings,
        "errors": errors,
        "capabilities": {
            "nmap": has_nmap,
            "node": has_node,
            "chrome": has_chrome,
            "chromedriver": has_chromedriver,
        },
    }
