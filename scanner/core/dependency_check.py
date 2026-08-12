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

    pw_chrome_found = False
    try:
        from pathlib import Path
        ms_pw = Path("/ms-playwright")
        if ms_pw.exists():
            found = list(ms_pw.glob("**/chrome-linux/chrome"))
            if found:
                pw_chrome_found = True
                if "CHROME_PATH" not in os.environ:
                    os.environ["CHROME_PATH"] = str(found[0])
    except Exception:
        pass

    has_chrome = has_browser_hint or pw_chrome_found or _binary_available([
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

    has_python_docx = False
    try:
        import docx  # noqa: F401
        has_python_docx = True
    except ImportError:
        pass

    if need_docx and not (has_node or has_python_docx):
        errors.append("Neither Node.js binary nor python-docx library is available; DOCX report export is unavailable.")


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
