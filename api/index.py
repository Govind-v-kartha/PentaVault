"""Vercel serverless function entry point for PentaVault.

Vercel's @vercel/python runtime auto-detects the FastAPI `app` object
and wraps it as an ASGI serverless handler.
"""

import os
import sys
from pathlib import Path

# Ensure the project root is on sys.path so `scanner.*` imports resolve
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# On Vercel the filesystem outside /tmp is read-only.
# Point writable dirs to /tmp so history saves don't crash.
if os.environ.get("VERCEL"):
    _tmp = Path("/tmp")
    os.environ.setdefault("PENTAVAULT_DATA_DIR", str(_tmp / "data"))
    os.environ.setdefault("PENTAVAULT_REPORTS_DIR", str(_tmp / "reports"))
    os.environ.setdefault("PENTAVAULT_LOGS_DIR", str(_tmp / "logs"))

from scanner.web.app import app  # noqa: E402  — path setup must come first
