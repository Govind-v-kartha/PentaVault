import unittest
from datetime import datetime
from unittest.mock import patch

from scanner.web import app as web_app


class _FakeThread:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    def start(self):
        return None


class TestScanRuntimeMetadata(unittest.IsolatedAsyncioTestCase):
    async def test_frontend_mode_info_defaults_to_legacy(self):
        with patch("scanner.web.app.FRONTEND_MODE", "legacy"):
            payload = await web_app.frontend_mode_info()

        self.assertEqual(payload.get("selected_mode"), "legacy")
        self.assertEqual(payload.get("active_mode"), "legacy")
        self.assertIsInstance(payload.get("available_modes"), list)
        self.assertIn("legacy", payload.get("available_modes"))

    async def test_start_scan_populates_runtime_metadata_from_request(self):
        req = web_app.ScanRequest(
            target="https://example.com",
            mode="full",
            threads=7,
            timeout=12.5,
            request_delay=0.4,
            use_browser=True,
            crawl_mode="hybrid",
        )

        with (
            patch("scanner.web.app.check_dependencies", return_value={"ok": True, "errors": [], "warnings": [], "capabilities": {}}),
            patch("threading.Thread", side_effect=lambda *a, **k: _FakeThread(*a, **k)),
        ):
            payload = await web_app.start_scan(req)

        scan_id = payload["scan_id"]
        try:
            scan = web_app.scans[scan_id]
            runtime = scan.get("runtime_config", {})
            execution = scan.get("execution_metadata", {})

            self.assertEqual(runtime.get("mode"), "full")
            self.assertEqual(runtime.get("threads"), 7)
            self.assertEqual(runtime.get("timeout_seconds"), 12.5)
            self.assertEqual(runtime.get("request_delay_seconds"), 0.4)
            self.assertEqual(runtime.get("use_browser"), True)
            self.assertEqual(runtime.get("crawl_mode"), "hybrid")

            self.assertEqual(execution.get("http_parallelization"), "threadpool")
            self.assertEqual(execution.get("http_module_workers"), 7)
            self.assertEqual(execution.get("resolved_crawl_mode"), "hybrid")
            self.assertEqual(execution.get("browser_module_execution"), "disabled")
            self.assertEqual(execution.get("browser_module_timeout_seconds"), 0)
        finally:
            web_app.scans.pop(scan_id, None)

    async def test_get_scan_status_backfills_runtime_metadata_for_legacy_scan(self):
        scan_id = "legacy-runtime-metadata"
        web_app.scans[scan_id] = {
            "scan_id": scan_id,
            "status": "running",
            "target": "https://legacy.example",
            "mode": "quick",
            "threads": 3,
            "timeout": 9.0,
            "request_delay": 0.2,
            "use_browser": False,
            "crawl_mode": "httpx",
            "progress": 10,
            "current_stage": "Target Input",
            "stages": [],
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "completed_at": None,
            "elapsed": 0,
            "findings": [],
            "findings_count": 0,
            "summary": {},
            "module_results": {},
        }

        try:
            payload = await web_app.get_scan_status(scan_id)
            runtime = payload.get("runtime_config", {})
            execution = payload.get("execution_metadata", {})

            self.assertEqual(runtime.get("mode"), "quick")
            self.assertEqual(runtime.get("threads"), 3)
            self.assertEqual(runtime.get("timeout_seconds"), 9.0)
            self.assertEqual(runtime.get("request_delay_seconds"), 0.2)
            self.assertEqual(runtime.get("use_browser"), False)
            self.assertEqual(runtime.get("crawl_mode"), "httpx")

            self.assertEqual(execution.get("http_parallelization"), "threadpool")
            self.assertEqual(execution.get("http_module_workers"), 3)
            self.assertEqual(execution.get("resolved_crawl_mode"), "httpx")
            self.assertEqual(execution.get("browser_module_execution"), "disabled")
            self.assertEqual(execution.get("browser_module_timeout_seconds"), 0)
            self.assertEqual(execution.get("http_module_count"), 0)
            self.assertEqual(execution.get("browser_module_count"), 0)
        finally:
            web_app.scans.pop(scan_id, None)

    async def test_patch_use_browser_updates_runtime_config(self):
        scan_id = "runtime-patch-test"
        web_app.scans[scan_id] = {
            "scan_id": scan_id,
            "status": "running",
            "target": "https://example.com",
            "mode": "quick",
            "threads": 5,
            "timeout": 10.0,
            "request_delay": 0.0,
            "use_browser": False,
            "crawl_mode": "auto",
            "progress": 15,
            "current_stage": "Web Crawling",
            "stages": [],
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "completed_at": None,
            "elapsed": 0,
            "findings": [],
            "findings_count": 0,
            "summary": {},
            "module_results": {},
        }

        try:
            await web_app.update_scan_config(scan_id, {"use_browser": True})
            payload = await web_app.get_scan_status(scan_id)
            runtime = payload.get("runtime_config", {})
            self.assertEqual(payload.get("use_browser"), True)
            self.assertEqual(runtime.get("use_browser"), True)
        finally:
            web_app.scans.pop(scan_id, None)

    async def test_root_uses_react_index_when_mode_is_react_and_dist_exists(self):
        fake_path = web_app.Path("D:/fake/react/index.html")
        with (
            patch("scanner.web.app.FRONTEND_MODE", "react"),
            patch("scanner.web.app.FRONTEND_DIST_DIR", web_app.Path("D:/fake/react")),
            patch.object(web_app.Path, "exists", return_value=True),
            patch.object(web_app.Path, "is_file", return_value=True),
        ):
            resolved = web_app._resolve_dashboard_index_path()

        self.assertEqual(str(resolved), str(fake_path))

    async def test_root_falls_back_to_legacy_when_react_dist_missing(self):
        with (
            patch("scanner.web.app.FRONTEND_MODE", "react"),
            patch("scanner.web.app.FRONTEND_DIST_DIR", web_app.Path("D:/fake/react")),
            patch.object(web_app.Path, "exists", return_value=False),
            patch.object(web_app.Path, "is_file", return_value=False),
        ):
            resolved = web_app._resolve_dashboard_index_path()

        self.assertEqual(str(resolved), str(web_app.STATIC_DIR / "index.html"))


if __name__ == "__main__":
    unittest.main()
