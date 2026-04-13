import sys
import types
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

_pdf_stub = types.ModuleType("scanner.utils.pdf_report")
_pdf_stub.generate_pdf = lambda *args, **kwargs: b""
_pdf_stub.generate_docx = lambda *args, **kwargs: b""
sys.modules.setdefault("scanner.utils.pdf_report", _pdf_stub)

from scanner.web import app as web_app


class TestScanFinalization(unittest.TestCase):
    def test_finalize_scan_sets_elapsed_and_completion_timestamp(self):
        started = (datetime.now() - timedelta(seconds=12)).isoformat(timespec="seconds")
        scan = {
            "started_at": started,
            "status": "running",
            "current_stage": "Scanning",
            "completed_at": None,
            "elapsed": 0,
        }

        with patch("scanner.web.app._save_history") as mocked_save:
            web_app._finalize_scan(scan, "completed", "Complete")

        self.assertEqual(scan["status"], "completed")
        self.assertEqual(scan["current_stage"], "Complete")
        self.assertIsNotNone(scan["completed_at"])
        self.assertGreater(scan["elapsed"], 0)
        mocked_save.assert_called_once()


class TestCancelEndpoint(unittest.IsolatedAsyncioTestCase):
    async def test_cancel_endpoint_sets_signal_only(self):
        scan_id = "unit-cancel-test"
        web_app.scans[scan_id] = {"status": "running", "current_stage": "Testing"}
        try:
            result = await web_app.cancel_scan(scan_id)
            self.assertTrue(result["cancelled"])
            self.assertTrue(web_app.scans[scan_id]["_cancel"])
            self.assertEqual(web_app.scans[scan_id]["status"], "running")
            self.assertEqual(web_app.scans[scan_id]["current_stage"], "Cancellation requested")
        finally:
            web_app.scans.pop(scan_id, None)


if __name__ == "__main__":
    unittest.main()
