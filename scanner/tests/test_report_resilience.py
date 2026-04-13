import unittest
from unittest.mock import patch

from scanner.utils import pdf_report


class TestReportResilience(unittest.TestCase):
    def test_generate_docx_fails_fast_when_node_missing(self):
        with patch("scanner.utils.pdf_report.shutil.which", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                pdf_report.generate_docx("https://example.com", [], {})

        self.assertIn("Node.js runtime not found", str(ctx.exception))

    def test_generate_pdf_raises_clear_error_when_dependency_import_failed(self):
        with patch.object(pdf_report, "_FPDF_IMPORT_ERROR", Exception("missing-fpdf2")):
            with self.assertRaises(RuntimeError) as ctx:
                pdf_report.generate_pdf("https://example.com", [], {})

        self.assertIn("PDF export dependency missing", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
