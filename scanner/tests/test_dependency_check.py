import unittest
from unittest.mock import patch

from scanner.core.dependency_check import check_dependencies


class TestDependencyCheck(unittest.TestCase):
    def test_browser_mode_fails_when_browser_dependencies_missing(self):
        with patch("scanner.core.dependency_check.shutil.which", return_value=None), \
             patch("scanner.core.dependency_check.os.path.exists", return_value=False), \
             patch.dict("scanner.core.dependency_check.os.environ", {}, clear=True):
            result = check_dependencies(mode="web-only", use_browser=True)

        self.assertFalse(result["ok"])
        self.assertTrue(any("Chrome/Chromium" in err for err in result["errors"]))

    def test_browser_mode_warns_when_driver_missing_but_browser_present(self):
        def fake_which(name: str):
            if name in {"chrome", "chrome.exe"}:
                return "C:/bin/chrome.exe"
            if name in {"chromedriver", "chromedriver.exe", "msedgedriver", "msedgedriver.exe"}:
                return None
            return "C:/bin/" + name

        with patch("scanner.core.dependency_check.shutil.which", side_effect=fake_which):
            result = check_dependencies(mode="web-only", use_browser=True)

        self.assertTrue(result["ok"])
        self.assertTrue(any("chromedriver" in warning for warning in result["warnings"]))

    def test_browser_mode_accepts_browser_env_hint_without_path_binary(self):
        def fake_which(name: str):
            if name in {"chrome", "chrome.exe", "google-chrome", "chromium", "chromium-browser", "msedge", "msedge.exe"}:
                return None
            if name in {"chromedriver", "chromedriver.exe", "msedgedriver", "msedgedriver.exe"}:
                return None
            return "C:/bin/" + name

        with patch("scanner.core.dependency_check.shutil.which", side_effect=fake_which), patch.dict("os.environ", {"CHROME_PATH": "C:/Program Files/Google/Chrome/Application/chrome.exe"}, clear=False):
            result = check_dependencies(mode="web-only", use_browser=True)

        self.assertTrue(result["ok"])
        self.assertTrue(any("chromedriver" in warning for warning in result["warnings"]))

    def test_network_mode_warns_when_nmap_missing(self):
        def fake_which(name: str):
            if name == "nmap":
                return None
            if name in {"chrome", "chrome.exe", "chromedriver", "chromedriver.exe", "node"}:
                return "C:/bin/" + name
            return None

        with patch("scanner.core.dependency_check.shutil.which", side_effect=fake_which):
            result = check_dependencies(mode="network-only", use_browser=False)

        self.assertTrue(result["ok"])
        self.assertTrue(any("nmap" in warning for warning in result["warnings"]))

    def test_docx_export_requires_node(self):
        def fake_which(name: str):
            if name == "node":
                return None
            return "C:/bin/" + name

        with patch("scanner.core.dependency_check.shutil.which", side_effect=fake_which):
            result = check_dependencies(mode="quick", use_browser=False, need_docx=True)

        self.assertFalse(result["ok"])
        self.assertTrue(any("Node.js" in err for err in result["errors"]))


if __name__ == "__main__":
    unittest.main()
