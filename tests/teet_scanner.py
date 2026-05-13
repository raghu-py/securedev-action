from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from securedev_action.config import ScanConfig
from securedev_action.models import Severity
from securedev_action.rules import scan_text
from securedev_action.scanner import SecureDevScanner


class RuleTests(unittest.TestCase):
    def test_detects_critical_private_key(self) -> None:
        content = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
        findings = scan_text("secret.pem", content)
        self.assertTrue(any(f.rule_id == "SEC003" and f.severity == Severity.CRITICAL for f in findings))

    def test_placeholder_secret_is_ignored(self) -> None:
        content = "API_KEY='your_api_key_here'\n"
        findings = scan_text("settings.py", content)
        self.assertFalse(any(f.rule_id == "SEC007" for f in findings))

    def test_python_shell_true_is_critical(self) -> None:
        content = "import subprocess\nsubprocess.run(user_input, shell=True)\n"
        findings = scan_text("app.py", content)
        self.assertTrue(any(f.rule_id == "PY004" and f.severity == Severity.CRITICAL for f in findings))

    def test_suppression_marker(self) -> None:
        content = "eval(user_input)  # securedev: ignore\n"
        findings = scan_text("app.py", content)
        self.assertFalse(any(f.rule_id == "PY001" for f in findings))


class ScannerTests(unittest.TestCase):
    def test_scanner_walks_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
            (root / "image.bin").write_bytes(b"\x00\x01\x02")
            config = ScanConfig(root=root, output_dir=root / "reports")
            summary = SecureDevScanner(config).scan()
            self.assertEqual(summary.scanned_files, 1)
            self.assertGreaterEqual(summary.skipped_files, 1)
            self.assertTrue(any(f.rule_id == "PY001" for f in summary.findings))


if __name__ == "__main__":
    unittest.main()
