"""Integration tests for end-to-end audit execution and report validation."""

import json
import os
import tempfile
import unittest

from auditor.cli import main
from auditor.engine import AuditEngine
from auditor.models import CheckStatus
from auditor.system import is_windows


class TestIntegration(unittest.TestCase):
    """End-to-end integration tests verifying real execution flows."""

    def test_e2e_scan_execution(self):
        """Run an end-to-end audit scan and thoroughly validate generated artifacts."""
        with tempfile.TemporaryDirectory() as temp_dir:
            exit_code = main(["scan", "--output", temp_dir, "--format", "all"])
            self.assertIn(exit_code, [0, 1], "Exit code must be 0 (no failures) or 1 (one or more controls failed)")

            files = os.listdir(temp_dir)
            html_files = [os.path.join(temp_dir, f) for f in files if f.endswith(".html")]
            json_files = [os.path.join(temp_dir, f) for f in files if f.endswith(".json")]

            self.assertEqual(len(html_files), 1, "Expected exactly 1 generated HTML report")
            self.assertEqual(len(json_files), 1, "Expected exactly 1 generated JSON report")

            # Validate JSON content and schema
            with open(json_files[0], "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertIn("metadata", data)
            self.assertIn("summary", data)
            self.assertIn("findings", data)
            self.assertEqual(data["summary"]["total_checks"], 6)

            # Ensure unavailable checks are not falsely reported as PASS
            for finding in data["findings"]:
                if finding["status"] in (CheckStatus.ERROR.value, CheckStatus.REVIEW.value, CheckStatus.NOT_APPLICABLE.value):
                    self.assertNotEqual(finding["status"], CheckStatus.PASS.value)

            # Validate HTML report content
            with open(html_files[0], "r", encoding="utf-8") as f:
                html_text = f.read()

            self.assertIn("<!DOCTYPE html>", html_text)
            self.assertIn("Automated IT Security Controls Auditor", html_text)
            self.assertIn("Prioritized Remediation Action Plan", html_text)

    def test_e2e_doctor_execution(self):
        """Verify that auditor doctor executes cleanly."""
        exit_code = main(["doctor"])
        self.assertEqual(exit_code, 0)

    def test_windows_host_audit_execution(self):
        """Execute checks directly on the host if Windows is detected."""
        if not is_windows():
            self.skipTest("Skipping live Windows integration test on non-Windows environment")

        engine = AuditEngine()
        report = engine.run_audit()

        self.assertEqual(len(report.findings), 6)
        check_ids = [f.check_id for f in report.findings]
        self.assertIn("WIN-FW-01", check_ids)
        self.assertIn("WIN-AV-01", check_ids)
        self.assertIn("WIN-PWD-01", check_ids)
        self.assertIn("WIN-ADM-01", check_ids)
        self.assertIn("WIN-UPD-01", check_ids)
        self.assertIn("WIN-AUD-01", check_ids)


if __name__ == "__main__":
    unittest.main()
