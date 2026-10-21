"""Unit tests for JSON and HTML report generators."""

import json
import os
import tempfile
import unittest

from auditor.engine import AuditEngine
from auditor.reporting.html_reporter import HtmlReporter
from auditor.reporting.json_reporter import JsonReporter


class TestReporting(unittest.TestCase):
    """Test suite for report generation, file output, and HTML safety."""

    def setUp(self):
        self.report = AuditEngine.get_demo_report()

    def test_json_reporter_serialization(self):
        json_str = JsonReporter.generate(self.report)
        data = json.loads(json_str)

        self.assertIn("metadata", data)
        self.assertIn("system_info", data)
        self.assertIn("summary", data)
        self.assertIn("findings", data)
        self.assertIn("limitations", data)
        self.assertEqual(data["system_info"]["hostname"], "DEMO-SEC-NODE01")

    def test_json_reporter_file_write(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            out_file = os.path.join(temp_dir, "nested", "report.json")
            JsonReporter.generate(self.report, output_path=out_file)

            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(loaded["summary"]["total_checks"], 6)

    def test_html_reporter_content(self):
        html_str = HtmlReporter.generate(self.report)

        self.assertIn("<!DOCTYPE html>", html_str)
        self.assertIn("DEMO-SEC-NODE01", html_str)
        self.assertIn("Automated IT Security Controls Auditor", html_str)
        self.assertIn("Prioritized Remediation Action Plan", html_str)
        self.assertIn("Assessment Scope &amp; Limitations", html_str)
        # Check badges
        self.assertIn("PASS", html_str)
        self.assertIn("FAIL", html_str)
        self.assertIn("REVIEW", html_str)

    def test_html_reporter_html_escaping(self):
        # Verify that malicious/special characters in evidence or explanation are escaped
        self.report.findings[0].explanation = "Testing <script>alert('xss')</script> & symbols"
        html_str = HtmlReporter.generate(self.report)

        self.assertNotIn("<script>", html_str)
        self.assertIn("&lt;script&gt;", html_str)

    def test_html_reporter_file_write(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            out_file = os.path.join(temp_dir, "reports", "report.html")
            HtmlReporter.generate(self.report, output_path=out_file)

            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("<!DOCTYPE html>", content)


if __name__ == "__main__":
    unittest.main()
