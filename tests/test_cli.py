"""Unit tests for the command-line interface, formatting, and exit code handling."""

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from auditor.cli import (
    build_parser,
    colorize,
    format_evidence_concise,
    get_terminal_width,
    main,
    supports_color,
    wrap_labeled_text,
)
from auditor.models import AuditReport, AuditSummary, CheckStatus, Finding, RiskLevel, SystemInfo


class TestCLI(unittest.TestCase):
    """Test suite for CLI argument handling, exit codes, and terminal formatting."""

    def test_parser_version(self):
        parser = build_parser()
        with self.assertRaises(SystemExit) as cm:
            parser.parse_args(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_parser_doctor(self):
        parser = build_parser()
        args = parser.parse_args(["doctor"])
        self.assertEqual(args.command, "doctor")

    def test_parser_scan_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["scan"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.output, "reports")
        self.assertEqual(args.format, "all")
        self.assertFalse(args.demo)
        self.assertFalse(args.verbose)
        self.assertFalse(args.quiet)

    def test_parser_scan_custom_options(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--output", "custom_reports", "--format", "json", "--demo", "--verbose", "--quiet"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.output, "custom_reports")
        self.assertEqual(args.format, "json")
        self.assertTrue(args.demo)
        self.assertTrue(args.verbose)
        self.assertTrue(args.quiet)

    def test_main_doctor_command(self):
        exit_code = main(["doctor"])
        self.assertIn(exit_code, [0, 1])

    def test_main_scan_failed_check_exit_code_one(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            # Demo scan has 1 FAIL check (WIN-PWD-01), so exit code should be 1
            exit_code = main(["scan", "--demo", "--output", temp_dir, "--format", "all"])
            self.assertEqual(exit_code, 1)

            # Confirm report files were created in temp_dir
            files = os.listdir(temp_dir)
            html_files = [f for f in files if f.endswith(".html")]
            json_files = [f for f in files if f.endswith(".json")]

            self.assertEqual(len(html_files), 1)
            self.assertEqual(len(json_files), 1)

    @patch("auditor.engine.AuditEngine.run_audit")
    def test_main_scan_all_pass_exit_code_zero(self, mock_run):
        # Create a report where all checks pass
        sys_info = SystemInfo("PASSHOST", "Windows", "11", "10.0", "AMD64", "3.14", False, "user")
        finding = Finding(
            "TEST-PASS", "All Pass Control", CheckStatus.PASS, {"status": "ok"},
            "Req", RiskLevel.INFORMATIONAL, "Passing explanation", "None needed", "None"
        )
        summary = AuditSummary(1, 1, 0, 0, 0, 0, 100.0, {"INFORMATIONAL": 1, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0})
        mock_report = AuditReport("1.0.0", "2026-10-21T00:00:00Z", sys_info, [finding], summary)
        mock_run.return_value = mock_report

        with tempfile.TemporaryDirectory() as temp_dir:
            exit_code = main(["scan", "--output", temp_dir, "--format", "json"])
            self.assertEqual(exit_code, 0)

    def test_main_scan_quiet_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            exit_code = main(["scan", "--demo", "--quiet", "--output", temp_dir])
            self.assertEqual(exit_code, 1)

    def test_main_no_args_displays_help(self):
        exit_code = main([])
        self.assertEqual(exit_code, 0)

    def test_wrap_labeled_text_narrow_terminal(self):
        label = "Finding"
        long_text = "This is a very long security finding explanation that will span across multiple wrapped lines when the terminal is narrow."
        wrapped = wrap_labeled_text(label, long_text, width=50)

        lines = wrapped.splitlines()
        self.assertGreater(len(lines), 1)
        self.assertTrue(lines[0].startswith("  Finding    "))
        # Continuation lines must be indented by 13 spaces
        for cont_line in lines[1:]:
            self.assertTrue(cont_line.startswith(" " * 13))

    def test_format_evidence_concise(self):
        evidence_dict = {
            "Domain": "ON",
            "Private": "ON",
            "Public": "ON",
            "nested": {"key1": "val1", "key2": "val2"},
        }
        res = format_evidence_concise(evidence_dict)
        self.assertIn("Domain: ON", res)
        self.assertIn("Public: ON", res)

    def test_color_disabled_environment(self):
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertFalse(supports_color())
            res = colorize("TEST", "32")
            self.assertEqual(res, "TEST")


if __name__ == "__main__":
    unittest.main()
