"""Unit tests for the command-line interface."""

import os
import tempfile
import unittest
from unittest.mock import patch

from auditor.cli import build_parser, main


class TestCLI(unittest.TestCase):
    """Test suite for CLI argument handling and execution commands."""

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

    def test_parser_scan_custom_options(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--output", "custom_reports", "--format", "json", "--demo"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.output, "custom_reports")
        self.assertEqual(args.format, "json")
        self.assertTrue(args.demo)

    def test_main_doctor_command(self):
        exit_code = main(["doctor"])
        self.assertIn(exit_code, [0, 1])

    def test_main_scan_demo_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            exit_code = main(["scan", "--demo", "--output", temp_dir, "--format", "all"])
            self.assertEqual(exit_code, 0)

            # Confirm report files were created in temp_dir
            files = os.listdir(temp_dir)
            html_files = [f for f in files if f.endswith(".html")]
            json_files = [f for f in files if f.endswith(".json")]

            self.assertEqual(len(html_files), 1)
            self.assertEqual(len(json_files), 1)

    def test_main_no_args_displays_help(self):
        exit_code = main([])
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
