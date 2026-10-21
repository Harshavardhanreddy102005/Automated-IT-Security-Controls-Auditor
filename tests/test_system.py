"""Unit tests for system interaction and command execution."""

import subprocess
import unittest
from unittest.mock import patch, MagicMock

from auditor.system import (
    CommandResult,
    get_system_info,
    is_elevated,
    is_windows,
    run_command,
    run_powershell,
)


class TestSystem(unittest.TestCase):
    """Test suite for system command execution and environment utilities."""

    def test_command_result_properties(self):
        res_ok = CommandResult(returncode=0, stdout="output", stderr="")
        self.assertTrue(res_ok.is_success)

        res_err = CommandResult(returncode=1, stdout="", stderr="error")
        self.assertFalse(res_err.is_success)

        res_timeout = CommandResult(returncode=-1, stdout="", stderr="", timed_out=True)
        self.assertFalse(res_timeout.is_success)

    @patch("subprocess.run")
    def test_run_command_success(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "hello world\n"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        result = run_command(["test_cmd"])
        self.assertTrue(result.is_success)
        self.assertEqual(result.stdout, "hello world")

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="slow_cmd", timeout=5))
    def test_run_command_timeout(self, mock_run):
        result = run_command(["slow_cmd"], timeout=5)
        self.assertFalse(result.is_success)
        self.assertTrue(result.timed_out)
        self.assertIn("TimeoutExpired", result.error)

    @patch("subprocess.run", side_effect=FileNotFoundError("Executable not found"))
    def test_run_command_not_found(self, mock_run):
        result = run_command(["missing_exe"])
        self.assertFalse(result.is_success)
        self.assertEqual(result.returncode, 127)
        self.assertIn("ExecutableNotFound", result.error)

    @patch("subprocess.run", side_effect=PermissionError("Access denied"))
    def test_run_command_permission_denied(self, mock_run):
        result = run_command(["privileged_exe"])
        self.assertFalse(result.is_success)
        self.assertEqual(result.returncode, 126)
        self.assertIn("PermissionDenied", result.error)

    @patch("shutil.which", return_value=None)
    @patch("auditor.system.is_windows", return_value=False)
    def test_run_powershell_unavailable(self, mock_is_win, mock_which):
        result = run_powershell("Get-Date")
        self.assertFalse(result.is_success)
        self.assertIn("PowerShell is not available", result.stderr)

    def test_get_system_info(self):
        info = get_system_info("3.14.0")
        self.assertIsNotNone(info.hostname)
        self.assertIsNotNone(info.os_name)
        self.assertEqual(info.python_version, "3.14.0")
        self.assertIsInstance(info.is_elevated, bool)


if __name__ == "__main__":
    unittest.main()
