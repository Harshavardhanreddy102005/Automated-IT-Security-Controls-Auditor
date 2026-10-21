"""Unit tests for all security control checks covering PASS, FAIL, REVIEW, and ERROR."""

import unittest
from unittest.mock import MagicMock, patch

from auditor.checks.administrators import LocalAdminsCheck
from auditor.checks.antivirus import AntivirusCheck
from auditor.checks.audit_policy import AuditPolicyCheck
from auditor.checks.base import BaseCheck
from auditor.checks.firewall import FirewallCheck
from auditor.checks.password_policy import PasswordPolicyCheck
from auditor.checks.windows_update import WindowsUpdateCheck
from auditor.config import AuditConfig, DEFAULT_CONFIG
from auditor.models import CheckStatus, Finding, RiskLevel
from auditor.system import CommandResult


class DummyFailingCheck(BaseCheck):
    check_id = "TEST-DUMMY-01"
    control_name = "Dummy Failing Check"
    requires_windows = True

    def execute(self, config: AuditConfig) -> Finding:
        raise RuntimeError("Simulated internal check failure")


class TestChecks(unittest.TestCase):
    """Test suite for security checks and evaluation logic."""

    # -------------------------------------------------------------
    # BaseCheck Tests
    # -------------------------------------------------------------
    @patch("auditor.checks.base.is_windows", return_value=False)
    def test_base_check_non_windows_handling(self, mock_win):
        check = FirewallCheck()
        finding = check.run()
        self.assertEqual(finding.status, CheckStatus.NOT_APPLICABLE)
        self.assertEqual(finding.risk_level, RiskLevel.INFORMATIONAL)
        self.assertIn("not Windows", finding.verification_limitations)

    def test_base_check_safe_exception_handling(self):
        check = DummyFailingCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()
        self.assertEqual(finding.status, CheckStatus.ERROR)
        self.assertEqual(finding.risk_level, RiskLevel.MEDIUM)
        self.assertIn("Simulated internal check failure", finding.explanation)

    # -------------------------------------------------------------
    # 1. Windows Firewall Check Tests
    # -------------------------------------------------------------
    @patch("auditor.checks.firewall.run_command")
    def test_firewall_all_profiles_on_pass(self, mock_cmd):
        mock_cmd.return_value = CommandResult(
            returncode=0,
            stdout=(
                "Domain Profile Settings:\nState ON\n"
                "Private Profile Settings:\nState ON\n"
                "Public Profile Settings:\nState ON\n"
            ),
            stderr="",
        )
        check = FirewallCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.PASS)
        self.assertEqual(finding.risk_level, RiskLevel.INFORMATIONAL)
        self.assertEqual(finding.observed_evidence.get("Public"), "ON")

    @patch("auditor.checks.firewall.run_command")
    def test_firewall_disabled_profile_fail(self, mock_cmd):
        mock_cmd.return_value = CommandResult(
            returncode=0,
            stdout=(
                "Domain Profile Settings:\nState ON\n"
                "Private Profile Settings:\nState ON\n"
                "Public Profile Settings:\nState OFF\n"
            ),
            stderr="",
        )
        check = FirewallCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.FAIL)
        self.assertEqual(finding.risk_level, RiskLevel.HIGH)
        self.assertIn("Public", finding.explanation)

    @patch("auditor.checks.firewall.run_command")
    @patch("auditor.checks.firewall.run_powershell")
    def test_firewall_command_failure_error(self, mock_ps, mock_cmd):
        mock_cmd.return_value = CommandResult(returncode=1, stdout="", stderr="netsh error")
        mock_ps.return_value = CommandResult(returncode=1, stdout="", stderr="ps error")

        check = FirewallCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.ERROR)
        self.assertEqual(finding.risk_level, RiskLevel.HIGH)

    # -------------------------------------------------------------
    # 2. Antivirus Check Tests
    # -------------------------------------------------------------
    @patch.object(AntivirusCheck, "_query_defender")
    @patch.object(AntivirusCheck, "_query_security_center")
    def test_antivirus_defender_active_pass(self, mock_sc, mock_def):
        mock_def.return_value = {
            "provider": "Microsoft Defender Antivirus",
            "antivirus_enabled": True,
            "realtime_protection": True,
            "signature_updated": "2026-10-21",
        }
        mock_sc.return_value = []

        check = AntivirusCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.PASS)
        self.assertEqual(finding.risk_level, RiskLevel.INFORMATIONAL)

    @patch.object(AntivirusCheck, "_query_defender")
    @patch.object(AntivirusCheck, "_query_security_center")
    def test_antivirus_realtime_disabled_fail(self, mock_sc, mock_def):
        mock_def.return_value = {
            "provider": "Microsoft Defender Antivirus",
            "antivirus_enabled": True,
            "realtime_protection": False,
        }
        mock_sc.return_value = []

        check = AntivirusCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.FAIL)
        self.assertEqual(finding.risk_level, RiskLevel.CRITICAL)

    @patch.object(AntivirusCheck, "_query_defender", return_value=None)
    @patch.object(AntivirusCheck, "_query_security_center", return_value=[])
    def test_antivirus_unverified_review(self, mock_sc, mock_def):
        check = AntivirusCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.REVIEW)
        self.assertEqual(finding.risk_level, RiskLevel.MEDIUM)
        self.assertIn("enterprise EDR", finding.explanation)

    # -------------------------------------------------------------
    # 3. Password and Account Policy Check Tests
    # -------------------------------------------------------------
    @patch("auditor.checks.password_policy.run_command")
    def test_password_policy_pass(self, mock_cmd):
        mock_cmd.return_value = CommandResult(
            returncode=0,
            stdout=(
                "Minimum password length: 14\n"
                "Maximum password age (days): 60\n"
                "Lockout threshold: 5\n"
            ),
            stderr="",
        )
        check = PasswordPolicyCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.PASS)
        self.assertEqual(finding.risk_level, RiskLevel.INFORMATIONAL)

    @patch("auditor.checks.password_policy.run_command")
    def test_password_policy_zero_length_fail(self, mock_cmd):
        mock_cmd.return_value = CommandResult(
            returncode=0,
            stdout=(
                "Minimum password length: 0\n"
                "Maximum password age (days): 42\n"
                "Lockout threshold: 5\n"
            ),
            stderr="",
        )
        check = PasswordPolicyCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.FAIL)
        self.assertEqual(finding.risk_level, RiskLevel.HIGH)

    @patch("auditor.checks.password_policy.run_command")
    def test_password_policy_lockout_zero_fail(self, mock_cmd):
        mock_cmd.return_value = CommandResult(
            returncode=0,
            stdout=(
                "Minimum password length: 8\n"
                "Maximum password age (days): 90\n"
                "Lockout threshold: 0\n"
            ),
            stderr="",
        )
        check = PasswordPolicyCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.FAIL)
        self.assertIn("lockout threshold is 0", finding.explanation.lower())

    # -------------------------------------------------------------
    # 4. Local Administrator Accounts Check Tests
    # -------------------------------------------------------------
    @patch.object(LocalAdminsCheck, "_query_net_localgroup")
    def test_administrators_approved_only_pass(self, mock_query):
        mock_query.return_value = ["Administrator"]
        check = LocalAdminsCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.PASS)
        self.assertEqual(finding.risk_level, RiskLevel.INFORMATIONAL)

    @patch.object(LocalAdminsCheck, "_query_net_localgroup")
    def test_administrators_unapproved_account_review(self, mock_query):
        mock_query.return_value = ["Administrator", "dev_user"]
        check = LocalAdminsCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.REVIEW)
        self.assertEqual(finding.risk_level, RiskLevel.MEDIUM)
        self.assertIn("dev_user", finding.explanation)

    @patch.object(LocalAdminsCheck, "_query_net_localgroup")
    def test_administrators_prohibited_guest_fail(self, mock_query):
        mock_query.return_value = ["Administrator", "Guest"]
        check = LocalAdminsCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.FAIL)
        self.assertEqual(finding.risk_level, RiskLevel.CRITICAL)
        self.assertIn("Guest", finding.explanation)

    # -------------------------------------------------------------
    # 5. Windows Update Status Check Tests
    # -------------------------------------------------------------
    @patch.object(WindowsUpdateCheck, "_query_update_service")
    @patch.object(WindowsUpdateCheck, "_query_hotfixes")
    def test_windows_update_recent_pass(self, mock_hf, mock_svc):
        mock_svc.return_value = {"status": "Running", "start_type": "Automatic"}
        mock_hf.return_value = (
            [{"hotfix_id": "KB123456", "installed_on": "2026-10-15"}],
            {"hotfix_id": "KB123456", "installed_on": "2026-10-15"},
            10,  # 10 days old
        )

        check = WindowsUpdateCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.PASS)
        self.assertEqual(finding.risk_level, RiskLevel.INFORMATIONAL)

    @patch.object(WindowsUpdateCheck, "_query_update_service")
    @patch.object(WindowsUpdateCheck, "_query_hotfixes")
    def test_windows_update_service_disabled_fail(self, mock_hf, mock_svc):
        mock_svc.return_value = {"status": "Stopped", "start_type": "Disabled"}
        mock_hf.return_value = ([], None, None)

        check = WindowsUpdateCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.FAIL)
        self.assertEqual(finding.risk_level, RiskLevel.HIGH)
        self.assertIn("Disabled", finding.explanation)

    @patch.object(WindowsUpdateCheck, "_query_update_service")
    @patch.object(WindowsUpdateCheck, "_query_hotfixes")
    def test_windows_update_stale_patches_fail(self, mock_hf, mock_svc):
        mock_svc.return_value = {"status": "Manual", "start_type": "Manual"}
        mock_hf.return_value = (
            [{"hotfix_id": "KB999999", "installed_on": "2026-05-01"}],
            {"hotfix_id": "KB999999", "installed_on": "2026-05-01"},
            120,  # 120 days old (> 90 days)
        )

        check = WindowsUpdateCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.FAIL)
        self.assertEqual(finding.risk_level, RiskLevel.HIGH)

    # -------------------------------------------------------------
    # 6. Windows Security Audit Policy Check Tests
    # -------------------------------------------------------------
    @patch.object(AuditPolicyCheck, "_query_auditpol")
    def test_audit_policy_elevation_required_error(self, mock_auditpol):
        mock_auditpol.return_value = ({}, "ELEVATION_REQUIRED")

        check = AuditPolicyCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.ERROR)
        self.assertEqual(finding.risk_level, RiskLevel.MEDIUM)
        self.assertIn("administrative privileges", finding.explanation)

    @patch.object(AuditPolicyCheck, "_query_auditpol")
    def test_audit_policy_all_active_pass(self, mock_auditpol):
        mock_auditpol.return_value = ({
            "Logon": "Success and Failure",
            "Logoff": "Success",
            "Account Lockout": "Failure",
            "User Account Management": "Success and Failure",
            "Security Group Management": "Success and Failure",
        }, None)

        check = AuditPolicyCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.PASS)
        self.assertEqual(finding.risk_level, RiskLevel.INFORMATIONAL)

    @patch.object(AuditPolicyCheck, "_query_auditpol")
    def test_audit_policy_missing_subcat_fail(self, mock_auditpol):
        mock_auditpol.return_value = ({
            "Logon": "No Auditing",
            "Logoff": "Success",
            "Account Lockout": "Failure",
            "User Account Management": "Success",
            "Security Group Management": "Success",
        }, None)

        check = AuditPolicyCheck()
        with patch("auditor.checks.base.is_windows", return_value=True):
            finding = check.run()

        self.assertEqual(finding.status, CheckStatus.FAIL)
        self.assertEqual(finding.risk_level, RiskLevel.MEDIUM)
        self.assertIn("Disabled: No Auditing", finding.explanation)


if __name__ == "__main__":
    unittest.main()
