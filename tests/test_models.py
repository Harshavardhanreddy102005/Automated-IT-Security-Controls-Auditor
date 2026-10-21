"""Unit tests for data models, finding serialization, and summary statistics."""

import unittest
from auditor.models import (
    AuditReport,
    AuditSummary,
    CheckStatus,
    Finding,
    RiskLevel,
    SystemInfo,
)


class TestModels(unittest.TestCase):
    """Test suite for domain models and data serialization."""

    def test_finding_to_dict(self):
        finding = Finding(
            check_id="TEST-01",
            control_name="Sample Control",
            status=CheckStatus.PASS,
            observed_evidence={"key": "val"},
            expected_requirement="Requirement text",
            risk_level=RiskLevel.INFORMATIONAL,
            explanation="Explanation text",
            recommended_remediation="Remediation text",
            verification_limitations="Limitation text",
        )
        d = finding.to_dict()
        self.assertEqual(d["check_id"], "TEST-01")
        self.assertEqual(d["status"], "PASS")
        self.assertEqual(d["risk_level"], "INFORMATIONAL")
        self.assertEqual(d["observed_evidence"], {"key": "val"})

    def test_system_info_to_dict(self):
        info = SystemInfo(
            hostname="TESTHOST",
            os_name="Windows",
            os_release="11",
            os_version="10.0.22000",
            os_architecture="AMD64",
            python_version="3.14.0",
            is_elevated=False,
            current_user="testuser",
        )
        d = info.to_dict()
        self.assertEqual(d["hostname"], "TESTHOST")
        self.assertFalse(d["is_elevated"])

    def test_audit_summary_defaults(self):
        summary = AuditSummary()
        self.assertEqual(summary.total_checks, 0)
        self.assertEqual(summary.pass_count, 0)
        self.assertEqual(summary.fail_count, 0)
        self.assertEqual(summary.compliance_score_percent, 0.0)
        self.assertIn("CRITICAL", summary.risk_breakdown)

    def test_audit_report_serialization(self):
        info = SystemInfo("HOST", "Windows", "11", "10.0", "AMD64", "3.14", True, "admin")
        finding = Finding(
            "TEST-01", "Control", CheckStatus.FAIL, {}, "Req", RiskLevel.HIGH, "Exp", "Rem", "Lim"
        )
        summary = AuditSummary(1, 0, 1, 0, 0, 0, 0.0, {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0})
        report = AuditReport("1.0.0", "2026-10-21T00:00:00Z", info, [finding], summary)

        d = report.to_dict()
        self.assertEqual(d["metadata"]["tool_version"], "1.0.0")
        self.assertEqual(len(d["findings"]), 1)
        self.assertEqual(d["findings"][0]["status"], "FAIL")
        self.assertGreater(len(d["limitations"]), 0)


if __name__ == "__main__":
    unittest.main()
