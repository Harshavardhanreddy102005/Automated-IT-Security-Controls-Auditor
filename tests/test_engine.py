"""Unit tests for the audit engine and summary calculations."""

import unittest
from unittest.mock import MagicMock

from auditor.config import DEFAULT_CONFIG
from auditor.engine import AuditEngine
from auditor.models import CheckStatus, Finding, RiskLevel


class MockCheck:
    def __init__(self, check_id: str, status: CheckStatus, risk: RiskLevel):
        self.check_id = check_id
        self.status = status
        self.risk = risk

    def run(self, config=DEFAULT_CONFIG):
        return Finding(
            check_id=self.check_id,
            control_name=f"Mock {self.check_id}",
            status=self.status,
            observed_evidence={"mock": True},
            expected_requirement="Mock requirement",
            risk_level=self.risk,
            explanation=f"Mock explanation for {self.check_id}",
            recommended_remediation="Mock remediation",
            verification_limitations="Mock limitations",
        )


class TestEngine(unittest.TestCase):
    """Test suite for the audit coordination engine."""

    def test_engine_summary_calculation(self):
        checks = [
            MockCheck("M-01", CheckStatus.PASS, RiskLevel.INFORMATIONAL),
            MockCheck("M-02", CheckStatus.PASS, RiskLevel.INFORMATIONAL),
            MockCheck("M-03", CheckStatus.FAIL, RiskLevel.HIGH),
            MockCheck("M-04", CheckStatus.REVIEW, RiskLevel.MEDIUM),
            MockCheck("M-05", CheckStatus.ERROR, RiskLevel.MEDIUM),
            MockCheck("M-06", CheckStatus.NOT_APPLICABLE, RiskLevel.INFORMATIONAL),
        ]
        engine = AuditEngine(checks=checks)
        report = engine.run_audit()
        s = report.summary

        self.assertEqual(s.total_checks, 6)
        self.assertEqual(s.pass_count, 2)
        self.assertEqual(s.fail_count, 1)
        self.assertEqual(s.review_count, 1)
        self.assertEqual(s.error_count, 1)
        self.assertEqual(s.not_applicable_count, 1)
        # Applicable = 6 - 1 = 5. Pass rate = 2 / 5 = 40.0%
        self.assertEqual(s.compliance_score_percent, 40.0)

        # Risk breakdown
        self.assertEqual(s.risk_breakdown[RiskLevel.HIGH.value], 1)
        self.assertEqual(s.risk_breakdown[RiskLevel.MEDIUM.value], 2)
        self.assertEqual(s.risk_breakdown[RiskLevel.INFORMATIONAL.value], 3)

    def test_engine_zero_applicable_checks(self):
        checks = [
            MockCheck("M-01", CheckStatus.NOT_APPLICABLE, RiskLevel.INFORMATIONAL),
        ]
        engine = AuditEngine(checks=checks)
        report = engine.run_audit()
        self.assertEqual(report.summary.compliance_score_percent, 0.0)

    def test_demo_report_generation(self):
        report = AuditEngine.get_demo_report()
        self.assertEqual(report.system_info.hostname, "DEMO-SEC-NODE01")
        self.assertEqual(len(report.findings), 6)
        self.assertGreater(report.summary.pass_count, 0)
        self.assertGreater(report.summary.fail_count, 0)
        self.assertGreater(report.summary.review_count, 0)
        self.assertGreater(report.summary.error_count, 0)


if __name__ == "__main__":
    unittest.main()
