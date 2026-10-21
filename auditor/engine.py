"""Audit execution engine for orchestrating checks and aggregating findings."""

from datetime import datetime, timezone
import platform
import time
from typing import List, Optional

from auditor import __version__
from auditor.checks import get_all_checks
from auditor.checks.base import BaseCheck
from auditor.config import AuditConfig, DEFAULT_CONFIG
from auditor.models import (
    AuditReport,
    AuditSummary,
    CheckStatus,
    Finding,
    RiskLevel,
    SystemInfo,
)
from auditor.system import get_system_info, is_windows


class AuditEngine:
    """Coordinates execution of security control checks and synthesizes audit reports."""

    def __init__(
        self,
        config: AuditConfig = DEFAULT_CONFIG,
        checks: Optional[List[BaseCheck]] = None,
    ):
        self.config = config
        self.checks = checks if checks is not None else get_all_checks()

    def run_audit(self) -> AuditReport:
        """
        Execute all configured security checks and compile the final audit report.
        """
        start_time = time.perf_counter()
        system_info = get_system_info(python_version=platform.python_version())
        timestamp = datetime.now(timezone.utc).isoformat()

        findings: List[Finding] = []
        for check in self.checks:
            finding = check.run(self.config)
            findings.append(finding)

        duration = round(time.perf_counter() - start_time, 2)
        summary = self._calculate_summary(findings)

        report = AuditReport(
            tool_version=__version__,
            timestamp=timestamp,
            system_info=system_info,
            findings=findings,
            summary=summary,
            duration_seconds=duration,
            author="HARSHA VARDHAN REDDY B",
        )
        return report

    def _calculate_summary(self, findings: List[Finding]) -> AuditSummary:
        """Calculate counts, risk distribution, and posture score from findings."""
        pass_count = sum(1 for f in findings if f.status == CheckStatus.PASS)
        fail_count = sum(1 for f in findings if f.status == CheckStatus.FAIL)
        review_count = sum(1 for f in findings if f.status == CheckStatus.REVIEW)
        error_count = sum(1 for f in findings if f.status == CheckStatus.ERROR)
        na_count = sum(1 for f in findings if f.status == CheckStatus.NOT_APPLICABLE)
        total = len(findings)

        applicable = total - na_count
        score = round((pass_count / applicable * 100.0), 1) if applicable > 0 else 0.0

        risk_breakdown = {
            RiskLevel.CRITICAL.value: sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL),
            RiskLevel.HIGH.value: sum(1 for f in findings if f.risk_level == RiskLevel.HIGH),
            RiskLevel.MEDIUM.value: sum(1 for f in findings if f.risk_level == RiskLevel.MEDIUM),
            RiskLevel.LOW.value: sum(1 for f in findings if f.risk_level == RiskLevel.LOW),
            RiskLevel.INFORMATIONAL.value: sum(1 for f in findings if f.risk_level == RiskLevel.INFORMATIONAL),
        }

        return AuditSummary(
            total_checks=total,
            pass_count=pass_count,
            fail_count=fail_count,
            review_count=review_count,
            error_count=error_count,
            not_applicable_count=na_count,
            compliance_score_percent=score,
            risk_breakdown=risk_breakdown,
        )

    @classmethod
    def get_demo_report(cls) -> AuditReport:
        """
        Produce a representative sample audit report with varied findings
        (PASS, FAIL, REVIEW, ERROR) for safe testing and demonstration.
        """
        demo_sysinfo = SystemInfo(
            hostname="DEMO-SEC-NODE01",
            os_name="Windows",
            os_release="11",
            os_version="10.0.22631",
            os_architecture="AMD64",
            python_version=platform.python_version(),
            is_elevated=False,
            current_user="DemoAnalyst",
        )

        sample_findings = [
            Finding(
                check_id="WIN-FW-01",
                control_name="Windows Firewall Configuration",
                status=CheckStatus.PASS,
                observed_evidence={"Domain": "ON", "Private": "ON", "Public": "ON"},
                expected_requirement="All required profiles (Domain, Private, Public) must be enabled (State: ON).",
                risk_level=RiskLevel.INFORMATIONAL,
                explanation="All required Windows Firewall profiles are active and enabled.",
                recommended_remediation="No remediation needed. Maintain current firewall enforcement via Group Policy.",
                verification_limitations="Read-only query of profile states. Individual rules not inspected.",
                short_finding="All required Windows Firewall profiles (Domain, Private, Public) are active and enabled.",
                impact="Inbound and outbound network connections are filtered according to defined firewall rules.",
                suggested_verification="Execute 'netsh advfirewall show allprofiles state' to verify profile states.",
            ),
            Finding(
                check_id="WIN-AV-01",
                control_name="Antivirus and Endpoint Protection",
                status=CheckStatus.PASS,
                observed_evidence={
                    "defender_status": {
                        "provider": "Microsoft Defender Antivirus",
                        "antivirus_enabled": True,
                        "realtime_protection": True,
                        "signature_updated": "2026-10-21",
                    }
                },
                expected_requirement="Active antivirus protection with real-time scanning enabled must be present.",
                risk_level=RiskLevel.INFORMATIONAL,
                explanation="Active antivirus protection verified with real-time scanning enabled.",
                recommended_remediation="Maintain regular signature updates and real-time monitoring.",
                verification_limitations="Verified via Defender API.",
                short_finding="Active antivirus protection verified: Microsoft Defender Antivirus with real-time protection enabled.",
                impact="Real-time scanning inspects files upon execution, providing critical frontline defense.",
                suggested_verification="Run 'Get-MpComputerStatus' and verify RealTimeProtectionEnabled is True.",
            ),
            Finding(
                check_id="WIN-PWD-01",
                control_name="Password and Account Lockout Policy",
                status=CheckStatus.FAIL,
                observed_evidence={
                    "min_password_length": 0,
                    "max_password_age_days": 42,
                    "lockout_threshold": 10,
                },
                expected_requirement="Minimum password length >= 8 chars, Account lockout threshold between 1 and 10 attempts.",
                risk_level=RiskLevel.HIGH,
                explanation="Local account policy does not meet baseline: Minimum password length is 0 characters (expected >= 8). Lockout threshold is 10 attempts.",
                recommended_remediation="Configure local account policies using secpol.msc or deploy GPO to enforce minimum password length.",
                verification_limitations="Evaluates local SAM database account policy via net accounts.",
                short_finding="Minimum password length is 0 (configured baseline requires >= 8). Lockout threshold is 10 attempts.",
                impact="Permitting zero-length passwords allows trivial passwords that can be easily guessed.",
                suggested_verification="Run 'net accounts' in Command Prompt to confirm updated password length.",
            ),
            Finding(
                check_id="WIN-ADM-01",
                control_name="Local Administrator Accounts Review",
                status=CheckStatus.REVIEW,
                observed_evidence={
                    "group_name": "Administrators",
                    "member_count": 2,
                    "members": ["Administrator", "harsha_admin"],
                },
                expected_requirement="Only approved accounts should hold local Administrator privileges.",
                risk_level=RiskLevel.MEDIUM,
                explanation="Local Administrators group contains member(s): Administrator, harsha_admin. Accounts require access justification review.",
                recommended_remediation="Review local administrator group members with the system owner against authorized access list.",
                verification_limitations="Enumerated local group members.",
                short_finding="Local Administrators group contains 2 member(s): Administrator, harsha_admin. Access review recommended.",
                impact="Unnecessary administrative accounts expand the attack surface for credential theft.",
                suggested_verification="Confirm business justification with asset owners.",
            ),
            Finding(
                check_id="WIN-UPD-01",
                control_name="Operating System Patching & Update Status",
                status=CheckStatus.PASS,
                observed_evidence={
                    "latest_recorded_hotfix": {"hotfix_id": "KB5127648", "installed_on": "2026-10-16"},
                    "patch_age_days": 5,
                },
                expected_requirement="Recent security patch recorded within 60 days.",
                risk_level=RiskLevel.INFORMATIONAL,
                explanation="Most recently recorded hotfix (KB5127648) was installed 5 days ago, meeting currency baseline.",
                recommended_remediation="Maintain scheduled monthly patch cycle.",
                verification_limitations="Evaluates installed hotfix entries reported by CBS store.",
                short_finding="Most recently recorded hotfix (KB5127648) installed 5 days ago.",
                impact="Regular monthly patching resolves known security flaws.",
                suggested_verification="Periodically review installed updates via 'Get-HotFix'.",
            ),
            Finding(
                check_id="WIN-AUD-01",
                control_name="Security Event Logging & Audit Policy",
                status=CheckStatus.ERROR,
                observed_evidence={"error": "A required privilege is not held by the client (Error 0x00000522)"},
                expected_requirement="Security audit logging must be active for critical event categories.",
                risk_level=RiskLevel.MEDIUM,
                explanation="Audit policy inspection requires administrative elevation (SeSecurityPrivilege).",
                recommended_remediation="Execute audit scan from an elevated prompt or configure audit policy via GPO.",
                verification_limitations="Non-elevated processes cannot query auditpol.",
                short_finding="Audit policy inspection requires administrative privileges (SeSecurityPrivilege) to query auditpol.",
                impact="Without verified audit logging, unauthorized logons and privilege escalation cannot be traced.",
                suggested_verification="Rerun 'python -m auditor scan' from an elevated PowerShell prompt ('Run as Administrator').",
            ),
        ]

        summary = AuditSummary(
            total_checks=len(sample_findings),
            pass_count=3,
            fail_count=1,
            review_count=1,
            error_count=1,
            not_applicable_count=0,
            compliance_score_percent=50.0,
            risk_breakdown={
                RiskLevel.CRITICAL.value: 0,
                RiskLevel.HIGH.value: 1,
                RiskLevel.MEDIUM.value: 2,
                RiskLevel.LOW.value: 0,
                RiskLevel.INFORMATIONAL.value: 3,
            },
        )

        return AuditReport(
            tool_version=__version__,
            timestamp=datetime.now(timezone.utc).isoformat(),
            system_info=demo_sysinfo,
            findings=sample_findings,
            summary=summary,
            duration_seconds=3.2,
            report_id="AUD-DEMO-SAMPLE",
            author="HARSHA VARDHAN REDDY B",
        )
