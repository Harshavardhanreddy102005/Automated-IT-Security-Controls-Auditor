"""Local Administrator accounts access review check."""

import re
from typing import Any, Dict, List

from auditor.checks.base import BaseCheck
from auditor.config import AuditConfig
from auditor.models import CheckStatus, Finding, RiskLevel
from auditor.system import run_command, run_powershell


class LocalAdminsCheck(BaseCheck):
    """Enumerates members of the local Administrators group for access control review."""

    check_id = "WIN-ADM-01"
    control_name = "Local Administrator Accounts Review"
    description = "Discovers members of the local Administrators group and verifies against approved access baselines."
    requires_windows = True

    def _query_net_localgroup(self) -> List[str]:
        """Query members using `net localgroup administrators`."""
        result = run_command(["net", "localgroup", "administrators"])
        if not result.is_success or not result.stdout:
            return []

        members: List[str] = []
        capture = False

        for line in result.stdout.splitlines():
            line_clean = line.strip()
            if "---" in line_clean:
                capture = True
                continue
            if "The command completed successfully" in line_clean:
                break
            if capture and line_clean:
                members.append(line_clean)

        return members

    def _query_powershell(self) -> List[str]:
        """Fallback query using PowerShell Get-LocalGroupMember."""
        cmd = "Get-LocalGroupMember -Group Administrators | Select-Object -ExpandProperty Name"
        result = run_powershell(cmd)
        if not result.is_success or not result.stdout:
            return []

        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def execute(self, config: AuditConfig) -> Finding:
        members = self._query_net_localgroup()
        if not members:
            members = self._query_powershell()

        if not members:
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.ERROR,
                observed_evidence={"error": "Failed to enumerate local Administrators group"},
                expected_requirement="Local Administrators group members must be identifiable and documented.",
                risk_level=RiskLevel.MEDIUM,
                explanation="Unable to retrieve local administrators membership via 'net localgroup' or PowerShell.",
                recommended_remediation="Verify user permissions and local Security Accounts Manager access.",
                verification_limitations="Local group enumeration command returned no results or failed.",
                short_finding="Unable to enumerate local Administrators group members.",
                impact="Unverified local administrator group membership impedes privileged access audits.",
                suggested_verification="Execute 'net localgroup administrators' in Command Prompt to confirm access.",
            )

        evidence: Dict[str, Any] = {
            "group_name": "Administrators",
            "member_count": len(members),
            "members": members,
        }

        # Check for explicitly prohibited or dangerous accounts (e.g. Guest)
        prohibited_found: List[str] = [
            m for m in members
            if any(p.lower() == m.split("\\")[-1].lower() for p in config.admin_prohibited_accounts)
        ]

        expected_req = (
            "Only approved accounts should hold local Administrator privileges. "
            f"Prohibited accounts ({', '.join(config.admin_prohibited_accounts)}) must never be in Administrators."
        )

        if prohibited_found:
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.FAIL,
                observed_evidence=evidence,
                expected_requirement=expected_req,
                risk_level=RiskLevel.CRITICAL,
                explanation=(
                    f"Prohibited / insecure account(s) detected in the local Administrators group: {', '.join(prohibited_found)}. "
                    "This creates a critical privilege escalation vector."
                ),
                recommended_remediation=(
                    f"Immediately remove {', '.join(prohibited_found)} from the local Administrators group using: "
                    "`net localgroup administrators <account> /delete`."
                ),
                verification_limitations="Enumerates local group members only.",
                short_finding=f"Insecure account(s) present in Administrators: {', '.join(prohibited_found)}.",
                impact="Anonymous, guest, or unauthenticated accounts with administrator privileges grant full system compromise without accountability.",
                suggested_verification="Run 'net localgroup administrators' and verify prohibited accounts are removed.",
            )

        # Check if non-standard accounts exist that require analyst review
        # Note: Do not automatically classify an account as a vulnerability solely because it is in Administrators.
        allowed_lower = [a.lower() for a in config.admin_allowed_accounts]
        unapproved = [m for m in members if m.split("\\")[-1].lower() not in allowed_lower]

        if not unapproved:
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.PASS,
                observed_evidence=evidence,
                expected_requirement=expected_req,
                risk_level=RiskLevel.INFORMATIONAL,
                explanation=f"Local Administrators group contains only baseline approved account(s): {', '.join(members)}.",
                recommended_remediation="Continue periodic privileged access reviews.",
                verification_limitations="Enumerated local group members. Nested domain group memberships were not expanded.",
                short_finding=f"Administrators group contains only approved baseline account(s): {', '.join(members)}.",
                impact="Restricting administrative access limits lateral movement opportunities across the network.",
                suggested_verification="Review local administrator group members quarterly against approved asset owner lists.",
            )

        # If accounts present require review:
        return Finding(
            check_id=self.check_id,
            control_name=self.control_name,
            status=CheckStatus.REVIEW,
            observed_evidence=evidence,
            expected_requirement=expected_req,
            risk_level=RiskLevel.MEDIUM,
            explanation=(
                f"Local Administrators group contains {len(members)} member(s): {', '.join(members)}. "
                f"Accounts {', '.join(unapproved)} require access review to verify active business justification "
                "under the principle of least privilege."
            ),
            recommended_remediation=(
                "Review the listed administrator accounts with system owners to ensure least privilege. "
                "Enforce standard user accounts for day-to-day operations and use Windows LAPS or privileged access management for administrative tasks."
            ),
            verification_limitations=(
                "Enumerated local group members. Does not assess whether individual accounts have multi-factor authentication (MFA) "
                "or dynamic Just-In-Time (JIT) access controls enabled."
            ),
            short_finding=f"Local Administrators group contains {len(members)} member(s) ({', '.join(members)}). Access review recommended.",
            impact="Holding excessive local administrator accounts expands the attack surface for credential dumping (e.g. LSASS access).",
            suggested_verification="Confirm business justification with asset owners and verify standard user accounts are used for normal work.",
        )
