"""Password and account lockout policy check."""

import re
from typing import Any, Dict, List

from auditor.checks.base import BaseCheck
from auditor.config import AuditConfig
from auditor.models import CheckStatus, Finding, RiskLevel
from auditor.system import run_command


class PasswordPolicyCheck(BaseCheck):
    """Inspects local password complexity, expiration, and account lockout thresholds."""

    check_id = "WIN-PWD-01"
    control_name = "Password and Account Lockout Policy"
    description = "Evaluates local password length, maximum password age, and account lockout threshold settings."
    requires_windows = True

    def _parse_net_accounts(self) -> Dict[str, Any]:
        """Parse settings from `net accounts` output."""
        result = run_command(["net", "accounts"])
        if not result.is_success or not result.stdout:
            return {}

        parsed: Dict[str, Any] = {}
        for line in result.stdout.splitlines():
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip().lower()
            val = val.strip()

            if "minimum password length" in key:
                try:
                    parsed["min_password_length"] = int(val)
                except ValueError:
                    parsed["min_password_length"] = 0
            elif "maximum password age" in key:
                try:
                    parsed["max_password_age_days"] = int(val)
                except ValueError:
                    parsed["max_password_age_days"] = val
            elif "minimum password age" in key:
                try:
                    parsed["min_password_age_days"] = int(val)
                except ValueError:
                    parsed["min_password_age_days"] = val
            elif "length of password history maintained" in key:
                try:
                    parsed["history_length"] = int(val)
                except ValueError:
                    parsed["history_length"] = 0 if val.lower() == "none" else val
            elif "lockout threshold" in key:
                try:
                    parsed["lockout_threshold"] = int(val)
                except ValueError:
                    parsed["lockout_threshold"] = 0 if val.lower() == "never" else val
            elif "lockout duration" in key:
                try:
                    parsed["lockout_duration_minutes"] = int(val)
                except ValueError:
                    parsed["lockout_duration_minutes"] = val
            elif "computer role" in key:
                parsed["computer_role"] = val

        return parsed

    def execute(self, config: AuditConfig) -> Finding:
        policy = self._parse_net_accounts()

        if not policy:
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.ERROR,
                observed_evidence={"error": "Failed to retrieve local account policy via 'net accounts'"},
                expected_requirement=f"Min length >= {config.password_min_length}, lockout threshold between {config.lockout_threshold_min} and {config.lockout_threshold_max}.",
                risk_level=RiskLevel.MEDIUM,
                explanation="The 'net accounts' command failed or produced unparseable output.",
                recommended_remediation="Verify user permissions and local Security Accounts Manager (SAM) availability.",
                verification_limitations="Local account policy could not be read.",
            )

        min_len = policy.get("min_password_length", 0)
        lockout = policy.get("lockout_threshold", 0)
        max_age = policy.get("max_password_age_days", 0)

        gaps: List[str] = []

        # Check minimum password length
        if min_len < config.password_min_length:
            gaps.append(
                f"Minimum password length is {min_len} characters (baseline requirement: >= {config.password_min_length})."
            )

        # Check account lockout threshold
        if lockout == 0:
            gaps.append(
                "Account lockout threshold is 0 (disabled). Accounts are vulnerable to unlimited brute-force attacks."
            )
        elif lockout > config.lockout_threshold_max:
            gaps.append(
                f"Account lockout threshold is {lockout} attempts (recommended: <= {config.lockout_threshold_max})."
            )

        expected_req = (
            f"Minimum password length >= {config.password_min_length} chars, "
            f"Account lockout threshold between {config.lockout_threshold_min} and {config.lockout_threshold_max} attempts."
        )

        if gaps:
            # Determine risk based on severity of gap
            risk = RiskLevel.HIGH if (min_len == 0 or lockout == 0) else RiskLevel.MEDIUM
            status = CheckStatus.FAIL
            explanation = "Local account policy does not meet the security baseline: " + " ".join(gaps)
            remediation = (
                "Configure local account policies using `secpol.msc` -> Account Policies -> Password Policy "
                "(Set Minimum password length >= 8) and Account Lockout Policy (Set Account lockout threshold between 3 and 10 attempts), "
                "or deploy baseline GPO via Active Directory / Microsoft Intune."
            )
        else:
            status = CheckStatus.PASS
            risk = RiskLevel.INFORMATIONAL
            explanation = (
                f"Local password policy satisfies baseline: Minimum password length is {min_len} chars, "
                f"lockout threshold is {lockout} attempts."
            )
            remediation = "Maintain current local account policy and monitor for unauthorized policy changes."

        return Finding(
            check_id=self.check_id,
            control_name=self.control_name,
            status=status,
            observed_evidence=policy,
            expected_requirement=expected_req,
            risk_level=risk,
            explanation=explanation,
            recommended_remediation=remediation,
            verification_limitations=(
                "Evaluates local SAM database account policy. If this computer is joined to an Active Directory domain "
                "or Azure AD (Microsoft Entra ID), domain GPOs and Fine-Grained Password Policies govern domain user accounts "
                "and supersede local SAM settings."
            ),
        )
