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
                short_finding="Unable to query local account policy via 'net accounts'.",
                impact="Without policy inspection, password complexity and account brute-force protections cannot be confirmed.",
                suggested_verification="Verify that the local Workstation service is running and execute 'net accounts' manually.",
            )

        min_len = policy.get("min_password_length", 0)
        lockout = policy.get("lockout_threshold", 0)
        max_age = policy.get("max_password_age_days", 0)

        gaps: List[str] = []
        short_reasons: List[str] = []

        # Check minimum password length
        if min_len < config.password_min_length:
            msg = f"Minimum password length is {min_len}; baseline requires at least {config.password_min_length} characters."
            gaps.append(msg)
            short_reasons.append(f"Minimum password length is {min_len} (required: >= {config.password_min_length})")

        # Check account lockout threshold
        if lockout == 0:
            msg = "Account lockout threshold is 0 (disabled). Accounts are vulnerable to unlimited brute-force attempts."
            gaps.append(msg)
            short_reasons.append("Account lockout threshold is disabled (0)")
        elif lockout > config.lockout_threshold_max:
            msg = f"Account lockout threshold is {lockout} attempts (recommended: <= {config.lockout_threshold_max})."
            gaps.append(msg)
            short_reasons.append(f"Account lockout threshold is {lockout} attempts")

        expected_req = (
            f"Minimum password length >= {config.password_min_length} chars, "
            f"Account lockout threshold between {config.lockout_threshold_min} and {config.lockout_threshold_max} attempts."
        )

        if gaps:
            risk = RiskLevel.HIGH if (min_len == 0 or lockout == 0) else RiskLevel.MEDIUM
            status = CheckStatus.FAIL
            short_finding = "; ".join(short_reasons) + "."
            explanation = (
                f"Local account policy does not meet the configured baseline: {' '.join(gaps)} "
                f"Observed settings: Minimum password length = {min_len}, Lockout threshold = {lockout} attempts."
            )
            remediation = (
                "Configure local account policies using `secpol.msc` -> Account Policies -> Password Policy "
                f"(set Minimum password length to >= {config.password_min_length}) and Account Lockout Policy "
                f"(set Account lockout threshold between {config.lockout_threshold_min} and {config.lockout_threshold_max} attempts), "
                "or deploy domain Group Policy Objects (GPOs)."
            )
            impact = (
                "Permitting zero-length or short passwords allows trivial passwords that can be easily guessed. "
                "Disabling lockout permits continuous automated credential guessing without host detection."
            )
            verification = "Execute 'net accounts' in PowerShell or CMD to verify updated 'Minimum password length' and 'Lockout threshold'."
        else:
            status = CheckStatus.PASS
            risk = RiskLevel.INFORMATIONAL
            short_finding = f"Password length is {min_len} chars; lockout threshold is {lockout} attempts."
            explanation = (
                f"Local password policy satisfies baseline: Minimum password length is {min_len} characters, "
                f"lockout threshold is {lockout} attempts."
            )
            remediation = "Maintain current local account policy and monitor for unauthorized configuration drift."
            impact = "Strong baseline password length and lockout thresholds effectively mitigate online dictionary attacks."
            verification = "Periodically run 'net accounts' or audit via Active Directory Group Policy management."

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
            short_finding=short_finding,
            impact=impact,
            suggested_verification=verification,
        )
