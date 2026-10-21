"""Windows Security Audit Policy configuration check."""

import re
from typing import Any, Dict, List, Tuple

from auditor.checks.base import BaseCheck
from auditor.config import AuditConfig
from auditor.models import CheckStatus, Finding, RiskLevel
from auditor.system import is_elevated, run_command


class AuditPolicyCheck(BaseCheck):
    """Inspects Windows Security Audit Policy for essential logon and account event logging."""

    check_id = "WIN-AUD-01"
    control_name = "Security Event Logging & Audit Policy"
    description = "Inspects whether critical security events (Logon, Logoff, Account Management) are audited."
    requires_windows = True
    requires_elevation = True

    def _query_auditpol(self) -> Tuple[Dict[str, str], Optional[str]]:
        """
        Execute auditpol to retrieve audit policies.
        
        Returns a tuple of (policy_dict, error_message).
        """
        result = run_command(["auditpol", "/get", "/category:*"])
        if not result.is_success or not result.stdout:
            err = result.stderr or result.error or "Unknown auditpol query failure"
            if "0x00000522" in err or "privilege is not held" in err.lower() or "access is denied" in err.lower():
                return {}, "ELEVATION_REQUIRED"
            return {}, err

        policies: Dict[str, str] = {}
        for line in result.stdout.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("Category") or line_str.startswith("System audit"):
                continue

            # Tab or multi-space separated: "Subcategory name       Setting"
            # Settings typically: "Success and Failure", "Success", "Failure", "No Auditing"
            match = re.match(r"^(.+?)\s{2,}(Success and Failure|Success|Failure|No Auditing)$", line_str, re.IGNORECASE)
            if match:
                subcat = match.group(1).strip()
                setting = match.group(2).strip()
                policies[subcat] = setting

        return policies, None

    def execute(self, config: AuditConfig) -> Finding:
        policies, error = self._query_auditpol()

        expected_req = (
            "Security audit logging must be active for critical event categories "
            f"({', '.join(config.required_audit_subcategories)}), capturing at least Success or Failure events."
        )

        # Handle lack of elevation gracefully without crashing or faking results
        if error == "ELEVATION_REQUIRED" or (not is_elevated() and not policies):
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.ERROR,
                observed_evidence={
                    "error": "A required privilege is not held by the client (Error 0x00000522)",
                    "is_elevated": False,
                    "policies_retrieved": False,
                },
                expected_requirement=expected_req,
                risk_level=RiskLevel.MEDIUM,
                explanation=(
                    "Windows Security Audit Policy inspection requires administrative privileges (SeSecurityPrivilege). "
                    "When executed in a non-elevated user context, auditpol cannot enumerate active audit subcategories."
                ),
                recommended_remediation=(
                    "Run the audit from an elevated PowerShell or Command Prompt ('Run as Administrator') to inspect auditpol settings, "
                    "or configure and verify audit policies centrally via Group Policy Object (GPO): "
                    "Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration."
                ),
                verification_limitations=(
                    "Querying auditpol directly requires an elevated administrative security token. "
                    "Non-elevated processes cannot query system audit policies."
                ),
            )

        if not policies:
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.ERROR,
                observed_evidence={"error": error or "Empty auditpol response"},
                expected_requirement=expected_req,
                risk_level=RiskLevel.MEDIUM,
                explanation="Failed to parse system audit policies from auditpol output.",
                recommended_remediation="Verify auditpol command availability and system language settings.",
                verification_limitations="Audit policy output could not be mapped to known categories.",
            )

        # If policies were retrieved successfully:
        missing_or_disabled: List[str] = []
        observed_matching: Dict[str, str] = {}

        for req in config.required_audit_subcategories:
            setting = policies.get(req)
            if not setting:
                # Look for partial matches (e.g. "User Account Management")
                matches = [v for k, v in policies.items() if req.lower() in k.lower()]
                setting = matches[0] if matches else None

            if setting is None:
                missing_or_disabled.append(f"{req} (Not Found)")
            elif setting.lower() == "no auditing":
                missing_or_disabled.append(f"{req} (Disabled: No Auditing)")
                observed_matching[req] = setting
            else:
                observed_matching[req] = setting

        evidence = {
            "required_subcategories_checked": config.required_audit_subcategories,
            "observed_settings": observed_matching,
            "total_subcategories_enumerated": len(policies),
        }

        if missing_or_disabled:
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.FAIL,
                observed_evidence=evidence,
                expected_requirement=expected_req,
                risk_level=RiskLevel.MEDIUM,
                explanation=(
                    f"One or more required audit subcategories are not auditing events: {', '.join(missing_or_disabled)}. "
                    "Without event auditing, unauthorized access attempts and account modifications will not appear in the Security Event Log."
                ),
                recommended_remediation=(
                    "Enable Success and Failure auditing for the missing categories using: "
                    "`auditpol /set /subcategory:\"<name>\" /success:enable /failure:enable` "
                    "or enforce through Advanced Audit Policy Configuration via GPO."
                ),
                verification_limitations="Evaluates local audit policy subcategories reported by auditpol.",
            )

        return Finding(
            check_id=self.check_id,
            control_name=self.control_name,
            status=CheckStatus.PASS,
            observed_evidence=evidence,
            expected_requirement=expected_req,
            risk_level=RiskLevel.INFORMATIONAL,
            explanation="All inspected security audit subcategories have active auditing configured.",
            recommended_remediation="Maintain existing audit policy and configure SIEM or event forwarding to monitor Security log Event IDs 4624, 4625, 4720, 4728.",
            verification_limitations="Evaluates audit subcategory configuration. Does not verify event log size limits, retention policies, or SIEM ingestion.",
        )
