"""Windows Firewall security configuration check."""

import json
import re
from typing import Dict, List

from auditor.checks.base import BaseCheck
from auditor.config import AuditConfig
from auditor.models import CheckStatus, Finding, RiskLevel
from auditor.system import run_command, run_powershell


class FirewallCheck(BaseCheck):
    """Inspects Windows Firewall profile states (Domain, Private, Public)."""

    check_id = "WIN-FW-01"
    control_name = "Windows Firewall Configuration"
    description = "Inspects Domain, Private, and Public Windows Firewall profiles to ensure they are enabled."
    requires_windows = True

    def _query_netsh(self) -> Dict[str, str]:
        """Query firewall profiles via netsh advfirewall."""
        result = run_command(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if not result.is_success or not result.stdout:
            return {}

        profiles: Dict[str, str] = {}
        current_profile: str = ""

        for line in result.stdout.splitlines():
            line = line.strip()
            # Match profile headers like "Domain Profile Settings:"
            header_match = re.match(r"^(Domain|Private|Public)\s+Profile\s+Settings:?", line, re.IGNORECASE)
            if header_match:
                current_profile = header_match.group(1).capitalize()
                continue

            # Match "State ON" or "State OFF"
            if current_profile and re.search(r"\bState\b", line, re.IGNORECASE):
                parts = line.split()
                if len(parts) >= 2:
                    profiles[current_profile] = parts[-1].upper()

        return profiles

    def _query_powershell(self) -> Dict[str, str]:
        """Fallback query using PowerShell Get-NetFirewallProfile."""
        cmd = "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
        result = run_powershell(cmd)
        if not result.is_success or not result.stdout:
            return {}

        profiles: Dict[str, str] = {}
        try:
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                name = str(item.get("Name", "")).capitalize()
                enabled = item.get("Enabled")
                state_str = "ON" if enabled is True or str(enabled).lower() in ["true", "1"] else "OFF"
                profiles[name] = state_str
        except json.JSONDecodeError:
            pass

        return profiles

    def execute(self, config: AuditConfig) -> Finding:
        profiles = self._query_netsh()
        if not profiles:
            profiles = self._query_powershell()

        if not profiles:
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.ERROR,
                observed_evidence={"error": "Failed to retrieve Windows Firewall profile states"},
                expected_requirement=f"All profiles ({', '.join(config.firewall_required_profiles)}) must be ON.",
                risk_level=RiskLevel.HIGH,
                explanation="Unable to query Windows Firewall profile status via netsh or PowerShell.",
                recommended_remediation="Verify that the Windows Firewall service (mpssvc) is running and accessible.",
                verification_limitations="Execution failed to extract profile states.",
            )

        disabled_profiles: List[str] = []
        missing_profiles: List[str] = []

        for req in config.firewall_required_profiles:
            state = profiles.get(req.capitalize())
            if state is None:
                missing_profiles.append(req)
            elif state != "ON":
                disabled_profiles.append(req)

        expected_req = f"All required profiles ({', '.join(config.firewall_required_profiles)}) must be enabled (State: ON)."

        if disabled_profiles:
            status = CheckStatus.FAIL
            risk = RiskLevel.HIGH
            explanation = (
                f"One or more required Windows Firewall profiles are disabled: {', '.join(disabled_profiles)}. "
                "Disabling firewall profiles leaves the system vulnerable to unauthorized network access and lateral movement."
            )
            remediation = (
                f"Enable the disabled firewall profile(s) ({', '.join(disabled_profiles)}) using: "
                "`netsh advfirewall set allprofiles state on` or via the Windows Defender Firewall Control Panel."
            )
        elif missing_profiles:
            status = CheckStatus.REVIEW
            risk = RiskLevel.MEDIUM
            explanation = (
                f"Some required firewall profiles could not be identified: {', '.join(missing_profiles)}. "
                f"Observed profiles: {profiles}."
            )
            remediation = "Verify network location settings and ensure Domain, Private, and Public profiles are configured."
        else:
            status = CheckStatus.PASS
            risk = RiskLevel.INFORMATIONAL
            explanation = (
                f"All required Windows Firewall profiles ({', '.join(config.firewall_required_profiles)}) "
                "are active and enabled."
            )
            remediation = "No remediation needed. Maintain current firewall enforcement via Group Policy or Intune."

        return Finding(
            check_id=self.check_id,
            control_name=self.control_name,
            status=status,
            observed_evidence=profiles,
            expected_requirement=expected_req,
            risk_level=risk,
            explanation=explanation,
            recommended_remediation=remediation,
            verification_limitations="Read-only query of profile states. Individual firewall inbound/outbound rules and port exceptions were not evaluated.",
        )
