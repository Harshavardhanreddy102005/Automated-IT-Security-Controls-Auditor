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
            header_match = re.match(r"^(Domain|Private|Public)\s+Profile\s+Settings:?", line, re.IGNORECASE)
            if header_match:
                current_profile = header_match.group(1).capitalize()
                continue

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
                short_finding="Unable to query Windows Firewall profile states via netsh or PowerShell.",
                impact="If the host firewall service is stopped or unresponsive, network ports may be unprotected.",
                suggested_verification="Verify the mpssvc service is running with 'Get-Service mpssvc' in PowerShell.",
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
            short_finding = f"Firewall profile(s) disabled: {', '.join(disabled_profiles)}."
            explanation = (
                f"One or more required Windows Firewall profiles are disabled: {', '.join(disabled_profiles)}. "
                "Disabling firewall profiles leaves the system vulnerable to unauthorized network access and lateral movement."
            )
            remediation = (
                f"Enable the disabled firewall profile(s) ({', '.join(disabled_profiles)}) using: "
                "`netsh advfirewall set allprofiles state on` or via Windows Defender Firewall with Advanced Security."
            )
            impact = "Disabled firewall profiles permit unmonitored inbound traffic, significantly increasing exposure to network worm replication and port scanning."
            verification = "Execute 'netsh advfirewall show allprofiles state' and ensure each profile reports State ON."
        elif missing_profiles:
            status = CheckStatus.REVIEW
            risk = RiskLevel.MEDIUM
            short_finding = f"Profiles could not be verified: {', '.join(missing_profiles)}."
            explanation = (
                f"Some required firewall profiles could not be identified: {', '.join(missing_profiles)}. "
                f"Observed profiles: {profiles}."
            )
            remediation = "Verify network location settings and ensure Domain, Private, and Public profiles are configured."
            impact = "Unidentified network profiles may allow untrusted networks to be assigned permissive traffic policies."
            verification = "Run 'Get-NetFirewallProfile' to inspect active network profile associations."
        else:
            status = CheckStatus.PASS
            risk = RiskLevel.INFORMATIONAL
            short_finding = "All required Windows Firewall profiles (Domain, Private, Public) are active and enabled."
            explanation = (
                f"All required Windows Firewall profiles ({', '.join(config.firewall_required_profiles)}) "
                "are active and enabled."
            )
            remediation = "No remediation needed. Maintain current firewall enforcement via Group Policy or Intune."
            impact = "Inbound and outbound network connections are filtered according to defined firewall rules."
            verification = "Periodically confirm profile states via Group Policy Objects or Intune endpoint security baselines."

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
            short_finding=short_finding,
            impact=impact,
            suggested_verification=verification,
        )
