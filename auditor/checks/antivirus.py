"""Antivirus and endpoint protection status check."""

import json
from typing import Any, Dict, List, Optional

from auditor.checks.base import BaseCheck
from auditor.config import AuditConfig
from auditor.models import CheckStatus, Finding, RiskLevel
from auditor.system import run_powershell


class AntivirusCheck(BaseCheck):
    """Inspects endpoint antivirus registration and real-time protection status."""

    check_id = "WIN-AV-01"
    control_name = "Antivirus and Endpoint Protection"
    description = "Checks whether antivirus protection is installed, active, and has real-time scanning enabled."
    requires_windows = True

    def _query_defender(self) -> Optional[Dict[str, Any]]:
        """Query Microsoft Defender status via Get-MpComputerStatus."""
        cmd = (
            "Get-MpComputerStatus | Select-Object "
            "AntivirusEnabled, RealTimeProtectionEnabled, "
            "AntivirusSignatureLastUpdated, AMServiceEnabled | "
            "ConvertTo-Json"
        )
        result = run_powershell(cmd)
        if not result.is_success or not result.stdout:
            return None

        try:
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                return {
                    "provider": "Microsoft Defender Antivirus",
                    "antivirus_enabled": bool(data.get("AntivirusEnabled", False)),
                    "realtime_protection": bool(data.get("RealTimeProtectionEnabled", False)),
                    "signature_updated": str(data.get("AntivirusSignatureLastUpdated", "Unknown")),
                    "service_enabled": bool(data.get("AMServiceEnabled", False)),
                }
        except json.JSONDecodeError:
            pass

        return None

    def _query_security_center(self) -> List[Dict[str, Any]]:
        """Query WMI / CIM root/SecurityCenter2 AntivirusProduct (supports 3rd-party AV)."""
        cmd = (
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | "
            "Select-Object displayName, productState, pathToSignedProductExe | "
            "ConvertTo-Json"
        )
        result = run_powershell(cmd)
        if not result.is_success or not result.stdout:
            return []

        providers: List[Dict[str, Any]] = []
        try:
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                display_name = item.get("displayName", "Unknown Provider")
                product_state = item.get("productState", 0)

                # Decode Windows Security Center productState bitmask
                # Format: 0x000000 (hex)
                # Byte 2 (middle byte): Real-time protection status (0x10 = enabled, 0x00/0x01 = disabled)
                # Byte 1 (least significant): Signatures (0x00 = up-to-date, 0x10 = out-of-date)
                hex_state = f"{int(product_state):06x}"
                rtp_hex = hex_state[2:4] if len(hex_state) >= 4 else "00"
                realtime_enabled = (rtp_hex == "10")

                providers.append({
                    "provider": display_name,
                    "product_state_raw": product_state,
                    "product_state_hex": f"0x{hex_state}",
                    "realtime_protection": realtime_enabled,
                })
        except Exception:
            pass

        return providers

    def execute(self, config: AuditConfig) -> Finding:
        defender_info = self._query_defender()
        sc_providers = self._query_security_center()

        evidence: Dict[str, Any] = {
            "defender_status": defender_info,
            "security_center_products": sc_providers,
        }

        # 1. Determine active protection
        has_active_rtp = False
        active_providers: List[str] = []
        inactive_providers: List[str] = []

        if defender_info and defender_info.get("realtime_protection"):
            has_active_rtp = True
            active_providers.append(defender_info["provider"])
        elif defender_info and not defender_info.get("realtime_protection"):
            inactive_providers.append(f"{defender_info['provider']} (Real-Time Protection Disabled)")

        for p in sc_providers:
            p_name = p.get("provider", "Unknown")
            if p.get("realtime_protection"):
                has_active_rtp = True
                if p_name not in active_providers:
                    active_providers.append(p_name)
            else:
                if p_name not in inactive_providers:
                    inactive_providers.append(f"{p_name} (Real-Time Protection Disabled)")

        expected_req = "Active antivirus protection with real-time scanning enabled must be present."

        # 2. Evaluate status
        if has_active_rtp:
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.PASS,
                observed_evidence=evidence,
                expected_requirement=expected_req,
                risk_level=RiskLevel.INFORMATIONAL,
                explanation=f"Active antivirus protection verified: {', '.join(active_providers)} with real-time protection enabled.",
                recommended_remediation="Maintain regular signature updates and real-time monitoring.",
                verification_limitations="Verified via Defender and Windows Security Center interfaces. Signature definitions and heuristics were not tested with test files.",
            )

        if inactive_providers:
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.FAIL,
                observed_evidence=evidence,
                expected_requirement=expected_req,
                risk_level=RiskLevel.CRITICAL,
                explanation=(
                    f"Antivirus software is installed but real-time protection is DISABLED: {', '.join(inactive_providers)}. "
                    "Endpoints without real-time protection are directly exposed to malware execution."
                ),
                recommended_remediation="Enable real-time protection in Windows Security or deploy policy via Group Policy / Intune / MDM.",
                verification_limitations="Antivirus software identified, but real-time scanning flag returned disabled.",
            )

        # If no provider could be verified
        # Per requirement: "Do not assume that a missing provider or inaccessible status means antivirus is definitely disabled."
        return Finding(
            check_id=self.check_id,
            control_name=self.control_name,
            status=CheckStatus.REVIEW,
            observed_evidence=evidence,
            expected_requirement=expected_req,
            risk_level=RiskLevel.MEDIUM,
            explanation=(
                "No registered antivirus or real-time protection provider could be automatically confirmed. "
                "This does not necessarily mean protection is absent; enterprise EDR agents (e.g. CrowdStrike Falcon, "
                "SentinelOne, Carbon Black) on Windows Server or managed machines may not register with the consumer SecurityCenter2 WMI namespace."
            ),
            recommended_remediation="Verify whether an enterprise endpoint protection agent is installed and running as a system service.",
            verification_limitations="WMI SecurityCenter2 and Get-MpComputerStatus returned no active provider records.",
        )
