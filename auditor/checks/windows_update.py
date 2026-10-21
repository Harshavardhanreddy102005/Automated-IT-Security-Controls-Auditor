"""Windows Update and hotfix patch management check."""

from datetime import datetime, timezone
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from auditor.checks.base import BaseCheck
from auditor.config import AuditConfig
from auditor.models import CheckStatus, Finding, RiskLevel
from auditor.system import run_powershell


class WindowsUpdateCheck(BaseCheck):
    """Inspects recent OS patch history and Windows Update service configuration."""

    check_id = "WIN-UPD-01"
    control_name = "Operating System Patching & Update Status"
    description = "Evaluates recent security hotfixes and confirms the Windows Update service is not disabled."
    requires_windows = True

    def _parse_installed_date(self, installed_on: Any) -> Optional[datetime]:
        """Parse various date formats returned by PowerShell Get-HotFix."""
        if not installed_on:
            return None

        # Format 1: dict with 'DateTime' or 'value' ("/Date(1234567890)/")
        if isinstance(installed_on, dict):
            date_val = installed_on.get("value")
            if date_val and isinstance(date_val, str):
                match = re.search(r"/Date\((\d+)\)/", date_val)
                if match:
                    try:
                        ms = int(match.group(1))
                        return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
                    except Exception:
                        pass
            dt_str = installed_on.get("DateTime")
            if dt_str and isinstance(dt_str, str):
                for fmt in ("%d %B %Y %H:%M:%S", "%B %d, %Y", "%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d"):
                    try:
                        return datetime.strptime(dt_str.strip(), fmt).replace(tzinfo=timezone.utc)
                    except ValueError:
                        pass

        # Format 2: string with /Date(1234567890)/
        if isinstance(installed_on, str):
            match = re.search(r"/Date\((\d+)\)/", installed_on)
            if match:
                try:
                    ms = int(match.group(1))
                    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
                except Exception:
                    pass

            for fmt in (
                "%d-%m-%Y %H:%M:%S",
                "%m/%d/%Y %H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%d-%m-%Y",
                "%m/%d/%Y",
                "%Y-%m-%d",
            ):
                try:
                    return datetime.strptime(installed_on.strip(), fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

        return None

    def _query_hotfixes(self) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]], Optional[int]]:
        """Query installed hotfixes using Get-HotFix."""
        cmd = "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID, Description, InstalledOn | ConvertTo-Json"
        result = run_powershell(cmd)
        if not result.is_success or not result.stdout:
            return [], None, None

        hotfixes: List[Dict[str, Any]] = []
        try:
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                raw_date = item.get("InstalledOn")
                parsed_dt = self._parse_installed_date(raw_date)
                date_str = parsed_dt.strftime("%Y-%m-%d") if parsed_dt else str(raw_date)
                hotfixes.append({
                    "hotfix_id": item.get("HotFixID", "Unknown"),
                    "description": item.get("Description", "Update"),
                    "installed_on": date_str,
                    "parsed_dt": parsed_dt,
                })
        except json.JSONDecodeError:
            return [], None, None

        latest_patch = None
        min_age_days = None
        now = datetime.now(timezone.utc)

        for hf in hotfixes:
            p_dt = hf.get("parsed_dt")
            if p_dt:
                age = (now - p_dt).days
                if min_age_days is None or age < min_age_days:
                    min_age_days = max(0, age)
                    latest_patch = hf

        clean_hotfixes = []
        for h in hotfixes:
            clean_copy = {k: v for k, v in h.items() if k != "parsed_dt"}
            clean_hotfixes.append(clean_copy)

        clean_latest = {k: v for k, v in latest_patch.items() if k != "parsed_dt"} if latest_patch else None
        return clean_hotfixes, clean_latest, min_age_days

    def _query_update_service(self) -> Dict[str, Any]:
        """Query the Windows Update service (wuauserv) state."""
        cmd = "Get-Service wuauserv | Select-Object Status, StartType | ConvertTo-Json"
        result = run_powershell(cmd)
        if not result.is_success or not result.stdout:
            return {"status": "Unknown", "start_type": "Unknown"}

        try:
            data = json.loads(result.stdout)
            status_map = {1: "Stopped", 2: "StartPending", 3: "StopPending", 4: "Running"}
            start_map = {2: "Automatic", 3: "Manual", 4: "Disabled"}

            raw_status = data.get("Status")
            raw_start = data.get("StartType")

            status_str = status_map.get(raw_status, str(raw_status))
            start_str = start_map.get(raw_start, str(raw_start))

            return {"status": status_str, "start_type": start_str}
        except Exception:
            return {"status": "Unknown", "start_type": "Unknown"}

    def execute(self, config: AuditConfig) -> Finding:
        hotfixes, latest_patch, patch_age_days = self._query_hotfixes()
        service_info = self._query_update_service()

        evidence: Dict[str, Any] = {
            "latest_recorded_hotfix": latest_patch,
            "patch_age_days": patch_age_days,
            "recent_hotfixes": hotfixes,
            "windows_update_service": service_info,
        }

        expected_req = (
            f"Recent security patch recorded within {config.patch_max_age_days_pass} days; "
            "Windows Update service must not be disabled."
        )

        if str(service_info.get("start_type", "")).lower() == "disabled":
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.FAIL,
                observed_evidence=evidence,
                expected_requirement=expected_req,
                risk_level=RiskLevel.HIGH,
                explanation=(
                    "The Windows Update service (wuauserv) is set to 'Disabled'. "
                    "This prevents the operating system from receiving critical security updates and definition files."
                ),
                recommended_remediation="Set the Windows Update service startup type to 'Manual' or 'Automatic' via Services.msc or Group Policy.",
                verification_limitations="Service status verified via Get-Service.",
                short_finding="Windows Update service (wuauserv) is Disabled.",
                impact="Disabling the update service leaves the operating system permanently unable to patch disclosed security vulnerabilities.",
                suggested_verification="Run 'Get-Service wuauserv' to verify Status is Running or StartType is Manual/Automatic.",
            )

        if not hotfixes or latest_patch is None or patch_age_days is None:
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.REVIEW,
                observed_evidence=evidence,
                expected_requirement=expected_req,
                risk_level=RiskLevel.MEDIUM,
                explanation=(
                    "No recent hotfix installation dates could be parsed from the Windows servicing store. "
                    "This may occur on newly provisioned machines, custom enterprise images, or when updates are delivered via WSUS/SCCM."
                ),
                recommended_remediation="Inspect Windows Update history in Settings or verify compliance through your enterprise patch management console.",
                verification_limitations="Get-HotFix returned no records or unparseable timestamps.",
                short_finding="No installed hotfix dates could be parsed from the Windows servicing store.",
                impact="Without verified patch history, the vulnerability status of the host cannot be reliably determined.",
                suggested_verification="Inspect Settings -> Windows Update -> Update history manually or check WSUS / Intune reporting.",
            )

        if patch_age_days <= config.patch_max_age_days_pass:
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.PASS,
                observed_evidence=evidence,
                expected_requirement=expected_req,
                risk_level=RiskLevel.INFORMATIONAL,
                explanation=(
                    f"Most recently recorded hotfix is {latest_patch['hotfix_id']}, installed on "
                    f"{latest_patch['installed_on']} ({patch_age_days} days ago). This satisfies the "
                    f"{config.patch_max_age_days_pass}-day patch-currency baseline."
                ),
                recommended_remediation="Maintain scheduled monthly patch cycle (Patch Tuesday).",
                verification_limitations=(
                    "Evaluates installed hotfix entries reported by Component-Based Servicing (CBS). "
                    "Does not check for pending, uninstalled updates against Microsoft catalogs, WSUS, or Intune."
                ),
                short_finding=f"Most recently recorded hotfix ({latest_patch['hotfix_id']}) installed {patch_age_days} days ago.",
                impact="Regular monthly patching resolves known security flaws, mitigating public exploit techniques.",
                suggested_verification="Periodically review installed updates via 'Get-HotFix' or Windows Update settings.",
            )

        if patch_age_days <= config.patch_max_age_days_review:
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.REVIEW,
                observed_evidence=evidence,
                expected_requirement=expected_req,
                risk_level=RiskLevel.MEDIUM,
                explanation=(
                    f"Most recently recorded hotfix is {latest_patch['hotfix_id']}, installed on "
                    f"{latest_patch['installed_on']} ({patch_age_days} days ago). "
                    f"This exceeds the {config.patch_max_age_days_pass}-day target but is under {config.patch_max_age_days_review} days."
                ),
                recommended_remediation="Review pending Windows updates and initiate patch deployment.",
                verification_limitations="Evaluates installed hotfix records reported by Component-Based Servicing.",
                short_finding=f"Most recently recorded hotfix ({latest_patch['hotfix_id']}) is {patch_age_days} days old (exceeds {config.patch_max_age_days_pass}-day baseline).",
                impact="Patch latency exposes the system to vulnerabilities disclosed within the preceding 60 to 90 days.",
                suggested_verification="Check Settings -> Windows Update for pending quality updates.",
            )

        return Finding(
            check_id=self.check_id,
            control_name=self.control_name,
            status=CheckStatus.FAIL,
            observed_evidence=evidence,
            expected_requirement=expected_req,
            risk_level=RiskLevel.HIGH,
            explanation=(
                f"Patching cadence is significantly delayed: most recently recorded hotfix ({latest_patch['hotfix_id']}) "
                f"was installed {patch_age_days} days ago ({latest_patch['installed_on']}). "
                "Systems lacking recent cumulative updates are vulnerable to publicly known security flaws."
            ),
            recommended_remediation="Immediately scan for, test, and apply missing Windows security updates.",
            verification_limitations="Evaluates installed hotfix records reported by Component-Based Servicing.",
            short_finding=f"Patching cadence significantly delayed: latest hotfix is {patch_age_days} days old.",
            impact="Unpatched systems are exposed to known exploited vulnerabilities (KEVs) and automated exploit kits.",
            suggested_verification="Run Windows Update and confirm pending cumulative updates are installed.",
        )
