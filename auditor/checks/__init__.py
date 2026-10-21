"""Registry and discovery of security control checks."""

from typing import Dict, List, Type

from auditor.checks.base import BaseCheck
from auditor.checks.firewall import FirewallCheck
from auditor.checks.antivirus import AntivirusCheck
from auditor.checks.password_policy import PasswordPolicyCheck
from auditor.checks.administrators import LocalAdminsCheck
from auditor.checks.windows_update import WindowsUpdateCheck
from auditor.checks.audit_policy import AuditPolicyCheck

ALL_CHECK_CLASSES: List[Type[BaseCheck]] = [
    FirewallCheck,
    AntivirusCheck,
    PasswordPolicyCheck,
    LocalAdminsCheck,
    WindowsUpdateCheck,
    AuditPolicyCheck,
]


def get_all_checks() -> List[BaseCheck]:
    """Instantiate and return all registered security control checks."""
    return [cls() for cls in ALL_CHECK_CLASSES]


def get_check_map() -> Dict[str, BaseCheck]:
    """Return a mapping of check_id to check instance."""
    return {check.check_id: check for check in get_all_checks()}
