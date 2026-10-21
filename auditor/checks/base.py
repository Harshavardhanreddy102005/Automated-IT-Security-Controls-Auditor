"""Base class and interface for security control checks."""

from abc import ABC, abstractmethod
import traceback

from auditor.config import AuditConfig, DEFAULT_CONFIG
from auditor.models import CheckStatus, Finding, RiskLevel
from auditor.system import is_windows


class BaseCheck(ABC):
    """Abstract base class for all IT security control checks."""

    check_id: str = "BASE-00"
    control_name: str = "Base Control"
    description: str = "Base security check description."
    requires_windows: bool = True
    requires_elevation: bool = False

    @abstractmethod
    def execute(self, config: AuditConfig) -> Finding:
        """
        Execute the check logic and return a structured Finding.
        
        Subclasses should implement this method.
        """
        raise NotImplementedError

    def run(self, config: AuditConfig = DEFAULT_CONFIG) -> Finding:
        """
        Safely execute the check with platform checks and defensive exception handling.
        
        Guarantees that an individual check failure will never crash the audit suite.
        """
        if self.requires_windows and not is_windows():
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.NOT_APPLICABLE,
                observed_evidence={"platform": "non-windows"},
                expected_requirement="Windows operating system required for this control.",
                risk_level=RiskLevel.INFORMATIONAL,
                explanation=f"{self.control_name} is only applicable to Windows operating systems.",
                recommended_remediation="No remediation required on non-Windows platforms.",
                verification_limitations="Check skipped because host operating system is not Windows.",
            )

        try:
            return self.execute(config)
        except Exception as exc:
            return Finding(
                check_id=self.check_id,
                control_name=self.control_name,
                status=CheckStatus.ERROR,
                observed_evidence={"error": str(exc), "traceback": traceback.format_exc(limit=2)},
                expected_requirement="Check execution must complete successfully.",
                risk_level=RiskLevel.MEDIUM,
                explanation=f"Check encountered an unexpected execution error: {type(exc).__name__}: {exc}",
                recommended_remediation="Inspect system logs, permissions, and tool configuration to identify why the check failed to execute.",
                verification_limitations="Execution failed before evidence could be collected or evaluated.",
            )
