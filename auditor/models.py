"""Data models, enumerations, and structures for audit findings and reports."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone


class CheckStatus(str, Enum):
    """Execution and evaluation status of an audit check."""
    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RiskLevel(str, Enum):
    """Categorized risk level of a finding."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass
class Finding:
    """Represents the structured result of an individual security control audit."""
    check_id: str
    control_name: str
    status: CheckStatus
    observed_evidence: Any
    expected_requirement: str
    risk_level: RiskLevel
    explanation: str
    recommended_remediation: str
    verification_limitations: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to a JSON-serializable dictionary."""
        return {
            "check_id": self.check_id,
            "control_name": self.control_name,
            "status": self.status.value,
            "observed_evidence": self.observed_evidence,
            "expected_requirement": self.expected_requirement,
            "risk_level": self.risk_level.value,
            "explanation": self.explanation,
            "recommended_remediation": self.recommended_remediation,
            "verification_limitations": self.verification_limitations,
        }


@dataclass
class SystemInfo:
    """Target host metadata gathered safely during the audit."""
    hostname: str
    os_name: str
    os_release: str
    os_version: str
    os_architecture: str
    python_version: str
    is_elevated: bool
    current_user: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditSummary:
    """Aggregated numerical metrics and risk breakdown for an audit run."""
    total_checks: int = 0
    pass_count: int = 0
    fail_count: int = 0
    review_count: int = 0
    error_count: int = 0
    not_applicable_count: int = 0
    compliance_score_percent: float = 0.0
    risk_breakdown: Dict[str, int] = field(default_factory=lambda: {
        RiskLevel.CRITICAL.value: 0,
        RiskLevel.HIGH.value: 0,
        RiskLevel.MEDIUM.value: 0,
        RiskLevel.LOW.value: 0,
        RiskLevel.INFORMATIONAL.value: 0,
    })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_checks": self.total_checks,
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "review_count": self.review_count,
            "error_count": self.error_count,
            "not_applicable_count": self.not_applicable_count,
            "compliance_score_percent": self.compliance_score_percent,
            "risk_breakdown": self.risk_breakdown,
        }


@dataclass
class AuditReport:
    """Complete audit report containing metadata, summary, findings, and disclaimers."""
    tool_version: str
    timestamp: str
    system_info: SystemInfo
    findings: List[Finding]
    summary: AuditSummary
    limitations: List[str] = field(default_factory=lambda: [
        "This tool is an educational IT security audit utility, not a penetration test or certified compliance platform.",
        "Checks are conducted using read-only host queries and inspect local configurations.",
        "Domain policies (Active Directory GPOs, Entra ID) may override local settings on enterprise workstations.",
        "A passing result indicates the specific configuration met the baseline rule at time of execution, not that the system is fully secure.",
    ])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": {
                "tool_name": "Automated IT Security Controls Auditor",
                "tool_version": self.tool_version,
                "timestamp": self.timestamp,
            },
            "system_info": self.system_info.to_dict(),
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "limitations": self.limitations,
        }
