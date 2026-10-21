"""Configurable security baselines and threshold settings for IT security audits."""

from dataclasses import dataclass, field
from typing import List


@dataclass
class AuditConfig:
    """Security control baselines and evaluation criteria."""
    
    # Check 1: Firewall Profiles
    firewall_required_profiles: List[str] = field(default_factory=lambda: [
        "Domain",
        "Private",
        "Public",
    ])
    
    # Check 2: Antivirus Protection
    antivirus_require_realtime: bool = True
    antivirus_require_uptodate_signatures: bool = True
    
    # Check 3: Password and Account Lockout Policy
    password_min_length: int = 8
    password_max_age_days: int = 90
    lockout_threshold_min: int = 1
    lockout_threshold_max: int = 10
    
    # Check 4: Local Administrator Accounts
    admin_allowed_accounts: List[str] = field(default_factory=lambda: [
        "Administrator",
    ])
    admin_prohibited_accounts: List[str] = field(default_factory=lambda: [
        "Guest",
        "DefaultAccount",
    ])
    
    # Check 5: Windows Update Status
    patch_max_age_days_pass: int = 60
    patch_max_age_days_review: int = 90
    
    # Check 6: Windows Security Audit Policy
    required_audit_subcategories: List[str] = field(default_factory=lambda: [
        "Logon",
        "Logoff",
        "Account Lockout",
        "User Account Management",
        "Security Group Management",
    ])


DEFAULT_CONFIG = AuditConfig()
