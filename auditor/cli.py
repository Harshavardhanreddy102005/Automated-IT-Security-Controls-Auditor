"""Command-line interface for the Automated IT Security Controls Auditor."""

import argparse
from datetime import datetime, timezone
import os
import platform
import shutil
import sys
from typing import List, Optional

from auditor import __version__
from auditor.engine import AuditEngine
from auditor.models import CheckStatus, RiskLevel
from auditor.reporting import HtmlReporter, JsonReporter
from auditor.system import is_elevated, is_windows


def print_banner() -> None:
    banner = f"""
======================================================================
  Automated IT Security Controls Auditor v{__version__}
  Cyber Risk & Security Controls Assessment Tool
======================================================================
"""
    print(banner)


def run_doctor() -> int:
    """Run diagnostic checks on environment, platform, commands, and permissions."""
    print("\nRunning environment diagnostics (auditor doctor)...\n")

    issues = 0
    warnings = 0

    # 1. Python version
    py_ver = sys.version_info
    py_ver_str = f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}"
    if py_ver >= (3, 8):
        print(f"  [PASS] Python Version: {py_ver_str} (>= 3.8 required)")
    else:
        print(f"  [FAIL] Python Version: {py_ver_str} (Python >= 3.8 required)")
        issues += 1

    # 2. Operating System
    os_name = platform.system()
    if is_windows():
        print(f"  [PASS] Platform: Windows ({platform.release()} - {platform.version()})")
    else:
        print(f"  [WARN] Platform: {os_name} (Unsupported for live Windows auditing)")
        print("         Notice: Live security checks require Windows. Use '--demo' flag on non-Windows hosts.")
        warnings += 1

    # 3. User Elevation / Administrator Privileges
    elevated = is_elevated()
    if elevated:
        print("  [PASS] Process Privileges: Elevated (Administrator)")
    else:
        print("  [INFO] Process Privileges: Standard User (Non-Elevated)")
        print("         Notice: Most checks run without elevation; WIN-AUD-01 (auditpol) requires Administrator.")

    # 4. Command Availability
    tools = [
        ("PowerShell", ["powershell", "pwsh"], True),
        ("Netsh (Firewall)", ["netsh"], is_windows()),
        ("Net CLI (Accounts)", ["net"], is_windows()),
        ("Auditpol (Audit Policy)", ["auditpol"], is_windows()),
    ]

    for tool_name, commands, expected in tools:
        found = any(shutil.which(cmd) is not None for cmd in commands)
        if found:
            print(f"  [PASS] CLI Utility: {tool_name} is available in PATH")
        elif expected:
            print(f"  [WARN] CLI Utility: {tool_name} was not found in PATH")
            warnings += 1
        else:
            print(f"  [INFO] CLI Utility: {tool_name} (Not applicable on {os_name})")

    # 5. Report Directory Writability
    test_dir = "reports"
    try:
        os.makedirs(test_dir, exist_ok=True)
        test_file = os.path.join(test_dir, ".doctor_write_test")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        print(f"  [PASS] Report Directory: '{test_dir}' is writable")
    except Exception as exc:
        print(f"  [FAIL] Report Directory: Cannot write to '{test_dir}': {exc}")
        issues += 1

    print("\n----------------------------------------------------------------------")
    if issues == 0 and warnings == 0:
        print("  Diagnostic Status: ALL CHECKS PASSED. Ready for live audit scan.")
    elif issues == 0:
        print("  Diagnostic Status: READY WITH WARNINGS. Scan can execute normally.")
    else:
        print("  Diagnostic Status: ISSUES DETECTED. Please address the errors above.")
    print("----------------------------------------------------------------------\n")

    return 1 if issues > 0 else 0


def run_scan(args: argparse.Namespace) -> int:
    """Execute the security audit scan and write reports."""
    print_banner()

    # Handle platform check
    if not is_windows() and not args.demo:
        print(f"[!] Warning: Host operating system '{platform.system()}' is not Windows.")
        print("    Windows Security Controls Auditor is tailored for Windows workstations and servers.")
        print("    Executing in non-Windows mode (checks will return NOT_APPLICABLE).")
        print("    Tip: Use 'python -m auditor scan --demo' to generate a sample report with simulated findings.\n")

    print(f"[*] Initializing security audit scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}...")

    if args.demo:
        print("[*] Running in DEMO mode with representative sample control findings...")
        report = AuditEngine.get_demo_report()
    else:
        engine = AuditEngine()
        report = engine.run_audit()

    s = report.summary
    info = report.system_info

    print(f"[*] Audit complete for host '{info.hostname}'.")
    print(f"[*] Execution context: {'Elevated (Administrator)' if info.is_elevated else 'Standard User'}\n")

    # Print summary table
    print("======================================================================")
    print("                       AUDIT SUMMARY RESULTS                          ")
    print("======================================================================")
    print(f"  Total Controls Evaluated : {s.total_checks}")
    print(f"  PASS                     : {s.pass_count}")
    print(f"  FAIL                     : {s.fail_count}")
    print(f"  REVIEW (Human Assessment): {s.review_count}")
    print(f"  ERROR (Privilege/Exec)   : {s.error_count}")
    print(f"  NOT APPLICABLE           : {s.not_applicable_count}")
    print(f"  Control Pass Rate        : {s.compliance_score_percent}%")
    print("----------------------------------------------------------------------")
    print("  Risk Breakdown:")
    for risk_label in (RiskLevel.CRITICAL.value, RiskLevel.HIGH.value, RiskLevel.MEDIUM.value, RiskLevel.LOW.value, RiskLevel.INFORMATIONAL.value):
        cnt = s.risk_breakdown.get(risk_label, 0)
        print(f"    {risk_label:<14}: {cnt}")
    print("======================================================================\n")

    # Print individual findings list
    print("Detailed Findings:")
    for f in report.findings:
        status_symbol = {
            CheckStatus.PASS: "[PASS]",
            CheckStatus.FAIL: "[FAIL]",
            CheckStatus.REVIEW: "[REVIEW]",
            CheckStatus.ERROR: "[ERROR]",
            CheckStatus.NOT_APPLICABLE: "[N/A]",
        }.get(f.status, f"[{f.status.value}]")

        print(f"  {status_symbol:<8} {f.check_id:<11} {f.control_name}")
        print(f"           Risk: {f.risk_level.value} | {f.explanation}")
        if f.status in (CheckStatus.FAIL, CheckStatus.REVIEW, CheckStatus.ERROR):
            print(f"           Remediation: {f.recommended_remediation}")
        print()

    # Generate Reports
    out_dir = args.output
    os.makedirs(out_dir, exist_ok=True)
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    html_file = os.path.join(out_dir, f"audit_report_{timestamp_slug}.html")
    json_file = os.path.join(out_dir, f"audit_report_{timestamp_slug}.json")

    fmt = args.format.lower()
    generated_files = []

    if fmt in ("all", "html"):
        HtmlReporter.generate(report, output_path=html_file)
        generated_files.append(html_file)

    if fmt in ("all", "json"):
        JsonReporter.generate(report, output_path=json_file)
        generated_files.append(json_file)

    print("======================================================================")
    print("                       GENERATED AUDIT REPORTS                        ")
    print("======================================================================")
    for path in generated_files:
        abs_path = os.path.abspath(path)
        print(f"  -> {abs_path}")
    print("======================================================================\n")

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="auditor",
        description="Automated IT Security Controls Auditor - Educational Windows Security Assessment Tool",
        epilog=(
            "Examples:\n"
            "  python -m auditor doctor\n"
            "  python -m auditor scan\n"
            "  python -m auditor scan --output reports --format all\n"
            "  python -m auditor scan --demo\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Auditor command to execute")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Run security controls audit scan")
    scan_parser.add_argument(
        "-o", "--output",
        default="reports",
        help="Directory to save generated reports (default: 'reports')",
    )
    scan_parser.add_argument(
        "-f", "--format",
        choices=["all", "html", "json"],
        default="all",
        help="Report format to generate (default: 'all')",
    )
    scan_parser.add_argument(
        "--demo",
        action="store_true",
        help="Generate a demo audit report with simulated findings for evaluation or non-Windows hosts",
    )

    # doctor subcommand
    subparsers.add_parser("doctor", help="Inspect system prerequisites, platform, and permissions")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "doctor":
        return run_doctor()
    elif args.command == "scan":
        return run_scan(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
