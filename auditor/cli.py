"""Command-line interface for the Automated IT Security Controls Auditor."""

import argparse
from datetime import datetime, timezone
import json
import os
import platform
import shutil
import sys
import textwrap
from typing import Any, Dict, List, Optional

from auditor import __version__
from auditor.engine import AuditEngine
from auditor.models import AuditReport, CheckStatus, Finding, RiskLevel
from auditor.reporting import HtmlReporter, JsonReporter
from auditor.system import is_elevated, is_windows


def supports_color() -> bool:
    """Return True if stdout supports ANSI color output."""
    if "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


def colorize(text: str, color_code: str) -> str:
    """Wrap text in ANSI escape sequence if supported."""
    if not supports_color():
        return text
    return f"\033[{color_code}m{text}\033[0m"


def get_terminal_width() -> int:
    """Detect current terminal width safely with 80-column fallback."""
    try:
        cols = shutil.get_terminal_size((80, 24)).columns
        return max(60, min(cols, 120))
    except Exception:
        return 80


def format_evidence_concise(evidence: Any) -> str:
    """Format evidence into a concise one or two line summary suitable for CLI."""
    if isinstance(evidence, dict):
        # Extract the most salient keys
        items = []
        for k, v in evidence.items():
            if k in ("error", "traceback"):
                items.append(f"{k}: {v}")
            elif isinstance(v, (str, int, float, bool)):
                items.append(f"{k}: {v}")
            elif isinstance(v, list):
                items.append(f"{k}: {len(v)} item(s)")
            elif isinstance(v, dict):
                sub_items = [f"{sk}={sv}" for sk, sv in list(v.items())[:2]]
                items.append(f"{k}=({', '.join(sub_items)})")
        return ", ".join(items[:5])
    return str(evidence).strip()


def wrap_labeled_text(label: str, text: str, width: int, indent_len: int = 13) -> str:
    """
    Wrap text so subsequent lines are indented beneath the associated label.
    Example:
      Label      First line of wrapped text...
                 Second line aligned here...
    """
    padded_label = f"  {label:<10} "
    indent_space = " " * indent_len
    available_width = max(30, width - indent_len)
    
    wrapped_lines = textwrap.wrap(text, width=available_width)
    if not wrapped_lines:
        return padded_label

    output = padded_label + wrapped_lines[0]
    for line in wrapped_lines[1:]:
        output += "\n" + indent_space + line
    return output


def print_compact_summary(report: AuditReport, width: int) -> None:
    """Print a clean, restrained executive summary to the terminal."""
    s = report.summary
    info = report.system_info

    run_mode = "Elevated (Administrator)" if info.is_elevated else "Standard user"

    print("AUTOMATED IT SECURITY CONTROLS AUDITOR")
    print(f"Version {report.tool_version}")
    print()
    print(f"Host       : {info.hostname}")
    print(f"Platform   : {info.os_name} {info.os_release}")
    print(f"Run mode   : {run_mode}")
    print(f"Duration   : {report.duration_seconds} seconds")
    print()
    print("AUDIT SUMMARY")
    print(f"Controls checked : {s.total_checks}")
    print(f"Passed           : {s.pass_count}")
    print(f"Failed           : {s.fail_count}")
    print(f"Needs review     : {s.review_count}")
    print(f"Could not verify : {s.error_count}")
    if s.not_applicable_count > 0:
        print(f"Not applicable   : {s.not_applicable_count}")
    print()
    print("Risk overview")
    if s.risk_breakdown.get(RiskLevel.CRITICAL.value, 0) > 0:
        print(f"Critical         : {s.risk_breakdown[RiskLevel.CRITICAL.value]}")
    print(f"High             : {s.risk_breakdown.get(RiskLevel.HIGH.value, 0)}")
    print(f"Medium           : {s.risk_breakdown.get(RiskLevel.MEDIUM.value, 0)}")
    print(f"Low              : {s.risk_breakdown.get(RiskLevel.LOW.value, 0)}")
    print()


def print_finding(f: Finding, width: int, verbose: bool = False) -> None:
    """Print an individual finding with clean visual hierarchy and wrapped indentation."""
    status_colors = {
        CheckStatus.PASS: "32",            # Green
        CheckStatus.FAIL: "31;1",          # Bold Red
        CheckStatus.REVIEW: "33;1",        # Bold Yellow
        CheckStatus.ERROR: "35;1",         # Bold Magenta
        CheckStatus.NOT_APPLICABLE: "37",  # Grey/White
    }

    badge = f"[{f.status.value}]"
    badge_colored = colorize(badge, status_colors.get(f.status, "0"))
    
    header = f"{badge_colored} {f.check_id} | {f.control_name}"
    print(header)

    # Risk level styling
    risk_label = f.risk_level.value.capitalize()
    print(wrap_labeled_text("Risk", risk_label, width))

    # Finding summary
    finding_text = f.short_finding or f.explanation
    print(wrap_labeled_text("Finding", finding_text, width))

    # Evidence
    concise_ev = format_evidence_concise(f.observed_evidence)
    print(wrap_labeled_text("Evidence", concise_ev, width))

    # Action / Remediation
    action_text = f.recommended_remediation
    print(wrap_labeled_text("Action", action_text, width))

    if verbose:
        print(wrap_labeled_text("Required", f.expected_requirement, width))
        if f.impact:
            print(wrap_labeled_text("Impact", f.impact, width))
        if f.suggested_verification:
            print(wrap_labeled_text("Verify", f.suggested_verification, width))
        if f.verification_limitations:
            print(wrap_labeled_text("Boundary", f.verification_limitations, width))

    print()


def run_doctor() -> int:
    """Run diagnostic checks on environment, platform, commands, and permissions."""
    print("AUTOMATED IT SECURITY CONTROLS AUDITOR - ENVIRONMENT DIAGNOSTICS\n")

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

    print()
    if issues == 0 and warnings == 0:
        print("Diagnostic Status: ALL CHECKS PASSED. Ready for live audit scan.\n")
    elif issues == 0:
        print("Diagnostic Status: READY WITH WARNINGS. Scan can execute normally.\n")
    else:
        print("Diagnostic Status: ISSUES DETECTED. Please address the errors above.\n")

    return 1 if issues > 0 else 0


def run_scan(args: argparse.Namespace) -> int:
    """Execute the security audit scan, render findings, and write reports."""
    width = get_terminal_width()

    # Handle platform notice
    if not is_windows() and not args.demo:
        print(f"[Notice] Host operating system '{platform.system()}' is not Windows.")
        print("         Windows Security Controls Auditor evaluates Windows systems.")
        print("         Executing in non-Windows mode (checks will return NOT_APPLICABLE).")
        print("         Tip: Use '--demo' to generate a sample report with simulated findings.\n")

    # Execute audit or generate demo report
    if args.demo:
        report = AuditEngine.get_demo_report()
    else:
        engine = AuditEngine()
        report = engine.run_audit()

    # 1. Print compact summary
    print_compact_summary(report, width)

    # 2. Print findings (unless --quiet or --summary-only is set)
    if not args.quiet:
        print("DETAILED FINDINGS")
        print("-" * min(width, 70))

        # Order findings by actionable priority: FAIL, then REVIEW, then ERROR, then PASS, then NOT_APPLICABLE
        status_order = {
            CheckStatus.FAIL: 1,
            CheckStatus.REVIEW: 2,
            CheckStatus.ERROR: 3,
            CheckStatus.PASS: 4,
            CheckStatus.NOT_APPLICABLE: 5,
        }
        sorted_findings = sorted(report.findings, key=lambda f: status_order.get(f.status, 99))

        for f in sorted_findings:
            print_finding(f, width, verbose=args.verbose)

    # 3. Generate Reports
    out_dir = args.output
    os.makedirs(out_dir, exist_ok=True)
    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    html_file = os.path.join(out_dir, f"audit_report_{timestamp_slug}.html")
    json_file = os.path.join(out_dir, f"audit_report_{timestamp_slug}.json")

    fmt = args.format.lower()
    html_generated = None
    json_generated = None

    if fmt in ("all", "html"):
        HtmlReporter.generate(report, output_path=html_file)
        html_generated = html_file

    if fmt in ("all", "json"):
        JsonReporter.generate(report, output_path=json_file)
        json_generated = json_file

    # 4. Print report location and copy-paste viewer command
    print("REPORTS GENERATED")
    if html_generated:
        print(f"  HTML : {os.path.abspath(html_generated)}")
    if json_generated:
        print(f"  JSON : {os.path.abspath(json_generated)}")
    print()

    if html_generated:
        # Provide unambiguous PowerShell command that never fails with wildcards
        rel_html = os.path.relpath(html_generated)
        print("To view report in browser (PowerShell):")
        print(f"  Invoke-Item \"{rel_html}\"")
        print()

    # 5. Determine exit code:
    # 0 if no FAIL controls; 1 if one or more controls FAIL
    if report.summary.fail_count > 0:
        return 1
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
            "  python -m auditor scan --verbose\n"
            "  python -m auditor scan --quiet\n"
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
    scan_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Display extended finding details, impacts, and verification limits in terminal",
    )
    scan_parser.add_argument(
        "-q", "--quiet", "--summary-only",
        dest="quiet",
        action="store_true",
        help="Display compact summary and report paths only",
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
