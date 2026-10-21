# Automated IT Security Controls Auditor

A lightweight, practical, educational security assessment and audit tool designed to evaluate host-based Windows security controls, compare configurations against defined baselines, identify control gaps, and generate executive-ready HTML and machine-readable JSON audit reports.

**Author:** HARSHA VARDHAN REDDY B  
**License:** MIT

---

## 1. Project Overview

The **Automated IT Security Controls Auditor** automates the manual inspection of core Windows workstation and server security configurations. It collects read-only configuration evidence, evaluates observed settings against documented cybersecurity baselines, calculates compliance metrics and risk ratings, and produces structured audit deliverables.

This tool is built for aspiring and practicing **Cyber Risk & Compliance Analysts**, **IT Auditors**, and **Security Operations Engineers** to demonstrate practical competence in:
- Technical control evaluation & verification
- Windows host security architecture
- Evidence-based gap analysis
- Audit reporting, communication, and risk prioritization
- Python-based security automation using the Python standard library

> **Educational Notice**: This is an educational IT security audit utility, not a penetration testing framework, antivirus replacement, or enterprise compliance platform. It does not modify system configurations, exploit vulnerabilities, or guarantee complete system security.

---

## 2. Why the Project Exists

In many organizations, IT compliance analysts spend hours manually validating whether endpoints adhere to hardening baselines (such as CIS Benchmarks, NIST SP 800-53, or ISO 27001 Annex A controls). Manual inspection via GUI utilities is time-consuming, prone to human error, and difficult to standardize.

This project solves that challenge by providing an automated, repeatable, read-only audit engine that:
1. Gathers factual configuration evidence without altering the host system.
2. Standardizes findings into consistent audit states (`PASS`, `FAIL`, `REVIEW`, `ERROR`, `NOT_APPLICABLE`).
3. Translates technical telemetry into actionable remediation guidance for leadership and IT operations.

---

## 3. Key Features

- **Six Core Windows Control Areas Audited**:
  - `WIN-FW-01`: **Host-Based Windows Firewall** (Domain, Private, and Public profile enforcement)
  - `WIN-AV-01`: **Antivirus & Real-Time Protection** (Microsoft Defender and SecurityCenter2 EDR status)
  - `WIN-PWD-01`: **Password & Account Lockout Policies** (Minimum length, age, and brute-force lockout thresholds)
  - `WIN-ADM-01`: **Local Administrator Accounts Access Review** (Privileged group membership & unauthorized accounts)
  - `WIN-UPD-01`: **Operating System Patching & Updates** (Recent hotfix currency and Windows Update service health)
  - `WIN-AUD-01`: **Security Event Logging & Audit Policy** (Logon, Logoff, and Account Management event auditing)
- **Zero Third-Party Runtime Dependencies**: Implemented 100% using the Python standard library (no pip packages required to run scans).
- **Dual Reporting**:
  - **Consulting-Grade HTML Report**: Clean light theme, responsive, with executive summaries, finding tables, prioritized action plan, and print-to-PDF support.
  - **Machine-Readable JSON**: Standardized schema for SIEM, compliance tracking, or automated CI pipelines.
- **Graceful Privilege & Platform Handling**: Runs safely under both standard user accounts and elevated Administrator tokens without crashing. Non-elevated restrictions (e.g. `auditpol`) are clearly reported as `ERROR` with context rather than failing the scan.
- **Diagnostic Doctor**: Built-in `doctor` command to inspect host OS, Python version, elevation level, command availability, and directory writability before scanning.
- **Safe Testing Mode**: Includes a `--demo` simulation mode that runs anywhere (including Linux and macOS) to generate sample reports for review.

---

## 4. Prerequisites

- **Operating System**:
  - Windows 10, Windows 11, or Windows Server 2016+ (for live host audits).
  - Linux or macOS (supported via `--demo` mode and unit tests).
- **Python**:
  - Python 3.8 or higher (Python 3.10+ recommended).
- **Permissions**:
  - Standard user permissions are sufficient for 5 of the 6 checks.
  - Administrator privileges ("Run as Administrator") are required only for `WIN-AUD-01` (`auditpol`).

---

## 5. Installation

### Option A: Direct Clone (Zero Installation Required)

Because the auditor uses only Python's standard library, you can clone and run immediately:

```powershell
# Clone the repository
git clone https://github.com/jothish-blip/Automated-IT-Security-Controls-Auditor.git

# Change into the project directory
cd Automated-IT-Security-Controls-Auditor
```

### Option B: Using a Virtual Environment (Recommended for Development)

```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Optional: install development dependencies (pytest)
pip install -r requirements.txt
```

---

## 6. Exact Commands to Run

### 1. Check System Health & Prerequisites
```powershell
python -m auditor doctor
```

### 2. Run a Full Live Security Audit Scan
```powershell
python -m auditor scan
```

### 3. Display Extended Telemetry & Verification Boundaries
```powershell
python -m auditor scan --verbose
```

### 4. Display Compact Summary Only
```powershell
python -m auditor scan --quiet
```

### 5. Save Reports to a Custom Directory
```powershell
python -m auditor scan --output my_reports --format all
```

### 6. Run Demo Mode (Safe Simulation / Non-Windows Platforms)
```powershell
python -m auditor scan --demo
```

### 7. View Help and Version
```powershell
python -m auditor --help
python -m auditor --version
```

---

## 7. Example Output

Terminal summary produced by `python -m auditor scan`:

```text
AUTOMATED IT SECURITY CONTROLS AUDITOR
Version 1.0.0

Host       : KiranmaiReddy11
Platform   : Windows 11
Run mode   : Standard user
Duration   : 2.96 seconds

AUDIT SUMMARY
Controls checked : 6
Passed           : 3
Failed           : 1
Needs review     : 1
Could not verify : 1

Risk overview
High             : 1
Medium           : 2
Low              : 0

DETAILED FINDINGS
----------------------------------------------------------------------
[FAIL] WIN-PWD-01 | Password and Account Lockout Policy
  Risk       High
  Finding    Minimum password length is 0 (required: >= 8).
  Evidence   min_password_age_days: 0, max_password_age_days: 42,
             min_password_length: 0, history_length: 0, lockout_threshold: 10
  Action     Configure local account policies using `secpol.msc` -> Account
             Policies -> Password Policy (set Minimum password length to >= 8)
             and Account Lockout Policy (set Account lockout threshold between 1
             and 10 attempts), or deploy domain Group Policy Objects (GPOs).

[REVIEW] WIN-ADM-01 | Local Administrator Accounts Review
  Risk       Medium
  Finding    Local Administrators group contains 3 member(s) (Administrator,
             kiran, LENOVO). Access review recommended.
  Evidence   group_name: Administrators, member_count: 3, members: 3 item(s)
  Action     Review the listed administrator accounts with system owners to
             ensure least privilege. Enforce standard user accounts for day-to-
             day operations and use Windows LAPS or privileged access management
             for administrative tasks.

[ERROR] WIN-AUD-01 | Security Event Logging & Audit Policy
  Risk       Medium
  Finding    Audit policy inspection requires administrative privileges
             (SeSecurityPrivilege) to query auditpol.
  Evidence   error: A required privilege is not held by the client (Error
             0x00000522), is_elevated: False, policies_retrieved: False
  Action     Run the audit from an elevated PowerShell or Command Prompt ('Run
             as Administrator') to inspect auditpol settings, or configure and
             verify audit policies centrally via Group Policy Object (GPO):
             Computer Configuration -> Policies -> Windows Settings -> Security
             Settings -> Advanced Audit Policy Configuration.

[PASS] WIN-FW-01 | Windows Firewall Configuration
  Risk       Informational
  Finding    All required Windows Firewall profiles (Domain, Private, Public)
             are active and enabled.
  Evidence   Domain: ON, Private: ON, Public: ON
  Action     No remediation needed. Maintain current firewall enforcement via
             Group Policy or Intune.

[PASS] WIN-AV-01 | Antivirus and Endpoint Protection
  Risk       Informational
  Finding    Active antivirus protection verified: Microsoft Defender Antivirus,
             Windows Defender.
  Evidence   defender_status=(provider=Microsoft Defender Antivirus,
             antivirus_enabled=True), security_center_products: 1 item(s)
  Action     Maintain regular definition updates and continuous monitoring.

[PASS] WIN-UPD-01 | Operating System Patching & Update Status
  Risk       Informational
  Finding    Most recently recorded hotfix (KB5127648) installed 5 days ago.
  Evidence   latest_recorded_hotfix=(hotfix_id=KB5127648, description=Security
             Update), patch_age_days: 5, recent_hotfixes: 5 item(s),
             windows_update_service=(status=Stopped, start_type=Manual)
  Action     Maintain scheduled monthly patch cycle (Patch Tuesday).

REPORTS GENERATED
  HTML : C:\Jothish\Automated-IT-Security-Controls-Auditor\reports\audit_report_20261021_180010.html
  JSON : C:\Jothish\Automated-IT-Security-Controls-Auditor\reports\audit_report_20261021_180010.json

To view report in browser (PowerShell):
  Invoke-Item "reports\audit_report_20261021_180010.html"
```

---

## 8. Report Locations & Opening Reports

By default, generated reports are saved into the `reports/` folder:
- **HTML Report**: `reports/audit_report_<YYYYMMDD_HHMMSS>.html`
- **JSON Report**: `reports/audit_report_<YYYYMMDD_HHMMSS>.json`

### Opening the Report in Your Browser

In PowerShell, open the generated HTML report using `Invoke-Item`:

```powershell
# Option 1: Open the exact file printed in the CLI output
Invoke-Item "reports\audit_report_20261021_180010.html"

# Option 2: Automatically open the latest report
Get-ChildItem reports\*.html | Sort-Object LastWriteTime | Select-Object -Last 1 | ForEach-Object { Invoke-Item $_.FullName }
```

> **Why did `Start-Process reports\audit_report_*.html` fail?**  
> PowerShell's `Start-Process` takes a literal string for `-FilePath` and does **not** expand wildcards like `*.html`. Passing a wildcard directly causes PowerShell to report:  
> `Start-Process : This command cannot be run due to the error: The system cannot find the file specified.`  
> Always use `Invoke-Item` or pipe the result of `Get-ChildItem` as shown above.

---

## 9. Test Instructions

The project features a comprehensive test suite with 54 unit and integration tests covering positive evaluations, negative failures, permission denials, data serialization, and report rendering.

```powershell
# Run with standard library unittest (no dependencies needed)
python -m unittest discover -s tests -p "test_*.py" -v
```

---

## 10. Documentation Index

Detailed engineering and operational documentation is available in the [`docs/`](file:///c:/Jothish/Automated-IT-Security-Controls-Auditor/docs) directory:
- [**Architecture Guide** (`docs/ARCHITECTURE.md`)](file:///c:/Jothish/Automated-IT-Security-Controls-Auditor/docs/ARCHITECTURE.md): System architecture, execution flow, data models, error boundaries, and Mermaid flowcharts.
- [**User Guide & Walkthrough** (`docs/USER_GUIDE.md`)](file:///c:/Jothish/Automated-IT-Security-Controls-Auditor/docs/USER_GUIDE.md): Beginner walkthrough, virtual environments, diagnostic execution, and report interpretation.
- [**Troubleshooting Guide** (`docs/TROUBLESHOOTING.md`)](file:///c:/Jothish/Automated-IT-Security-Controls-Auditor/docs/TROUBLESHOOTING.md): Actionable solutions for permissions, wildcards, Python versions, and environment issues.
- [**Security Controls Reference** (`docs/SECURITY_CONTROLS.md`)](file:///c:/Jothish/Automated-IT-Security-Controls-Auditor/docs/SECURITY_CONTROLS.md): In-depth specification of the six security controls, observation sources, status logic, and limitations.

---

## 11. Security and Ethical Use Notes

- **Read-Only Operations**: This tool strictly issues read-only inspection commands. It never executes remediation commands, never disables firewalls, never modifies account permissions, and never alters registry hives.
- **Privacy & Credential Protection**: The auditor does not log passwords, tokens, API keys, personal documents, or sensitive environment variables.
- **Intended Use**: This software is intended for educational demonstrations, authorized internal IT audits, baseline configuration assessments, and cybersecurity job interviews. It should only be executed on systems you own or have explicit authorization to assess.
