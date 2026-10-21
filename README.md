# Automated IT Security Controls Auditor

A lightweight, practical, educational security assessment and audit tool designed to evaluate host-based Windows security controls, compare configurations against defined baselines, identify control gaps, and generate executive-ready HTML and machine-readable JSON audit reports.

---

## 1. Project Overview

The **Automated IT Security Controls Auditor** automates the manual inspection of core Windows workstation and server security configurations. It collects read-only configuration evidence, evaluates the observed settings against documented cybersecurity baselines, calculates compliance metrics and risk ratings, and produces structured audit deliverables.

This tool is built for aspiring and practicing **Cyber Risk & Compliance Analysts**, **IT Auditors**, and **Security Operations Engineers** to demonstrate practical competence in:
- Technical control evaluation & verification
- Windows host security architecture
- Evidence-based gap analysis
- Audit reporting, communication, and risk prioritization
- Python-based security automation using the Python standard library

> **Disclaimer**: This is an educational IT security audit utility, not a penetration testing framework, antivirus replacement, or enterprise compliance platform. It does not modify system configurations, exploit vulnerabilities, or guarantee complete system security.

---

## 2. Why the Project Exists

In many small-to-midsize organizations and during security reviews, IT compliance analysts frequently spend hours manually validating whether endpoints adhere to hardening baselines (such as CIS Benchmarks, NIST SP 800-53, or ISO 27001 Annex A controls). Manual inspection via GUI utilities is time-consuming, prone to human oversight, and difficult to standardize.

This project exists to solve that challenge by providing an automated, repeatable, read-only audit engine that:
1. Gathers factual configuration evidence without modifying the system.
2. Standardizes findings into consistent audit states (`PASS`, `FAIL`, `REVIEW`, `ERROR`, `NOT_APPLICABLE`).
3. Translates technical telemetry into actionable remediation guidance for leadership and IT teams.

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
  - **Executive HTML Dashboard**: Self-contained, responsive, with visual scorecards, risk badges, evidence blocks, prioritized action plan, and print-to-PDF support.
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

On Linux / macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
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

### 3. Save Reports to a Custom Directory
```powershell
python -m auditor scan --output my_reports --format all
```

### 4. Generate Only JSON or HTML
```powershell
python -m auditor scan --format json
python -m auditor scan --format html
```

### 5. Run Demo Mode (Safe Simulation / Non-Windows Platforms)
```powershell
python -m auditor scan --demo
```

### 6. View Help and Version
```powershell
python -m auditor --help
python -m auditor --version
```

---

## 7. Example Output

Terminal summary produced by `python -m auditor scan`:

```text
======================================================================
  Automated IT Security Controls Auditor v1.0.0
  Cyber Risk & Security Controls Assessment Tool
======================================================================

[*] Initializing security audit scan at 2026-10-21 23:04:38...
[*] Audit complete for host 'SEC-WORKSTATION'.
[*] Execution context: Standard User

======================================================================
                       AUDIT SUMMARY RESULTS                          
======================================================================
  Total Controls Evaluated : 6
  PASS                     : 3
  FAIL                     : 1
  REVIEW (Human Assessment): 1
  ERROR (Privilege/Exec)   : 1
  NOT APPLICABLE           : 0
  Control Pass Rate        : 50.0%
----------------------------------------------------------------------
  Risk Breakdown:
    CRITICAL      : 0
    HIGH          : 1
    MEDIUM        : 2
    LOW           : 0
    INFORMATIONAL : 3
======================================================================

Detailed Findings:
  [PASS]   WIN-FW-01   Windows Firewall Configuration
           Risk: INFORMATIONAL | All required Windows Firewall profiles (Domain, Private, Public) are active and enabled.

  [PASS]   WIN-AV-01   Antivirus and Endpoint Protection
           Risk: INFORMATIONAL | Active antivirus protection verified: Microsoft Defender Antivirus with real-time protection enabled.

  [FAIL]   WIN-PWD-01  Password and Account Lockout Policy
           Risk: HIGH | Local account policy does not meet the security baseline: Minimum password length is 0 characters (baseline requirement: >= 8).
           Remediation: Configure local account policies using `secpol.msc` -> Account Policies -> Password Policy (Set Minimum password length >= 8) and Account Lockout Policy (Set Account lockout threshold between 3 and 10 attempts), or deploy baseline GPO via Active Directory / Microsoft Intune.

  [REVIEW] WIN-ADM-01  Local Administrator Accounts Review
           Risk: MEDIUM | Local Administrators group contains 3 member(s): Administrator, kiran, LENOVO. Accounts kiran, LENOVO require access review against the approved administrative authorization list.
           Remediation: Review the listed administrator accounts with system owners to ensure least privilege. Enforce standard user accounts for day-to-day operations and use Windows LAPS or privileged access management for administrative tasks.

  [PASS]   WIN-UPD-01  Operating System Patching & Update Status
           Risk: INFORMATIONAL | Latest verified security update (KB5127648) was installed on 2026-10-15 (5 days ago), satisfying the 60-day patch currency baseline.

  [ERROR]  WIN-AUD-01  Security Event Logging & Audit Policy
           Risk: MEDIUM | Windows Security Audit Policy inspection requires administrative privileges (SeSecurityPrivilege). When executed in a non-elevated user context, auditpol cannot enumerate active audit subcategories.
           Remediation: Run the audit from an elevated PowerShell or Command Prompt ('Run as Administrator') to inspect auditpol settings, or configure and verify audit policies centrally via Group Policy Object (GPO): Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration.

======================================================================
                       GENERATED AUDIT REPORTS                        
======================================================================
  -> C:\Jothish\Automated-IT-Security-Controls-Auditor\reports\audit_report_20261021_173441.html
  -> C:\Jothish\Automated-IT-Security-Controls-Auditor\reports\audit_report_20261021_173441.json
======================================================================
```

---

## 8. Report Locations

By default, generated reports are saved into the `reports/` folder:
- **HTML Report**: `reports/audit_report_<YYYYMMDD_HHMMSS>.html`
- **JSON Report**: `reports/audit_report_<YYYYMMDD_HHMMSS>.json`

Open the HTML report in Google Chrome, Microsoft Edge, or Firefox:
```powershell
# Open in default browser (Windows)
Start-Process reports\audit_report_*.html
```

---

## 9. Test Instructions

The project features a comprehensive unit and integration test suite with 45+ test cases covering positive evaluations, negative failures, permission denials, data serialization, and report rendering.

### Running with Standard Library `unittest` (No Installation Required)

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### Running with `pytest` (Optional)

```powershell
pip install pytest
pytest -v
```

---

## 10. Troubleshooting Guide

| Issue | Root Cause | User vs Code Fix | Actionable Solution |
| :--- | :--- | :--- | :--- |
| **Python not installed or wrong version** | Python `< 3.8` or not registered in system `PATH`. | User Fix | Install Python 3.10+ from python.org and check *"Add Python to PATH"* during setup. Run `python --version` to verify. |
| **Virtual environment activation blocked** | PowerShell execution policy restricts script execution (`PSSecurityException`). | User Fix | Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` in PowerShell, then re-run `.\.venv\Scripts\Activate.ps1`. |
| **Missing dependencies** | Optional test packages missing. | User Fix | Run `pip install -r requirements.txt`. Note: the core auditor runs without any external dependencies. |
| **Unsupported operating system** | Running live scans on Linux or macOS. | User Fix | Run `python -m auditor scan --demo` to view simulated sample findings, or run on a Windows machine for live telemetry. |
| **WIN-AUD-01 returns ERROR** | `auditpol` requires `SeSecurityPrivilege` available only in an elevated token. | User Fix | Right-click PowerShell or Command Prompt, select **"Run as Administrator"**, and re-run `python -m auditor scan`. |
| **Windows commands (`netsh`, `net`) unavailable** | System `PATH` does not include `C:\Windows\System32`. | User Fix | Verify that `%SystemRoot%\System32` is present in system environment variables (`PATH`). |
| **Antivirus status shows REVIEW** | 3rd-party EDR agent (e.g. CrowdStrike, SentinelOne) or Windows Server without SecurityCenter2. | User Fix / Review | As an analyst, review the enterprise EDR management portal. The tool deliberately flags unverified EDR as `REVIEW` rather than assuming failure. |
| **Report directory permission error** | Write access denied to output directory. | User Fix | Ensure user has write permissions to current directory or pass a writable path via `--output C:\Temp\reports`. |
| **Reports not generated** | Invalid `--output` argument or disk full. | User Fix | Run `python -m auditor doctor` to test directory writability. |
| **Tests failing** | Operating system command differences or modified files. | Code/Env Fix | Run `python -m unittest discover -s tests -p "test_*.py"` to see individual failure traces. Ensure tests run against unmodified repo files. |
| **Incorrect CLI usage** | Unknown subcommands or misspelled flags. | User Fix | Run `python -m auditor --help` or `python -m auditor scan --help` for usage syntax. |

> **Security Rule**: Never disable Windows Defender, turn off the firewall, or downgrade security settings as a troubleshooting shortcut.

---

## 11. Known Limitations

1. **Host-Based Scope**: Inspects the local workstation configuration via read-only APIs and commands (`netsh`, `net`, `Get-CimInstance`, `Get-HotFix`, `auditpol`). It does not audit network switches, firewalls, cloud infrastructure, or external web applications.
2. **Local Policy vs Domain GPO**: On domain-joined machines (Active Directory / Microsoft Entra ID), local password settings (`net accounts`) may differ from effective domain Group Policy Objects (GPOs). The tool documents this limitation in every password policy finding.
3. **Elevated Privilege Boundary**: Querying advanced security audit policies via `auditpol` requires an administrative token. In non-elevated user contexts, the check safely returns `ERROR` with remediation context rather than guessing or falsifying data.
4. **Third-Party EDR Namespaces**: Some enterprise EDR agents do not register in the consumer WMI `root\SecurityCenter2` namespace. When third-party EDR cannot be verified, the tool returns `REVIEW` with an analyst disclaimer.

---

## 12. Security and Ethical Use Notes

- **Read-Only Operations**: This tool strictly issues read-only inspection commands. It never executes remediation commands, never disables firewalls, never modifies account permissions, and never alters registry hives.
- **Privacy & Credential Protection**: The auditor does not log passwords, tokens, API keys, personal documents, or sensitive environment variables.
- **Intended Use**: This software is intended for educational demonstrations, authorized internal IT audits, baseline configuration assessments, and cybersecurity job interviews. It should only be executed on systems you own or have explicit authorization to assess.
