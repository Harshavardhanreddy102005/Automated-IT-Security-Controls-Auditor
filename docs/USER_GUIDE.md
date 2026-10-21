# User Guide & Walkthrough

A practical, step-by-step guide for installing, running, and interpreting the **Automated IT Security Controls Auditor**.

---

## 1. Prerequisites & Environment Setup

### A. Python Requirements
- **Python Version**: Python 3.8 or higher is required (Python 3.10+ recommended).
- **Verify Python Installation**:
  Open Windows PowerShell and run:
  ```powershell
  python --version
  ```
  If Python is not recognized, ensure that the path to `python.exe` is added to your user or system `PATH` environment variable.

### B. Opening the Project
1. Clone or download the repository:
   ```powershell
   git clone https://github.com/jothish-blip/Automated-IT-Security-Controls-Auditor.git
   ```
2. Navigate into the repository folder:
   ```powershell
   cd Automated-IT-Security-Controls-Auditor
   ```

### C. Optional: Virtual Environment
Because the auditor relies **exclusively on the Python standard library**, creating a virtual environment is optional. If you wish to create one:
```powershell
# Create virtual environment
python -m venv .venv

# Activate in PowerShell
.\.venv\Scripts\Activate.ps1
```
*(If PowerShell blocks script execution with a `PSSecurityException`, run: `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` and retry).*

---

## 2. Environment Diagnostics (`doctor`)

Before running your first scan, execute the diagnostic pre-flight check:
```powershell
python -m auditor doctor
```

### What `doctor` validates:
- **Python Version**: Confirms Python $\ge 3.8$.
- **Platform Support**: Detects Windows 10/11 or Windows Server.
- **Process Privileges**: Identifies whether the current shell is running as a **Standard User** or **Elevated Administrator**.
- **CLI Utilities**: Confirms availability of `powershell`, `netsh`, `net`, and `auditpol`.
- **Writability**: Ensures reports can be written to disk.

---

## 3. Running an Audit Scan

### A. Standard Live Audit
Run a security audit against the local Windows host:
```powershell
python -m auditor scan
```

### B. Verbose Diagnostics Mode
To see full telemetry, security impacts, and verification limits in the terminal:
```powershell
python -m auditor scan --verbose
```

### C. Quiet / Summary-Only Mode
To display only the compact summary and generated report paths:
```powershell
python -m auditor scan --quiet
```

### D. Custom Output Directory
To output reports to a specific destination folder:
```powershell
python -m auditor scan --output C:\AuditReports --format all
```

### E. Demo / Simulation Mode (Works Anywhere)
To evaluate the tool on a non-Windows machine or demonstrate safe sample findings:
```powershell
python -m auditor scan --demo
```

---

## 4. Understanding Audit Findings & Statuses

Every evaluated control produces one of five authoritative statuses:

| Status | Meaning | Cyber Risk Interpretation |
| :---: | :--- | :--- |
| **`PASS`** | The observed configuration met the configured security baseline. | Baseline satisfied at execution time. Maintain current policy. |
| **`FAIL`** | The observed configuration violated the baseline. | Control gap identified. Corrective remediation required. |
| **`REVIEW`** | Telemetry requires human analyst assessment. | Not an automatic vulnerability. Requires business verification (e.g. administrator accounts or enterprise EDR). |
| **`ERROR`** | Execution failed or elevation was restricted. | Privilege limitation (e.g. `auditpol` requiring Administrator). Run elevated to verify. |
| **`NOT_APPLICABLE`** | Control does not apply to the host platform. | Skipped on non-Windows systems. |

---

## 5. Viewing Audit Reports

Every scan automatically generates both an executive HTML report and a machine-readable JSON report in the `reports/` folder.

### A. Opening the HTML Report in Your Browser
To open the generated report in PowerShell, copy and run the exact command displayed at the end of the scan, or use:
```powershell
# Open the most recently generated HTML report
Get-ChildItem reports\*.html | Sort-Object LastWriteTime | Select-Object -Last 1 | ForEach-Object { Invoke-Item $_.FullName }
```

> **Why not `Start-Process reports\audit_report_*.html`?**  
> In PowerShell, `Start-Process` takes a literal `-FilePath` and does **not** expand wildcard patterns like `*.html`. If wildcards are used directly with `Start-Process`, PowerShell throws:  
> `Start-Process : This command cannot be run due to the error: The system cannot find the file specified.`  
> Always use `Invoke-Item "reports\audit_report_<timestamp>.html"` or pipe through `Get-ChildItem` as shown above.

### B. Machine-Readable JSON Report
JSON reports are saved alongside HTML reports:
`reports/audit_report_<YYYYMMDD_HHMMSS>.json`

Inspect JSON contents directly in PowerShell:
```powershell
Get-ChildItem reports\*.json | Select-Object -Last 1 | Get-Content | ConvertFrom-Json | Select-Object -ExpandProperty summary
```

---

## 6. Running Automated Tests

Run the full automated test suite containing 50+ unit and integration tests:

```powershell
# Run using standard library unittest
python -m unittest discover -s tests -p "test_*.py" -v
```
