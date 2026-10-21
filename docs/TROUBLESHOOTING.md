# Troubleshooting Guide

This guide provides symptoms, root causes, user versus code classifications, and verified fixes for common runtime and environment issues.

> **Security Rule**: Never disable Windows Defender, turn off the Windows Firewall, or downgrade security settings as a troubleshooting shortcut.

---

## 1. Quick Reference Issue Matrix

| Symptom | Likely Cause | Fix Type | Solution Summary |
| :--- | :--- | :---: | :--- |
| `The system cannot find the file specified` when opening report | PowerShell `Start-Process` does not expand wildcards | User Fix | Use `Invoke-Item (Get-ChildItem reports\*.html \| Select-Object -Last 1).FullName` |
| `python : The term 'python' is not recognized` | Python not in system `PATH` | User Fix | Reinstall Python and select *"Add Python to PATH"* |
| `PSSecurityException` activating virtual environment | PowerShell execution policy restricted | User Fix | Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` |
| `WIN-AUD-01` returns `ERROR` | `auditpol` requires `SeSecurityPrivilege` | User Fix | Right-click PowerShell, select **Run as Administrator**, and rerun scan |
| `auditpol : Error 0x00000522 occurred` | Non-elevated shell session | User Fix | Run scan from an elevated administrative command prompt |
| Antivirus check returns `REVIEW` | 3rd-party EDR agent or Windows Server | User / Analyst | Verify enterprise EDR agent service in Task Manager or management console |
| Report directory permission denied | Lack of write access to `./reports` | User Fix | Specify custom writable path via `--output C:\Temp\reports` |
| Tests fail on non-Windows host | Platform commands not mocked in test | Code Fix | Run `python -m unittest discover tests`; core checks handle non-Windows |
| Git push fails with authentication error | GitHub credentials expired or missing PAT | User Fix | Update GitHub Personal Access Token or configure Windows Credential Manager |

---

## 2. In-Depth Resolutions

### Issue A: `Start-Process reports\audit_report_*.html` Fails with "The system cannot find the file specified"
- **Symptom**:
  ```powershell
  Start-Process : This command cannot be run due to the error: The system cannot find the file specified.
  ```
- **Root Cause**: PowerShell's `Start-Process` cmdlet takes a literal file path for `-FilePath`. It does **not** perform automatic globbing/wildcard expansion on patterns like `*.html`. If you pass a wildcard directly to `Start-Process`, PowerShell attempts to open a nonexistent file literally named `audit_report_*.html`.
- **Solution**:
  Use `Invoke-Item` or pipe the resolved file object from `Get-ChildItem`:
  ```powershell
  # Option 1: Open the exact file displayed in the CLI output
  Invoke-Item "reports\audit_report_20261021_180000.html"

  # Option 2: Automatically open the latest report
  Get-ChildItem reports\*.html | Sort-Object LastWriteTime | Select-Object -Last 1 | ForEach-Object { Invoke-Item $_.FullName }
  ```

---

### Issue B: Python Not Found or Wrong Python Version
- **Symptom**: `python: command not found` or `auditor doctor` reports `[FAIL] Python Version`.
- **Root Cause**: Python 3.8+ is not installed or not registered in the system environment variable `PATH`.
- **Solution**:
  1. Download the latest Python 3.10+ installer from [python.org](https://www.python.org/downloads/).
  2. Launch installer and ensure the checkbox **"Add Python to PATH"** is enabled.
  3. Reopen PowerShell and verify:
     ```powershell
     python --version
     ```

---

### Issue C: Virtual Environment Activation Blocked
- **Symptom**:
  ```powershell
  .\.venv\Scripts\Activate.ps1 : File cannot be loaded because running scripts is disabled on this system.
  ```
- **Root Cause**: PowerShell execution policy is set to `Restricted` by default on Windows client workstations.
- **Solution**:
  Allow locally created scripts for the current user:
  ```powershell
  Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
  .\.venv\Scripts\Activate.ps1
  ```

---

### Issue D: `WIN-AUD-01` Returns `ERROR` (Error 0x00000522)
- **Symptom**:
  `[ERROR] WIN-AUD-01 | Security Event Logging & Audit Policy`
  Evidence shows: `A required privilege is not held by the client (Error 0x00000522)`.
- **Root Cause**: Querying Windows security audit policies via `auditpol /get /category:*` requires `SeSecurityPrivilege`, which is only granted to administrative tokens. Standard non-elevated user accounts cannot inspect security auditing settings.
- **Solution**:
  1. Close the current PowerShell window.
  2. Press the Windows Key, type `PowerShell`, right-click **Windows PowerShell**, and select **"Run as Administrator"**.
  3. Navigate to the project directory and rerun:
     ```powershell
     python -m auditor scan
     ```
  *(Note: All other 5 checks run successfully under standard user privileges. The auditor isolates elevation requirements without failing the entire audit).*

---

### Issue E: Antivirus Check Returns `REVIEW` Instead of `PASS`
- **Symptom**:
  `[REVIEW] WIN-AV-01 | Antivirus and Endpoint Protection`
  Finding: `No registered antivirus provider could be automatically confirmed in SecurityCenter2`.
- **Root Cause**:
  - The host is running Windows Server (which omits consumer SecurityCenter2 WMI namespaces).
  - An enterprise EDR agent (e.g. CrowdStrike Falcon, SentinelOne, Tanium) is installed as a kernel driver and does not publish to the consumer desktop security center.
- **Solution**:
  As an auditor, check `services.msc` or Task Manager for running EDR services (e.g. `CSFalconService`, `SentinelAgent`). Document this finding as an enterprise architecture limitation.

---

### Issue F: Local Password Policy Reports Minimum Length is 0
- **Symptom**:
  `[FAIL] WIN-PWD-01 | Password and Account Lockout Policy`
  Finding: `Minimum password length is 0 (configured baseline requires >= 8)`.
- **Root Cause**: By default on standalone Windows workstations, the local SAM database password length is set to `0`. If the computer is joined to an Active Directory domain or Microsoft Entra ID (Azure AD), domain Group Policy Objects (GPOs) govern domain accounts, but local accounts remain at `0`.
- **Solution**:
  - Open `secpol.msc` (Local Security Policy).
  - Navigate to: **Security Settings -> Account Policies -> Password Policy**.
  - Configure **Minimum password length** to at least `8` characters.
  - Navigate to **Account Lockout Policy** and configure **Account lockout threshold** to `5` attempts.

---

### Issue G: Reports Not Generated / Directory Permission Denied
- **Symptom**: `PermissionError: [Errno 13] Permission denied: 'reports/...'`
- **Root Cause**: The current user lacks write permissions to the repository directory.
- **Solution**:
  Provide an explicit, writable output directory using the `--output` flag:
  ```powershell
  python -m auditor scan --output "$env:USERPROFILE\Desktop\AuditReports"
  ```

---

### Issue H: Git Push Fails
- **Symptom**: `fatal: Authentication failed for 'https://github.com/...'`
- **Root Cause**: GitHub no longer accepts account passwords; a Personal Access Token (PAT) or SSH key is required.
- **Solution**:
  1. Generate a Fine-Grained or Classic Personal Access Token on GitHub (with `repo` permissions).
  2. In Windows Credential Manager (`control /name Microsoft.CredentialManager`), update the GitHub entry with your username and PAT.
  3. Retry `git push origin main`.
