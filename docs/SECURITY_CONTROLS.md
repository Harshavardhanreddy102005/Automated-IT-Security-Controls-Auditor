# Security Controls Reference Guide

This document defines the technical scope, observation sources, baseline requirements, status evaluation logic, and risk models for the six host-based controls inspected by the **Automated IT Security Controls Auditor**.

> **Audit Baseline Notice**: The evaluation requirements documented below represent educational security baselines adapted from common industry standards (such as CIS Microsoft Windows Desktop Benchmarks, NIST SP 800-53 Rev. 5, and Microsoft Security Baselines). They do not represent official certification baselines for regulatory compliance (e.g. PCI-DSS, HIPAA, or ISO 27001).

---

## Control Summary Matrix

| Control ID | Control Name | Evidence Source | Expected Baseline | Default Risk |
| :---: | :--- | :--- | :--- | :---: |
| **`WIN-FW-01`** | Windows Firewall Configuration | `netsh advfirewall show allprofiles state` | Domain, Private, and Public profiles enabled (`State: ON`) | **HIGH** |
| **`WIN-AV-01`** | Antivirus and Endpoint Protection | `Get-MpComputerStatus`, `root\SecurityCenter2` | Active antivirus provider with Real-Time Protection enabled | **CRITICAL** |
| **`WIN-PWD-01`** | Password and Account Lockout Policy | `net accounts` | Length $\ge 8$, Lockout between $1$ and $10$ attempts | **HIGH** |
| **`WIN-ADM-01`** | Local Administrator Accounts Review | `net localgroup administrators` | Only approved administrative accounts; no `Guest` account | **MEDIUM** |
| **`WIN-UPD-01`** | Operating System Patching & Update Status | `Get-HotFix`, `Get-Service wuauserv` | Hotfix installed within $60$ days; update service not disabled | **HIGH** |
| **`WIN-AUD-01`** | Security Event Logging & Audit Policy | `auditpol /get /category:*` | Logon, Logoff, and Account Management auditing enabled | **MEDIUM** |

---

## 1. `WIN-FW-01`: Windows Firewall Configuration

- **Control Objective**: Ensure host-based network packet filtering is continuously enforced across all network profiles to block unauthorized inbound traffic and mitigate lateral threat replication.
- **Evidence Source**: 
  - Primary: `netsh advfirewall show allprofiles state`
  - Fallback: PowerShell `Get-NetFirewallProfile -PolicyStore ActiveStore`
- **Expected Baseline**:
  - `Domain` Profile State == `ON`
  - `Private` Profile State == `ON`
  - `Public` Profile State == `ON`
- **Evaluation & Status Logic**:
  - **`PASS`**: All three required profiles report `State: ON`. (Risk: *Informational*)
  - **`FAIL`**: Any required profile reports `State: OFF`. (Risk: *High*)
  - **`REVIEW`**: Profile state cannot be determined or required profile is missing. (Risk: *Medium*)
  - **`ERROR`**: Firewall service (`mpssvc`) is stopped or commands fail. (Risk: *High*)
- **Remediation**:
  Enable all profiles via administrative shell:
  ```cmd
  netsh advfirewall set allprofiles state on
  ```
- **Audit Limitations**:
  Read-only query of profile states. Does not inspect individual inbound/outbound rules or application exemptions.

---

## 2. `WIN-AV-01`: Antivirus and Endpoint Protection

- **Control Objective**: Confirm that an active endpoint protection or EDR agent is operational with real-time on-access scanning enabled to intercept malware execution.
- **Evidence Source**:
  - Microsoft Defender: `Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled`
  - WMI / CIM Security Center: `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct`
- **Expected Baseline**:
  - At least one registered antivirus provider is detected.
  - Real-time threat protection (`RealTimeProtectionEnabled`) is confirmed active (`True`).
- **Evaluation & Status Logic**:
  - **`PASS`**: Active provider confirmed with real-time protection enabled. (Risk: *Informational*)
  - **`FAIL`**: Antivirus software is detected, but real-time scanning is explicitly disabled. (Risk: *Critical*)
  - **`REVIEW`**: No active provider could be automatically confirmed in WMI `SecurityCenter2` (e.g. enterprise EDR agents like CrowdStrike on Windows Server). (Risk: *Medium*)
- **Remediation**:
  Enable real-time scanning in Windows Security -> Virus & threat protection settings, or verify enterprise EDR agent service status.
- **Audit Limitations**:
  Queries local API registrations. Does not test signature heuristics against live test files (e.g. EICAR).

---

## 3. `WIN-PWD-01`: Password and Account Lockout Policy

- **Control Objective**: Prevent trivial password selection and automated online brute-force credential stuffing against local user accounts.
- **Evidence Source**:
  - Command: `net accounts` (queries local Security Accounts Manager / SAM database).
- **Expected Baseline**:
  - Minimum password length: $\ge 8$ characters (configurable; CIS recommends $\ge 14$).
  - Account lockout threshold: between $1$ and $10$ invalid logon attempts.
- **Evaluation & Status Logic**:
  - **`PASS`**: Minimum password length $\ge 8$ and lockout threshold between $1$ and $10$. (Risk: *Informational*)
  - **`FAIL`**: Minimum password length is $0$ or lockout threshold is disabled ($0$ / Never). (Risk: *High*)
  - **`ERROR`**: `net accounts` fails or SAM is inaccessible. (Risk: *Medium*)
- **Remediation**:
  Configure local security policy via `secpol.msc` -> Account Policies -> Password Policy / Account Lockout Policy, or enforce domain GPOs.
- **Audit Limitations**:
  Evaluates the local workstation SAM database. On Active Directory or Microsoft Entra ID joined hosts, effective password policies are enforced at the domain level by Group Policy Objects (GPOs) or Fine-Grained Password Policies, overriding local SAM settings.

---

## 4. `WIN-ADM-01`: Local Administrator Accounts Review

- **Control Objective**: Enforce the principle of least privilege by ensuring administrative privileges are restricted to approved personnel.
- **Evidence Source**:
  - Primary: `net localgroup administrators`
  - Fallback: `Get-LocalGroupMember -Group Administrators`
- **Expected Baseline**:
  - Built-in `Administrator` and documented authorized admin accounts.
  - Prohibited accounts (`Guest`, `DefaultAccount`, `Everyone`) must never belong to Administrators.
- **Evaluation & Status Logic**:
  - **`PASS`**: Only approved baseline accounts are present in Administrators. (Risk: *Informational*)
  - **`FAIL`**: Explicitly prohibited accounts (e.g. `Guest`) detected in Administrators. (Risk: *Critical*)
  - **`REVIEW`**: Additional user or workstation accounts present. Flagged for human review to confirm active business justification. (Risk: *Medium*)
  - **`ERROR`**: Group enumeration command fails. (Risk: *Medium*)
- **Remediation**:
  Conduct access certification review. Remove unapproved accounts using:
  ```cmd
  net localgroup administrators <username> /delete
  ```
- **Audit Limitations**:
  Enumerates direct local group members. Does not expand nested domain groups or temporary JIT PAM sessions.

---

## 5. `WIN-UPD-01`: Operating System Patching & Update Status

- **Control Objective**: Verify that the operating system regularly receives and applies cumulative security patches to mitigate known exploited vulnerabilities (KEVs).
- **Evidence Source**:
  - Hotfix History: `Get-HotFix | Sort-Object InstalledOn -Descending`
  - Update Service: `Get-Service wuauserv`
- **Expected Baseline**:
  - At least one recorded hotfix installed within the preceding $60$ days.
  - Windows Update service (`wuauserv`) must not be set to `Disabled`.
- **Evaluation & Status Logic**:
  - **`PASS`**: Most recently recorded hotfix is $\le 60$ days old and update service is active. (Risk: *Informational*)
  - **`REVIEW`**: Most recent hotfix is between $61$ and $90$ days old, or hotfix records cannot be parsed. (Risk: *Medium*)
  - **`FAIL`**: Windows Update service is `Disabled`, or no updates recorded within $90$ days. (Risk: *High*)
- **Remediation**:
  Check for and install pending quality updates in Windows Settings -> Windows Update, or set `wuauserv` startup to Manual/Automatic.
- **Audit Limitations**:
  Reflects installed hotfixes registered in the Windows CBS store. Does not scan upstream Microsoft catalogs, WSUS, or Intune for pending uninstalled updates.

---

## 6. `WIN-AUD-01`: Security Event Logging & Audit Policy

- **Control Objective**: Confirm that critical authentication, account management, and logon events are recorded in the Windows Security event log for forensic tracing.
- **Evidence Source**:
  - Command: `auditpol /get /category:*`
- **Expected Baseline**:
  - `Logon` subcategory auditing: Success and Failure.
  - `Logoff` subcategory auditing: Success.
  - `Account Lockout` subcategory auditing: Failure.
  - `User Account Management`: Success.
- **Evaluation & Status Logic**:
  - **`PASS`**: All required subcategories have active event auditing configured. (Risk: *Informational*)
  - **`FAIL`**: One or more critical subcategories report `No Auditing`. (Risk: *Medium*)
  - **`ERROR`**: Execution denied due to missing administrative elevation (Error `0x00000522: A required privilege is not held by the client`). (Risk: *Medium*)
- **Remediation**:
  Run the auditor from an elevated terminal ("Run as Administrator") to verify policies, or configure Advanced Audit Policy Configuration via Group Policy.
- **Audit Limitations**:
  Requires `SeSecurityPrivilege` administrative token to inspect via `auditpol`. Does not inspect event log disk size limits or SIEM forwarding pipelines.
