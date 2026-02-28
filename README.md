# 🛡️ Threat Hunt Report — AZUKI BREACH (Port of Entry)

**Date of Investigation:** November 19–20, 2025  
**Analyst:** Zmar Ismail  
**Tools:** Microsoft Defender for Endpoint (MDE) Advanced Hunting (KQL), Microsoft Sentinel

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [IOC Summary](#ioc-summary)
- [Findings (Flags)](#findings-flags)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Recommendations](#recommendations)
- [Appendix — KQL Queries](#appendix--kql-queries)

---

## Executive Summary

Azuki Import/Export was compromised via stolen credentials that permitted RDP access to the IT admin workstation **AZUKI-SL**. The attacker performed discovery, staged malware in a hidden directory, added Windows Defender exclusions, used native binaries (`certutil.exe`, `schtasks.exe`, `wevtutil.exe`) and a PowerShell script to automate execution, dumped credentials, compressed stolen data into `export-data.zip`, exfiltrated to Discord, cleared event logs (starting with Security), created a backdoor account (`support`), and attempted lateral movement to `10.1.0.188` via `mstsc.exe`.

---

## IOC Summary

| Indicator | Value |
|-----------|-------|
| Compromised account | `kenji.sato` |
| Initial access source IP | `88.97.178.12` |
| C2 IP | `78.141.196.6` (port 443) |
| Staging directory | `C:\ProgramData\WindowsCache` |
| Credential dumper | `mm.exe` |
| Module used | `sekurlsa::logonpasswords` |
| Scheduled task | `Windows Update Check` → `svchost.exe` |
| Exfil archive | `export-data.zip` |
| Exfil channel | Discord |
| Backdoor account | `support` |
| Malicious script | `wupdate.ps1` |
| Lateral movement target | `10.1.0.188` |
| Lateral tool | `mstsc.exe` |

---

## Findings (Flags)

> Each flag includes: Answer, KQL Query, and Screenshot placeholder.

---

### Flag 1 — INITIAL ACCESS: Remote Access Source

Remote Desktop Protocol connections leave network traces that identify the source of unauthorized access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.

**Answer:** `88.97.178.12`

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType == "LogonAttempted" or ActionType == "LogonFailed"
| project Timestamp, DeviceName, ActionType, AccountName, RemoteDeviceName, RemoteIP
```

<img width="835" height="307" alt="image" src="https://github.com/user-attachments/assets/a7cb2ea1-76e7-4164-a190-8bf33dc542f4" />


---

### Flag 2 — INITIAL ACCESS: Compromised User Account

> Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts including password resets and privilege reviews.

**Answer:** `kenji.sato`

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIP == "88.97.178.12"
| project Timestamp, DeviceName, AccountDomain, AccountName, RemoteDeviceName
```

<img width="835" height="157" alt="image" src="https://github.com/user-attachments/assets/710b09ac-f317-4edf-b420-6e58175f28a4" />


---

### Flag 3 — DISCOVERY: Network Reconnaissance

> Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

**Answer:** `"ARP.EXE" -a`

```kql
DeviceProcessEvents
| where AccountName == @"kenji.sato"
| where Timestamp >= datetime(2025-11-19T18:36:21Z)
| where ProcessCommandLine contains "arp"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
```

<img width="800" height="230" alt="image" src="https://github.com/user-attachments/assets/3b1e99a4-68d2-4954-9aa9-fc51225fcfb0" />


---

### Flag 4 — DEFENCE EVASION: Malware Staging Directory

> Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.

**Answer:** `C:\ProgramData\WindowsCache`

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where AccountName == @"kenji.sato"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "mkdir" or ProcessCommandLine contains "md "
      or ProcessCommandLine contains "New-Item" or ProcessCommandLine contains "attrib"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

<img width="838" height="106" alt="image" src="https://github.com/user-attachments/assets/f8ef05df-000b-4358-abdf-0e75082c1934" />


---

### Flag 5 — DEFENCE EVASION: File Extension Exclusions

> Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.

**Answer:** `3`

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey contains @"Exclusions\Extensions"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName
```

<img width="833" height="106" alt="image" src="https://github.com/user-attachments/assets/667ad806-d758-4da2-942f-a5060b025e36" />

---

### Flag 6 — DEFENCE EVASION: Temporary Folder Exclusion

> Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

**Answer:** `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey contains @"Exclusions\Paths"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName
```

<img width="833" height="202" alt="image" src="https://github.com/user-attachments/assets/a9b9faa4-5f25-48fa-9ff3-6f7ea0aa51cb" />


---

### Flag 7 — DEFENCE EVASION: Download Utility Abuse

> Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

**Answer:** `certutil.exe`

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "http" or ProcessCommandLine contains "https"
| project Timestamp, DeviceName, ProcessCommandLine, FileName
```

<img width="837" height="214" alt="image" src="https://github.com/user-attachments/assets/6c58dcaa-34ab-44b3-90be-a84ff655432f" />


---

### Flag 8 — PERSISTENCE: Scheduled Task Name

> Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.

**Answer:** `Windows Update Check`

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

<img width="836" height="151" alt="image" src="https://github.com/user-attachments/assets/2160600e-a17b-4bbf-a1bb-967e5a74a07e" />


---

### Flag 9 — PERSISTENCE: Scheduled Task Target

> The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.

**Answer:** `C:\ProgramData\WindowsCache\svchost.exe`

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

<img width="838" height="159" alt="image" src="https://github.com/user-attachments/assets/009bb8eb-4139-4538-8c35-440743d2aaf6" />


---

### Flag 10 — C2 Server IP

> Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

**Answer:** `78.141.196.6`

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessFileName contains "certutil.exe"
| project Timestamp, DeviceName, RemoteIP, InitiatingProcessFileName
```

<img width="699" height="199" alt="image" src="https://github.com/user-attachments/assets/8fc4657c-2838-4474-95f2-6efd61ef116a" />


---

### Flag 11 — COMMAND & CONTROL: C2 Communication Port

> C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

**Answer:** `443`

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIP == "78.141.196.6"
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
```

<img width="838" height="275" alt="image" src="https://github.com/user-attachments/assets/a2f60c5c-07e1-4df2-b500-af2eff192399" />


---

### Flag 12 — CREDENTIAL ACCESS: Credential Theft Tool

> Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

**Answer:** `mm.exe`

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath startswith @"C:\ProgramData\WindowsCache"
| where FileName endswith ".exe"
| project Timestamp, DeviceName, FileName, FolderPath
```

<img width="725" height="242" alt="image" src="https://github.com/user-attachments/assets/de797965-ddb3-49c2-8586-5ba03e4d9f50" />


---

### Flag 13 — CREDENTIAL ACCESS: Memory Extraction Module

> Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.

**Answer:** `sekurlsa::logonpasswords`

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName == "mm.exe"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

<img width="700" height="205" alt="image" src="https://github.com/user-attachments/assets/476db558-c2d7-4dba-88fa-b2d9183ddb67" />


---

### Flag 14 — COLLECTION: Data Staging Archive

> Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

**Answer:** `export-data.zip`

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath startswith @"C:\ProgramData\WindowsCache"
| where FileName endswith ".zip"
| project Timestamp, DeviceName, FileName, FolderPath
```

<img width="713" height="206" alt="image" src="https://github.com/user-attachments/assets/c4276fc4-96ef-41fa-9e18-0f92cc13d740" />


---

### Flag 15 — EXFILTRATION: Exfiltration Channel

> Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

**Answer:** `discord`

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine contains "export-data"
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessCommandLine
```

<img width="779" height="269" alt="image" src="https://github.com/user-attachments/assets/4ccbd88a-021a-496a-bae1-9b6966f4be61" />


---

### Flag 16 — ANTI-FORENSICS: Log Tampering

> Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

**Answer:** `Security`

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FileName == "wevtutil.exe"
| where ProcessCommandLine contains "cl"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| sort by Timestamp asc
| limit 1
```

<img width="732" height="207" alt="image" src="https://github.com/user-attachments/assets/0ab0a680-e823-4182-858d-5f548e1d65d3" />


---

### Flag 17 — IMPACT: Persistence Account

> Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

**Answer:** `support`

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains " /add"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

<img width="836" height="162" alt="image" src="https://github.com/user-attachments/assets/b2b57529-3c4a-4fd0-b60a-0a2fb2f5c1da" />


---

### Flag 18 — EXECUTION: Malicious Script

> Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

**Answer:** `wupdate.ps1`

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath contains "temp" or FolderPath contains "downloads"
| where FileName endswith ".ps1"
| where InitiatingProcessCommandLine contains "temp"
| project Timestamp, DeviceName, FileName, InitiatingProcessCommandLine
```

<img width="837" height="148" alt="image" src="https://github.com/user-attachments/assets/ac806071-f853-4224-8448-cef5750b879e" />


---

### Flag 19 — LATERAL MOVEMENT: Secondary Target

> Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

**Answer:** `10.1.0.188`

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "cmdkey" or ProcessCommandLine contains "mstsc" or ProcessCommandLine contains "/add"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

<img width="830" height="219" alt="image" src="https://github.com/user-attachments/assets/28e57121-5035-4846-9d27-0da6ee854778" />


---

### Flag 20 — LATERAL MOVEMENT: Remote Access Tool

> Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

**Answer:** `mstsc.exe`

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "cmdkey" or ProcessCommandLine contains "mstsc" or ProcessCommandLine contains "/add"
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

<img width="836" height="221" alt="image" src="https://github.com/user-attachments/assets/0cfaa16c-4f3e-4f01-8919-44b262784e70" />


---

## MITRE ATT&CK Mapping

| Tactic | Technique ID |
|--------|-------------|
| Initial Access | T1078 |
| Execution | T1059 |
| Persistence | T1053, T1136 |
| Privilege Escalation | T1003 |
| Defense Evasion | T1562 |
| Discovery | T1016 |
| Lateral Movement | T1021 |
| Collection | T1074 |
| Exfiltration | T1041 |
| Impact / Anti-Forensics | T1070 |

---

## Conclusion

The investigation confirmed that Azuki Import/Export suffered a targeted compromise involving unauthorized RDP access, malware staging, credential theft, data exfiltration, and attempted lateral movement. The attacker leveraged legitimate Windows tools to evade detection and maintain persistence, demonstrating a deliberate and sophisticated intrusion.

Immediate actions — such as resetting compromised credentials, reimaging the affected host, removing the backdoor account, and blocking malicious IPs — are necessary for full remediation. Strengthening authentication, restricting RDP access, and improving monitoring of LOLBin activity will help prevent similar incidents in the future.
