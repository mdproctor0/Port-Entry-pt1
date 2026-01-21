# Incident Report: Azuki Import/Export Intrusion

## Executive Summary
On November 19, 2025, a financially motivated threat actor gained unauthorized access to an IT administrative workstation within the Azuki Import/Export environment via externally exposed Remote Desktop Protocol (RDP). The attacker leveraged compromised credentials, executed PowerShell-based automation, impaired endpoint security controls, established persistence, exfiltrated sensitive data, and attempted lateral movement to an additional internal system.  

The intrusion demonstrates a mature, hands-on-keyboard attack leveraging native Windows tooling and living-off-the-land techniques to evade detection and maintain access.

---

## Incident Scope
- **Affected Endpoint:** AZUKI-SL (IT Administrative Workstation)
- **Compromised User Account:** kenji.sato
- **Attack Window:** November 19–21, 2025
- **Threat Motivation:** Financial
- **Threat Actor:** JADE SPIDER (APT-SL44)
- **Initial Access Vector:** External RDP

---

## Detection & Investigation Overview
The incident was identified and investigated using Microsoft Sentinel and Microsoft Defender for Endpoint telemetry. Key detection signals included anomalous external RDP authentication, suspicious PowerShell execution, Windows Defender configuration tampering, unauthorized scheduled task creation, abnormal outbound network traffic, and evidence of credential dumping and data exfiltration.

---

## Attack Narrative

### Initial Access
The attacker established an initial foothold by authenticating to AZUKI-SL via external RDP from the public IP address **88.97.178.12**. Authentication logs show failed attempts followed by a successful **RemoteInteractive** logon, consistent with credential-based intrusion rather than brute force.

### Credential Compromise
The account **kenji.sato** was confirmed as compromised and used during the unauthorized RDP session. The account authenticated from an untrusted external IP and accessed an IT administrative workstation, significantly increasing attack impact.

### Execution & Automation
Following access, a malicious PowerShell script (**wupdate.ps1**) was downloaded from **78.141.196.6:8080** and executed with **ExecutionPolicy Bypass**. This script served as the automation backbone for subsequent attack stages, orchestrating discovery, defense evasion, persistence, and exfiltration activity.

### Discovery
The attacker executed **arp -a** to enumerate local network neighbors and identify potential lateral movement targets. This activity occurred shortly after initial access and was executed under the compromised user context.

### Defense Evasion
Endpoint security controls were impaired by modifying Windows Defender configuration to exclude:
- Entire file extensions (**.exe, .ps1, .bat**)
- The user’s temporary directory  

These changes allowed malicious scripts and executables to run without antivirus inspection. The attacker also created a hidden staging directory (**C:\ProgramData\WindowsCache**) using system file attributes to conceal malicious artifacts.

### Malware Staging & Tool Transfer
Using the trusted Windows utility **certutil.exe**, the attacker downloaded multiple payloads (**svchost.exe**, **mm.exe**) into the staging directory. Abuse of native binaries enabled payload delivery while bypassing basic detection mechanisms.

### Persistence
Persistence was established via a scheduled task named **“Windows Update Check”**, configured to execute a masquerading binary (**svchost.exe**) from the staging directory under the SYSTEM account. The task name and execution context were designed to blend into legitimate system activity.

### Command and Control
The malicious payload initiated outbound HTTPS communication to **78.141.196.6** over port **443**, indicating encrypted command-and-control traffic designed to blend into normal web traffic.

### Credential Access
The attacker executed a renamed credential dumping tool (**mm.exe**) that accessed **lsass.exe** and invoked the **sekurlsa::logonpasswords** module. This confirms successful credential harvesting from memory and elevated access on the compromised host.

### Collection & Exfiltration
Collected data was compressed into **export-data.zip** within the staging directory using PowerShell. The archive was subsequently exfiltrated using **curl.exe** to a Discord webhook over HTTPS, leveraging a legitimate cloud service to conceal outbound data transfer.

### Indicator Removal
To hinder forensic analysis, the attacker cleared Windows event logs using **wevtutil.exe**, targeting the Security log first, followed by System and Application logs.

### Lateral Movement Attempt
Post-exfiltration, the attacker attempted lateral movement to **10.1.0.188** by storing credentials with **cmdkey.exe** and initiating an RDP session via **mstsc.exe**. This confirms deliberate intent to expand access beyond the initial host.

---

## Impact Assessment
- Unauthorized administrative access achieved
- Endpoint security controls significantly impaired
- Credentials harvested from LSASS memory
- Sensitive data exfiltrated to an external service
- Persistence mechanisms established
- Lateral movement attempted to an internal system

---

## MITRE ATT&CK Mapping
| Tactic | Technique | ID |
|------|---------|----|
| Initial Access | External Remote Services | T1133 |
| Initial Access | Valid Accounts | T1078 |
| Execution | PowerShell | T1059.001 |
| Discovery | Network Configuration Discovery | T1016 |
| Defense Evasion | Impair Defenses | T1562 |
| Defense Evasion | Hide Artifacts | T1564 |
| Persistence | Scheduled Task / Job | T1053.005 |
| Credential Access | LSASS Memory | T1003.001 |
| Command & Control | Web Protocols | T1071.001 |
| Collection | Archive Collected Data | T1560.001 |
| Exfiltration | Exfiltration Over Web Service | T1567.002 |
| Defense Evasion | Clear Windows Event Logs | T1070.001 |
| Lateral Movement | Remote Services (RDP) | T1021.001 |

---

## Containment & Remediation Recommendations
- Disable compromised accounts and force credential resets
- Remove malicious scheduled tasks and staged binaries
- Restore Windows Defender configurations and exclusions
- Enable MFA for all remote access
- Restrict or eliminate external RDP exposure
- Monitor Defender exclusion and scheduled task creation events
- Implement LSASS protection and credential theft mitigations

---

## Lessons Learned
- External RDP exposure significantly increases attack surface
- PowerShell execution policy bypass remains a high-risk vector
- Defender exclusion monitoring is critical for early detection
- Living-off-the-land techniques enable stealthy multi-stage attacks

---

## Disclaimer
This investigation was conducted using a controlled lab environment and simulated telemetry for educational and portfolio demonstration purposes.
