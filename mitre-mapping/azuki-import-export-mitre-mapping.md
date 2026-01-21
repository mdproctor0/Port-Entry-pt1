# MITRE ATT&CK Mapping – Azuki Import/Export Intrusion

This document maps observed attacker behaviors during the Azuki Import/Export
intrusion to MITRE ATT&CK tactics and techniques. The mapping is based on
Microsoft Defender for Endpoint and Microsoft Sentinel telemetry, correlated
with confirmed malicious activity across the attack lifecycle.

---

## Initial Access

| Tactic | Technique | ID | Evidence |
|------|----------|----|---------|
| Initial Access | External Remote Services (RDP) | T1133 | External RDP logons to AZUKI-SL from public IP 88.97.178.12 |
| Initial Access | Valid Accounts | T1078 | Compromised user account kenji.sato used for interactive access |

---

## Execution

| Tactic | Technique | ID | Evidence |
|------|----------|----|---------|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | wupdate.ps1 downloaded and executed with ExecutionPolicy Bypass |

---

## Discovery

| Tactic | Technique | ID | Evidence |
|------|----------|----|---------|
| Discovery | System Network Configuration Discovery | T1016 | arp -a executed via PowerShell to enumerate network neighbors |

---

## Defense Evasion

| Tactic | Technique | ID | Evidence |
|------|----------|----|---------|
| Defense Evasion | Impair Defenses | T1562 | Windows Defender exclusions for .exe, .ps1, .bat |
| Defense Evasion | Modify Registry | T1112 | Registry changes under Defender Exclusions keys |
| Defense Evasion | Hide Artifacts | T1564 | Hidden staging directory created with attrib +h +s |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | wevtutil.exe used to clear Security, System, and Application logs |

---

## Persistence

| Tactic | Technique | ID | Evidence |
|------|----------|----|---------|
| Persistence | Scheduled Task / Job | T1053.005 | Scheduled task “Windows Update Check” executing svchost.exe |
| Persistence | Create Account: Local Account | T1136.001 | Local admin account “support” created and added to Administrators |

---

## Credential Access

| Tactic | Technique | ID | Evidence |
|------|----------|----|---------|
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | mm.exe accessed lsass.exe and executed sekurlsa::logonpasswords |

---

## Command and Control

| Tactic | Technique | ID | Evidence |
|------|----------|----|---------|
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | svchost.exe established outbound HTTPS C2 on port 443 |

---

## Collection

| Tactic | Technique | ID | Evidence |
|------|----------|----|---------|
| Collection | Archive Collected Data | T1560.001 | export-data.zip created in staging directory |

---

## Exfiltration

| Tactic | Technique | ID | Evidence |
|------|----------|----|---------|
| Exfiltration | Exfiltration Over Web Service | T1567.002 | export-data.zip uploaded to Discord via curl.exe |

---

## Lateral Movement

| Tactic | Technique | ID | Evidence |
|------|----------|----|---------|
| Lateral Movement | Use Alternate Authentication Material | T1550 | Credentials stored using cmdkey.exe |
| Lateral Movement | Remote Services: RDP | T1021.001 | mstsc.exe used to connect to 10.1.0.188 |

---

## Summary
The Azuki Import/Export intrusion demonstrates a full-spectrum,
hands-on-keyboard attack leveraging valid credentials, native Windows tooling,
and living-off-the-land techniques to evade detection, maintain persistence,
exfiltrate data, and attempt lateral movement within the environment.
