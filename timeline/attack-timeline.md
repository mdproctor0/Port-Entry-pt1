# Azuki Import/Export – Attack Timeline

This timeline documents the chronological progression of a financially motivated intrusion
targeting the Azuki Import/Export environment. The attack was investigated using Microsoft
Sentinel and Microsoft Defender for Endpoint telemetry and represents a full end-to-end
hands-on-keyboard intrusion lifecycle.

---

## Phase 1: Initial Access
**Date:** November 19, 2025  
**Technique:** External Remote Services (RDP) – T1133  
**Evidence Source:** DeviceLogonEvents (Microsoft Sentinel)

**Details:**  
The attacker gained initial access to the IT administrative workstation **AZUKI-SL** via
external Remote Desktop Protocol (RDP). Authentication attempts originated from the public
IP address **88.97.178.12**, with failed logons followed by a successful interactive session.
The access pattern indicates credential-based intrusion rather than brute-force activity.

---

## Phase 2: Compromised Credentials
**Date:** November 19, 2025  
**Technique:** Valid Accounts – T1078  
**Evidence Source:** DeviceLogonEvents (Microsoft Defender for Endpoint)

**Details:**  
The user account **kenji.sato** was confirmed as compromised and used to authenticate during
the unauthorized external RDP session. The account established **RemoteInteractive** access
to AZUKI-SL from the same external IP, confirming stolen credential abuse.

---

## Phase 3: Initial Execution & Automation
**Date/Time:** November 19, 2025 – 18:49:48 UTC  
**Technique:** Command and Scripting Interpreter: PowerShell – T1059.001  
**Evidence Source:** DeviceFileEvents / DeviceProcessEvents

**Details:**  
A malicious PowerShell script (**wupdate.ps1**) was downloaded from an external server
(**78.141.196.6:8080**) and executed with **ExecutionPolicy Bypass**. This script served as
the primary automation mechanism and controller for subsequent attack activity.

---

## Phase 4: Discovery
**Date:** November 19, 2025  
**Technique:** System Network Configuration Discovery – T1016  
**Evidence Source:** DeviceProcessEvents

**Details:**  
Following execution, the attacker performed local network reconnaissance using
**arp -a** to enumerate neighboring devices and identify potential lateral movement targets.
The command was executed under the compromised user context and spawned via PowerShell.

---

## Phase 5: Defense Evasion (Security Control Impairment)
**Date:** November 19, 2025  
**Techniques:**  
- Impair Defenses – T1562  
- Modify Registry – T1112  
**Evidence Source:** DeviceRegistryEvents

**Details:**  
Windows Defender was tampered with to exclude entire file extensions
(**.exe, .ps1, .bat**) and the user’s temporary directory from antivirus scanning. These
changes significantly reduced detection coverage and enabled malware execution without
interference.

---

## Phase 6: Malware Staging
**Date:** November 19, 2025  
**Techniques:**  
- Hide Artifacts – T1564  
- Data Staged – T1074  
**Evidence Source:** DeviceProcessEvents

**Details:**  
The attacker created a hidden staging directory at
**C:\ProgramData\WindowsCache** using **attrib +h +s**. This directory was used to store
downloaded payloads and staged data, indicating preparation for extended activity.

---

## Phase 7: Ingress Tool Transfer
**Date:** November 19, 2025  
**Technique:** Ingress Tool Transfer – T1105  
**Evidence Source:** DeviceProcessEvents

**Details:**  
The attacker abused the Windows-native utility **certutil.exe** to download multiple
malicious binaries (**svchost.exe**, **mm.exe**) from an external server. The use of a trusted
LOLBIN allowed payload delivery while bypassing traditional download detections.

---

## Phase 8: Persistence
**Date:** November 19, 2025  
**Technique:** Scheduled Task / Job – T1053.005  
**Evidence Source:** DeviceProcessEvents

**Details:**  
Persistence was established via a scheduled task named **“Windows Update Check”**, configured
to execute a masquerading binary (**svchost.exe**) from the staging directory under the
**SYSTEM** account. The task name and execution context were designed to blend into normal
system operations.

---

## Phase 9: Command and Control
**Date:** November 19, 2025  
**Technique:** Application Layer Protocol: Web Protocols – T1071.001  
**Evidence Source:** DeviceNetworkEvents

**Details:**  
The persistent malware established outbound HTTPS connections to the external IP
**78.141.196.6** over port **443**. The traffic originated from the masquerading binary in
ProgramData, indicating encrypted command-and-control communication.

---

## Phase 10: Credential Access
**Date:** November 19, 2025  
**Technique:** OS Credential Dumping: LSASS Memory – T1003.001  
**Evidence Source:** DeviceEvents

**Details:**  
A renamed credential dumping tool (**mm.exe**) accessed **lsass.exe** and executed the
**sekurlsa::logonpasswords** module. This activity confirms successful credential harvesting
and privilege abuse.

---

## Phase 11: Collection & Data Staging
**Date:** November 19, 2025  
**Technique:** Archive Collected Data – T1560.001  
**Evidence Source:** DeviceFileEvents

**Details:**  
Collected data was compressed into **export-data.zip** within the staging directory using
PowerShell. The archive creation occurred after credential dumping and immediately before
external data transfer.

---

## Phase 12: Exfiltration
**Date/Time:** November 19, 2025 – Post 19:08 UTC  
**Technique:** Exfiltration Over Web Service – T1567.002  
**Evidence Source:** DeviceNetworkEvents

**Details:**  
The attacker exfiltrated **export-data.zip** using **curl.exe** via a Discord webhook over
HTTPS. The use of a legitimate cloud service allowed data exfiltration to blend into normal
encrypted traffic.

---

## Phase 13: Indicator Removal
**Date:** November 19, 2025  
**Technique:** Clear Windows Event Logs – T1070.001  
**Evidence Source:** DeviceProcessEvents

**Details:**  
Windows event logs (**Security**, **System**, **Application**) were cleared using
**wevtutil.exe**, with the Security log targeted first. This indicates an attempt to erase
evidence related to authentication and credential access activity.

---

## Phase 14: Lateral Movement Attempt
**Date:** November 19, 2025  
**Techniques:**  
- Use Alternate Authentication Material – T1550  
- Remote Services: RDP – T1021.001  
**Evidence Source:** DeviceProcessEvents

**Details:**  
The attacker attempted lateral movement to **10.1.0.188** by storing credentials using
**cmdkey.exe** and initiating a Remote Desktop session via **mstsc.exe**. The activity was
script-driven and confirms intent to expand access beyond the initial host.

---

## Summary
The attacker successfully achieved initial access, executed automated tooling, impaired
endpoint defenses, established persistence, exfiltrated sensitive data, and attempted lateral
movement. The intrusion demonstrates a mature, multi-stage attack leveraging native Windows
utilities and living-off-the-land techniques consistent with hands-on-keyboard intrusions.
