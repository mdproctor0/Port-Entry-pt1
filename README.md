![Azuki Import/Export Threat Hunt Banner](assets/port-entry-pt1-header.png)

# Azuki Import/Export Threat Hunt

## Overview
This repository documents a full end-to-end threat hunting investigation conducted in Microsoft Sentinel and Microsoft Defender for Endpoint.

The investigation analyzes a financially motivated intrusion targeting a small logistics company, resulting in data theft, persistence, and attempted lateral movement.

## Threat Actor
**JADE SPIDER**  
Aliases: APT-SL44, SilentLynx  
Motivation: Financial  
Target Sector: Logistics (East Asia)

## Tools Used
- Microsoft Sentinel
- Microsoft Defender for Endpoint
- KQL (Kusto Query Language)
- MITRE ATT&CK Framework

## Investigation Scope
- Initial Access
- Credential Compromise
- Discovery
- Defense Evasion
- Persistence
- Command & Control
- Exfiltration
- Lateral Movement

## Repository Structure
- `incident-report/` – Full SOC-style incident report
- `queries/` – KQL queries used for each investigation flag
- `timeline/` – Chronological attack progression
- `mitre-mapping/` – ATT&CK technique mapping
- `screenshots/` – Supporting evidence

## Outcome
The attacker successfully:
- Gained access via external RDP
- Compromised administrative credentials
- Staged malware and data
- Disabled security controls
- Established persistence
- Exfiltrated sensitive data

This project demonstrates practical threat hunting and incident response skills aligned with real-world SOC operations.
