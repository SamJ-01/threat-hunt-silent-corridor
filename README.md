# Operation Silent Corridor — Threat Hunt Challenge Write-up

**Context:** LOG(N) Pacific weekly threat-hunt challenge · **My role:** participant
**Environment:** Azure Log Analytics (LAW-SilentCorridor), multi-host lab · **Tooling:** KQL, Sysmon telemetry, Windows Event Logs · **Framework:** MITRE ATT&CK
**In this repo:** [Incident report](report/incident-report.md) · [KQL queries](queries/) · [IOC list](iocs.md)

> **Lab scope:** Silent Corridor is a training scenario run by LOG(N) Pacific. Every
> host, account and domain in it (e.g. `haldric.local`, `s.brandt`) is synthetic.
> This is my write-up of what I found while taking part; it is not a real incident.

## Summary

The challenge was to hunt through Sysmon telemetry in Log Analytics and reconstruct
a multi-host intrusion, from initial access through data exfiltration and
anti-forensics. I used KQL to find the indicators of compromise at each stage.
The attacker used only living-off-the-land binaries — no malware — and cleared the
Security event log on exit, but the Sysmon telemetry forwarded to Log Analytics
preserved the evidence chain.

## Attack Chain Identified

| Phase | Technique | Evidence |
|---|---|---|
| Initial access | T1078 Valid Accounts | Compromised credentials (s.brandt) → beachhead workstation WS-ENG04 |
| Reconnaissance | Discovery | systeminfo, directory/host enumeration |
| Credential access | T1003 Credential Dumping | Credential theft and reuse (m.richter) |
| Lateral movement | T1047 WMIC · T1021 RDP | Cross-host execution via WmiPrvSE.exe → SRV-FILES02, SRV-DC01 |
| Collection | T1560 Archive Collected Data | ntds.dit + engineering data staged; Compress-Archive |
| Exfiltration | T1041 | certutil -encode → Invoke-WebRequest POST to CDN-lookalike domain |
| Persistence | T1090 Proxy | netsh portproxy 8443 → DC:445, surviving credential resets |
| Anti-forensics | T1070 Indicator Removal | wevtutil cl Security + remote artefact deletion |

Full details, commands and narrative: [report/incident-report.md](report/incident-report.md).

## Key Findings

1. **Log clearing failed as anti-forensics** — off-host Sysmon telemetry preserved the
   complete process-execution record, and the clearing itself became evidence of intent.
2. **Persistence outlived containment** — the portproxy tunnel would have permitted
   re-entry after credential resets; the attacker returned about two days after the
   exfiltration.
3. **Camouflage at every stage** — staging dir named McAfee_Logs, archive named as a
   Windows update KB, egress domain built from CDN/telemetry vocabulary.

## What I Did

- Used KQL queries to find each stage of the attack in the telemetry
- Correlated activity across the three hosts and two accounts involved
- Traced the WMIC and RDP lateral movement, the exfiltration and the persistence
- Wrote up the findings, IOCs and ATT&CK mapping in the report

## Queries

[`queries/`](queries/) holds one query per phase, run against the challenge's custom
log table `SilentCorridorX_CL`. Query 01 is copied from my original notes; the others
were rewritten afterwards from the commands recorded in the report, to show how each
IOC can be surfaced. Each file says which it is.

## Related Detections

The behaviours in this hunt are written up as reusable, ATT&CK-mapped detections for
Defender / Sentinel tables in [kql-detection-library](https://github.com/SamJ-01/kql-detection-library):
certutil -encode usage · WMIC remote execution · wevtutil log clearing ·
portproxy configuration changes · Compress-Archive on sensitive paths ·
POST to newly observed domains.

## Skills Demonstrated

KQL query development · multi-host telemetry correlation · lateral movement tracking ·
exfiltration analysis · persistence hunting · IOC identification · ATT&CK mapping ·
incident write-up.
