# Operation Silent Corridor — Enterprise Threat Hunt & Incident Investigation

**Role:** Lead investigator (solo hunt) · **Environment:** Azure Log Analytics (LAW-SilentCorridor), multi-host enterprise lab
**Tooling:** KQL, Sysmon telemetry, Windows Event Logs · **Framework:** MITRE ATT&CK, PEAK
**Deliverables:** [Master Incident Report](./report/) · [KQL query set](./queries/) · [IOC list](./iocs.md) · [Hunt tracker](./tracker/)

## Summary

End-to-end reconstruction of a multi-host intrusion, from initial access through
data exfiltration and anti-forensics. The attacker used only living-off-the-land
binaries — no malware — and cleared the Security event log on exit. Sysmon
telemetry forwarded to Log Analytics preserved the evidence chain, enabling
full timeline reconstruction.

## Confirmed Attack Chain

| Phase | Technique | Evidence |
|---|---|---|
| Initial access | T1078 Valid Accounts | Compromised credentials (s.brandt) → beachhead workstation WS-ENG04 |
| Reconnaissance | Discovery | systeminfo, directory/host enumeration |
| Credential access | T1003 Credential Dumping | Credential theft and reuse (m.richter) |
| Lateral movement | T1047 WMIC · T1021 RDP | Cross-host execution via WmiPrvSE.exe → SRV-FILES02, SRV-DC01 |
| Collection | T1560 Archive Collected Data | ntds.dit + engineering data staged; Compress-Archive |
| Exfiltration | T1041 | certutil -encode → Invoke-WebRequest POST to attacker CDN-lookalike domain |
| Persistence | T1090 Proxy | netsh portproxy 8443 → DC:445, surviving credential resets |
| Anti-forensics | T1070 Indicator Removal | wevtutil cl Security + remote artefact deletion |

## Key Findings

1. **Log clearing failed as anti-forensics** — off-host Sysmon telemetry preserved the
   complete process-execution record, and the clearing itself became evidence of intent.
2. **Persistence outlived containment** — the portproxy tunnel would have permitted
   re-entry after credential resets; identified only by hunting beyond the "obvious" end
   of the attack.
3. **Camouflage at every stage** — staging dir named McAfee_Logs, archive named as a
   Windows update KB, egress domain built from CDN/telemetry vocabulary.

## Detection Engineering Output

Detections proposed from this hunt (implemented in [kql-detection-library](https://github.com/SamJ-01/kql-detection-library)):
certutil -encode usage · WMIC remote execution · wevtutil log clearing ·
portproxy configuration changes · Compress-Archive on sensitive paths ·
large POST to newly-observed domains.

## Skills Demonstrated

KQL query development · multi-host telemetry correlation · lateral movement tracking ·
exfiltration analysis · persistence hunting · IOC development · ATT&CK mapping ·
executive reporting (CISO brief).

> Lab environment — all hostnames, accounts, and domains are synthetic.
