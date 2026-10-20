# Microsoft Sentinel Investigation Report

**Incident ID:** IR-2026-004  
**Title:** Suspicious Sign-In and PowerShell Execution Correlated in Microsoft Sentinel  
**Severity:** High  
**Status:** Contained  
**Analyst:** Stiven Sharma  
**Sentinel Incident:** INC-48291  
**Opened:** 2026-10-12 08:14 UTC  
**Contained:** 2026-10-12 08:41 UTC  

## Executive Summary

Microsoft Sentinel generated an incident after correlating a high-risk Azure AD sign-in with subsequent PowerShell execution on the same user’s workstation. The sign-in originated from an IP with no prior history for the account and was followed within four minutes by an encoded PowerShell process that contacted an external domain. The user was contacted and confirmed they were not responsible for either activity. The host was isolated via the Sentinel playbook, the account was disabled, and the external domain was blocked. No persistence or lateral movement was identified before containment.

## Timeline (from Sentinel)

| Time (UTC) | Event | Sentinel Table / Source |
|------------|-------|-------------------------|
| 08:07 | High-risk sign-in from 91.219.236.44 | SigninLogs |
| 08:09 | MFA satisfied (user later denied approving) | SigninLogs / AADNonInteractiveUserSignInLogs |
| 08:11 | Encoded PowerShell spawned by explorer.exe | DeviceProcessEvents |
| 08:12 | Outbound connection to cdn-update-service[.]net | DeviceNetworkEvents |
| 08:14 | Sentinel incident created (analytics rule: Risky Sign-in + Suspicious Process) | SecurityIncident |
| 08:22 | User confirmed activity was unauthorized | Ticket / phone |
| 08:28 | Host isolated via playbook | Sentinel automation |
| 08:41 | Account disabled and sessions revoked | Identity action |

## Technical Analysis

The analytics rule that fired combines Azure AD Identity Protection risk detections with Defender for Endpoint process events. The sign-in carried a risk level of High and used a user-agent consistent with a browser rather than the user’s normal corporate device. Four minutes later DeviceProcessEvents showed explorer.exe spawning powershell.exe with a long `-enc` argument. The process immediately generated a network connection recorded in DeviceNetworkEvents.

The short gap between the sign-in and the PowerShell execution is the strongest indicator that the same actor controlled both events. No other processes of interest appeared on the host in the following window, and no additional high-risk sign-ins occurred for the account.

**Alternative explanations considered:**
- User working from a new location and running a legitimate script: contradicted by the user’s statement and the encoded command line.
- Separate unrelated events coincidentally close in time: unlikely given the four-minute gap and shared user entity.
- False positive on encoded PowerShell: parent process and immediate external connection make this improbable.

### MITRE ATT&CK

| Technique | Name | Supporting Evidence | Confidence |
|-----------|------|---------------------|------------|
| T1078 | Valid Accounts | Successful high-risk sign-in | High |
| T1059.001 | PowerShell | Encoded powershell.exe from explorer.exe | High |
| T1027 | Obfuscated Files or Information | -enc argument | High |
| T1071.001 | Application Layer Protocol: Web Protocols | Connection to external domain | Medium |

## Indicators of Compromise

| Type | Indicator | Notes | Confidence |
|------|-----------|-------|------------|
| IP | 91.219.236.44 | High-risk sign-in source | High |
| Domain | cdn-update-service[.]net | Destination of PowerShell callback | Medium |
| Process | powershell.exe -enc … | Parent: explorer.exe | High |
| Account | m.chen@company.example | Affected user | High |

## KQL Used During Investigation

```kusto
// High-risk sign-ins for the user in the window
SigninLogs
| where TimeGenerated between (datetime(2026-10-12 08:00) .. datetime(2026-10-12 08:20))
| where UserPrincipalName == "m.chen@company.example"
| where RiskLevelDuringSignIn == "high" or RiskState == "atRisk"
| project TimeGenerated, IPAddress, Location, AppDisplayName, RiskLevelDuringSignIn, UserAgent

// Process events on the user’s devices
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-10-12 08:05) .. datetime(2026-10-12 08:20))
| where AccountName == "m.chen"
| where FileName =~ "powershell.exe"
| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessCommandLine, SHA256

// Network connections from the same process
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-10-12 08:10) .. datetime(2026-10-12 08:15))
| where InitiatingProcessFileName =~ "powershell.exe"
| where RemoteUrl contains "cdn-update-service"
| project TimeGenerated, DeviceName, RemoteIP, RemoteUrl, RemotePort
```

## Scope and Impact

Single user and single workstation (WS-MKT-112). Sentinel entity graph showed no additional hosts or accounts linked to the IP or domain in the prior seven days. No scheduled tasks, registry Run keys, or service creations were recorded on the host before isolation. No data exfiltration volume was observed.

Impact is limited to temporary account and endpoint exposure. The user works in marketing and does not hold privileged roles.

## Response Actions

- Ran the “Isolate Device” playbook from the Sentinel incident at 08:28.
- Disabled the account and revoked sessions.
- Added the domain and IP to the Microsoft Defender indicator block list via the Sentinel playbook.
- Confirmed with the user that neither the sign-in nor the PowerShell activity was theirs.
- Performed a 7-day hunt for the domain and IP across SigninLogs and DeviceNetworkEvents (no additional hits).

## Recommendations

| Priority | Action | Owner | Target |
|----------|--------|-------|--------|
| High | Enable the Sentinel automation rule to auto-isolate on this analytics rule for High severity | SOC / Sentinel admin | 2026-10-19 |
| High | Require phishing-resistant MFA and block legacy authentication | Identity | 2026-10-26 |
| Medium | Tune the analytics rule to include a minimum command-line length filter to reduce noise | Detection | 2026-10-20 |
| Medium | Add the domain pattern to the custom indicator feed | Threat intel | 2026-10-18 |

## Open Questions

- Full de-obfuscation of the PowerShell command line is still pending (base64 fragment captured but not fully decoded).
- Whether the external connection returned a payload that executed in memory has not been confirmed from the available network logs.
- User’s normal sign-in locations and devices should be re-baselined after the password reset.

## Appendix

Sentinel incident link and full entity timeline are stored in the case. The analytics rule that fired is “Azure AD Risky Sign-in followed by Suspicious PowerShell”. Playbook run history is available under the incident’s automation tab.
