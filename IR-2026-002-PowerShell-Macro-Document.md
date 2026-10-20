# Incident Investigation Report

**Incident ID:** IR-2026-002  
**Title:** Macro-Enabled Document Leading to Obfuscated PowerShell Execution and Outbound Callback  
**Severity:** High  
**Status:** Contained  
**Analyst:** Stiven Sharma  
**Opened:** 2026-09-22 09:21 UTC  
**Contained:** 2026-09-22 09:35 UTC  

## Executive Summary

A finance workstation triggered an EDR alert for suspicious PowerShell shortly after the user opened a macro-enabled Word document received via email. Process telemetry and command-line logging showed the macro spawning an encoded PowerShell instance that immediately made an outbound HTTPS connection to a newly registered domain. The host was isolated within seven minutes of the alert. No persistence, credential access, or lateral movement was identified before isolation. The short dwell time and lack of follow-on activity support a contained single-host compromise, though the exact payload delivered remains unconfirmed pending full traffic reconstruction.

## Timeline

| Time (UTC) | Event | Source |
|------------|-------|--------|
| 09:14 | Email containing Invoice_Q3.docm delivered and opened | Email gateway, endpoint file telemetry |
| 09:16:12 | WINWORD.EXE spawned powershell.exe with -enc argument | Sysmon Event ID 1, EDR process tree |
| 09:16:14 | Encoded PowerShell executed; network connection initiated | Command-line logging, EDR |
| 09:17 | HTTPS connection to updates-cdn[.]net (45.133.248.67) | Proxy / firewall logs |
| 09:21 | EDR high-severity alert generated | EDR console |
| 09:28 | Host network isolation applied | SOC response |
| 09:35 | PowerShell process terminated; document quarantined | EDR response actions |

## Technical Analysis

The initial vector was a macro-enabled document. The user (a.patel, finance) opened Invoice_Q3.docm, which triggered AutoOpen or Document_Open macro code. The process tree is clear: WINWORD.EXE → powershell.exe -enc <base64>. This pattern is consistent with common macro-to-PowerShell droppers rather than a user manually launching PowerShell.

The encoded command was not fully recovered in the initial triage window, but the length and entropy matched typical download-and-execute stubs. Within seconds of execution the process made a single outbound connection on 443 to updates-cdn[.]net. Proxy logs show the connection was established but provide limited insight into the response body. No secondary processes were spawned and no files were written to disk in the brief window before isolation, which reduces the likelihood of a successful multi-stage download in this specific instance.

**Alternative explanations considered:**
- Benign macro from a legitimate vendor: ruled out by the external domain, encoding, and lack of any known business process matching the behavior.
- User-initiated PowerShell: process parent and timing do not support this.
- False positive on encoded PowerShell: the parent process and immediate external connection make this unlikely.

### MITRE ATT&CK

| Technique | Name | Supporting Evidence | Confidence |
|-----------|------|---------------------|------------|
| T1566.001 | Phishing: Spearphishing Attachment | .docm received via email and opened | High |
| T1204.002 | User Execution: Malicious File | Document opened by user | High |
| T1059.001 | PowerShell | Encoded powershell.exe spawned by WINWORD | High |
| T1027 | Obfuscated Files or Information | -enc argument and high-entropy command | High |
| T1071.001 | Application Layer Protocol: Web Protocols | Immediate 443 connection to external domain | Medium |

## Indicators of Compromise

| Type | Indicator | Notes | Confidence |
|------|-----------|-------|------------|
| File | Invoice_Q3.docm | SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | High |
| Process | powershell.exe -enc ... | Parent: WINWORD.EXE | High |
| Domain | updates-cdn[.]net | Newly observed; no prior organizational traffic | Medium |
| IP | 45.133.248.67 | Resolved at time of connection | Medium |

## Scope and Impact

Only WS-FIN-047 was affected. Retrospective EDR and SIEM searches for the domain, IP, and document hash across the environment returned no additional hits. No scheduled tasks, Run keys, services, or WMI subscriptions were created. No LSASS access or credential dumping tools were observed. The connection was outbound only; no inbound callbacks or secondary beacons appeared before isolation.

Impact is limited to the single workstation and the brief exposure window. Business impact is low given the rapid containment and the user’s role (no privileged access).

## Response Actions

- Isolated the host at 09:28.
- Terminated the PowerShell process and quarantined the document.
- Blocked the domain and IP at the proxy and firewall.
- Collected the document and a limited memory snapshot for offline analysis.
- Ran a targeted hunt for the hash and domain across the last 7 days (negative).

## Recommendations

| Priority | Action | Owner | Target |
|----------|--------|-------|--------|
| High | Enable Attack Surface Reduction rule “Block Office applications from creating child processes” and disable macros from the internet via GPO | Endpoint | 2026-09-29 |
| High | Move high-risk users (finance) to PowerShell Constrained Language Mode or application control | Endpoint | 2026-10-06 |
| Medium | Add the document hash and domain to the email gateway block list and review similar attachment types | Email security | 2026-09-30 |
| Low | Brief finance team on macro risks; no broad phishing simulation required at this time | Awareness | 2026-10-10 |

## Open Questions

- Did the HTTPS connection return a payload that was executed in memory? Traffic reconstruction is still pending.
- Full de-obfuscation of the PowerShell command and static analysis of the macro are incomplete.
- Confirm whether the sending email address was previously used in the environment or is a new external sender.

## Appendix

Process tree and full command-line fragment are stored in the EDR case. Proxy logs for the 09:16–09:28 window are attached to the ticket. Memory dump is available for offline review if second-stage activity needs confirmation.
