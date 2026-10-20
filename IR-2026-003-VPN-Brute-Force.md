# Incident Investigation Report

**Incident ID:** IR-2026-003  
**Title:** Brute-Force Success Against Contractor VPN Account  
**Severity:** Medium  
**Status:** Contained  
**Analyst:** Stiven Sharma  
**Opened:** 2026-10-03 02:51 UTC  
**Contained:** 2026-10-03 02:55 UTC  

## Executive Summary

On 3 October 2026 the VPN concentrator logged 47 failed authentication attempts against the contractor account contractor.r.kumar between 02:14 and 02:41 UTC, followed by a successful login at 02:43 from an IP with no prior association to the account. The session immediately initiated an RDP connection to an internal jump host. The SOC terminated the VPN session at 02:55 after the impossible-travel alert fired. The contractor confirmed they were not the source of the activity. No further access or data movement was observed in the 12-minute window. The account has been locked and the password reset.

## Timeline

| Time (UTC) | Event | Source |
|------------|-------|--------|
| 02:14–02:41 | 47 failed VPN authentications | VPN appliance logs |
| 02:43 | Successful authentication from 103.75.119.88 | VPN logs |
| 02:44 | RDP session started to jump host | Network flow / RDP logs |
| 02:51 | Impossible-travel / anomalous-login alert | SIEM |
| 02:55 | VPN session disconnected by SOC | Response action |
| 03:02 | Account locked and password reset initiated | Identity / VPN admin |

## Technical Analysis

The attack pattern is consistent with password guessing rather than a targeted spray across many accounts: all 47 failures were against this single contractor account, followed by success on the 48th attempt. The source IP (103.75.119.88) had not been seen against this account or the VPN concentrator in the preceding 30 days. The client string OpenVPN/2.5.7 is unremarkable and does not by itself indicate malice.

Once connected, the only observed activity was an RDP connection to the designated jump host. Jump-host logs for the session window show no interactive commands beyond the initial connection; the session was terminated before any further activity could occur.

**Alternative explanations considered:**
- Contractor logging in from a new location: contradicted by the high volume of failures immediately preceding success and by the contractor’s confirmation.
- Shared or previously leaked password used by a third party without brute force: possible, but the failure volume makes pure credential stuffing less likely than online guessing.
- Misconfigured monitoring generating false failures: the successful authentication and subsequent RDP rule this out.

### MITRE ATT&CK

| Technique | Name | Supporting Evidence | Confidence |
|-----------|------|---------------------|------------|
| T1110.001 | Brute Force: Password Guessing | 47 failures then success against one account | High |
| T1078 | Valid Accounts | Successful VPN authentication | High |
| T1133 | External Remote Services | VPN used for initial access | High |
| T1021.001 | Remote Services: Remote Desktop Protocol | RDP to jump host immediately after connect | Medium |

## Indicators of Compromise

| Type | Indicator | Notes | Confidence |
|------|-----------|-------|------------|
| IP | 103.75.119.88 | Source of failures and successful login | High |
| Account | contractor.r.kumar | Targeted account | High |
| Client | OpenVPN/2.5.7 | Observed user-agent / client string | Low |

## Scope and Impact

The compromise was limited to one contractor VPN account for approximately 12 minutes. Access reached only the jump host; no privileged systems, file shares, or cloud consoles were touched. No persistence mechanisms were added on the jump host, and no data transfer was recorded. The contractor and their manager were notified the same morning.

Impact is low: temporary unauthorized access to a jump host that was terminated before meaningful activity, plus the operational cost of the password reset and account review.

## Response Actions

- Forcibly disconnected the VPN session at 02:55.
- Locked the account and initiated password reset.
- Temporarily blocked 103.75.119.88 at the VPN concentrator.
- Reviewed jump-host session logs for the window (no commands of interest).
- Notified the contractor and their manager.

## Recommendations

| Priority | Action | Owner | Target |
|----------|--------|-------|--------|
| High | Enforce MFA on all VPN accounts, including contractors | Network / Identity | 2026-10-10 |
| High | Enable account lockout or progressive rate-limiting on VPN authentications | Network | 2026-10-08 |
| Medium | Review contractor account privileges and remove any access not required for the engagement | Identity / IAM | 2026-10-17 |
| Medium | Add or tune impossible-travel detection for VPN sign-ins | Detection | 2026-10-15 |

## Open Questions

- Whether the password had previously appeared in a public breach has not yet been checked.
- Other contractor accounts have not been reviewed for similar weak-password patterns.
- Jump-host session recording (if enabled) has not been fully reviewed.

## Appendix

VPN authentication log extract and the RDP flow details are attached to the ticket. The source IP was not present in the organization’s prior 30-day VPN logs.
