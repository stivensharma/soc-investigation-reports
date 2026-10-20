# Incident Investigation Report

**Incident ID:** IR-2026-001  
**Title:** Phishing Link Leading to Credential Use and Anomalous Sign-In  
**Severity:** High  
**Status:** Contained  
**Analyst:** Stiven Sharma  
**Opened:** 2026-09-15 14:22 UTC  
**Contained:** 2026-09-15 14:55 UTC  

## Executive Summary

A user reported a suspicious email at 14:22 UTC on 15 September 2026. The email directed them to a look-alike Microsoft 365 login page where they entered their credentials. Eighteen minutes later Azure AD recorded a successful sign-in from an IP outside the user’s normal locations, followed by an MFA approval the user stated they did not initiate. The account was disabled, sessions revoked, and the password reset within 33 minutes of the user’s report. Mailbox rules, OAuth consents, and download activity in the active window showed no further malicious action. The incident is contained; residual risk is limited to any credentials or session tokens that may have been captured before the reset.

## Timeline

| Time (UTC) | Event | Source |
|------------|-------|--------|
| 13:47 | Phishing email delivered to j.smith | Email gateway / Microsoft 365 Defender |
| 14:08 | User clicked link and submitted credentials | Safe Links / proxy logs |
| 14:22 | User reported the email to the SOC | Ticket |
| 14:40 | Successful sign-in from 185.234.219.12 | Azure AD sign-in logs |
| 14:42 | MFA push approved | Azure AD authentication logs |
| 14:55 | Account disabled and all sessions revoked | SOC / Identity action |
| 15:10 | Password reset and MFA re-registration completed | Identity team |

## Technical Analysis

The email used a spoofed sender (noreply@accounts-verify[.]net) and linked to login-microsoft365-secure[.]com, a domain that resolved to a credential-harvesting page mimicking the Microsoft login flow. The user confirmed they entered their password on that page.

The subsequent sign-in from 185.234.219.12 occurred from a country with no prior activity for this account. Azure AD Identity Protection flagged the sign-in as high risk. The MFA approval two minutes later is the weakest point in the timeline: the user stated they did not approve the push. This is consistent with either accidental approval, MFA fatigue, or the attacker already possessing a valid session token, but the logs alone do not distinguish between those possibilities.

**Alternative explanations considered:**
- User traveling and legitimately signing in: contradicted by the user’s statement and the timing relative to the phishing report.
- Compromised password from an earlier unrelated breach used without the phishing event: possible but less likely given the tight temporal correlation.
- False positive on the look-alike domain: the domain and page behavior do not match any legitimate Microsoft infrastructure.

### MITRE ATT&CK

| Technique | Name | Supporting Evidence | Confidence |
|-----------|------|---------------------|------------|
| T1566.002 | Phishing: Spearphishing Link | Email with link to look-alike login | High |
| T1598.003 | Phishing for Information: Spearphishing Link | User entered credentials | High |
| T1078 | Valid Accounts | Successful authentication with the stolen password | High |
| T1621 | Multi-Factor Authentication Request Generation | MFA push approved shortly after anomalous login | Medium |

## Indicators of Compromise

| Type | Indicator | Notes | Confidence |
|------|-----------|-------|------------|
| Domain | login-microsoft365-secure[.]com | Phishing page | High |
| URL | https://login-microsoft365-secure[.]com/auth | Credential collection endpoint | High |
| IP | 185.234.219.12 | Anomalous sign-in source | High |
| Email sender | noreply@accounts-verify[.]net | Spoofed sender address | High |

## Scope and Impact

Only the single Microsoft 365 account for j.smith was affected. No mailbox forwarding rules were created, no new OAuth applications were consented, and no large downloads or sharing activity appeared in the 14:40–14:55 window. No other accounts showed similar sign-ins from the same IP or interactions with the same domain. Lateral movement into other systems was not observed.

Business impact is limited to the temporary loss of the account and the time required for the user to re-establish MFA. The risk of business-email compromise was present but not realized before containment.

## Response Actions

- Disabled the account and revoked all refresh tokens at 14:55.
- Forced password reset and new MFA registration.
- Blocked the phishing domain and URL at the proxy and email gateway.
- Searched the tenant for the same sender and domain (no additional hits).
- Opened a full mailbox audit for the active window (still in progress at time of writing).

## Recommendations

| Priority | Action | Owner | Target |
|----------|--------|-------|--------|
| High | Require number matching or phishing-resistant MFA for all users | Identity | 2026-09-22 |
| High | Tighten Conditional Access to block or step-up high-risk sign-ins from non-corporate locations | Identity | 2026-09-20 |
| Medium | Targeted awareness note to the user’s department on look-alike login pages | Awareness | 2026-09-30 |
| Medium | Move toward DMARC enforcement (p=reject) for the primary domains | Email team | 2026-10-15 |

## Open Questions

- Whether the MFA push was approved by the user accidentally or by the attacker remains unresolved; the user interview did not clarify it.
- Full mailbox and OneDrive activity review for the 15-minute window is not yet complete.
- Confirm whether any other users received the same email but did not report it.

## Appendix

Email headers and the Azure AD sign-in risk details are stored in the ticket. The Identity Protection risk score for the 14:40 sign-in was High.
