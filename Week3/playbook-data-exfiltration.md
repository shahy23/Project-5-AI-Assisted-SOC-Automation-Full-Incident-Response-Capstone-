# SOAR Playbook — Data Exfiltration

**Project 5, Week 3.** Platform: Shuffle (workflow) + TheHive (ticketing).

> **Golden rule:** destructive/irreversible actions (blocking a destination,
> cutting a user's traffic, disabling an account, isolating a host) are **never
> fully automatic** — they wait for analyst approval. Read-only enrichment runs on its own.

## Trigger
An alert for unusual outbound transfer: a large/anomalous upload, a DLP hit, or a
connection to an unknown/file-sharing destination. Fields: host, user, destination
IP/domain, data volume, protocol.

## Steps
| # | Step | What it does | Auto / Manual |
|---|---|---|---|
| 1 | Receive alert | host, user, destination, data volume, protocol | **[AUTO]** |
| 2 | Enrich — destination | reputation + type of destination (known cloud / file-share / unknown) via TI feed | **[AUTO]** |
| 3 | Enrich — baseline | is this volume/destination normal for this user/host? compare to baseline | **[AUTO]** |
| 4 | Check — what data | which files/shares were accessed just before the transfer? sensitive data involved? | **[AUTO]** |
| 5 | Decide TP/FP + severity | High if sensitive data + unknown destination + off-baseline; Low if sanctioned cloud backup | **[AUTO] proposes, [MANUAL] confirms** |
| 6 | Create ticket | TheHive case: observables = destination IP/domain, user, host, files | **[AUTO]** |
| 7 | Contain — block destination | block the destination IP/domain at the firewall/proxy | **[MANUAL — approval]** |
| 8 | Contain — host/user | if active exfil → isolate the host and/or disable the user account | **[MANUAL — approval]** |
| 9 | Escalate | escalate to IR; if sensitive/regulated data left → notify legal/DPO | **[MANUAL]** |
| 10 | Evidence + close | preserve logs/netflow as evidence; close FP or document for IR | **[AUTO] collect / [MANUAL] close** |

## Why the manual gates (7–8)
Blocking a destination or disabling a user can break legitimate work (a real cloud
backup, a user's normal upload). And "data left the building" may trigger legal
duties — a human must own that call. Enrichment (2–4) only reads data, so it is safe
to automate.

## What a correct run should show (test)
- Destination + baseline + data-accessed enrichment runs automatically; a case is created.
- The playbook **stops for approval** before blocking the destination or disabling the user.
- Verdict distinguishes "confirmed exfiltration of sensitive data" from "large but
  sanctioned transfer" using the baseline + data-sensitivity evidence.

## Mapping
Incident: **Data Exfiltration** · MITRE **T1041** (over C2) / **T1567** (over web
service) / **T1048** (alternative protocol); staging **T1074**. IR lifecycle:
Detection → Triage (2–5) → Containment (7–8) → Escalation/Recovery (9–10).
