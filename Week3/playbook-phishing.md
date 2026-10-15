# SOAR Playbook — Phishing

**Project 5, Week 3.** Platform: Shuffle (workflow) + TheHive (ticketing).

> **Golden rule:** destructive/irreversible actions (deleting mail from mailboxes,
> blocking a sender, resetting a password, isolating a host) are **never fully
> automatic** — they wait for analyst approval. Read-only enrichment runs on its own.

## Trigger
An alert for a suspicious email: malicious attachment/link, or a user-reported phish.
Fields: sender, recipient(s), subject, attachment hash, URL, mail server.

## Steps
| # | Step | What it does | Auto / Manual |
|---|---|---|---|
| 1 | Receive alert | sender, recipient, subject, attachment hash, URL | **[AUTO]** |
| 2 | Enrich — sender/URL/hash | reputation of sender domain, URL/domain, and attachment hash (TI feed / VirusTotal) | **[AUTO]** |
| 3 | Enrich — blast radius | how many mailboxes received the same email (subject/hash/sender) | **[AUTO]** |
| 4 | Check click/open | did any recipient open the attachment or click the link? (mail + proxy logs) | **[AUTO]** |
| 5 | Decide TP/FP + severity | High if clicked/credentials likely entered; Medium if delivered only | **[AUTO] proposes, [MANUAL] confirms** |
| 6 | Create ticket | TheHive case: observables = sender, URL, hash; tasks | **[AUTO]** |
| 7 | Contain — remove email | quarantine/delete the email from all mailboxes | **[MANUAL — approval]** |
| 8 | Contain — block | block sender domain / URL / attachment hash | **[MANUAL — approval]** |
| 9 | Contain — user | if a user clicked / may have entered credentials → reset their password, review their recent logons | **[MANUAL — approval]** |
| 10 | Escalate | if malware ran or credentials compromised → escalate to IR | **[MANUAL]** |
| 11 | Notify + close | notify affected users; close FP or hand TP to IR | **[MANUAL]** |

## Why the manual gates (7–9)
Deleting mail, blocking a sender, or resetting a password can disrupt real business
(a legitimate sender blocked, a user locked out). A human confirms first. Enrichment
(2–4) only **reads** data, so it is safe to automate.

## What a correct run should show (test)
- Enrichment of sender/URL/hash + blast-radius runs automatically; a TheHive case is created.
- The playbook **stops for approval** before deleting mail / blocking / resetting.
- Verdict states success only if evidence shows a click/credential entry; otherwise
  "delivered, execution unconfirmed."

## Mapping
Incident: **Phishing** · MITRE **T1566** (T1566.001 Attachment / T1566.002 Link) ·
if a link harvested credentials: **T1598 / T1056**. IR lifecycle: Detection → Triage
(2–5) → Containment (7–9) → Escalation/Recovery (10–11).
