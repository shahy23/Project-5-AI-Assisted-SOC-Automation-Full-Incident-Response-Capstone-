# SOAR Playbook — Brute Force

**Project 5, Week 3 — SOAR Playbooks & Automation.**
Platform: Shuffle (workflow engine) + TheHive (case/ticketing).
Based on the Week 2 brute-force scenario (100 failed logons on `Administrator`).

> **Golden rule:** anything destructive or irreversible (disabling an account,
> blocking an IP, isolating a host) is **never fully automatic** — it waits for a
> human to approve. Only safe, read-only steps run on their own.

---

## Trigger
The SIEM raises a **"Brute Force"** alert (e.g. ≥10 failed logons `4625` for one
account within 5 minutes) and sends it to Shuffle (webhook). The playbook starts.

## Steps

| # | Step | What it does | Auto / Manual |
|---|---|---|---|
| 1 | **Receive alert** | Shuffle receives the alert: account, source IP, host, failure count, time window | **[AUTO]** |
| 2 | **Enrich — account** | Look up the targeted account: is it a real/privileged account? still enabled? | **[AUTO]** |
| 3 | **Enrich — source IP** | Look up the source IP: internal or external? known/owned asset? reputation (TI feed) | **[AUTO]** |
| 4 | **Check for success** | Search the logs for a **successful logon (4624)** for that account from that IP **after** the failures | **[AUTO]** |
| 5 | **Decide true/false positive + severity** | If success found → likely compromise (High). If only failures → attempt (Medium). If known scanner/service account → likely FP (Low) | **[AUTO] proposes, [MANUAL] confirms** |
| 6 | **Create ticket** | Open a case in **TheHive**: title, severity, observables (IP, account, host), tasks | **[AUTO]** |
| 7 | **Contain — block IP** | Block the source IP at the firewall | **[MANUAL — needs approval]** |
| 8 | **Contain — disable/reset account** | Disable the account or force a password reset | **[MANUAL — needs approval]** |
| 9 | **Escalate** | If step 4 found a success (possible compromise) → escalate to L2/IR | **[MANUAL]** |
| 10 | **Close / document** | If false positive → close the ticket with a reason; else hand to IR | **[MANUAL]** |

## Why the manual gates (steps 7, 8, 9)
Blocking an IP or disabling an account can **lock out a real user or break a
service** if the alert is a false positive. A human confirms first. Everything up
to the decision (enrichment + success check) is safe to automate, because it only
**reads** data — it changes nothing.

## What a correct run should show (for the test)
- The playbook enriches the IP + account and checks for a 4624 success **automatically**.
- It opens a TheHive case automatically.
- It **stops and asks for approval** before blocking the IP / disabling the account.
- On the Week 2 data (no 4624 success for Administrator) → verdict = "attempt, success
  unconfirmed, Medium," ticket created, containment awaits approval. No auto-block.

## Standard mapping
- Incident type: **Brute Force** · MITRE **T1110.001** (Password Guessing)
- IR lifecycle (NIST): Detection → Triage (steps 2–5) → Containment (7–8) →
  Escalation/Recovery (9–10)
