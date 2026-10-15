# Automation Decision Matrix + Manual vs Automated Steps

**Project 5, Week 3.** Covers two deliverables: the automation decision matrix,
and the manual-vs-automated breakdown of every playbook.

## 1. The principle
Automation and the AI handle the **safe, read-only, reversible** work. A **human
approves** anything that **changes or breaks** something. The AI **never decides** a
destructive action — it only *proposes*, and the analyst confirms.

## 2. Decision criteria
A step is automated **only if ALL are true**:
- **Read-only** — it changes nothing on a system.
- **Reversible** — easy to undo if wrong.
- **Low blast radius** — affects nothing/no one beyond the alert.
- **Safe on a false positive** — no harm done if the alert turns out benign.

If **any** criterion fails → the step is **manual, with analyst approval**.

## 3. Decision matrix (by action type)
| Action | Reversible? | Blast radius | If the alert is wrong | Decision |
|---|---|---|---|---|
| Enrich IP / hash / user (lookups) | read-only | none | none | **AUTOMATED** |
| Gather related logs | read-only | none | none | **AUTOMATED** |
| Correlate events / timeline | read-only | none | none | **AUTOMATED** |
| Create ticket (TheHive) | easily closed | none | a noisy ticket | **AUTOMATED** |
| Collect / preserve evidence | read-only | none | none | **AUTOMATED** |
| Triage verdict + severity | n/a | none | wrong priority | **AI PROPOSES → ANALYST CONFIRMS** |
| Block IP / domain / URL | hard to undo fast | can cut legit traffic | business disruption | **MANUAL — APPROVAL** |
| Disable / delete account | disruptive | locks a user out | locks a real user | **MANUAL — APPROVAL** |
| Reset password | disruptive | one user | locks a real user | **MANUAL — APPROVAL** |
| Isolate host | disruptive | machine offline | downs production | **MANUAL — APPROVAL** |
| Delete / quarantine email | partly reversible | mailboxes | removes legit mail | **MANUAL — APPROVAL** |
| Escalate to IR / legal | n/a | the team | wasted effort | **MANUAL** |

## 4. Manual vs Automated — per playbook
Legend: **A** = automated · **P** = AI proposes, analyst confirms · **M** = manual (analyst approval)

| Playbook | Enrich / gather | Triage verdict | Create ticket | Containment | Escalate / close |
|---|---|---|---|---|---|
| **Brute force** | A (steps 1–4) | P (5) | A (6) | M (7–8: block IP / disable acct) | M (9–10) |
| **Phishing** | A (1–4) | P (5) | A (6) | M (7–9: delete mail / block / reset pw) | M (10–11) |
| **Malware** | A (1–4) | P (5) | A (6) | M (7–8: isolate host / kill / block) | M (9–10) |
| **Data exfiltration** | A (1–4) | P (5) | A (6) | M (7–8: block dest / isolate / disable) | M (9–10) |

**Pattern across all four:** the first ~6 steps (enrichment + correlation + ticket)
are automated or AI-proposed; every **containment** step waits for analyst approval.

## 5. Where the AI sits
- The **AI (Mistral)** does **analysis only**: summarise, correlate, propose a verdict,
  propose response actions — all as *suggestions*.
- The **playbook / SOAR tool** executes the **deterministic** response.
- The **analyst** approves every destructive action.

This keeps the risky power (changing systems) with a human, and uses the AI where it
helps (fast analysis) — the core safety design of the whole project.
