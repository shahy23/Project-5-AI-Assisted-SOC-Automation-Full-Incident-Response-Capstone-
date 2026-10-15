# Test Result + Validation — Brute Force (live pipeline run)

**Project 5, Week 3.** End-to-end run: collector → detection_engine → bridge → Mistral.
Alert `b33058fbcc26c7b9` (brute force on Administrator). The AI report was validated
against the evidence (the logs the bridge sent).

## Pipeline test — did the system work?
| Stage | Result |
|---|---|
| detection_engine | ✅ produced 3 alerts (brute force, account created, privilege change) |
| bridge → Mistral | ✅ gathered 9 related logs, built the prompt, got a report, saved it |
| Output | ✅ `ai_reports/report_b33058fbcc26c7b9.md` |

**The pipeline works end to end.** The rest is validating the *content* of the AI report.

## AI report validation — what Mistral wrote vs. what is correct
| What the model wrote | Verdict | What is correct |
|---|---|---|
| Facts in §2 (6 failures, success, source IP, user) all cited | ✅ Correct | Accurate and evidence-cited |
| Connected the chain: brute force → success → ShadowAdmin created → added to Administrators | ✅ Correct | Right correlation, marked as inference |
| Marked "block IP 10.0.0.9" as [requires analyst approval] | ✅ Correct | Destructive action correctly gated |
| §4 "Did it succeed?" → **"unconfirmed"** | ❌ Under-called | A 4624 **success** for Administrator from the same IP occurred, then ShadowAdmin was created — evidence points **strongly to success/compromise**. Should say "likely successful (login + post-exploitation)", not "unconfirmed". Contradicts its own §2 |
| §5 IOCs → only user + source IP | ⚠️ Incomplete | Missed the **ShadowAdmin** backdoor account and the host (WIN-PC) |
| §6 marked "investigate ShadowAdmin" as [approval] | ⚠️ Wrong gate | Investigation is not destructive — no approval needed; and it missed "disable/remove ShadowAdmin + reset Administrator password" |
| §7 "need password hashes for password analysis" | ❌ Irrelevant | Password hashes do not help confirm a brute force — off-target suggestion |

## Key finding (behaviour note)
In **Week 2** the model tended to **over-claim** (e.g. asserting an attack or wrong
MITRE IDs). Here, with a structured alert + strict prompt, it swung the other way:
accurate and no hallucination, but **over-cautious** — it under-called a success that
the evidence clearly supports. So the strict "do not claim success" rule helped
avoid hallucination but pushed the model to under-report. The analyst's correction
is to restore the (evidence-backed) "likely successful" verdict.

## Verdict
The AI report is a **usable first-pass triage**: facts correct, chain correct,
approval gates correct. A human must fix: the success verdict (§4), the IOC list
(§5), and drop the off-target evidence ask (§7). Exactly the week's thesis —
**AI assists, analyst validates and decides.**
