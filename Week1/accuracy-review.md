# AI Accuracy Review — Local SOC Assistant

## 1. Objective

This document defines how the project evaluates the accuracy and reliability of AI-generated SOC analysis, records the reference findings used to grade the Week 1 outputs, and summarizes the results for Llama 3, Mistral, and Phi-3.

The purpose is not to assume that an AI model is correct, but to establish a verification process that identifies hallucinations, unsupported conclusions, incorrect technical mappings, and unsafe recommendations.

Detailed findings for each model are in:
- `AI_Accuracy_Review_Llama3.md`
- `AI_Accuracy_Review_Mistral.md`
- `AI_Accuracy_Review_Phi3.md`

## 2. Why AI Accuracy Matters in SOC Operations

SOC analysts work with security alerts, authentication records, endpoint events, and network logs. Incorrect AI-generated conclusions may cause analysts to waste time, overlook relevant evidence, or take unnecessary containment actions.

A model can produce a well-written report while still making technical mistakes. Response quality must therefore be evaluated by checking the underlying evidence rather than relying on confidence, fluency, or formatting.

## 3. Main Accuracy Risks

### 3.1 Hallucinated Evidence

The model may invent or alter log IDs, timestamps, IP addresses, usernames, hostnames, event descriptions, or indicators of compromise (IOCs).

**Verification:** Compare every identifier and factual claim against the original input.

### 3.2 Unsupported Attack Conclusions

A model may interpret suspicious-looking activity as proof of an attack. Three failed logins followed by one success do not by themselves prove brute force or account compromise.

**Verification:** Separate observed events from hypotheses and state what additional evidence would be needed.

### 3.3 Incorrect MITRE ATT&CK Mappings

A model may assign a wrong technique ID, pair an ID with the wrong name, or choose a technique the evidence does not support.

**Verification:** Check the ID and name against https://attack.mitre.org. Record a mapping only as a hypothesis when the evidence is insufficient to establish it.

### 3.4 Unsupported Impact Claims

A report may claim that an attacker accessed sensitive systems, escalated privileges, or moved laterally without corresponding evidence.

**Verification:** Confirm the activity appears in the supplied logs or corroborating telemetry. Otherwise describe it only as a potential risk, not an observed event.

### 3.5 Unsafe or Disproportionate Recommendations

A model may recommend blocking an IP address, disabling an account, or forcing a password reset before sufficient investigation.

**Verification:** Assess the evidence, business context, operational impact, and incident-response procedures before any action.

### 3.6 Incomplete Input Handling

A model may silently fill gaps when a prompt or dataset is incomplete, or generate instructions and data that were never supplied.

**Verification:** Require the model to identify missing information and state what cannot be concluded. Treat any content not traceable to the input as a hallucination.

## 4. Accuracy Verification Workflow

1. **Preserve the original evidence.** Keep the logs unchanged. Record the exact prompt, model name, model tag, and full output.
2. **Verify factual details.** Check event IDs, timestamps, hostnames, usernames, IP addresses, and event descriptions against the input.
3. **Check the reasoning.** For every finding ask: which log supports it, does the evidence support the conclusion, are alternative explanations possible, and is information missing?
4. **Separate facts and hypotheses.** Classify each statement as **Confirmed fact** (directly in the evidence), **Hypothesis** (possible explanation needing investigation), or **Unknown** (cannot be determined from the data).
5. **Verify technical references.** Check ATT&CK IDs, technique names, and event meanings against authoritative documentation.
6. **Review recommendations.** Prefer evidence collection before disruptive containment unless procedures or stronger evidence justify immediate action.
7. **Document errors.** Record the model's claim, the evidence, the issue, the correction, and whether it could affect a security decision.
8. **Produce a corrected report.** Only after verification may the output be used as a draft by an analyst.

## 5. Reference Findings for the Week 1 Dataset

These are the expected findings for `test-logs.json`, written by the reviewer before grading. Every model output was compared against them.

### 5.1 Confirmed facts
- LOG-001, LOG-002, LOG-003: event ID 4625 (failed logon) for account `alice` on host `WS-01` from `192.0.2.25` at 10:00:00, 10:00:15, and 10:00:30 on 2026-10-13.
- LOG-004: event ID 4624 (successful logon) for the same account, host, and source IP at 10:01:00.
- The whole sequence lasts 60 seconds. Alert SOC-001 (SIEM severity Medium) was raised on it.

### 5.2 Not supported by the evidence
- That the person Alice performed these logons. The logs show the **account** was used, not who used it.
- That an attack, brute force, or account compromise occurred.
- The failure reason, logon type, activity after LOG-004, and whether 192.0.2.25 is Alice's usual workstation.
- Any threat-intelligence result for 192.0.2.25: it is a documentation address (RFC 5737), not a real host.

### 5.3 Acceptable hypotheses (must be labelled as hypotheses)
- **Benign:** the user mistyped or forgot the password, or a saved credential was outdated, then the correct password was used.
- **Malicious:** password guessing against this account that succeeded on the fourth attempt.
- **Untestable with this data:** password spraying from 192.0.2.25 across several accounts, which would need logs for other accounts.

### 5.4 ATT&CK mapping (only as hypothesis)
- T1110.001 — Brute Force: Password Guessing, if the malicious hypothesis is confirmed.
- T1078 — Valid Accounts, if the LOG-004 logon is shown to be unauthorized.
- Not supported: T1003 (OS Credential Dumping), T1110.004 (Credential Stuffing, needs breached credential pairs), T1110.003 (Password Spraying, needs multiple accounts), phishing, lateral movement.

### 5.5 Key evidence gaps
- 4625 Status / Sub Status codes (wrong password, unknown user, locked out).
- Logon type, workstation name, authentication package, logon ID.
- Activity after LOG-004 under the same logon ID.
- The account's normal hosts, source IPs, and working hours.
- Other accounts tried from 192.0.2.25; other hosts this account logged into.
- Lockout policy, MFA status, any recent password change or user report.

### 5.6 Expected safe actions
1. Pull the full 4625/4624 event details.
2. Check whether 192.0.2.25 is the account owner's assigned device.
3. Verify the activity with the account owner through a separate channel.
4. Search for the same source IP against other accounts and the same account on other hosts.
5. Review activity after LOG-004.
6. Escalate if the source is unknown, the owner denies the activity, or other accounts were targeted. Containment only with evidence and human approval.

## 6. Review Checklist

For each generated response, verify:

- [ ] Log IDs match the original input.
- [ ] Timestamps and identifiers are preserved exactly.
- [ ] No evidence, instructions, or IOCs were invented.
- [ ] Confirmed facts are separated from hypotheses.
- [ ] Account activity is not presented as a confirmed action by a person.
- [ ] Attack claims are supported by evidence.
- [ ] ATT&CK mappings use valid IDs with matching names.
- [ ] Potential impacts are not presented as observed events.
- [ ] Uncertainty and missing information are acknowledged.
- [ ] Recommendations are proportionate to the available evidence.
- [ ] The final report has been reviewed by a human analyst.

## 7. Results Summary

All three models received the same four log lines, the same alert, the same investigation data, and the same five prompts.

| Check | Llama 3 | Mistral | Phi-3 |
|---|---|---|---|
| Altered identifiers (host, IP, log ID) | 0 | 0 | 4 (`WSbon-01`, `192.002.25` ×2, `LOG-0bon`) |
| Invented instructions or log entries | None | None | Yes — fake tasks, fake networks, a fake log set reusing LOG-001 to LOG-005 |
| Wrong ATT&CK ID or name | 1 (T1003 named "Credential Stuffing") | 1 (T1077 named "Initial Access") | 0 IDs given |
| Unsupported technique suggestions | Credential stuffing | None (T1110 only if confirmed) | Credential stuffing, spraying, phishing, lateral movement |
| Declined an unsupported mapping | No | Yes (first answer) | No |
| Benign explanation in threat summary | No | Yes | Yes |
| Disruptive action without evidence | IP blocking | None | Account suspension; immediate password change |
| Account activity stated as a person's action in Confirmed Facts | Yes | Yes (minor wording) | Yes ("present on the system") |
| Self-evaluation completed | Yes, unreliable | Yes, partly accurate | No |

**Conclusion:** Mistral produced the fewest evidence and safety errors. Llama 3 was accurate on identifiers but weaker on reasoning and safety. Phi-3 altered identifiers and fabricated content and is not suitable for SOC analysis in this configuration. Model selection is in `benchmark.md`.

These findings show why an AI-generated response should not be accepted because it appears detailed or confident.

## 8. Limitations of the Review

This review uses a small fictional dataset and qualitative evaluation by one reviewer. It does not establish a statistically valid accuracy rate or predict performance on real incidents.

Test-execution issues that limit the results:
- Each model ran all prompts in one session, so earlier answers could influence later ones.
- Some multi-line pastes were split or followed by extra responses with no visible new instruction (details in each model review).
- Each prompt was run once, with default settings, so repeatability is unknown.
- Response speed was not measured.

A stronger evaluation in later weeks should add: a fresh session per prompt, repeated runs, more varied and realistic logs (including benign-only cases), a numeric scoring rubric, a second reviewer, and timing data.

## 9. Conclusion

AI-generated SOC analysis can help with summarization, evidence organization, and report drafting. However, the Week 1 tests showed models hallucinating details, mapping techniques incorrectly, and recommending actions not justified by the evidence.

The project therefore uses a human-in-the-loop approach: the AI provides preliminary analysis, and the analyst verifies its claims against the original logs and makes the final security decisions.

**Core principle: No AI-generated security finding is treated as confirmed without supporting evidence and human verification.**
