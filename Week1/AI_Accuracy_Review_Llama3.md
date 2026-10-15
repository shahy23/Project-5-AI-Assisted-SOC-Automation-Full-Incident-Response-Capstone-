# AI Accuracy Review — Llama 3

## 1. Objective

Evaluate the accuracy and reliability of the local Llama 3 model when analyzing security logs and assisting with SOC tasks.

The evaluation focuses on factual accuracy, evidence-based reasoning, uncertainty, missing information, and the safety of recommended actions. Outputs are compared against the reference findings in `accuracy-review.md` §5.

## 2. Test Environment

- **Operating System:** Windows 10
- **Local LLM Runtime:** Ollama
- **Model:** Llama 3 (`llama3`)
- **Dataset:** Fictional authentication logs (`test-logs.json`)
- **Raw output:** `test-result/Llama3.md`
- **Offline operation:** Verified in a separate offline test with Llama 3 — Passed (`screenshots/offline-test.png`; see `privacy-ethics-checklist.md`). The network state during the transcript runs below was not recorded.
- **Evaluation Type:** Manual review of the model's generated responses
- **Evaluation Status:** Provisional

## 3. Evidence Used

```text
LOG-001 | 2026-10-13 10:00:00 | host=WS-01 | user=alice | source_ip=192.0.2.25 | event_id=4625 | result=failed_login
LOG-002 | 2026-10-13 10:00:15 | host=WS-01 | user=alice | source_ip=192.0.2.25 | event_id=4625 | result=failed_login
LOG-003 | 2026-10-13 10:00:30 | host=WS-01 | user=alice | source_ip=192.0.2.25 | event_id=4625 | result=failed_login
LOG-004 | 2026-10-13 10:01:00 | host=WS-01 | user=alice | source_ip=192.0.2.25 | event_id=4624 | result=successful_login
```

The logs show three failed logins followed by one successful login for the same account, host, and source IP. These events alone do not confirm a brute-force attack or account compromise.

## 4. Accuracy Findings

### 4.1 Log Analysis

**Correct observations:**
- Identified the sequence of three failed logins followed by a successful login, in the correct order with correct log IDs and timestamps.
- Recognized that the sequence could warrant further investigation and that additional evidence was needed.

**Issues identified:**
- Described the behaviour as "unusual" without any baseline of normal authentication activity for the account.
- Assigned "moderate" confidence and justified it with the unsupported "unusual" claim.
- Did not separate confirmed facts from hypotheses, which the prompt required (instruction 4).
- Suggested "rate limiting or IP blocking" although the prompt asked for safe investigation steps. 192.0.2.25 could be the account owner's own workstation.
- Listed "the login attempts' success or failure reasons" as missing. Success and failure are recorded; what is missing is the failure **reason** (4625 Sub Status).

**Assessment:** Accurate event extraction; reasoning and recommendations needed more care.

### 4.2 Alert Triage

The first run was broken: the multi-line prompt was split during paste and the model started answering before the last two lines arrived. That run is excluded; the second, complete run is assessed.

**Correct observations:**
- Explained the trigger correctly and cited LOG-001 to LOG-004.
- Separated Confirmed Facts from Hypotheses, and gave both a benign explanation (incorrect credentials) and a malicious one.
- Recommended investigation rather than containment.

**Issues identified:**
- Restated the SIEM's Medium severity without assessing it independently (instruction 3).
- Recommendations were generic; they did not name specific evidence to collect (failure sub-status, logon type, activity after LOG-004).

**Assessment:** Useful preliminary triage; severity and next steps need analyst input.

### 4.3 Threat Summarization

**Correct observations:**
- Summarized the sequence and listed the correct host, account, and source IP.
- Stated that the mapping was "not a confirmed attack scenario".

**Issues identified:**
- Mapped the events to "T1003: Credential Stuffing". T1003 is OS Credential Dumping; Credential Stuffing is T1110.004. Neither is supported: credential stuffing needs breached credential pairs, which are not in the evidence. A defensible hypothesis would be T1110.001 (Password Guessing).
- Gave no benign or alternative explanation, which the prompt required (instruction 6).
- Repeated the unsupported "unusual" claim in the Confidence section.

**Assessment:** The summary was usable, but the ATT&CK mapping was factually wrong and must be corrected before any report uses it.

### 4.4 Incident Report Writing

**Correct observations:**
- Correct timeline with log IDs.
- Stated that impact was unknown and that no containment had been performed. No invented business impact.

**Issues identified:**
- Confirmed Facts states "User 'alice' made a series of authentication attempts". The logs show the account was used; who used it is the open question of the incident.
- The Findings and Evidence section cites no log IDs and does not mention the related alert SOC-001 (instruction 3).
- No list of outstanding investigation tasks, and recommendations are not prioritized (instructions 6 and 7).

**Assessment:** Appropriate as a preliminary draft, but it presents an attribution as a fact and misses required report elements.

### 4.5 AI Limitations Evaluation (self-evaluation)

The model was asked to evaluate its own Log Analysis output.

**Useful findings:**
- Correctly flagged the "unusual behaviour" claim as unsupported.
- Identified missing context and the need for more evidence.

**Issues identified:**
- Listed the hedged phrase "suggesting a possible brute-force attack" under **Hallucinated facts**. A clearly labelled possibility is a hypothesis, not a hallucination; no invented IDs, timestamps, or IOCs existed.
- Under Safety Issues, it flagged "monitor user behaviour" (a safe step) and did not identify the IP-blocking suggestion as the disproportionate recommendation.
- Did not label its evaluation provisional, although the prompt required this when no reference answer is supplied.
- Repeated the same "Comparison" paragraph about seven times; its corrective recommendations addressed the logs rather than the model.

**Assessment:** The self-evaluation found one real issue but also produced a false positive and a false negative. It cannot replace human review.

### 4.6 Additional General Question (Llama 3 only — excluded from comparison)

Llama 3 was also asked what an analyst should check after three failed logins and one success. The "cannot be concluded" list was accurate. One recommendation was wrong in practice: "verify the user account information, including the username, password". Analysts do not view or verify user passwords; they check account status, recent password changes, lockout, and MFA. The answer also used alice, WS-01, and 192.0.2.25, which were not in this prompt, showing that earlier prompts in the same session influenced it.

## 5. Hallucination and Evidence Check

- No invented or altered log IDs, timestamps, accounts, hosts, or IP addresses in any reviewed output.
- One factual error: T1003 presented as Credential Stuffing.
- Unsupported interpretations: "unusual" behaviour (twice); account activity presented as a person's action.
- Brute force and account compromise remain hypotheses, not findings.

This review covers the outputs examined; it does not establish that the model never hallucinates.

## 6. Safety and Recommendation Review

The model recommended monitoring, reviewing logs, verifying the account, and "rate limiting or IP blocking". Monitoring and evidence collection are reasonable first steps. Blocking an IP may disrupt legitimate activity and is not justified by these four events.

Before containment, a SOC analyst should:

1. Pull the full 4625/4624 details (failure sub-status, logon type, logon ID).
2. Check whether 192.0.2.25 is the account owner's usual device and verify the activity with the owner.
3. Review activity after LOG-004 and search for other accounts targeted from the same IP.
4. Follow the incident-response procedure and obtain approval before any disruptive action.

## 7. Overall Evaluation

**Strength:** Llama 3 reproduced the supplied evidence reliably, with no altered identifiers, and produced structured preliminary drafts.

**Limitations:**
- Incorrect MITRE ATT&CK technique ID and name.
- Unsupported "unusual" judgement and loosely justified confidence.
- No benign explanation in the threat summary.
- Account activity presented as a person's action in Confirmed Facts.
- One disproportionate recommendation (IP blocking).
- Unreliable self-evaluation.

## 8. Conclusion

Llama 3 can draft timelines and report skeletons from supplied logs, but its output is not a verified security finding. ATT&CK mappings, confidence levels, attributions, and recommended actions must be checked by an analyst.

Compared with the other models (see `accuracy-review.md` §7 and `benchmark.md`), Llama 3 ranked second: as accurate as Mistral on identifiers, but weaker on reasoning and recommendation safety. It is the fallback model if Mistral proves too slow.

**Review Status:** Provisional — single run per prompt, single reviewer.
