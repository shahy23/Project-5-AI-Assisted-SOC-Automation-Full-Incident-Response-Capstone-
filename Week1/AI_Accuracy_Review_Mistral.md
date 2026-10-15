# AI Accuracy Review — Mistral

## 1. Objective

Evaluate the accuracy and reliability of the local Mistral model on defensive SOC tasks: log analysis, alert triage, threat summarization, incident report writing, and self-evaluation.

The review focuses on factual accuracy, evidence-based reasoning, MITRE ATT&CK mapping, uncertainty, missing evidence, and the safety of recommendations. Outputs are compared against the reference findings in `accuracy-review.md` §5.

## 2. Test Environment

- **Operating System:** Windows 10
- **Local LLM Runtime:** Ollama
- **Model:** Mistral (`mistral`)
- **Dataset:** Fictional authentication logs (`test-logs.json`)
- **Raw output:** `test-result/Mistral.md`
- **Offline operation:** Not separately tested with Mistral (the offline test used Llama 3). Pending — see `privacy-ethics-checklist.md`.
- **Evaluation Method:** Manual review of the model's actual outputs
- **Evaluation Status:** Provisional

## 3. Evidence Used

```text
LOG-001 | 2026-10-13 10:00:00 | host=WS-01 | user=alice | source_ip=192.0.2.25 | event_id=4625 | result=failed_login
LOG-002 | 2026-10-13 10:00:15 | host=WS-01 | user=alice | source_ip=192.0.2.25 | event_id=4625 | result=failed_login
LOG-003 | 2026-10-13 10:00:30 | host=WS-01 | user=alice | source_ip=192.0.2.25 | event_id=4625 | result=failed_login
LOG-004 | 2026-10-13 10:01:00 | host=WS-01 | user=alice | source_ip=192.0.2.25 | event_id=4624 | result=successful_login
```

The evidence shows three failed logins followed by one successful login for the same account, host, and source IP. It does not confirm a brute-force attack, a compromised account, a weak password policy, or unauthorized access.

## 4. Accuracy Findings

### 4.1 Log Analysis

**Correct observations:**
- Correctly summarized the four events with the right times, account, host, and source IP.
- Gave both a malicious hypothesis (brute force) and a benign one (a user trying to remember the password).
- Stated that the pattern "is not definitive evidence" and that more logs were needed.

**Issues identified:**
- The suggestion that "the login system has a weak security mechanism" was speculative; nothing in the logs indicates a configuration weakness.
- The Confidence section gave no level (low/medium/high), only a qualitative statement.
- The timeline and findings did not cite log IDs per entry; the IDs were listed only once under Evidence (instruction 3).

**Assessment:** Accurate timeline and balanced interpretation, with one speculative explanation.

### 4.2 Alert Triage

**Correct observations:**
- Correctly explained the trigger and cited LOG-001 to LOG-004.
- Separated Confirmed Facts from Hypotheses and included the benign explanation.
- Added an "Additional Evidence Needed" section, as the prompt required (instruction 7).
- No disruptive containment was recommended.

**Issues identified:**
- Severity was taken from the SIEM ("based on the SIEM's initial assessment") rather than assessed independently.
- Confirmed Facts describes the attempts as made "by the same user"; the logs establish the account, not the person.
- Repeated the "weak security mechanism" speculation.
- Suggested threat intelligence on the source IP. 192.0.2.25 is a documentation address, so a lookup would return nothing useful here.

**Assessment:** Suitable as preliminary triage, with minor speculation.

### 4.3 Threat Summarization

**Correct observations:**
- Accurately summarized the sequence and listed the relevant indicators, including event IDs 4625 and 4624.
- Stated that the evidence did not justify a specific MITRE ATT&CK mapping. This matches the reference findings and was the most cautious answer of the three models.
- Gave a benign alternative explanation.

**Issues identified:**
- After this answer, the model produced an extra response with no new instruction visible in the transcript. In it, it wrote "Initial Access (T1077) - Brute Force (T1110)". T1077 was the ATT&CK ID for Windows Admin Shares (now deprecated); it is not Initial Access (tactic TA0001) and not Brute Force. T1110 is Brute Force under the Credential Access tactic.
- The extra response kept the caveat that the evidence was insufficient, but changed the mapping without any new evidence.

**Assessment:** The first answer was correct and appropriately cautious. The follow-up introduced a factually wrong technique ID.

### 4.4 Incident Report Writing

**Correct observations:**
- Included the incident reference, host, account, source IP, and timeline.
- Findings and Evidence cites LOG-001 to LOG-004 and the related alert SOC-001.
- Acknowledged that the investigation was preliminary and that no response actions had been performed.
- Recommendations were numbered, and containment was conditional on the incident being confirmed.

**Issues identified:**
- Potential Impact lists "lateral movement or privilege escalation". It was phrased conditionally ("if the attacker gains access"), but nothing in the evidence suggests either; this wording can lead readers to overestimate the risk.
- Listed the source IP 192.0.2.25 as an "affected asset". A source address is an indicator, not an affected asset.
- The timeline did not include the date or per-entry log IDs.
- Repeated the "weak security mechanism" hypothesis.

**Assessment:** The best-structured report of the three models; the potential-impact section went beyond the evidence.

### 4.5 AI Limitations Evaluation (self-evaluation)

The model was asked to evaluate its own Log Analysis output. It was not shown its other outputs, so it is assessed only on that response.

**Correct observations:**
- Correctly flagged the "weak security mechanism" explanation as speculation.
- Correctly noted that the Confidence section gave no clear confidence level.
- Correctly judged the recommendations as generally safe and proportional.
- Added a reasonable extra alternative (misconfiguration or a transient issue).

**Issues identified:**
- Claimed the response "does not acknowledge the uncertainty of its findings and fails to provide alternative explanations". The original stated the evidence was not definitive and offered a benign explanation, so this is a false negative.
- Used the word "provisional", but applied it to the reviewed response rather than labelling its own evaluation provisional as instructed.
- Did not quote exact claims for each issue, as the prompt required.

**Assessment:** Partly accurate, with one significant mischaracterization. Self-evaluation should not be treated as ground truth.

## 5. Hallucination and Evidence Check

- Event sequence, timestamps, account, host, source IP, and log IDs matched the evidence in every output.
- No invented events, log IDs, or instructions.
- One factual error: T1077 presented as Initial Access / Brute Force (in an extra, unrequested response).
- Unsupported hypothesis: a weak authentication mechanism.
- Lateral movement and privilege escalation were mentioned as potential impacts with no supporting evidence.
- Brute force remains unconfirmed.

This assessment applies only to the reviewed outputs and does not establish that Mistral never hallucinates.

## 6. Safety Review

The model recommended investigation, monitoring, reviewing authentication configuration, and possibly 2FA or rate limiting. These are reasonable. No immediate disruptive action (blocking, suspension, password reset) was recommended, and containment was explicitly conditional on confirmation.

Recommended safeguards:
1. Require each finding to cite its supporting log IDs.
2. Separate observed events, hypotheses, and general potential risks.
3. Verify ATT&CK technique IDs against https://attack.mitre.org.
4. Require human approval before disruptive response actions.
5. Preserve the original model output for auditing and reproducibility.

## 7. Overall Evaluation

**Strengths:** No altered identifiers; consistent benign alternatives; correctly declined an unsupported ATT&CK mapping in its first answer; the most complete incident report; no disruptive recommendations.

**Limitations:**
- Speculation about a weak authentication mechanism, repeated across outputs.
- A wrong ATT&CK ID (T1077) in an extra response.
- Potential impacts beyond the evidence (lateral movement, privilege escalation).
- Severity copied from the SIEM rather than assessed.
- A self-evaluation that misjudged the original response's handling of uncertainty.

## 8. Conclusion

Mistral produced the fewest evidence and safety errors of the three models and is the selected model for Week 2 (see `benchmark.md`). Its outputs still require human validation, especially ATT&CK mappings and potential-impact statements.

**Review Status:** Provisional — single run per prompt, single reviewer.
