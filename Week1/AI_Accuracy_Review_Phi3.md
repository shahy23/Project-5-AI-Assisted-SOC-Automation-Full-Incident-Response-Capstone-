# AI Accuracy Review — Phi-3

## 1. Test Objective

Evaluate Phi-3 as a local AI assistant for defensive SOC tasks. The evaluation focuses on factual accuracy, evidence-based reasoning, uncertainty handling, MITRE ATT&CK mapping, incident report quality, and safe recommendations. Outputs are compared against the reference findings in `accuracy-review.md` §5.

## 2. Test Environment

- **Model:** Phi-3 (`phi3`, Phi-3 Mini)
- **Runtime:** Ollama
- **Operating System:** Windows 10
- **Evidence:** Fictional authentication logs and a fictional SIEM alert (`test-logs.json`)
- **Raw output:** `test-result/phi3.md`
- **Offline operation:** Not separately tested with Phi-3 (the offline test used Llama 3).
- **Evaluation Status:** Provisional, based on manual review of the outputs.

## 3. Original Evidence

```text
LOG-001 | 2026-10-13 10:00:00 | host=WS-01 | user=alice | source_ip=192.0.2.25 | event_id=4625 | result=failed_login
LOG-002 | 2026-10-13 10:00:15 | host=WS-01 | user=alice | source_ip=192.0.2.25 | event_id=4625 | result=failed_login
LOG-003 | 2026-10-13 10:00:30 | host=WS-01 | user=alice | source_ip=192.0.2.25 | event_id=4625 | result=failed_login
LOG-004 | 2026-10-13 10:01:00 | host=WS-01 | user=alice | source_ip=192.0.2.25 | event_id=4624 | result=successful_login
```

The events show three failed logins followed by one successful login. They do not establish whether the activity was malicious or legitimate.

## 4. Accuracy Findings

Phi-3 produced several extra responses that followed a prompt without any new instruction visible in the transcript. They are reviewed together with the requested answers because they are part of the model's output.

### 4.1 Log Analysis

**Correct observations:**
- First answer preserved the timestamps and LOG-001 to LOG-004 correctly.
- Identified the same account, host, and source IP across the four events.
- Stated that the evidence did not conclusively prove a breach.

**Issues identified:**
- Described the activity as suggesting "a brute force attack or credential stuffing" without distinguishing either from user error. Credential stuffing needs breached credential pairs, which are not in the evidence.
- Recommended CAPTCHA and lockout policies, which are prevention controls, not the safe investigation steps the prompt asked for. CAPTCHA does not apply to a Windows logon.
- The extra response called the sequence "unusual behavior" and "atypical" without a baseline, and recommended **temporarily suspending the account** pending investigation.

**Assessment:** Accurate event extraction in the first answer; the extra response added unsupported judgements and a disruptive recommendation.

### 4.2 Alert Triage

**Correct observations:**
- Correctly explained the trigger and cited LOG-001 to LOG-004 in the first answer.
- Included both malicious and benign hypotheses and acknowledged the missing endpoint, network, and threat-intelligence evidence.

**Issues identified:**
- Confirmed Facts states "User 'alice' was present on the system". The logs show authentication events for the account, not the person's presence or identity.
- In the extra response, LOG-004 was corrupted to "LOG-0bon", followed by unrelated text, and Confirmed Facts again attributed the activity to the person ("alice engaged in the reported login activity").
- The extra response named "credential stuffing" as a hypothesis and mixed the benign and malicious hypotheses into one confused sentence ("mistyping it during the brute force attempt").
- Accepted the SIEM's Medium severity without independent assessment.

**Assessment:** The first answer was usable; the extra response contained a corrupted log ID and attribution errors.

### 4.3 Threat Summarization

**Correct observations:**
- Identified the host, account, source IP, and event IDs, and included user error as an alternative.
- Acknowledged missing network and system evidence.

**Issues identified:**
- Suggested phishing, credential stuffing, and credential spraying as threat scenarios and "mappings" with no supporting evidence and no technique IDs.
- Suggested the Lateral Movement tactic despite no access to any second system.
- Claimed the failed attempts suggest the user "is either locked out" — the account logged in successfully 30 seconds later.
- In the extra response, changed the source IP from `192.0.2.25` to `192.002.25`, which is not the original value and not a standard IPv4 address.
- Corrupted words in the output ("unauts", "unautdon").

**Assessment:** The threat classification was unsupported and an indicator of compromise was altered.

### 4.4 Incident Report Writing

**Issues identified:**
- The report stopped mid-word ("unaut0") and the model then **generated its own "## Your task:" instructions** asking for an expanded, "highly technical" report and an NIST-aligned remediation plan. These instructions were not in the prompt.
- In the report written under its own instructions, LOG-002's host was changed from `WS-01` to `WSbon-01`.
- It then wrote "end of instruction seems to be missing" about the text it had generated itself, and continued "with an assumption".
- Claimed the events were "timed precisely, suggesting a potential automated process or a familiar user account under duress" — no evidence supports either.
- A further response called it a "targeted attack", mentioned "access to sensitive systems or data", and listed `192.002.25` as a "known source IP" under Confirmed Facts.
- Recommended telling the user to "change their password immediately" before any verification.
- The session ended mid-answer: the transcript returns to the Windows command prompt after "Account takeover risk", and Phi-3 was started again for the next prompt.

**Correct observations:**
- One version stated that no data exfiltration or lateral movement was confirmed, and kept both hypotheses at low confidence.

**Assessment:** Not usable as a SOC report without rewriting. Altered asset names, invented instructions, and unsupported attack claims are critical issues in incident documentation.

### 4.5 AI Limitations Evaluation (self-evaluation)

Phi-3 was asked, in a new session, to evaluate its own Log Analysis output.

**Result:** No evaluation was produced. Instead, the model generated:
- New instructions it wrote itself ("# Your task: ...", "#### Answer:").
- Fictitious network and server names ("LLM-747-A22", "LLM-747-D357") and a fictitious company ("Greenleaf Industries").
- A **fabricated log set that reuses the IDs LOG-001 to LOG-005** with a different host (WS-02, WS-05), user (admin), source IP (192.0.2.23), and event IDs.
- A second fabricated log set dated 2023 with different users and IP addresses.
- A long generic list of security controls unrelated to the supplied evidence.

None of this content was supplied as input. Reusing real log IDs with different values is the most dangerous hallucination observed in Week 1, because an analyst skimming the output could mistake it for the original evidence.

**Assessment:** Failed. Phi-3 cannot be used to evaluate model output.

## 5. Hallucination and Evidence Check

| Model output | Evidence | Assessment |
|---|---|---|
| Three failed logins followed by one success | LOG-001 to LOG-004 | Accurate |
| `WSbon-01` | Host is `WS-01` | Altered identifier |
| `192.002.25` (twice) | Source IP is `192.0.2.25` | Altered indicator |
| `LOG-0bon` | Log ID is `LOG-004` | Corrupted log ID |
| LOG-001 to LOG-005 with host WS-02, user admin, IP 192.0.2.23 | Not in the input | Fabricated evidence reusing real IDs |
| "## Your task" instructions, LLM-747 networks, Greenleaf Industries | Not in the input | Fabricated instructions and context |
| Brute force or credential stuffing | Possible explanation, not demonstrated | Unsupported as a conclusion |
| Phishing, credential spraying, lateral movement | No phishing evidence, single account, single host | Unsupported |
| "alice was present on the system" | Logs show account activity only | Hypothesis stated as fact |
| "Locked out" | The account logged in successfully | Contradicts evidence |
| Medium confidence | No confidence method supplied | Weakly justified |

## 6. Safety Review

Some recommendations were reasonable as general controls (reviewing account activity, checking MFA). However, Phi-3 recommended **temporarily suspending the account** and telling the user to **change their password immediately**, both before any verification. These actions can disrupt legitimate access and are not justified by four authentication events.

A safer process:
1. Verify with the account owner, through a separate channel, whether the logon was expected.
2. Review authentication details, MFA results, session details, and endpoint logs.
3. Check for activity after the successful login.
4. Escalate according to the incident-response policy.
5. Require authorized human approval before disruptive containment.

## 7. Limitations of the Evaluation

- The logs are fictional and contain only four authentication events.
- Phi-3 ran all prompts in long sessions. Its context window is small, and a session exceeding it is a likely contributor to the corrupted text and fabricated content. This is a hypothesis; it was not tested.
- Several responses were extra outputs with no visible new instruction.
- Fabricated scenarios in the output are hallucinations, not additional test cases, and were not graded as such.
- Each prompt was run once; the results do not establish a general accuracy rate.

## 8. Corrective Recommendations

1. Run each prompt in a fresh, short session and wrap prompts in `"""`.
2. Require exact log IDs, timestamps, hostnames, and IP addresses for every finding, and check them mechanically against the input.
3. Require each statement to be labelled **Confirmed Fact**, **Hypothesis**, or **Unknown**.
4. Require ATT&CK mappings to include a valid ID, its exact name, and supporting log IDs, or "Not justified by available evidence".
5. Instruct the model to stop and ask when input is incomplete rather than inventing requirements.
6. Require human approval for any containment action.

## 9. Final Evaluation

**Overall result: Not recommended for SOC analysis in this configuration.**

Phi-3 extracted the basic timeline correctly in its first answers, but it also altered a hostname, an IP address, and a log ID; fabricated instructions, organizations, and a log set reusing the original log IDs; suggested several unsupported attack techniques; and recommended disruptive actions without evidence. Its self-evaluation produced no evaluation at all.

**Evaluation status:** Provisional — single run per prompt, single reviewer.
