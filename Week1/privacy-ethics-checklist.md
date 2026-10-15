# Privacy and Ethics Checklist — Week 1

## 1. Purpose

This checklist evaluates the privacy, security, and ethical considerations of using a locally hosted Large Language Model (LLM) as a SOC analysis assistant.

The objective is to reduce the risk of exposing sensitive security information, prevent unsafe automated decisions, and ensure that AI-generated findings are reviewed by a human analyst.

## 2. Privacy Checklist

| Check | Description | Status |
|-------|-------------|---|
| Local model execution | Models run on the local machine through Ollama; prompts are processed locally. | Met |
| Offline operation | Model generated a response with the device disconnected from the internet (tested with Llama 3). | Passed — `screenshots/offline-test.png` |
| Offline operation — selected model | Repeat the offline test with Mistral, the model selected for Week 2. | Pending |
| Local API exposure | Ollama API should listen on `127.0.0.1:11434` only, not `0.0.0.0`. Check with `netstat -ano \| findstr :11434`. | Not yet verified |
| External data transmission | Confirm Ollama opens no outbound connections while analysing prompts (procedure in `setup-guide.md` §7). | Not yet verified |
| Model downloads | `ollama pull` contacts the model registry. Pull models deliberately, before analysis, not while handling sensitive data. | Required |
| Test data | Only fictional data was used; IPs are from the 192.0.2.0/24 documentation range (RFC 5737). No real user or company data. | Met |
| Sensitive information | Do not include passwords, access tokens, private keys, or unnecessary personal information in prompts. | Required |
| Log minimization | Provide only the log fields needed for the analysis task. | Recommended |
| CLI prompt history | The Ollama CLI saves typed prompts to `%USERPROFILE%\.ollama\history`. Clear it after sessions that contain real log data. | Required for real data |
| Stored outputs | Transcripts in `test-result/` contain full prompts and logs. Protect them like the source logs. | Required |
| Access control | Restrict access to stored logs, reports, and test results. | Not yet verified |
| Data retention | Define how long raw logs, transcripts, and generated reports are kept. | To be defined |
| Model licences | Llama 3: Meta Llama 3 Community License. Mistral 7B: Apache 2.0. Phi-3: MIT. | Documented |

## 3. Ethical and Safety Checklist

| Check | Description | Status |
|---|---|---|
| Human oversight | A SOC analyst reviews AI-generated findings before acting on them. | Required |
| Evidence-based analysis | Findings must reference the supplied evidence by log ID. | Required |
| Uncertainty | The model must distinguish confirmed facts from hypotheses. | Required |
| Account vs person | Logs show which account was used, not who used it. AI output must not present a named person as responsible without verification. | Required |
| Hallucination review | Check for invented or altered log details, incorrect ATT&CK mappings, and unsupported conclusions. | Required |
| Safe recommendations | No disruptive action (IP block, account suspension, forced password reset) without sufficient evidence and human approval. | Required |
| Fair interpretation | Do not label a user or activity malicious based on insufficient evidence. | Required |
| Accountability | Record the model, test inputs, outputs, and human corrections. | Met for Week 1 (`test-result/`, accuracy reviews) |
| Transparency | Clearly mark AI-generated content as preliminary analysis. | Required |

## 4. Limitations and Risks

Local execution reduces exposure to external AI services, but it does not automatically guarantee complete privacy or security.

Potential risks include:

- Sensitive information remaining in local files, transcripts, or the Ollama CLI history file.
- Other applications or users on the same machine accessing stored logs.
- The Ollama API becoming reachable from the network if it is configured to listen on all interfaces.
- Incorrect AI conclusions leading to unnecessary incident-response actions against a legitimate user.
- Hallucinated facts, altered identifiers, or inaccurate MITRE ATT&CK mappings. In Week 1, Phi-3 altered a hostname and an IP address and generated fictitious log entries.
- Unverified network activity from other software or model-management components.

The system must therefore combine local execution with access controls, data minimization, human review, and secure handling of stored data.

## 5. Current Test Results

- **Local execution:** All three models ran on the local machine through Ollama.
- **Offline operation:** Passed (`screenshots/offline-test.png`). 
- **Accuracy and safety:** All three models produced at least one unsupported interpretation. Llama 3 and Mistral each gave an incorrect MITRE ATT&CK technique ID. Phi-3 altered identifiers, invented instructions and log entries, and recommended suspending the account without sufficient evidence.
- **Human oversight:** Manual review was necessary to identify and correct these issues.
- **Complete privacy verification:** Not established by the offline test alone. API exposure and outbound connections still need to be checked.

## 6. Conclusion

A local LLM reduces dependence on external AI services when analysing SOC alerts. Offline operation alone does not guarantee that every part of the environment is secure or that sensitive data cannot be accessed locally.

The SOC assistant is a decision-support tool, not an autonomous authority. Security findings and response actions must be validated by a human analyst before being accepted or executed.

**Status:** Week 1 checklist complete. Open items: offline test with Mistral, local API exposure check, outbound connection check, access control, and a retention period.
