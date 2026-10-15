# Local Model Benchmark — SOC AI Assistant

## 1. Objective

Compare three locally running language models — Llama 3, Mistral, and Phi-3 — and select one for the SOC assistant used in the following weeks: analyzing security logs, triaging alerts, summarizing potential threats, and drafting incident reports.

The benchmark considers evidence accuracy, reasoning quality, uncertainty handling, ATT&CK mapping, report quality, recommendation safety, self-evaluation, and response speed.

The data behind this comparison is in `benchmark.csv`. Detailed findings are in the three `AI_Accuracy_Review_*.md` files.

## 2. Test Environment

| Item | Value |
|---|---|
| Operating system | Windows 10 (build 19045) |
| RAM | 16 GB |
| Runtime | Ollama (CLI) |
| Models | `llama3` (8B), `mistral` (7B), `phi3` (3.8B) — default tags; see `setup-guide.md` §2 |
| Input | `test-logs.json` — four fictional authentication events, alert SOC-001, investigation IR-001 |
| Prompts | Five prompts from `soc-prompts/`, same order for every model |
| Evaluation | Manual review against the reference findings in `accuracy-review.md` §5 |

## 3. Test Dataset

| Log ID | Timestamp | Event |
|---|---|---|
| LOG-001 | 2026-10-13 10:00:00 | 4625 — failed logon |
| LOG-002 | 2026-10-13 10:00:15 | 4625 — failed logon |
| LOG-003 | 2026-10-13 10:00:30 | 4625 — failed logon |
| LOG-004 | 2026-10-13 10:01:00 | 4624 — successful logon |

All events involve account `alice`, host `WS-01`, and source IP `192.0.2.25`. The dataset confirms three failed logins followed by a successful login. It does not prove brute force, credential compromise, or unauthorized access.

## 4. Evaluation Criteria

| Criterion | What was checked |
|---|---|
| Evidence preservation | Log IDs, timestamps, hosts, accounts, and IPs copied exactly; nothing invented |
| Reasoning quality | Conclusions supported by the logs; alternative explanations considered |
| Uncertainty handling | Facts separated from hypotheses; no attack presented as confirmed |
| ATT&CK mapping | Valid ID with matching name, and supported by evidence |
| Report quality | Clear structure, log IDs cited, required sections present |
| Recommendation safety | Evidence collection before containment; no disruptive action without approval |
| Self-evaluation | Ability to find real errors in its own output without inventing false ones |
| Response speed | Load time and generation rate (tokens/s) |

## 5. Comparative Results

| Criterion | Llama 3 | Mistral | Phi-3 |
|---|---|---|---|
| Evidence preservation | No altered identifiers | No altered identifiers | 4 altered identifiers; fabricated log set reusing LOG-001 to LOG-005 |
| Reasoning quality | Called behaviour "unusual" without baseline; no benign option in threat summary | Benign option in every output; speculated about a "weak security mechanism" | Several unsupported scenarios (phishing, spraying, lateral movement) |
| Uncertainty handling | Hedged language; "alice made" attempts stated as fact | Clearly hedged; minor "by the same user" wording | Inconsistent; "alice was present on the system" stated as fact |
| ATT&CK mapping | T1003 wrongly named Credential Stuffing | Correctly declined to map; later wrote T1077 as Initial Access | Technique names with no IDs; none supported |
| Incident report quality | Usable draft; no log IDs in findings, no SOC-001 | Best structured; cited log IDs and SOC-001; potential impact overstated | Altered host name; invented its own instructions; session ended mid-answer |
| Recommendation safety | Suggested IP blocking | No disruptive action; containment conditional on confirmation | Account suspension; immediate password change |
| Self-evaluation | Completed; one false positive, missed IP blocking | Completed; partly accurate, one false negative | Failed — produced fabricated content instead |
| Response speed | Not measured (felt fastest) | Not measured | Not measured |

These are qualitative findings from one run per prompt, not statistically validated rankings.

**Accuracy ranking:** 1. Mistral · 2. Llama 3 · 3. Phi-3

## 6. Selected Model

**Selected model: Mistral**

Reasons, from the Week 1 evidence:
- No altered or invented identifiers in any output.
- Correctly stated that the evidence did not justify an ATT&CK mapping in its first threat summary — the only model to do so.
- Offered a benign explanation in every analysis.
- Recommended no disruptive actions and made containment conditional on confirmation.
- Produced the most complete incident report, citing log IDs and the related alert.

Known weaknesses to control in Week 2:
- One wrong ATT&CK ID (T1077) in an extra response — ATT&CK IDs must always be checked by the analyst.
- Speculation about authentication weaknesses and overstated potential impact — the Week 2 prompts add explicit evidence rules (see `soc-prompts/README.md`).

**Fallback:** Llama 3, if Mistral proves too slow on this hardware once speed is measured. Phi-3 is not recommended for SOC analysis in this configuration.

Accuracy was weighted above speed because in SOC work an incorrect identifier or an unjustified containment action costs more than a slower answer.

## 7. Measuring Speed (to complete `benchmark.csv`)

Run the same Log Analysis prompt once per model in a fresh session:

```
ollama run mistral --verbose
```

After the answer, copy `load duration` and `eval rate` into the `load_duration_s` and `eval_rate_tokens_per_s` columns of `benchmark.csv`. Repeat for `llama3` and `phi3`.

## 8. Limitations

- The dataset contains only four fictional authentication events.
- Each prompt was run once per model, in a single long session per model.
- Several outputs were extra responses with no visible new instruction, caused by how prompts were pasted.
- Speed was not measured.
- Results may differ with other datasets, prompts, model tags, hardware, and settings.
- All three models produced outputs requiring human review.

## 9. Conclusion

Mistral is the selected model for Week 2 because it made the fewest evidence and safety errors. Llama 3 is a reasonable fallback. Phi-3 altered identifiers and fabricated content and is excluded.

Whichever model is used, it remains an assistant to the SOC analyst, not an autonomous decision-maker. Its outputs must be checked against the original evidence before they support any security decision.

## 10. Related Files

- `benchmark.csv` — comparison data
- `accuracy-review.md` — review method, reference findings, results summary
- `AI_Accuracy_Review_Llama3.md`
- `AI_Accuracy_Review_Mistral.md`
- `AI_Accuracy_Review_Phi3.md`
- `test-result/` — raw transcripts
