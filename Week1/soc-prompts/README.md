# SOC Prompt Library — Week 1

Prompts used to test local LLMs (Llama 3, Mistral, Phi-3) on defensive SOC tasks.
Each file is the exact prompt used in the Week 1 tests, with a placeholder where the input goes.
The inputs themselves are in `../test-logs.json`; the raw model outputs are in `../test-result/`.

## Prompts

| File | SOC task | Input placeholder | Input used in Week 1 | Run on |
|---|---|---|---|---|
| `Log Analysis.md` | Log analysis | `[PASTE LOGS HERE]` | `raw_log_lines` in `test-logs.json` | Llama 3, Mistral, Phi-3 |
| `Alert Triage.md` | Alert triage | `[PASTE ALERT HERE]` | `alert` (SOC-001) in `test-logs.json` | Llama 3, Mistral, Phi-3 |
| `Threat Summarization.md` | Threat summarization | `[PASTE EVENTS HERE]` | `raw_log_lines` in `test-logs.json` | Llama 3, Mistral, Phi-3 |
| `Incident Report Writing.md` | Report writing | `[PASTE INVESTIGATION DATA HERE]` | `investigation` (IR-001) in `test-logs.json` | Llama 3, Mistral, Phi-3 |
| `AI Limitations Test.md` | Model self-evaluation | `[PASTE LOGS HERE]`, `[PASTE MODEL RESPONSE HERE]` | The logs + the model's own Log Analysis output | Llama 3, Mistral, Phi-3 |
| `Offline Privacy Test.md` | Helper for designing the offline test | none | — | Planning aid only |

`Offline Privacy Test.md` only asks the model to help design the test. The test itself is done manually (see `../privacy-ethics-checklist.md`), because a model cannot verify its own network behaviour.

## How to run a prompt in Ollama

1. Start a fresh session for each prompt: `ollama run mistral --verbose` (or type `/clear` before the next prompt).
2. Type `"""`, press Enter, paste the full prompt with the input filled in, then type `"""` and press Enter. This sends the multi-line paste as one message.
3. Copy the output into `../test-result/<model>.md`, together with the `--verbose` timing lines.

Week 1 lesson: running all prompts in one long session and pasting without `"""` caused split prompts, extra unrequested responses, and earlier answers leaking into later ones (details in the accuracy reviews).

## Evidence rules to add in Week 2 (based on Week 1 errors)

All three models made the same kinds of mistakes. Append this block to any prompt above:

```text
Evidence rules:
- Label every statement as Confirmed Fact, Hypothesis, or Unknown.
- Cite the log ID(s) that support each finding. If no log supports it, do not state it as a finding.
- A log proves that an account was used, not who used it. Do not attribute account activity to a person as a confirmed fact.
- MITRE ATT&CK: give the technique ID and its exact name, plus the log IDs that justify it. If the evidence does not justify a mapping, write "Not justified by available evidence."
- Do not judge behaviour as "unusual" without a baseline in the evidence.
- Recommend evidence collection before containment. Any blocking, suspension, or password reset requires human approval and must be labelled as such.
- Copy hostnames, usernames, IP addresses, and timestamps exactly as they appear in the input.
```
