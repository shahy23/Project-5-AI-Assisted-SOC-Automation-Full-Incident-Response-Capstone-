# Local AI Lab Setup Guide — Week 1

**Project 5 — AI-Assisted SOC Automation & Full Incident Response Capstone**

## 1. Objective

Set up a local LLM runtime on a Windows workstation, run three open models (Llama 3, Mistral, Phi-3) entirely on the local machine, and use them to test SOC prompts on fictional security data.

## 2. Lab Environment

| Item             | Value |
|------------------|---|
| Operating system | Windows 10  |
| RAM              | 16 GB |
| CPU / GPU        | Intel(R) Xeon(R) CPU E3-1505M v6 @ 3.00GHz/ Intel(R) HD Graphics P630 NVIDIA Quadro M1200 |
| Runtime          | Ollama (CLI) — version 0.40.3: output of `ollama --version`_ |
| Interface        | Windows Command Prompt |
| Test data        | `test-logs.json` (fictional events only) |

### Models

| Model   | Command used          | Default tag     | Parameters | Licence |
|---------|-----------------------|-----------------|------------|---------|
| Llama 3 | `ollama run llama3`   | `llama3:latest` | 8B         | Meta Llama 3 Community License |
| Mistral | `ollama run mistral`  | `mistral:latest`| 7B         | Apache 2.0 |
| Phi-3   | `ollama run phi3`     | `phi3:latest`   | 3.8B       | MIT |

Model names in Ollama are not case-sensitive, so `ollama run Llama3` and `ollama run llama3` start the same model. Confirm the exact tag, size on disk, and quantization with `ollama list`  :

   `ollama run Llama`
   `ollama run Mistral`
   `ollama run phi3`


## 3. Installation

1. Download and install Ollama for Windows from https://ollama.com/download/windows.
2. Open Command Prompt or PowerShell and confirm the install:
   ```
   ollama --version
   ```
3. Download the three models (requires internet, one time only):
   ```
   ollama pull llama3
   ollama pull mistral
   ollama pull phi3
   ```
4. Confirm they are installed and note their tags and sizes:
   ```
   ollama list
   ollama show mistral
   ```

Model files are stored under `%USERPROFILE%\.ollama\models`. After this step no internet connection is needed to run the models.

## 4. Running a Prompt

1. Start the model with timing statistics enabled:
   ```
   ollama run mistral --verbose
   ```
2. At the `>>>` prompt type `"""` and press Enter, paste the full prompt from `soc-prompts/` with the input filled in from `test-logs.json`, then type `"""` and press Enter. Without the triple quotes, a multi-line paste can be sent as several separate messages.
3. After the answer, `--verbose` prints load duration, prompt eval rate, and eval rate (tokens/s). Copy them into `benchmark.csv`.
4. Type `/clear` before the next prompt so the previous answer is not in the model's context, or exit with `/bye` and start a new session.
5. Save the full terminal output to `test-result/<model>.md`.

## 5. Week 1 Test Procedure

Each model received the same five prompts in the same order:
1. Log Analysis — input: the four log lines (LOG-001 → LOG-004).
2. Alert Triage — input: alert SOC-001.
3. Threat Summarization — input: the four log lines.
4. Incident Report Writing — input: investigation data IR-001.
5. AI Limitations Test — input: the four log lines plus the model's own Log Analysis output.

Llama 3 also received one extra general question (what an analyst should check after three failed logins and one success). It is reviewed in the Llama 3 accuracy review but excluded from the model comparison.

Outputs were reviewed manually against the reference findings in `accuracy-review.md`.

## 6. Offline Test
**Procedure (performed with Llama 3):**

1. Confirm the model is already downloaded (`ollama list`).
2. Disconnect Wi-Fi and Ethernet.
3. Show that the machine is offline, for example `ping -n 2 8.8.8.8` fails.
4. Run `ollama run llama3` and submit a SOC prompt.
5. Screenshot the disconnected network state and the model's answer in one frame.

**Result:** Passed. The model generated a response with no network connection. Evidence: `screenshots/offline-test.png`.

Because Mistral is the selected model for Week 2


## 7. Folder Structure

```
Week1/
├── setup-guide.md                  This guide
├── test-logs.json                  Test inputs (logs, alert, investigation data)
├── soc-prompts/                    Prompt library + README
├── test-result/                    Raw terminal output per model
├── screenshots/                    Evidence (offline test, etc.)
├── accuracy-review.md              Review method, reference findings, summary
├── AI_Accuracy_Review_Llama3.md    Detailed findings per model
├── AI_Accuracy_Review_Mistral.md
├── AI_Accuracy_Review_Phi3.md
├── benchmark.md                    Model comparison and selection
├── benchmark.csv                   Comparison data
└── privacy-ethics-checklist.md
```

