# Detection Improvement Notes — Week 2 (DEPI Project 5)

> **Deliverable 3 of 4.** The detections to **add or tune** so the attacks analysed
> this week get caught automatically next time, plus the **IOC context** the task
> asks for. Grounded in the *validated* behaviours from the log-analysis and the
> brute-force scenario. All MITRE IDs verified on attack.mitre.org.
>
> **Note on the AI:** Mistral's own detection output failed validation (3–5 of its
> MITRE IDs were wrong and all its Sigma rules were malformed — see
> `detection-validation-bruteforce.md` and validation-log rows DT-01…DT2-06). These
> notes are therefore **human-authored and corrected**, which is itself the week's
> headline: the local model could not produce usable detections unaided.


| Evidence | brute-force logs (`attack-events-curated.txt`), `ai-assisted-log-analysis.md` |

---

## 1. Detections to add

| # | Behaviour (with evidence) | Detection logic (plain English) | MITRE | Priority |
|---|---|---|---|---|
| D1 | One account, 100 failed logons (4625) in 3 s — A-009 | Alert when one account has ≥10 failed logons (4625) within 5 min | **T1110.001** | High |
| D2 | Encoded PowerShell spawned by **rundll32.exe** (Win log-analysis W-001) | Alert when rundll32 is the parent of a shell, OR PowerShell runs with `-Enc` | **T1059.001 + T1218.011 + T1027** | High |
| D3 | Local **backdoor account** created (W-002 ShadowAdmin; Linux L-005 backdoor_user) | Alert on local account creation (4720 / `useradd`), especially outside change windows | **T1136.001** | High |
| D4 | **NTDS.dit** extraction via `ntdsutil … ifm … create full` (W-003) | Alert on any `ntdsutil` with `ifm` / `create full` | **T1003.003** | High |
| D5 | SSH **failed→success** then backdoor (Linux L-004/L-005) | Alert when an account fails SSH then succeeds, followed by `useradd` | **T1110.001 + T1136.001** | Medium |
| D6 | **RIP auth failure** from a peer (Network N-004) | Alert on repeated routing-auth failures from one source | routing integrity *(no clean ATT&CK ID — verify)* | Low–Medium |

### Example rule D1 — brute force (Sigma, corrected)
```yaml
title: Rapid Failed Logons - Single Account
status: experimental
logsource: { product: windows, service: security }
detection:
  sel: { EventID: 4625 }
  timeframe: 5m
  condition: sel | count() by TargetUserName >= 10
tags: [attack.credential_access, attack.t1110.001]
# Draft for human review. Exclude known service accounts that fail for benign reasons.
```

### Example rule D2 — rundll32 spawning a shell (Sigma)
```yaml
title: Shell or Encoded PowerShell Spawned by Rundll32
status: experimental
logsource: { product: windows, category: process_creation }
detection:
  rundll32_parent:
    ParentImage|endswith: '\rundll32.exe'
    Image|endswith: ['\cmd.exe', '\powershell.exe']
  encoded_ps:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: ' -enc'
  condition: rundll32_parent or encoded_ps
tags: [attack.execution, attack.t1059.001, attack.t1218.011]
```

---

## 2. MITRE ATT&CK mapping (verified)
T1110.001 Brute Force: Password Guessing · T1059.001 PowerShell · T1218.011 Rundll32 ·
T1027 Obfuscated Files · T1136.001 Create Account: Local · T1003.003 OS Credential
Dumping: NTDS · T1021.004 Remote Services: SSH · T1069.001 Permission Groups
Discovery: Local Groups.

> Corrections from the AI's wrong mappings (kept here so the error is documented):
> the AI said T1089 for enum (wrong → **T1069.001**), T1055 for service persistence
> (wrong → **T1543.003**), and T1136 for "account maintenance" / DLL hijack (wrong).

---

## 3. IOC context (indicators from the evidence)

> **Process only** for enrichment — no invented reputation (no threat-intel feed).
> Verify each in a TI feed / VirusTotal before acting.

| Indicator | Type | Source | Note (to enrich, not asserted) |
|---|---|---|---|
| 192.168.1.100:8080 | C2 (IP:port) | decoded from Windows W-001 `-Enc` payload | reverse-shell callback |
| 192.168.1.13 | IP | brute-force logs (A-009) | source of the 100 failed Administrator logons — attacker host or the host itself? |
| Administrator | account (targeted) | A-009 | the brute-forced account |
| ShadowAdmin | account (created) | W-002 | backdoor account — confirm removed |
| backdoor_user | account (created) | Linux L-005 | backdoor account — confirm removed |
| 185.220.101.5 | IP | Linux L-004 | external SSH source; 185.220.101.0/24 commonly Tor — **verify** |
| Win10-Target-VM / DESKTOP-32GLMCG / kali-control | hosts | logs | affected hosts |

*(If the LetsDefend alert set is kept as supplementary: also enrich 149.88.25.133,
18.218.132.237, 89.187.177.73, 84.38.130.118 and the RTF hash df99…4184.)*

---

## 4. Tuning / false-positive notes
- **D1:** service accounts with stale cached credentials fail often — exclude them.
- **D2:** legitimate software rarely has rundll32 spawn a shell — low FP; whitelist known installers.
- **D3:** admins/helpdesk create accounts legitimately — scope to *new account + privileged-group add in one window*.
- **D4:** on a workstation (non-DC), `ntdsutil ifm` should essentially never run — treat as critical there.
- **D6:** a misconfigured neighbour also fails RIP auth — correlate volume/source before escalating.

---

## 5. How the AI did on detection
Across two runs on the same logs, Mistral produced **no usable detection**: wrong
MITRE IDs (it even broke the one it got right on the second run), malformed Sigma
rules built on fabricated EventIDs and fields, and benign SYSTEM/Defender activity
flagged as threats. The detections above were authored and corrected by hand. This
is the strongest evidence in the whole week that a small local model is **not
reliable for detection engineering or ATT&CK mapping** without human validation.
