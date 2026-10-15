# Alert Triage Summaries — Week 2 (DEPI Project 5)

> **AI-drafted, human-validated.** Mistral triaged four real SIEM alerts
> (LetsDefend). Each AI output was checked against the alert's own evidence;
> corrections and errors are recorded in `validation-log.csv`
> (rows T-01 … T-12).



> **Why these are a better test than the log-analysis inputs:** real alerts, not
> pre-labelled with a verdict — so the model had to reason. The key thing to grade
> is whether it resisted the temptation to declare the attack **successful**. It
> did, on all four — the headline positive this week.

---

## Alert 1 — SOC324 · Sudoers access (host: Kristine)

| | |
|---|---|
| Verdict | **Needs more data** (suspicious, not confirmed) |
| Original severity | Brute Force · Medium |
| Independent severity | **Low–Medium** (see correction) |
| Success confirmed? | **No** — unknown (L1 note couldn't confirm the brute force) |

**Validated read:** the command is `sudo cat /etc/sudoers` — a **read** of the
sudoers file, i.e. reconnaissance / a precursor to sudo abuse. A prior brute-force
attempt from **149.88.25.133** is reported by the L1 analyst.

**Correction (T-01):** the rule is named "Sudoers File **Modification**," and the
AI echoed "modification" throughout — but `cat` only **reads** the file. There is
**no evidence of any modification**. This lowers the independent severity: reading
sudoers is recon, not privilege escalation in itself. The AI's Medium→High bump was
based on a modification that isn't in the evidence.

**Good (T-02):** the AI correctly kept "brute force succeeded" as a *hypothesis*,
not a fact.

**Next steps:** confirm whether the prior brute force from 149.88.25.133 succeeded
(auth logs); check for any *actual* change to `/etc/sudoers` (file-integrity / `4719`
/ auditd `watch`); review what the user did after the read.

---

## Alert 2 — SOC176 · RDP brute force (user: Olivia)

| | |
|---|---|
| Verdict | **True positive (behaviour)** — a brute-force *attempt*; success unproven |
| Original severity | Easy (difficulty) |
| Independent severity | **Low–Medium** |
| Success confirmed? | **No** — only failures seen |

**Validated read:** 5 failed RDP logins for `Olivia` from **18.218.132.237** within
5 minutes; firewall **Allowed** the traffic; target 172.16.17.66. This is the
cleanest, most accurate of the four AI outputs.

**Correction (T-04):** the AI wrote "Original severity Medium, as per difficulty
Easy." Difficulty is **not** severity, and the alert gave no explicit severity —
"Medium" was asserted. Minor, but don't derive one from the other.

**Good (T-05):** no invented threat intel on the IP; success correctly listed as
unknown.

**Next steps:** search for a **4624 (success)** for Olivia from that IP after the
failures (did it eventually work?); check whether RDP should be exposed at all;
consider account lockout / NLA / MFA. Enrich 18.218.132.237 in a TI feed.

---

## Alert 3 — SOC336 · OLE zero-click RCE, CVE-2025-21298 (email to Austin)

| | |
|---|---|
| Verdict | **True positive** — malicious RTF delivered; execution unconfirmed |
| Original severity | Malware · Medium |
| Independent severity | **High** (zero-click RCE, CVSS 9.8) |
| Success confirmed? | **No** — delivery seen, not execution |

**Validated read:** a malicious `mail.rtf` exploiting **CVE-2025-21298** (a real
Windows OLE zero-click RCE, verified on Microsoft MSRC) was emailed from
`projectmanagement@pm.me` (SMTP 84.38.130.118) to `Austin@letsdefend.io`; device
action **Allowed**. Hash `df99…4184`.

**Correction (T-06):** the AI named "device with IP **172.16.17.126**" as the
target — **that IP is not in this alert**; it belongs to the SOC321 (Elenora) alert.
This is cross-alert contamination / a fabricated indicator. SOC336 has no host IP —
the target is the **mailbox** `Austin@letsdefend.io`.

**Note (T-08):** "High confidence, hash matches known patterns" leans on reputation
the model can't verify — reframe as "the alert reports a known pattern; verify the
hash in VirusTotal / a TI feed."

**Next steps:** confirm whether Austin opened/previewed the RTF and whether the host
is patched for CVE-2025-21298; detonate the hash in a sandbox / check VT; search mail
flow for other recipients of the same sender/subject/hash.

---

## Alert 4 — SOC321 · Windows Defender evasion, rundll32 (host: Elenora)

| | |
|---|---|
| Verdict | **True positive (behaviour)** — LOLBin evasion technique executed |
| Original severity | Malware · Medium |
| Independent severity | **Medium–High** |
| Success confirmed? | **No** — and the payload suggests a test (see note) |

**Validated read:** `rundll32 vbscript:"..\mshtml..\RunHTMLApplication " + …Run("calc.exe")`
ran on **Elenora (172.16.17.126)**; **EDR action: Not Detected**. This is the
classic rundll32 + mshtml `RunHTMLApplication` LOLBin technique.

**Correction (T-10):** the AI's recommendations/limitations mention a "brute force
attempt" — **copy-paste boilerplate** from the sudoers triage. There is no brute
force in this alert's core evidence (only a side-mention in the L1 note re
89.187.177.73). Tie the limitations to *this* alert instead.

**Note (T-11):** the payload is **`calc.exe`** — the textbook benign
proof-of-concept. A sharp analyst flags this as "likely a PoC/test, not a weaponized
payload," which changes the urgency. The AI missed it.

**Next steps:** confirm who ran it (attacker vs admin/red-team — the L1 note is
unsure); check the parent process and what else ran; given EDR "Not Detected,"
review the detection gap.


---

## How the AI did on triage
Across the four real alerts (12 checked claims): the model's **biggest strength was
restraint** — it never declared an attack "successful," correctly keeping that as
unknown on every alert, and it avoided inventing threat-intel reputation. Its
failures were **specificity errors**: a read mislabelled as a modification (SOC324),
an IP pulled from the wrong alert (SOC336), boilerplate bleeding between alerts
(SOC321), and one fully hallucinated output. Verdict: **usable as a first-pass
triage draft, not as the final word** — every specific claim needs a human check,
which is exactly the week's thesis.
