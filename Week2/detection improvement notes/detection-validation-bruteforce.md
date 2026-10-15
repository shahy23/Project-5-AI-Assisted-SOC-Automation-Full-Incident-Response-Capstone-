# Validation — Detection Suggestions (Mistral output)

**Scenario:** detection suggestions generated from the brute-force Windows logs
(`attack-events-curated.txt`). **Model:** mistral (local). Every claim checked
against the evidence and against MITRE ATT&CK (attack.mitre.org). This was the
**weakest** output of the week — many fabrications.

## What the model wrote vs. what is correct

| What the model wrote | Verdict | What is correct |
|---|---|---|
| Detect the brute force on Administrator (A-009) | ✅ Correct | The one genuinely useful detection here |
| Detect SYSTEM group-enumeration, the A-031 service, and SYSTEM logons | ❌ Noise | All benign (routine SYSTEM activity + a legitimate Defender driver) — these would fire as false positives |
| "Directory Services Reconnaissance = **T1089**" | ❌ Wrong ID | T1089 = "Disabling Security Tools" (deprecated). Local group enum = **T1069.001** |
| "Persistence – Service = **T1055**" | ❌ Wrong ID | T1055 = Process Injection. Windows service persistence = **T1543.003** |
| "Account Maintenance = **T1136**" | ❌ Wrong | T1136 = Create Account, and there is **no account creation** in the logs at all |
| "Brute Force = **T1110**" | ✅ Correct | Right (more precisely **T1110.001** Password Guessing) |
| Sigma rule for enum: lists ~18 EventIDs (4650–4667), SubjectLogonId==4294967295 | ❌ Fabricated | None of those IDs are in the logs; the real enum events are 4798/4799; the LogonId value is invented |
| Sigma rule for service: uses **EventID 4688** + TargetObjectName/OperationName | ❌ Wrong | Service install = **7045** (not 4688); those fields don't exist for it |
| Sigma rule for brute force: 4625 + Administrator + "NTLM_SSSP"/"NTLM_SSP" | ⚠️ Half-right | Core (4625 + Administrator) is right, but "NTLM_SSSP" is invented and the rule has **no count threshold** — a brute-force rule needs ≥N failures in M minutes |
| (format) skipped the plain-English logic, tuning, and **IOC** sections; no "(verify)" on any ID | ❌ Ignored format | The prompt required 6 sections incl. IOCs and "(verify)" on uncertain IDs; the model produced none of those |

## The corrected detection (what should have been produced)
**Behaviour:** one account (Administrator) with 100 failed logons (4625) in 3 s — A-009.
**MITRE:** T1110.001 (Brute Force: Password Guessing).
**Rule (Sigma, correct shape):**
```yaml
title: Rapid Failed Logons - Single Account
logsource: { product: windows, service: security }
detection:
  sel: { EventID: 4625 }
  timeframe: 5m
  condition: sel | count() by TargetUserName >= 10
tags: [attack.credential_access, attack.t1110.001]
# Tuning: exclude known service accounts that fail for benign reasons.
```

## Summary
The model found the right behaviour (the brute force) but almost everything around
it was wrong: **3 of 4 MITRE IDs were incorrect**, all four Sigma rules were
malformed or based on fabricated fields/EventIDs, three of the four "behaviours"
targeted benign activity, and it ignored the required format (no IOCs, no
"(verify)"). **Conclusion: the AI's detection output is not usable as-is — it needs
heavy human correction.** This is the clearest demonstration this week of why
every AI claim must be validated.
