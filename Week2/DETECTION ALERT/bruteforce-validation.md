# Validation — Brute Force Alert (Mistral output)

**Scenario:** self-generated alert from Windows logs (`attack-events-curated.txt`).
**Model:** mistral (local, Ollama). **Method:** every claim checked against the log evidence (ground truth).

## What the model wrote vs. what is correct

| What the model wrote | Verdict | What is correct |
|---|---|---|
| A-009: 100 failed logons for Administrator in 3 s = brute force | ✅ Correct | Accurate — this is a genuine brute force (4625 ×100, 07:37:03→07:37:06, src 192.168.1.13) |
| Did not claim it succeeded; flagged the source as internal / possible misconfig | ✅ Correct | Right call — there is **no 4624 success for Administrator**, so success is unconfirmed |
| "A-020 is a duplicate of A-019" | ❌ Wrong | Two different events (09:42:**42** and 09:42:**56**) — not a duplicate |
| "A-023, A-028, A-032 = PowerShell activity / post-exploitation" | ❌ Wrong (fabricated) | A-023/A-032 are **group enumeration (4798)**, A-028 is **special privileges (4672)** — none are PowerShell. The only PowerShell event is A-033, a routine engine start |
| Replied twice and "self-corrected" ("I missed some events") | ⚠️ Correction made it worse | The redo should have *removed* the error — instead it *added* the false PowerShell claim |
| "A-031 service install may be part of the attack" | ⚠️ Half-right | A-031 = **MpKslDrv.sys**, a legitimate Windows Defender driver — benign, not part of the attack |

## Summary
The model got the core right — it identified the brute force and correctly **did not claim
it succeeded**. Its errors were specificity failures: it invented a "duplicate," mislabelled
three enumeration/privilege events as "PowerShell," and its self-correction *added* an error
instead of fixing one. **Conclusion: usable as a first-pass draft, but every specific claim
needs human validation.**
