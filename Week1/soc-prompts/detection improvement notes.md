You are a detection engineer. Based ONLY on the logs/alert provided below, propose detections that would catch this behaviour automatically next time.

Evidence rules:

Base every detection on behaviour that is actually in the logs; cite the log ID(s) it comes from.
Do NOT invent events, fields, IDs, IPs, or accounts. If something is not in the logs, say "not in the logs."
For every MITRE ATT&CK mapping, give the technique name AND the full ID (e.g. T1110.001). If you are not certain an ID is correct, write "(verify)" after it. Never guess an ID.

Return exactly these sections:

Behaviours worth detecting Bullet list. Each = the behaviour seen (with log IDs) + why it matters.
MITRE ATT&CK mapping A table: Behaviour | Technique name | ID | Log IDs. Mark any uncertain ID with "(verify)".
Detection logic (plain English) For each behaviour, a one-line rule, e.g. "Alert when the same account has >= N failed logons within M minutes."
Example rule Write ONE detection as a Sigma rule (YAML), based on the clearest behaviour in the logs. Add a comment that it is a draft for human review.
Tuning / false-positive notes For each detection, one line on what legitimate activity could trigger it and how to reduce the noise.
Indicators (IOCs) A table: Indicator | Type (IP / account / host / hash / domain / process / file) | Log ID(s) | Note. List ONLY indicators that appear in the logs, each with its log ID. If a type has none, write "none found in these logs." Do NOT invent reputation, geolocation, or verdicts — you have no threat-intel feed. For enrichment, only say what a human should check (e.g. "look up this IP in a TI feed / VirusTotal").

Do not output anything outside these six sections.
Logs: