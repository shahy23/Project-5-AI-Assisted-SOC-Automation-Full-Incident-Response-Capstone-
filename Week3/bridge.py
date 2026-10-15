#!/usr/bin/env python3
"""
Bridge script — Project 5, Week 3 (AI Integration).

Flow:
  alerts.json  --(pick alert)-->  gather related logs from normalized_events.jsonl
               --(build prompt)-->  send to local AI (Mistral via Ollama)
               --(save)-->  ai_reports/report_<alert_id>.md   [AI-drafted, analyst validates]

The AI is an ASSISTANT: it drafts the analysis. The analyst validates it, and any
destructive action (block IP / disable account / isolate host) needs analyst approval.

Run:
  python3 bridge.py                 # process every alert in alerts.json
  python3 bridge.py --alert-id XXXX # process one alert
  python3 bridge.py --dry-run       # build + print the prompt, do NOT call the AI
"""

import json
import os
import sys
import argparse
import urllib.request
import urllib.error

ALERTS_FILE = "alerts.json"
EVENTS_FILE = "normalized_events.jsonl"
OUT_DIR = "ai_reports"

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "mistral"
NUM_CTX = 8192

# How much context around the alert to collect
RELATED_MAX = 60   # cap the logs we send so we stay inside the context window


PROMPT_TEMPLATE = """You are a SOC analyst assistant helping triage ONE alert. Use ONLY the alert and logs below.

Evidence rules:
- Cite the evidence (log line) for every factual statement.
- Do NOT invent events, IPs, accounts, timestamps, or counts. If something is not in the data, write "not in the data".
- Separate CONFIRMED FACTS from HYPOTHESES (mark each hypothesis "Inference:" with confidence low/medium/high).
- Do NOT claim the attack SUCCEEDED unless a successful event proves it. If unknown, say "success unconfirmed".
- Any destructive action (block IP, disable account, isolate host) must be marked "[requires analyst approval]".

Return these sections:
1. Alert summary
2. What the logs show (confirmed facts, each with evidence)
3. Interpretation (hypotheses, with confidence)
4. Did it succeed? (yes/no/unconfirmed, with evidence)
5. IOCs (only those present in the data)
6. Recommended response actions (mark destructive ones [requires analyst approval])
7. What extra evidence is still needed

=== ALERT ===
{alert_block}

=== RELATED LOGS ({n_logs}) ===
{logs_block}
"""


def load_alerts(path):
    alerts = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return alerts


def load_events(path):
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    events.sort(key=lambda e: e.get("@timestamp", ""))
    return events


def gather_related(alert, events):
    """Collect the logs tied to this alert: the evidence events, plus anything
       for the same user or the same source IP (that is the 'related data'
       the analyst would pull for this alert type)."""
    ids = set(alert.get("evidence_event_ids", []) or [])
    data = alert.get("data", {})
    user = data.get("target_user") or data.get("user")
    src_ips = set(data.get("source_ips", []) or [])
    if data.get("source_ip"):
        src_ips.add(data["source_ip"])

    related = []
    for e in events:
        eid = e.get("event", {}).get("id")
        euser = e.get("user", {}).get("name")
        esrc = e.get("source", {}).get("ip")
        if eid in ids or (user and euser == user) or (esrc and esrc in src_ips):
            related.append(e)
    return related[:RELATED_MAX]


def fmt_event(e):
    ev = e.get("event", {})
    tag = ev.get("code") or ev.get("action") or ev.get("dataset") or "?"
    return (
        f"{e.get('@timestamp', '?')} | {tag} | "
        f"user={e.get('user', {}).get('name', '-')} | "
        f"src={e.get('source', {}).get('ip', '-')} | "
        f"outcome={ev.get('outcome', '-')} | "
        f"{(e.get('message', '') or '')[:80]}"
    )


def build_prompt(alert, related):
    alert_block = json.dumps({
        "rule": alert.get("rule"),
        "agent": alert.get("agent"),
        "data": alert.get("data"),
        "first_seen": alert.get("first_seen"),
        "last_seen": alert.get("last_seen"),
    }, indent=2)
    logs_block = "\n".join(fmt_event(e) for e in related) or "(no related logs found)"
    return PROMPT_TEMPLATE.format(
        alert_block=alert_block, n_logs=len(related), logs_block=logs_block
    )


def ask_ollama(prompt):
    payload = json.dumps({
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"num_ctx": NUM_CTX},
    }).encode()
    req = urllib.request.Request(
        OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=600) as resp:
            out = json.loads(resp.read().decode())
        return out.get("response", "").strip()
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Could not reach Ollama at {OLLAMA_URL}. Is it running? "
            f"Start it with 'ollama serve' and pull the model with 'ollama pull {MODEL}'. "
            f"({e})"
        )


def save_report(alert, prompt, ai_text):
    os.makedirs(OUT_DIR, exist_ok=True)
    aid = alert.get("alert_id", "unknown")
    path = os.path.join(OUT_DIR, f"report_{aid}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# AI Report — alert {aid}\n\n")
        f.write("> **AI-drafted, analyst-validated.** The analyst must verify every "
                "claim; destructive actions require analyst approval.\n\n")
        f.write(f"**Rule:** {alert.get('rule', {}).get('description')} "
                f"(level {alert.get('rule', {}).get('level')})\n\n")
        f.write("## AI analysis (Mistral)\n\n")
        f.write(ai_text + "\n\n")
        f.write("---\n## Prompt + evidence sent to the model\n\n```\n")
        f.write(prompt + "\n```\n")
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", default=ALERTS_FILE)
    ap.add_argument("--events", default=EVENTS_FILE)
    ap.add_argument("--alert-id", default=None, help="process only this alert_id")
    ap.add_argument("--dry-run", action="store_true",
                    help="build and print the prompt, do NOT call the AI")
    args = ap.parse_args()

    if not os.path.exists(args.alerts):
        print(f"ERROR: '{args.alerts}' not found. Run detection_engine.py first.")
        sys.exit(1)

    alerts = load_alerts(args.alerts)
    events = load_events(args.events) if os.path.exists(args.events) else []
    if args.alert_id:
        alerts = [a for a in alerts if a.get("alert_id") == args.alert_id]
    if not alerts:
        print("No alerts to process.")
        return

    print(f"Processing {len(alerts)} alert(s) with model '{MODEL}'"
          f"{' (dry run)' if args.dry_run else ''}\n")

    for a in alerts:
        related = gather_related(a, events)
        prompt = build_prompt(a, related)
        print(f"[{a.get('alert_id')}] {a.get('rule', {}).get('description')} "
              f"| {len(related)} related log(s)")

        if args.dry_run:
            print("-" * 60)
            print(prompt)
            print("-" * 60 + "\n")
            continue

        try:
            ai_text = ask_ollama(prompt)
        except RuntimeError as e:
            print(f"  !! {e}")
            sys.exit(2)
        path = save_report(a, prompt, ai_text)
        print(f"  -> saved {path}")


if __name__ == "__main__":
    main()
