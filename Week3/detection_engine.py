#!/usr/bin/env python3
"""
Lightweight Detection Engine — Project 5, Week 3.

Reads the normalized events produced by the collector (normalized_events.jsonl,
ECS format) and applies simple correlation rules to produce alerts.json.

alerts.json uses a Wazuh-style shape, so the rest of the pipeline (the script
that sends an alert + its logs to the local AI) does not care whether the alert
came from this engine or from Wazuh — both write the same file.

Run:  python3 detection_engine.py
      python3 detection_engine.py <input.jsonl> <output.json>
"""

import json
import sys
import hashlib
from datetime import datetime, timezone
from collections import defaultdict

# ------------------------- configuration (tune me) -------------------------
IN_FILE = "normalized_events.jsonl"
OUT_FILE = "alerts.json"

BRUTE_FORCE_THRESHOLD = 5        # how many failures...
BRUTE_FORCE_WINDOW_SEC = 300     # ...within this many seconds = brute force

# Windows Security event IDs we treat as notable
WIN_ACCOUNT_CREATED = {"4720"}
WIN_PRIV_GROUP_ADD = {"4732", "4728", "4756"}   # added to a privileged group

# malware: processes that are commonly abused (LOLBins) or an EDR "malicious" verdict
LOLBINS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "powershell.exe", "wmic.exe"}
# data exfiltration: outbound volume (bytes) above this = possible exfiltration
EXFIL_BYTES_THRESHOLD = 100 * 1024 * 1024       # 100 MB
# ---------------------------------------------------------------------------


def parse_ts(ts):
    """ISO timestamp (…Z) -> aware datetime, or None."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None


def g(event, *path, default=None):
    """Safe nested get: g(e, 'event', 'outcome')."""
    cur = event
    for key in path:
        if isinstance(cur, dict):
            cur = cur.get(key)
        else:
            return default
    return cur if cur is not None else default


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


def make_alert(rule_id, level, description, mitre_ids, mitre_names,
               host, data, evidence_ids, first_seen, last_seen):
    alert_id = hashlib.sha256(
        f"{rule_id}|{host}|{first_seen}|{json.dumps(data, sort_keys=True)}".encode()
    ).hexdigest()[:16]
    return {
        "alert_id": alert_id,
        "timestamp": last_seen,
        "rule": {
            "id": rule_id,
            "level": level,                       # Wazuh-style 0-15
            "description": description,
            "mitre": {"id": mitre_ids, "technique": mitre_names},
        },
        "agent": {"name": host},
        "data": data,
        "evidence_event_ids": evidence_ids,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "status": "new",
        "note": "AI/analyst must validate; destructive actions require analyst approval",
    }


# ------------------------------ detection rules ------------------------------

def rule_brute_force(events):
    """R1: >= THRESHOLD failed auth events for one user within the time window.
       Also checks for a later SUCCESS for the same user (possible compromise)."""
    alerts = []

    failures = [
        e for e in events
        if g(e, "event", "outcome") == "failure"
        and "authentication" in (g(e, "event", "category", default=[]) or [])
    ]
    successes = [
        e for e in events
        if g(e, "event", "outcome") == "success"
        and "authentication" in (g(e, "event", "category", default=[]) or [])
    ]

    by_user = defaultdict(list)
    for e in failures:
        by_user[g(e, "user", "name", default="unknown")].append(e)

    for user, evs in by_user.items():
        evs = [e for e in evs if parse_ts(e.get("@timestamp"))]
        evs.sort(key=lambda e: parse_ts(e.get("@timestamp")))

        # two-pointer: largest burst inside the window
        left = 0
        best = []
        for right in range(len(evs)):
            t_right = parse_ts(evs[right]["@timestamp"])
            while (t_right - parse_ts(evs[left]["@timestamp"])).total_seconds() > BRUTE_FORCE_WINDOW_SEC:
                left += 1
            window = evs[left:right + 1]
            if len(window) > len(best):
                best = window

        if len(best) < BRUTE_FORCE_THRESHOLD:
            continue

        first_seen = best[0]["@timestamp"]
        last_seen = best[-1]["@timestamp"]
        src_ips = sorted({g(x, "source", "ip", default="?") for x in best})
        host = g(best[0], "host", "name", default="unknown")

        # did a success for the same user happen at/after the burst started?
        t_first = parse_ts(first_seen)
        later_success = any(
            g(s, "user", "name", default="unknown") == user
            and parse_ts(s.get("@timestamp"))
            and parse_ts(s.get("@timestamp")) >= t_first
            for s in successes
        )

        level = 12 if later_success else 10
        desc = f"Possible brute force: {len(best)} failed logons for '{user}'"
        if later_success:
            desc += " followed by a SUCCESS (possible compromise — verify)"

        alerts.append(make_alert(
            "100001", level, desc,
            ["T1110.001"], ["Brute Force: Password Guessing"],
            host,
            {
                "target_user": user,
                "source_ips": src_ips,
                "failed_count": len(best),
                "window_seconds": BRUTE_FORCE_WINDOW_SEC,
                "possible_success": later_success,
            },
            [g(x, "event", "id") for x in best],
            first_seen, last_seen,
        ))
    return alerts


def rule_account_created(events):
    """R2: a new local account was created (Windows 4720 / Linux useradd)."""
    alerts = []
    for e in events:
        code = str(g(e, "event", "code", default=""))
        msg = (g(e, "message", default="") or "").lower()
        dataset = (g(e, "event", "dataset", default="") or "").lower()
        is_win = code in WIN_ACCOUNT_CREATED
        is_lin = ("useradd" in dataset) or ("new user" in msg)
        if not (is_win or is_lin):
            continue
        host = g(e, "host", "name", default="unknown")
        alerts.append(make_alert(
            "100002", 8, "Local account created",
            ["T1136.001"], ["Create Account: Local Account"],
            host,
            {"user": g(e, "user", "name", default="unknown"),
             "source_ip": g(e, "source", "ip", default="?")},
            [g(e, "event", "id")],
            e.get("@timestamp"), e.get("@timestamp"),
        ))
    return alerts


def rule_privilege_change(events):
    """R3: account added to a privileged group / privilege escalation."""
    alerts = []
    for e in events:
        code = str(g(e, "event", "code", default=""))
        msg = (g(e, "message", default="") or "").lower()
        action = (g(e, "event", "action", default="") or "").lower()
        is_win = code in WIN_PRIV_GROUP_ADD
        is_lin = ("to group 'sudo'" in msg or "to group 'wheel'" in msg
                  or action == "privilege_elevation")
        if not (is_win or is_lin):
            continue
        host = g(e, "host", "name", default="unknown")
        alerts.append(make_alert(
            "100003", 9, "Privileged group change / privilege escalation",
            ["T1098.007", "T1548.003"],
            ["Additional Local or Domain Groups", "Sudo and Sudo Caching"],
            host,
            {"user": g(e, "user", "name", default="unknown"),
             "detail": g(e, "message", default="")},
            [g(e, "event", "id")],
            e.get("@timestamp"), e.get("@timestamp"),
        ))
    return alerts


def rule_malware(events):
    """R4: suspicious process / malware — a known LOLBin OR an EDR 'malicious' verdict."""
    alerts = []
    for e in events:
        cats = g(e, "event", "category", default=[]) or []
        if "process" not in cats:
            continue
        proc = (g(e, "process", "name", default="") or "")
        reputation = (g(e, "threat", "reputation", default="") or "").lower()
        if not (reputation == "malicious" or proc.lower() in LOLBINS):
            continue
        host = g(e, "host", "name", default="unknown")
        alerts.append(make_alert(
            "100004", 10, f"Suspicious process / malware: {proc or 'unknown'}",
            ["T1204.002", "T1218.011"],
            ["User Execution: Malicious File", "System Binary Proxy Execution: Rundll32"],
            host,
            {"user": g(e, "user", "name", default="unknown"),
             "source_ip": g(e, "source", "ip", default="?"),
             "process": proc,
             "parent": g(e, "process", "parent_name", default="?")},
            [g(e, "event", "id")],
            e.get("@timestamp"), e.get("@timestamp"),
        ))
    return alerts


def rule_phishing(events):
    """R5: phishing email flagged malicious (sender / URL / attachment reputation)."""
    alerts = []
    for e in events:
        cats = g(e, "event", "category", default=[]) or []
        if "email" not in cats:
            continue
        if (g(e, "threat", "reputation", default="") or "").lower() != "malicious":
            continue
        host = g(e, "host", "name", default="unknown")
        alerts.append(make_alert(
            "100005", 8, "Phishing email delivered (flagged malicious)",
            ["T1566.001", "T1566.002"],
            ["Phishing: Spearphishing Attachment", "Phishing: Spearphishing Link"],
            host,
            {"user": g(e, "user", "name", default="unknown"),
             "sender": g(e, "email", "sender", default="?"),
             "url": g(e, "email", "url", default="?")},
            [g(e, "event", "id")],
            e.get("@timestamp"), e.get("@timestamp"),
        ))
    return alerts


def rule_exfil(events):
    """R6: large outbound transfer -> possible data exfiltration."""
    alerts = []
    for e in events:
        cats = g(e, "event", "category", default=[]) or []
        if "network" not in cats:
            continue
        try:
            bytes_out = int(g(e, "network", "bytes_out", default=0) or 0)
        except (ValueError, TypeError):
            bytes_out = 0
        if bytes_out < EXFIL_BYTES_THRESHOLD:
            continue
        host = g(e, "host", "name", default="unknown")
        dest = g(e, "destination", "domain", default=None) or g(e, "destination", "ip", default="?")
        alerts.append(make_alert(
            "100006", 11, f"Possible data exfiltration: {bytes_out // (1024 * 1024)} MB outbound",
            ["T1048", "T1567"],
            ["Exfiltration Over Alternative Protocol", "Exfiltration Over Web Service"],
            host,
            {"user": g(e, "user", "name", default="unknown"),
             "source_ip": g(e, "source", "ip", default="?"),
             "destination": dest,
             "bytes_out": bytes_out},
            [g(e, "event", "id")],
            e.get("@timestamp"), e.get("@timestamp"),
        ))
    return alerts


RULES = [rule_brute_force, rule_account_created, rule_privilege_change,
         rule_malware, rule_phishing, rule_exfil]


def main():
    in_file = sys.argv[1] if len(sys.argv) > 1 else IN_FILE
    out_file = sys.argv[2] if len(sys.argv) > 2 else OUT_FILE

    try:
        events = load_events(in_file)
    except FileNotFoundError:
        print(f"ERROR: input file '{in_file}' not found. Run the collector first.")
        sys.exit(1)

    print(f"Loaded {len(events)} normalized events from {in_file}")

    all_alerts = []
    for rule in RULES:
        all_alerts.extend(rule(events))

    # write one JSON alert per line (same shape Wazuh's alerts.json uses)
    with open(out_file, "w", encoding="utf-8") as f:
        for a in all_alerts:
            f.write(json.dumps(a) + "\n")

    print(f"Generated {len(all_alerts)} alert(s) -> {out_file}")
    for a in all_alerts:
        print(f"  [{a['rule']['id']}] level {a['rule']['level']:>2} | {a['rule']['description']}")


if __name__ == "__main__":
    main()
