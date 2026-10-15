import socket
import re
import json
import hashlib
from datetime import datetime, timezone

UDP_IP = "0.0.0.0"
UDP_PORT = 514
PARSER_VERSION = "1.3.0"

NORMALIZED_FILE = "normalized_events.jsonl"
RAW_LOGS_FILE = "raw_logs.json"
QUARANTINE_FILE = "quarantine.jsonl"


CISCO_PATTERN = re.compile(
    r"<(?P<pri>\d+)>(?P<seq>\d+): (?:(?P<hostname>\S+): )?\*?(?P<timestamp>[A-Za-z]+ \d+ \d+:\d+:\d+(?:\.\d+)?): "
    r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d+)-(?P<mnemonic>[A-Z0-9_]+): (?P<message>.*)"
)


# NXLog Windows logs are expected as JSON
LOGIN_FAILED_DETAILS = re.compile(
    r"\[user: (?P<user>[^\]]+)\] \[Source: (?P<source_ip>[^\]]+)\]"
)


CISCO_EVENT_MAP = {
    "LINEPROTO-UPDOWN": {
        "category": ["network"],
        "type": ["info"]
    },
    "SEC_LOGIN-LOGIN_FAILED": {
        "category": ["authentication"],
        "type": ["denied"]
    },
}


WINDOWS_EVENT_MAP = {
    "4624": {
        "category": ["authentication"],
        "type": ["info"]
    },
    "4625": {
        "category": ["authentication"],
        "type": ["denied"]
    },
    "4634": {
        "category": ["authentication"],
        "type": ["info"]
    },
    "4720": {
        "category": ["iam"],
        "type": ["creation"]
    },
    "4722": {
        "category": ["iam"],
        "type": ["change"]
    }
}


LINUX_EVENT_MAP = {
    "sudo": {
        "category": ["process", "privilege"],
        "type": ["info"]
    },
    "sshd": {
        "category": ["authentication"],
        "type": ["info"]
    },
    "su": {
        "category": ["authentication", "user"],
        "type": ["change"]
    }
}


def map_severity(sev_input):
    mapping = {
        0: ("emergency", 0),
        1: ("alert", 1),
        2: ("critical", 2),
        3: ("error", 3),
        4: ("warning", 4),
        5: ("notice", 5),
        6: ("info", 6),
        7: ("debug", 7)
    }


    try:
        sev_int = int(sev_input)
        return mapping.get(sev_int, ("info", 6))
    except (ValueError, TypeError):
        pass

    # FIX: recognise NXLog audit strings so AUDIT_FAILURE is not treated as "info"
    sl = str(sev_input).lower()
    if sl in ["error", "crit", "critical", "failure", "audit_failure"]:
        return ("error", 3)
    elif sl in ["warn", "warning"]:
        return ("warning", 4)
    elif sl in ["notice"]:
        return ("notice", 5)
    elif sl in ["info", "information", "audit_success"]:
        return ("info", 6)

    return ("info", 6)

#     severity 5, 6, 7 → Normal     → label 0
# severity 2, 3, 4 → Suspicious → label 1
# severity 0, 1    → Malicious  → label 2
def get_ai_label(severity):
    if severity in [5, 6, 7]:
        return 0
    elif severity in [2, 3, 4]:
        return 1
    else:
        return 2



def normalize_cisco_timestamp(raw_ts):
    try:
        current_year = datetime.now().year
        dt = datetime.strptime(
            f"{current_year} {raw_ts}",
            "%Y %b %d %H:%M:%S.%f"
        )
        dt = dt.replace(tzinfo=timezone.utc)

        return dt.strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"

    except Exception:
        return datetime.now(
            timezone.utc
        ).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"


def parse_gns3_event(raw_message, source_ip, iso_now):
    match = CISCO_PATTERN.match(raw_message)

    if not match:
        return None

    fields = match.groupdict()
    event_key = f"{fields['facility']}-{fields['mnemonic']}"

    event_info = CISCO_EVENT_MAP.get(
        event_key,
        {
            "category": ["network"],
            "type": ["info"]
        }
    )

    raw_hash = hashlib.sha256(
        raw_message.encode()
    ).hexdigest()[:16]

    event_time = normalize_cisco_timestamp(
        fields["timestamp"]
    )

    log_lvl, sev_num = map_severity(
        fields["severity"]
    )
    ai_label = get_ai_label(sev_num)

    normalized_event = {
        "@timestamp": event_time,
        "ecs": {
            "version": "9.3.0"
        },
        "log": {
            "level": log_lvl
        },
        "event": {
            "id": raw_hash,
            "kind": "event",
            "category": event_info["category"],
            "type": event_info["type"],
            "sequence": int(fields["seq"]),
            "severity": sev_num,
            "created": event_time,
            "ingested": iso_now,
            "dataset": "gns3.syslog",
            "module": "python-udp-collector",
            "original": raw_message
        },
        "host": {
            "name": fields.get("hostname") or "unknown-cisco-device",
            "ip": source_ip
        },
        "source": {
            "ip": source_ip
        },
        "ai": {
            "label": ai_label
        },
        "message": fields["message"],
        "parser": {
            "version": PARSER_VERSION,
            "name": "cisco_ios"
        }
    }

    if event_key == "SEC_LOGIN-LOGIN_FAILED":
        details = LOGIN_FAILED_DETAILS.search(
            fields["message"]
        )

        if details:
            normalized_event["user"] = {
                "name": details.group("user")
            }

            normalized_event["source"]["ip"] = (
                details.group("source_ip")
            )

    return normalized_event


# Windows NXLog JSON parser
def parse_windows_event(raw_message, source_ip, iso_now):
    try:
        data = json.loads(raw_message)
    except json.JSONDecodeError:
        return None

    timestamp_str = data.get("EventTime")
    computer = data.get("Hostname", "unknown-host")
    event_id = str(data.get("EventID", 0))

    user = data.get(
        "AccountName",
        data.get("UserID", "SYSTEM")
    )

    message = data.get("Message", "")

    level_raw = str(
        data.get("Severity", "info")
    ).lower()

    log_lvl, sev_num = map_severity(level_raw)
    ai_label = get_ai_label(sev_num)

    event_info = WINDOWS_EVENT_MAP.get(
        event_id,
        {
            "category": ["system"],
            "type": ["info"]
        }
    )

    # If the EventID is not specifically mapped,
    # use NXLog Opcode to determine the event type.
    if event_id not in WINDOWS_EVENT_MAP:
        opcode = str(
            data.get("Opcode", "Info")
        ).lower()

        opcode_type_map = {
            "start": ["start"],
            "stop": ["end"],
            "info": ["info"]
        }

        event_type = opcode_type_map.get(
            opcode,
            ["info"]
        )

        event_info = {
            "category": ["system"],
            "type": event_type
        }

    if timestamp_str:
        try:
            timestamp_clean = (
                timestamp_str
                .strip()
                .replace("Z", "")
            )

            if "." in timestamp_clean:
                dt = datetime.fromisoformat(
                    timestamp_clean
                )
            else:
                dt = datetime.strptime(
                    timestamp_clean,
                    "%Y-%m-%dT%H:%M:%S"
                )

            dt = dt.replace(
                tzinfo=timezone.utc
            )

            iso_ts = dt.strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            )[:-3] + "Z"

        except (ValueError, TypeError):
            iso_ts = iso_now
    else:
        iso_ts = iso_now

    raw_hash = hashlib.sha256(
        raw_message.encode()
    ).hexdigest()[:16]

    normalized_event = {
        "@timestamp": iso_ts,
        "ecs": {
            "version": "9.3.0"
        },
        "log": {
            "level": log_lvl
        },
        "event": {
            "id": raw_hash,
            "kind": "event",
            "category": event_info["category"],
            "type": event_info["type"],
            "code": event_id,
            "severity": sev_num,
            "created": iso_ts,
            "ingested": iso_now,
            "dataset": data.get(
                "Channel",
                "windows.system"
            ),
            "module": "nxlog-udp-collector",
            "original": raw_message
        },
        "host": {
            "name": computer,
            "ip": source_ip,
            "os": {
                "family": "windows"
            }
        },
        "source": {
            "ip": source_ip
        },
        "ai": {
        "label": ai_label
     },
        "message": message,
        "parser": {
            "version": PARSER_VERSION,
            "name": "nxlog_json"
        }
    }

    if event_id == "4625":
        normalized_event["event"]["action"] = "logon-failed"
        normalized_event["event"]["outcome"] = "failure"

    elif event_id == "4624":
        normalized_event["event"]["action"] = "logon-success"
        normalized_event["event"]["outcome"] = "success"

    if user and user != "N/A":
        normalized_event["user"] = {
            "name": user
        }

    # FIX: capture the real attacker source IP from the event data (not the syslog sender)
    ip_field = data.get("IpAddress")
    if ip_field and ip_field not in ("-", "::1", "127.0.0.1", "::", "0.0.0.0"):
        normalized_event["source"]["ip"] = ip_field

    # FIX: security-relevant Windows events must not be labelled "normal" (0)
    SUSPICIOUS_WIN_IDS = {
        "4625", "4740", "4720", "4722", "4723", "4724",
        "4728", "4732", "4756", "1102", "4719"
    }
    if event_id in SUSPICIOUS_WIN_IDS:
        normalized_event["ai"]["label"] = max(
            normalized_event["ai"]["label"], 1
        )

    return normalized_event


def parse_linux_event(raw_message, source_ip, iso_now):
    linux_pattern = (
        r"<(?P<pri>\d+)>"
        r"(?P<timestamp>[A-Za-z]{3}\s+\d+\s+[\d:]+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?:(?P<tag>\S+):\s+)?"
        r"(?P<process>[a-zA-Z0-9_\-\/\.]+)"
        r"(?:\[(?P<pid>\d+)\])?:\s*"
        r"(?P<msg>.*)"
    )

    match = re.search(
        linux_pattern,
        raw_message
    )

    if not match:
        return None

    fields = match.groupdict()

    process_name = fields["process"]
    msg_body = fields["msg"]
    hostname = fields["hostname"]

    if "sudo" in msg_body and process_name != "sudo":
        process_name = "sudo"

    event_info = LINUX_EVENT_MAP.get(
        process_name,
        {
            "category": ["system"],
            "type": ["info"]
        }
    )

    raw_hash = hashlib.sha256(
        raw_message.encode()
    ).hexdigest()[:16]

    try:
        current_year = datetime.now().year

        dt = datetime.strptime(
            f"{current_year} {fields['timestamp']}",
            "%Y %b %d %H:%M:%S"
        )

        dt = dt.replace(
            tzinfo=timezone.utc
        )

        iso_ts = dt.strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"

    except Exception:
        iso_ts = iso_now

    log_lvl, sev_num = map_severity(
        int(fields["pri"]) % 8
        if fields.get("pri")
        else "info"
    )
    ai_label = get_ai_label(sev_num)

    ecs_event = {
        "@timestamp": iso_ts,
        "ecs": {
            "version": "9.3.0"
        },
        "log": {
            "level": log_lvl
        },
        "event": {
            "id": raw_hash,
            "kind": "event",
            "category": event_info["category"],
            "type": event_info["type"],
            "severity": sev_num,
            "created": iso_ts,
            "ingested": iso_now,
            "dataset": f"linux.{process_name.lower()}",
            "module": "rsyslog",
            "original": raw_message
        },
        "host": {
            "name": hostname,
            "ip": source_ip,
            "os": {
                "family": "linux"
            }
        },
        "source": {
            "ip": source_ip
        },
        "process": {
            "name": process_name
        },
        "ai": {
            "label": ai_label
        },
        "message": msg_body,
        "parser": {
            "version": PARSER_VERSION,
            "name": "linux_rsyslog"
        }
    }

    # FIX: extract the attacker source IP and user from SSH auth messages,
    # and label auth failures as suspicious (not normal)
    low_msg = msg_body.lower()
    ip_match = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", msg_body)
    if ip_match:
        ecs_event["source"]["ip"] = ip_match.group(1)
    user_match = re.search(r"for (?:invalid user )?(\S+) from", msg_body)
    if user_match:
        ecs_event["user"] = {"name": user_match.group(1)}
    if ("failed password" in low_msg or "invalid user" in low_msg
            or "authentication failure" in low_msg):
        ecs_event["event"]["action"] = "logon-failed"
        ecs_event["event"]["outcome"] = "failure"
        ecs_event["ai"]["label"] = max(ecs_event["ai"]["label"], 1)
    elif "accepted password" in low_msg or "session opened" in low_msg:
        ecs_event["event"]["action"] = "logon-success"
        ecs_event["event"]["outcome"] = "success"

    if "sudo" in process_name or "COMMAND=" in msg_body:
        sudo_pattern = (
            r"(\S+)\s+:.*?"
            r"USER=(\S+)\s+;\s+"
            r"COMMAND=(.+)$"
        )

        sudo_match = re.search(
            sudo_pattern,
            msg_body
        )

        if sudo_match:
            user, target_user, command = (
                sudo_match.groups()
            )

            ecs_event["user"] = {
                "name": user,
                "target": {
                    "name": target_user
                }
            }

            ecs_event["process"]["command_line"] = (
                command.strip()
            )

            ecs_event["event"]["category"] = [
                "process",
                "privilege"
            ]

            ecs_event["event"]["action"] = (
                "privilege_elevation"
            )

            ecs_event["event"]["outcome"] = (
                "success"
            )

    return ecs_event


def save_event(event_dict, filepath):
    with open(
        filepath,
        "a",
        encoding="utf-8"
    ) as f:
        f.write(
            json.dumps(event_dict) + "\n"
        )


if __name__ == "__main__":
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.bind(
        (UDP_IP, UDP_PORT)
    )

    print(
        f"Listening for Syslog messages "
        f"on UDP port {UDP_PORT}..."
    )

    while True:
        data, addr = sock.recvfrom(65535)

        raw_message = data.decode(
            errors="replace"
        ).strip()

        source_ip = addr[0]

        iso_now = datetime.now(
            timezone.utc
        ).isoformat()

        print(
            f"\nReceived from {addr}: "
            f"{raw_message}"
        )

        raw_hash = hashlib.sha256(
            raw_message.encode()
        ).hexdigest()[:16]

        raw_entry = {
            "event_id": raw_hash,
            "received_at": iso_now,
            "source_ip": source_ip,
            "raw_payload": raw_message
        }

        save_event(
            raw_entry,
            RAW_LOGS_FILE
        )

        # Cisco -> Windows NXLog -> Linux
        normalized = parse_gns3_event(
            raw_message,
            source_ip,
            iso_now
        )

        if not normalized:
            normalized = parse_windows_event(
                raw_message,
                source_ip,
                iso_now
            )

        if not normalized:
            normalized = parse_linux_event(
                raw_message,
                source_ip,
                iso_now
            )

        if normalized:
            print(
                f"Normalized "
                f"({normalized['parser']['name']}) ->",
                json.dumps(
                    normalized,
                    indent=2
                )
            )

            save_event(
                normalized,
                NORMALIZED_FILE
            )

        else:
            print(
                "Could NOT parse this event - "
                "sent to quarantine."
            )

            quarantine_entry = {
                "raw": raw_message,
                "source_ip": source_ip,
                "reason":
                    "did not match any known "
                    "regex patterns or NXLog JSON",
                "received_at": iso_now
            }

            save_event(
                quarantine_entry,
                QUARANTINE_FILE
            )