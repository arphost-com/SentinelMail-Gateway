#!/usr/bin/env python3
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

def validate_api_url(raw_url):
    parsed = urllib.parse.urlparse(raw_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print("SMG_SMTP_EVENT_URL must be an http(s) URL with a host", file=sys.stderr, flush=True)
        sys.exit(2)
    if parsed.username or parsed.password or parsed.fragment:
        print("SMG_SMTP_EVENT_URL must not include credentials or fragments", file=sys.stderr, flush=True)
        sys.exit(2)
    return urllib.parse.urlunparse(parsed)


SECRET = os.environ.get("SMG_INGEST_HMAC_KEY", "")
API_URL = validate_api_url(os.environ.get("SMG_SMTP_EVENT_URL", "http://api:8080/api/v1/smtp/events"))
HOST_RE = re.compile(r"from ([^\s\[]+)\[([^\]]+)\]")
QUEUE_RE = re.compile(r"postfix/[^\[]+\[\d+\]: ([A-F0-9]+):")


def main():
    for raw in sys.stdin:
        line = raw.rstrip("\n")
        print(line, flush=True)
        if len(SECRET) < 16:
            continue
        event = parse_line(line)
        if not event:
            continue
        post_event(event)


def parse_line(line):
    lowered = line.lower()
    event = base_event(line)
    if "noqueue: reject:" in lowered or "milter-reject:" in lowered:
        event.update(parse_common_fields(line))
        event["event_type"] = "reject"
        event["phase"] = "end_of_message" if "milter-reject:" in lowered else "recipient"
        event["reason"] = reason_after(line, "reject:") or reason_after(line, "milter-reject:")
        event["status_code"] = first_status_code(line)
        return compact(event)
    if "status=deferred" in lowered or "status=bounced" in lowered or "status=expired" in lowered:
        event.update(parse_common_fields(line))
        event["event_type"] = "deferred" if "status=deferred" in lowered else "bounced"
        event["phase"] = "delivery"
        event["to_addr"] = angle_value(line, "to") or event.get("to_addr", "")
        event["relay"] = field_value(line, "relay")
        event["dsn"] = field_value(line, "dsn")
        event["reason"] = paren_reason(line)
        return compact(event)
    if "tls" in lowered and ("error" in lowered or "certificate" in lowered or "lost connection" in lowered):
        event.update(parse_common_fields(line))
        event["event_type"] = "tls_error"
        event["phase"] = "tls"
        event["reason"] = line[-600:]
        return compact(event)
    if "lost connection" in lowered and ("after starttls" in lowered or "from unknown" in lowered):
        event.update(parse_common_fields(line))
        event["event_type"] = "disconnect"
        event["phase"] = "connect"
        event["reason"] = line[-600:]
        return compact(event)
    return None


def base_event(line):
    event = {
        "raw_log": line[-2000:],
        "occurred_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    match = QUEUE_RE.search(line)
    if match:
        event["queue_id"] = match.group(1)
    return event


def parse_common_fields(line):
    fields = {
        "from_addr": angle_value(line, "from"),
        "to_addr": angle_value(line, "to"),
        "helo": angle_value(line, "helo"),
    }
    host = HOST_RE.search(line)
    if host:
        fields["client_ip"] = host.group(2)
    return fields


def angle_value(line, key):
    match = re.search(rf"\b{re.escape(key)}=<([^>]*)>", line)
    return match.group(1).strip() if match else ""


def field_value(line, key):
    match = re.search(rf"\b{re.escape(key)}=([^,\s]+)", line)
    return match.group(1).strip() if match else ""


def reason_after(line, marker):
    idx = line.lower().find(marker)
    if idx < 0:
        return ""
    tail = line[idx + len(marker):].strip()
    if "; from=<" in tail:
        tail = tail.split("; from=<", 1)[0]
    return tail[-600:]


def paren_reason(line):
    start = line.rfind("(")
    end = line.rfind(")")
    if start >= 0 and end > start:
        return line[start + 1:end][-600:]
    return ""


def first_status_code(line):
    match = re.search(r"\b([245]\d\d(?:[ .-]\d+\.\d+\.\d+)?)\b", line)
    return match.group(1) if match else ""


def compact(event):
    return {key: value for key, value in event.items() if value}


def post_event(event):
    body = json.dumps(event, separators=(",", ":"), sort_keys=True).encode()
    signature = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        API_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-SMG-Signature": signature,
        },
    )
    for attempt in range(2):
        try:
            # API_URL is validated at startup to allow only http(s) URLs with a host and no credentials.
            with urllib.request.urlopen(request, timeout=3):  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
                return
        except (urllib.error.URLError, TimeoutError):
            if attempt == 0:
                time.sleep(0.5)


if __name__ == "__main__":
    main()
