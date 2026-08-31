#!/usr/bin/env bash
set -euo pipefail

DEPLOY_PATH="${DEPLOY_PATH:-$(pwd)}"
cd "${DEPLOY_PATH}"

compose=(docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml)
token="$(date -u +%Y%m%d%H%M%S)-$$"
test_slug="op2204-${token}"
test_domain="op2204-${token}.invalid"
subject_prefix="OP2204-${token}"
api_port="$(sed -n 's/^SMG_API_PORT=//p' deploy/docker/.env | tail -1 | tr -d '"')"
api_url="http://127.0.0.1:${api_port:-8081}/api/v1/mail/events"

psql_exec() {
  "${compose[@]}" exec -T postgres psql -X -v ON_ERROR_STOP=1 -U sentinelmail -d sentinelmail "$@"
}

cleanup() {
  psql_exec -v subject_prefix="${subject_prefix}" -v test_domain="${test_domain}" -v test_slug="${test_slug}" <<'SQL' >/dev/null
DELETE FROM quarantine_entries
 WHERE mail_log_id IN (
   SELECT id FROM mail_logs WHERE subject LIKE :'subject_prefix' || '%'
 );
DELETE FROM mail_logs WHERE subject LIKE :'subject_prefix' || '%';
DELETE FROM mail_campaigns
 WHERE domain_id IN (SELECT id FROM domains WHERE name = :'test_domain');
DELETE FROM domains WHERE name = :'test_domain';
DELETE FROM organizations WHERE slug = :'test_slug';
SQL
}
trap cleanup EXIT

psql_exec -v test_domain="${test_domain}" -v test_slug="${test_slug}" <<'SQL' >/dev/null
INSERT INTO organizations (name, slug)
VALUES ('OP#2204 health lead-generation smoke', :'test_slug')
RETURNING id AS selected_org
\gset

INSERT INTO domains (organization_id, name, is_active)
VALUES (:'selected_org', :'test_domain', true)
RETURNING id AS created_domain
\gset

INSERT INTO gateways (organization_id, domain_id, host, port, use_tls, is_active)
VALUES (:'selected_org', :'created_domain', '127.0.0.1', 9, false, true);

INSERT INTO policies (organization_id, domain_id, name, settings)
VALUES (
  :'selected_org',
  :'created_domain',
  'OP#2204 health lead-generation smoke',
  '{"common_scam_detection_enabled":true,"common_scam_health_miracle_enabled":true,"challenge_response_enabled":false}'::jsonb
);
SQL

python3 - "${api_url}" "${test_domain}" "${subject_prefix}" deploy/docker/.env <<'PY'
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request

api_url, domain, subject_prefix, env_path = sys.argv[1:]
sender_domain = f"source-{subject_prefix.lower()}.invalid"
secret = ""
with open(env_path, encoding="utf-8") as env_file:
    for line in env_file:
        if line.startswith("SMG_INGEST_HMAC_KEY="):
            secret = line.split("=", 1)[1].strip().strip('"').strip("'")
            break
if len(secret) < 16:
    raise SystemExit("SMG_INGEST_HMAC_KEY is missing or too short")

messages = [
    (
        "pancreas-reset",
        "Could your pancreas need a reset?",
        "Scientists describe a blood sugar reset and claim the real cause starts in the pancreas.",
        "quarantined",
    ),
    (
        "brain-video",
        "Explore practical brain health tips",
        "A memory discovery could change your routine. Watch this video to learn more.",
        "quarantined",
    ),
    (
        "sleep-3am",
        "What if your sleep problem starts with 3AM wake-ups?",
        "A doctor reveals a breakthrough. Click here to watch the video presentation.",
        "quarantined",
    ),
    (
        "nail-fungus",
        "What happens after you rub your nail this way?",
        "This nail fungus cure is presented as a simple discovery. Find out more.",
        "quarantined",
    ),
    (
        "legitimate-education",
        "Practical brain health tips",
        "Maintain a regular sleep schedule, exercise, and discuss memory concerns with your clinician.",
        "delivered",
    ),
]

for index, (name, subject, body_text, expected) in enumerate(messages, start=1):
    payload = {
        "direction": "inbound",
        "queue_id": f"{subject_prefix}-{index}",
        "message_id": f"<{name}-{subject_prefix.lower()}@example.test>",
        "from": f"newsletter-{name}@{sender_domain}",
        "to": [f"sink@{domain}"],
        "subject": f"{subject_prefix} {subject}",
        "body_text": body_text,
        "score": 0,
        "action": "no action",
        "symbols": {
            "R_SPF_ALLOW": True,
            "R_DKIM_ALLOW": True,
            "DMARC_POLICY_ALLOW": True,
        },
    }
    body = json.dumps(payload, separators=(",", ":")).encode()
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        api_url,
        data=body,
        headers={"Content-Type": "application/json", "X-SMG-Signature": signature},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.load(response)
            if response.status != 202:
                raise SystemExit(f"{name}: HTTP {response.status}, expected 202")
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"{name}: HTTP {exc.code}: {exc.read().decode(errors='replace')}") from exc
    print(f"{name}: {result.get('disposition')} (expected {expected})")
PY

quarantined_count="$(psql_exec -At -v subject_prefix="${subject_prefix}" <<'SQL'
SELECT count(*)
  FROM mail_logs
 WHERE subject LIKE :'subject_prefix' || '%'
   AND disposition = 'quarantined'
   AND reason = 'detected health lead-generation spam';
SQL
)"
if [[ "${quarantined_count}" != "4" ]]; then
  echo "Expected four health lead-generation quarantine logs, found ${quarantined_count}" >&2
  exit 1
fi

held_count="$(psql_exec -At -v subject_prefix="${subject_prefix}" <<'SQL'
SELECT count(*)
  FROM quarantine_entries q
  JOIN mail_logs m ON m.id = q.mail_log_id
 WHERE m.subject LIKE :'subject_prefix' || '%'
   AND q.state = 'held'
   AND q.threat_class = 'SPAM';
SQL
)"
if [[ "${held_count}" != "4" ]]; then
  echo "Expected four held SPAM quarantine entries, found ${held_count}" >&2
  exit 1
fi

legitimate_count="$(psql_exec -At -v subject_prefix="${subject_prefix}" <<'SQL'
SELECT count(*)
  FROM mail_logs
 WHERE queue_id = :'subject_prefix' || '-5'
   AND disposition = 'delivered'
   AND COALESCE(reason, '') = '';
SQL
)"
if [[ "${legitimate_count}" != "1" ]]; then
  legitimate_actual="$(psql_exec -At -F '|' -v subject_prefix="${subject_prefix}" <<'SQL'
SELECT disposition::text, COALESCE(reason, '')
  FROM mail_logs
 WHERE queue_id = :'subject_prefix' || '-5';
SQL
)"
  echo "Expected the legitimate health education control to be delivered, found ${legitimate_count}; actual=${legitimate_actual:-missing}" >&2
  exit 1
fi

echo "Health lead-generation smoke passed: 4/4 held as SPAM; legitimate health education delivered"
