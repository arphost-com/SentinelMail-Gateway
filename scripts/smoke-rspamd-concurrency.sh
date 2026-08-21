#!/usr/bin/env bash
set -euo pipefail

DEPLOY_PATH="${DEPLOY_PATH:-$(pwd)}"
cd "${DEPLOY_PATH}"

compose=(docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml)
token="$(date -u +%Y%m%d%H%M%S)-$$"
test_domain="op2038-${token}.invalid"
test_sender="op2038-${token}@example.com"
test_recipient="sink@${test_domain}"
subject_prefix="OP2038-CONCURRENCY-${token}"
message_count="${SMG_RSPAMD_CONCURRENCY_COUNT:-20}"
smtp_port="$(sed -n 's/^SMG_SMTP_PORT=//p' deploy/docker/.env | tail -1 | tr -d '"')"
smtp_port="${smtp_port:-25}"
smtp_host="$(sed -n 's/^SMG_SMTP_LISTEN_IP=//p' deploy/docker/.env | tail -1 | tr -d '"')"
smtp_host="${smtp_host:-127.0.0.1}"
if [[ "${smtp_host}" == "0.0.0.0" || "${smtp_host}" == "::" ]]; then
  smtp_host="127.0.0.1"
fi

psql_exec() {
  "${compose[@]}" exec -T postgres psql -X -v ON_ERROR_STOP=1 -U sentinelmail -d sentinelmail "$@"
}

cleanup() {
  psql_exec -v subject_prefix="${subject_prefix}" -v test_domain="${test_domain}" <<'SQL' >/dev/null
DELETE FROM mail_logs WHERE subject LIKE :'subject_prefix' || '%';
DELETE FROM domains WHERE name = :'test_domain';
SQL
}
trap cleanup EXIT

psql_exec -v test_domain="${test_domain}" -v test_sender="${test_sender}" <<'SQL' >/dev/null
SELECT id AS selected_org
  FROM organizations
 WHERE is_active
 ORDER BY is_system, created_at
 LIMIT 1
\gset

INSERT INTO domains (organization_id, name, is_active)
VALUES (:'selected_org', :'test_domain', true)
RETURNING id AS created_domain
\gset

INSERT INTO gateways (organization_id, domain_id, host, port, use_tls, is_active)
VALUES (:'selected_org', :'created_domain', '127.0.0.1', 9, false, true);

INSERT INTO policies (organization_id, domain_id, name, settings)
VALUES (:'selected_org', :'created_domain', 'OP#2038 concurrency smoke', '{"sender_blacklist_enabled":true}'::jsonb);

INSERT INTO list_entries (organization_id, domain_id, scope, action, pattern, note)
VALUES (:'selected_org', :'created_domain', 'domain', 'block', :'test_sender', 'Temporary OP#2038 concurrency smoke entry');
SQL

rspamd_container="$("${compose[@]}" ps -q rspamd)"
before_pid="$(docker inspect -f '{{.State.Pid}}' "${rspamd_container}")"
before_restarts="$(docker inspect -f '{{.RestartCount}}' "${rspamd_container}")"
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python3 - "${smtp_host}" "${smtp_port}" "${test_sender}" "${test_recipient}" "${subject_prefix}" "${message_count}" <<'PY'
import concurrent.futures
import smtplib
import sys

host = sys.argv[1]
port = int(sys.argv[2])
sender = sys.argv[3]
recipient = sys.argv[4]
subject_prefix = sys.argv[5]
count = int(sys.argv[6])

def send(index: int) -> tuple[int, int]:
    message = (
        f"From: {sender}\r\n"
        f"To: {recipient}\r\n"
        f"Subject: {subject_prefix}-{index}\r\n"
        f"Message-ID: <{subject_prefix.lower()}-{index}@example.com>\r\n"
        "Date: Thu, 13 Aug 2026 00:00:00 +0000\r\n"
        "\r\n"
        "Concurrency policy validation message.\r\n"
    )
    try:
        with smtplib.SMTP(host, port, timeout=20) as client:
            client.ehlo("op2038-smoke.example.com")
            client.sendmail(sender, [recipient], message)
    except smtplib.SMTPDataError as exc:
        return index, int(exc.smtp_code)
    raise RuntimeError(f"message {index} was unexpectedly accepted")

with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
    results = list(executor.map(send, range(count)))

bad = [(index, code) for index, code in results if code < 500 or code >= 600]
if bad:
    raise SystemExit(f"unexpected SMTP responses: {bad}")
print(f"concurrent SMTP policy rejects: {len(results)}/{count} ({sorted({code for _, code in results})})")
PY

sleep 2
after_pid="$(docker inspect -f '{{.State.Pid}}' "${rspamd_container}")"
after_restarts="$(docker inspect -f '{{.RestartCount}}' "${rspamd_container}")"
if [[ "${before_pid}" != "${after_pid}" || "${before_restarts}" != "${after_restarts}" ]]; then
  echo "Rspamd process changed during concurrency smoke" >&2
  exit 1
fi

logged_count="$(psql_exec -At -v subject_prefix="${subject_prefix}" <<'SQL'
SELECT count(*)
  FROM mail_logs
 WHERE subject LIKE :'subject_prefix' || '%'
   AND disposition = 'rejected'
   AND reason = 'sender matched blacklist';
SQL
)"
if [[ "${logged_count}" != "${message_count}" ]]; then
  echo "Expected ${message_count} rejected mail logs, found ${logged_count}" >&2
  exit 1
fi

if "${compose[@]}" logs --since "${started_at}" rspamd 2>&1 | grep -Eqi 'segmentation fault|segfault|invalid dynamic item|lua.*(panic|crash)|application error'; then
  echo "Rspamd emitted a concurrency fault signature" >&2
  exit 1
fi

echo "Rspamd concurrency smoke passed: ${message_count} rejects, stable PID/restart count, no fault signatures"
