#!/usr/bin/env bash
set -euo pipefail

deploy_path="${DEPLOY_PATH:-$(pwd)}"
cd "${deploy_path}"
compose=(docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml)
token="smg-challenge-$(date -u +%Y%m%d%H%M%S)-$$"
sink="${token}-sink"
domain="${token}.invalid"
recipient="recipient@${domain}"
admin="admin@${domain}"
inactive="inactive@${domain}"
unknown="unknown-${token}@example.net"
blocked="blocked-${token}@example.net"
subject_unknown="SMG-CHALLENGE-UNKNOWN-${token}"
subject_inactive="SMG-CHALLENGE-INACTIVE-${token}"
subject_blocked="SMG-CHALLENGE-BLOCKED-${token}"
smtp_host="$(sed -n 's/^SMG_SMTP_LISTEN_IP=//p' deploy/docker/.env | tail -1 | tr -d '"')"
smtp_port="$(sed -n 's/^SMG_SMTP_PORT=//p' deploy/docker/.env | tail -1 | tr -d '"')"
smtp_host="${smtp_host:-127.0.0.1}"
smtp_port="${smtp_port:-25}"
if [[ "${smtp_host}" == "0.0.0.0" || "${smtp_host}" == "::" ]]; then smtp_host="127.0.0.1"; fi

psql_exec() {
  "${compose[@]}" exec -T postgres psql -X -v ON_ERROR_STOP=1 -U sentinelmail -d sentinelmail "$@"
}
cleanup() {
  docker rm -f "${sink}" >/dev/null 2>&1 || true
  psql_exec -c "DELETE FROM organizations WHERE slug = '${token}'" >/dev/null
}
trap cleanup EXIT

docker run -d --name "${sink}" --network sentinelmail_sentinelmail sentinelmail-worker python -u -c '
import socketserver
class Handler(socketserver.StreamRequestHandler):
    def send_line(self, value):
        self.wfile.write((value + "\r\n").encode()); self.wfile.flush()
    def handle(self):
        self.send_line("220 challenge-smoke ESMTP"); data = False
        while True:
            line = self.rfile.readline()
            if not line: return
            if data:
                if line == b".\r\n": print("MESSAGE", flush=True); data = False; self.send_line("250 queued")
                continue
            command = line.decode(errors="replace").upper()
            if command.startswith("DATA"): data = True; self.send_line("354 end")
            elif command.startswith("QUIT"): self.send_line("221 bye"); return
            else: self.send_line("250 ok")
class Server(socketserver.ThreadingTCPServer): allow_reuse_address = True
Server(("0.0.0.0", 2525), Handler).serve_forever()
' >/dev/null
sleep 1

psql_exec -v name="Challenge smoke ${token}" -v slug="${token}" -v domain="${domain}" -v sink="${sink}" -v recipient="${recipient}" -v admin="${admin}" -v inactive="${inactive}" <<'SQL' >/dev/null
INSERT INTO organizations(name, slug) VALUES(:'name', :'slug') RETURNING id AS org_id \gset
INSERT INTO domains(organization_id, name) VALUES(:'org_id', :'domain') RETURNING id AS domain_id \gset
INSERT INTO gateways(organization_id, domain_id, host, port, use_tls) VALUES(:'org_id', :'domain_id', :'sink', 2525, false);
INSERT INTO policies(organization_id, domain_id, name, enable_greylist, settings)
VALUES(:'org_id', :'domain_id', 'Challenge-response SMTP smoke', false,
       '{"challenge_response_enabled":true,"challenge_response_require_verified_source":true,"sender_blacklist_enabled":true}');
INSERT INTO users(organization_id, email, password_hash, role, is_active, challenge_response_alert_frequency) VALUES
(:'org_id', :'recipient', 'smoke-no-login', 'org_user', true, 'immediate'),
(:'org_id', :'admin', 'smoke-no-login', 'org_admin', true, 'immediate'),
(:'org_id', :'inactive', 'smoke-no-login', 'org_user', false, 'immediate');
SQL

python3 - "${smtp_host}" "${smtp_port}" "${unknown}" "${recipient}" "${subject_unknown}" "${unknown}" "${inactive}" "${subject_inactive}" <<'PY'
import smtplib, sys, time
host, port, *values = sys.argv[1:]
for index, (sender, recipient, subject) in enumerate((values[:3], values[3:])):
    message = f"From: {sender}\r\nTo: {recipient}\r\nSubject: {subject}\r\nMessage-ID: <{subject.lower()}@example.net>\r\nDate: Sun, 31 Aug 2026 15:15:00 +0000\r\n\r\nScheduled business meeting.\r\n"
    with smtplib.SMTP(host, int(port), timeout=20) as client:
        client.ehlo("mail.example.net"); client.sendmail(sender, [recipient], message)
    if index == 0:
        # Immediate recipient/admin notification is asynchronous. Let the first
        # delivery finish before asserting that a second pending message for an
        # inactive mailbox produces a fresh admin notice without notifying the
        # inactive user.
        time.sleep(6)
PY
sleep 8

psql_exec -v slug="${token}" -v domain="${domain}" -v blocked="${blocked}" <<'SQL' >/dev/null
SELECT id AS org_id FROM organizations WHERE slug=:'slug' \gset
SELECT id AS domain_id FROM domains WHERE name=:'domain' \gset
INSERT INTO list_entries(organization_id, domain_id, scope, action, kind, pattern, note)
VALUES(:'org_id', :'domain_id', 'domain', 'block', 'email', :'blocked', 'Temporary challenge-response smoke block');
SQL

python3 - "${smtp_host}" "${smtp_port}" "${blocked}" "${recipient}" "${subject_blocked}" <<'PY'
import smtplib, sys
host, port, sender, recipient, subject = sys.argv[1:]
message = f"From: {sender}\r\nTo: {recipient}\r\nSubject: {subject}\r\nMessage-ID: <{subject.lower()}@example.net>\r\nDate: Sun, 31 Aug 2026 15:15:00 +0000\r\n\r\nBlocked source.\r\n"
try:
    with smtplib.SMTP(host, int(port), timeout=20) as client:
        client.ehlo("mail.example.net"); client.sendmail(sender, [recipient], message)
except smtplib.SMTPDataError as exc:
    if not 500 <= exc.smtp_code < 600: raise
else:
    raise SystemExit("blocked challenge-response sender was accepted")
PY
sleep 4

result="$(psql_exec -At -F '|' -v su="${subject_unknown}" -v si="${subject_inactive}" -v sb="${subject_blocked}" -v recipient="${recipient}" -v admin="${admin}" -v inactive="${inactive}" <<'SQL'
WITH target AS (SELECT subject,id,disposition::text,reason FROM mail_logs WHERE subject IN(:'su',:'si',:'sb')) SELECT
(SELECT count(*) FROM target WHERE subject=:'su' AND disposition='quarantined' AND reason='pending recipient challenge-response approval'),
(SELECT count(*) FROM quarantine_entries q JOIN target t ON t.id=q.mail_log_id WHERE t.subject=:'su' AND q.state='held'),
(SELECT count(*) FROM sent_emails s JOIN target t ON t.id=s.mail_log_id WHERE t.subject=:'su' AND s.status='sent' AND :'recipient'=ANY(s.to_addrs)),
(SELECT count(*) FROM sent_emails s JOIN target t ON t.id=s.mail_log_id WHERE t.subject=:'su' AND s.status='sent' AND :'admin'=ANY(s.to_addrs)),
(SELECT count(*) FROM target WHERE subject=:'si' AND disposition='quarantined' AND reason='pending recipient challenge-response approval'),
(SELECT count(*) FROM sent_emails s JOIN target t ON t.id=s.mail_log_id WHERE t.subject=:'si' AND :'inactive'=ANY(s.to_addrs)),
(SELECT count(*) FROM sent_emails s JOIN target t ON t.id=s.mail_log_id WHERE t.subject=:'si' AND s.status='sent' AND :'admin'=ANY(s.to_addrs)),
(SELECT count(*) FROM target WHERE subject=:'sb' AND disposition='rejected' AND reason='sender matched blacklist'),
(SELECT count(*) FROM sent_emails s JOIN target t ON t.id=s.mail_log_id WHERE t.subject=:'sb'),
(SELECT count(*) FROM quarantine_entries q JOIN target t ON t.id=q.mail_log_id WHERE t.subject=:'sb');
SQL
)"
IFS='|' read -r unknown_log unknown_held recipient_notice admin_notice inactive_log inactive_notice inactive_admin_notice blocked_log blocked_notice blocked_quarantine <<<"${result}"
for value in "${unknown_log}" "${unknown_held}" "${recipient_notice}" "${admin_notice}" "${inactive_log}" "${inactive_admin_notice}" "${blocked_log}"; do
  [[ "${value}" -ge 1 ]] || { echo "challenge-response smoke failed: ${result}" >&2; exit 1; }
done
[[ "${inactive_notice}" = 0 && "${blocked_notice}" = 0 && "${blocked_quarantine}" = 0 ]] || { echo "challenge-response silent behavior failed: ${result}" >&2; exit 1; }
sink_count="$(docker logs "${sink}" 2>&1 | grep -c '^MESSAGE$' || true)"
[[ "${sink_count}" -ge 3 ]] || { echo "challenge-response sink received ${sink_count}, expected at least 3" >&2; exit 1; }

cleanup
trap - EXIT
remaining="$(psql_exec -At -c "SELECT count(*) FROM organizations WHERE slug = '${token}'")"
[[ "${remaining}" = 0 ]]
echo "challenge-response SMTP smoke passed: ${result}; sink=${sink_count}; cleanup=verified"
