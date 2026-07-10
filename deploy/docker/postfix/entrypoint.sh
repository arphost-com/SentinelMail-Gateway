#!/bin/sh
set -eu

: "${POSTFIX_MYHOSTNAME:?POSTFIX_MYHOSTNAME required}"
: "${POSTFIX_MYNETWORKS:=127.0.0.0/8 10.0.0.0/8}"
: "${POSTGRES_USER:?POSTGRES_USER required for relay_domains lookup}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD required for relay_domains lookup}"
: "${POSTGRES_DB:?POSTGRES_DB required for relay_domains lookup}"

postconf -e "myhostname=${POSTFIX_MYHOSTNAME}"
postconf -e "mynetworks=${POSTFIX_MYNETWORKS}"
postconf -e "maillog_file=/var/log/mail.log"

# Render the pgsql lookup files with the live credentials. The .cf files
# end up at /etc/postfix/pgsql-*.cf with mode 0640 (postfix group readable,
# no world). The password never lives baked into the image.
render_pgsql() {
    src="/etc/postfix/${1}.cf.template"
    dst="/etc/postfix/${1}.cf"
    sed \
        -e "s|\${POSTGRES_USER}|${POSTGRES_USER}|g" \
        -e "s|\${POSTGRES_PASSWORD}|${POSTGRES_PASSWORD}|g" \
        -e "s|\${POSTGRES_DB}|${POSTGRES_DB}|g" \
        "$src" > "$dst"
    chown root:postfix "$dst"
    chmod 0640 "$dst"
}
render_pgsql pgsql-relay-domains
render_pgsql pgsql-transport

# Ensure snakeoil certs exist (debian-postfix package usually provides them; regen if missing).
if [ ! -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]; then
  apt-get update >/dev/null 2>&1 || true
  apt-get install -y --no-install-recommends ssl-cert >/dev/null 2>&1 || true
  make-ssl-cert generate-default-snakeoil --force-overwrite || true
fi

touch /var/log/mail.log
chmod 0644 /var/log/mail.log
tail -n0 -F /var/log/mail.log | /usr/local/bin/smtp-event-forwarder.py &

# Foreground; Postfix forks workers but `postfix start-fg` keeps stdio attached.
exec postfix start-fg
