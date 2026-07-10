#!/bin/sh
set -eu

: "${RSPAMD_PASSWORD:?RSPAMD_PASSWORD required}"
: "${RSPAMD_CONTROLLER_PASSWORD:?RSPAMD_CONTROLLER_PASSWORD required}"

PW_HASH=$(rspamadm pw --encrypt --password "${RSPAMD_PASSWORD}")
CTRL_HASH=$(rspamadm pw --encrypt --password "${RSPAMD_CONTROLLER_PASSWORD}")

cat > /etc/rspamd/local.d/worker-controller.inc <<EOF
bind_socket = "*:11334";
password = "${CTRL_HASH}";
enable_password = "${CTRL_HASH}";
EOF

cat > /etc/rspamd/local.d/options.inc <<EOF
local_addrs = [127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16];
EOF

exec rspamd -f -u _rspamd -g _rspamd
