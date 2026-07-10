#!/bin/sh
# SentinelMail Gateway — Caddy front-end.
#
# Templates /etc/caddy/Caddyfile from three env vars, then exec's caddy.
# The TLS settings the operator picks in System Settings end up in .env
# (or directly, depending on the operator workflow) and the next caddy
# restart picks them up.
#
#   TLS_MODE          off | self_signed | lets_encrypt   (default: off)
#   TLS_HOSTNAME      public FQDN (required for lets_encrypt; SAN for self_signed)
#   TLS_ACME_EMAIL    contact email for Let's Encrypt expiry warnings
#
# Layout:
#   /healthz          always served directly by Caddy (200 "ok")
#   everything else   proxied to web:8080 (the nginx serving the SPA)
set -eu

MODE="${TLS_MODE:-off}"
HOST="${TLS_HOSTNAME:-}"
EMAIL="${TLS_ACME_EMAIL:-}"

cf=/etc/caddy/Caddyfile
legacy_data="${HOME:-/home/smgcaddy}/.local/share/caddy"
persisted_data="${XDG_DATA_HOME:-/data}/caddy"

mkdir -p "$persisted_data"
if [ ! -d "$persisted_data/certificates" ] && [ -d "$legacy_data/certificates" ]; then
  echo "==> Migrating legacy Caddy ACME storage into persisted volume"
  cp -a "$legacy_data/." "$persisted_data/"
fi

case "$MODE" in
  lets_encrypt)
    if [ -z "$HOST" ]; then
      echo "ERROR: TLS_MODE=lets_encrypt requires TLS_HOSTNAME" >&2
      exit 2
    fi
    if [ -z "$EMAIL" ]; then
      echo "WARN: TLS_ACME_EMAIL is empty; Let's Encrypt will not send expiry warnings" >&2
    fi
    # Do NOT add an explicit ":80" block here. Caddy's automatic HTTPS for
    # the hostname block below already:
    #   - listens on :80
    #   - serves /.well-known/acme-challenge/* for HTTP-01 validation
    #   - redirects every other plain-HTTP request to HTTPS
    # An explicit :80 site collides with that and breaks ACME issuance.
    cat > "$cf" <<EOF
{
    storage file_system ${persisted_data}
${EMAIL:+    email ${EMAIL}}
}

${HOST} {
    handle /healthz {
        respond "ok" 200
    }
    handle {
        reverse_proxy web:8080
    }
}
EOF
    ;;
  self_signed)
    cat > "$cf" <<EOF
{
    storage file_system ${persisted_data}
    local_certs
}

:443 {
    handle /healthz {
        respond "ok" 200
    }
    handle {
        reverse_proxy web:8080
    }
}

:80 {
    handle /healthz {
        respond "ok" 200
    }
    handle {
        reverse_proxy web:8080
    }
}
EOF
    ;;
  off|*)
    cat > "$cf" <<EOF
{
    storage file_system ${persisted_data}
}

:80 {
    handle /healthz {
        respond "ok" 200
    }
    handle {
        reverse_proxy web:8080
    }
}
EOF
    ;;
esac

echo "==> Caddy starting in TLS_MODE=${MODE} (HOST=${HOST:-<unset>})"
exec caddy run --config "$cf" --adapter caddyfile
