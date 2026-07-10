#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="${1:-${repo_root}/deploy/docker/.env}"

if [[ -e "${env_file}" ]]; then
  echo "${env_file} already exists; refusing to overwrite."
  echo "Edit it in place for configuration changes, or remove it intentionally before regenerating."
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to generate secrets." >&2
  exit 1
fi

mkdir -p "$(dirname "${env_file}")"
umask 077

{
  echo "COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-sentinelmail}"
  echo "SMG_ENV=${SMG_ENV_DEFAULT:-dev}"
  echo "SMG_SMTP_PORT=${SMG_SMTP_PORT:-25}"
  echo "SMG_SMTP_LISTEN_IP=${SMG_SMTP_LISTEN_IP_DEFAULT:-0.0.0.0}"
  echo "SMG_SUBMISSION_PORT=${SMG_SUBMISSION_PORT:-587}"
  echo "SMG_HTTP_PORT=${SMG_HTTP_PORT:-8080}"
  echo "SMG_API_PORT=${SMG_API_PORT:-8081}"
  echo "SMG_CADDY_HTTP_PORT=${SMG_CADDY_HTTP_PORT_DEFAULT:-80}"
  echo "SMG_CADDY_HTTPS_PORT=${SMG_CADDY_HTTPS_PORT_DEFAULT:-443}"
  echo "POSTGRES_DB=${POSTGRES_DB:-sentinelmail}"
  echo "POSTGRES_USER=${POSTGRES_USER:-sentinelmail}"
  echo "POSTGRES_PASSWORD=$(openssl rand -hex 24)"
  echo "API_SESSION_SECRET=$(openssl rand -hex 32)"
  echo "API_AUDIT_HMAC_KEY=$(openssl rand -hex 32)"
  echo "SMG_INGEST_HMAC_KEY=$(openssl rand -hex 32)"
  echo "POSTFIX_MYHOSTNAME=${POSTFIX_MYHOSTNAME_DEFAULT:-mx.example.com}"
  echo 'POSTFIX_MYNETWORKS="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12"'
  echo "RSPAMD_PASSWORD=$(openssl rand -hex 16)"
  echo "RSPAMD_CONTROLLER_PASSWORD=$(openssl rand -hex 16)"
  echo "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}"
  echo "TLS_MODE=${TLS_MODE_DEFAULT:-off}"
  echo "TLS_HOSTNAME=${TLS_HOSTNAME_DEFAULT:-}"
  echo "TLS_ACME_EMAIL=${TLS_ACME_EMAIL:-}"
  echo "SMG_SEED_ADMIN_EMAIL=${SMG_SEED_ADMIN_EMAIL:-}"
  echo "SMG_SEED_ADMIN_PASSWORD=${SMG_SEED_ADMIN_PASSWORD:-}"
} > "${env_file}"

chmod 0600 "${env_file}"
echo "Wrote ${env_file}."
echo "Review POSTFIX_MYHOSTNAME, TLS_MODE, TLS_HOSTNAME, TLS_ACME_EMAIL, and optional seed admin values before first start."
