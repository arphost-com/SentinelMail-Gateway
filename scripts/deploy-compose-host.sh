#!/usr/bin/env bash
set -exo pipefail

step() { echo; echo "==> $*"; }

: "${DEPLOY_PATH:?DEPLOY_PATH is required}"
: "${COMPOSE:?COMPOSE is required}"

step "1. verify staged deploy directory ownership"
test -d "${DEPLOY_PATH}"
test -w "${DEPLOY_PATH}"
test "$(stat -c '%U' "${DEPLOY_PATH}")" = "$(id -un)"
cd "${DEPLOY_PATH}"

step "2. bootstrap deploy/docker/.env if missing"
install -d -m 0755 deploy/docker
if [ ! -f deploy/docker/.env ]; then
  if [ -n "${SMG_DOTENV_FILE:-}" ] && [ -f "${SMG_DOTENV_FILE}" ]; then
    echo "  copying from staged CI variable SMG_DOTENV_FILE"
    install -m 0600 "${SMG_DOTENV_FILE}" deploy/docker/.env
  elif [ -f .env ]; then
    echo "  migrating existing root .env to deploy/docker/.env"
    install -m 0600 .env deploy/docker/.env
  else
    echo "  generating with random secrets (SMG_ENV=${SMG_ENV_DEFAULT}, SMTP listen=${SMG_SMTP_LISTEN_IP_DEFAULT})"
    POSTFIX_MYHOSTNAME_DEFAULT=mx.sentinelmail.local ./scripts/bootstrap-env.sh deploy/docker/.env
  fi
else
  echo "  deploy/docker/.env already present — preserving secrets"
fi
if [ -n "${SMG_DOTENV_FILE:-}" ] && [ "${SMG_DOTENV_FILE}" != "deploy/docker/.env" ]; then
  rm -f -- "${SMG_DOTENV_FILE}"
fi
set +x
if ! grep -q '^SMG_SETTINGS_ENCRYPTION_KEY=' deploy/docker/.env; then
  printf 'SMG_SETTINGS_ENCRYPTION_KEY=%s\n' "$(openssl rand -hex 32)" >> deploy/docker/.env
fi
set -x
ls -la deploy/docker/.env

step "3. docker compose build"
export SMG_VERSION="$(tr -d '[:space:]' < VERSION)"
test -n "${SMG_VERSION}"
echo "  building SentinelMail ${SMG_VERSION}"
${COMPOSE} build --pull

step "4. docker compose up (waits for healthchecks)"
compose_up_log="$(mktemp)"
compose_up_status=0
${COMPOSE} up -d --remove-orphans --wait --wait-timeout 120 2>&1 | tee "${compose_up_log}" || compose_up_status=$?
if [ "${compose_up_status}" -ne 0 ] && grep -Eq 'network .* not found|No such network' "${compose_up_log}"; then
  echo "WARN: docker reported a stale Compose network; removing stopped/orphaned containers and retrying once"
  ${COMPOSE} down --remove-orphans || true
  compose_up_status=0
  ${COMPOSE} up -d --remove-orphans --wait --wait-timeout 120 2>&1 | tee -a "${compose_up_log}" || compose_up_status=$?
fi
if [ "${compose_up_status}" -ne 0 ]; then
  echo "WARN: compose up --wait reported unhealthy; capturing logs and continuing"
  ${COMPOSE} ps
  for svc in api postfix rspamd unbound web; do
    echo "----- ${svc} -----"
    ${COMPOSE} logs --tail=30 "${svc}" || true
  done
  api_health=""
  for attempt in $(seq 1 24); do
    api_health=$(${COMPOSE} ps --format json api | jq -r '.Health // ""' | head -1)
    [ "${api_health}" = "healthy" ] && break
    echo "waiting for api health (${attempt}/24): ${api_health:-missing}"
    sleep 5
  done
  if [ "${api_health}" != "healthy" ]; then
    echo "FATAL: api is not healthy (${api_health})"
    exit 1
  fi
fi
rm -f "${compose_up_log}"

step "5. run migrations"
${COMPOSE} exec -T api /app/migrate up

step "6. seed default admin (no-op if org already present)"
${COMPOSE} exec -T \
  -e SMG_SEED_ADMIN_EMAIL="${SMG_SEED_ADMIN_EMAIL:-admin@sentinelmail.local}" \
  api /app/migrate seed || true

step "7. final stack state"
${COMPOSE} ps
