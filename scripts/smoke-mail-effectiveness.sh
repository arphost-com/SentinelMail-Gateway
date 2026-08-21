#!/usr/bin/env bash
set -euo pipefail

deploy_path="${DEPLOY_PATH:-$(pwd)}"
cd "${deploy_path}"

compose=(docker compose --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml)
psql_cmd=("${compose[@]}" exec -T postgres psql -X -v ON_ERROR_STOP=1 -U sentinelmail -d sentinelmail -At)

ai_mode=$("${psql_cmd[@]}" -c "SELECT value #>> '{}' FROM system_settings WHERE organization_id IS NULL AND key = 'ai.mode'")
case "${ai_mode}" in
  disabled|suspicious|all) ;;
  *) echo "invalid or missing ai.mode: ${ai_mode:-missing}" >&2; exit 1 ;;
esac

tag_policies=$("${psql_cmd[@]}" -c "SELECT count(*) FROM policies WHERE settings->>'auto_created' = 'true' AND quarantine_action = 'tag'")
test "${tag_policies}" = "0"

unsupported_feeds=$("${psql_cmd[@]}" -c "SELECT count(*) FROM threat_feed_config WHERE feed IN ('openphish', 'phishtank_brands')")
test "${unsupported_feeds}" = "0"

analysis_column=$("${psql_cmd[@]}" -c "SELECT count(*) FROM information_schema.columns WHERE table_name = 'mail_logs' AND column_name = 'deep_analysis_state'")
test "${analysis_column}" = "1"

echo "mail-effectiveness smoke passed: ai_mode=${ai_mode}, auto-created tag policies=${tag_policies}, unsupported feeds=${unsupported_feeds}"
