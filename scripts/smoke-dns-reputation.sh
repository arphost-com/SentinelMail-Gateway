#!/bin/sh
set -eu

compose() {
  docker compose \
    --env-file deploy/docker/.env \
    -f deploy/docker/docker-compose.yml \
    "$@"
}

diagnose_failure() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "DNS reputation smoke failed; resolver status follows" >&2
    compose ps unbound >&2 || true
    compose logs --tail=80 unbound >&2 || true
    echo "Direct root-authority UDP/53 diagnostic follows" >&2
    compose exec -T unbound drill @198.41.0.4 . NS >&2 || true
  fi
  exit "$status"
}

trap diagnose_failure EXIT

query() {
  # drill parses options before positional @server/name arguments.
  compose exec -T unbound drill -p 5353 @127.0.0.1 "$1" "$2"
}

echo "==> full-recursion baseline"
query example.com A | grep -Eq '[[:space:]]IN[[:space:]]A[[:space:]][0-9.]+' 

echo "==> URIBL provider test point"
query 2.0.0.127.multi.uribl.com A \
  | grep -Eq '[[:space:]]IN[[:space:]]A[[:space:]]127\.0\.0\.14$'

echo "==> DNSWL IP provider test point"
query 2.0.0.127.list.dnswl.org A \
  | grep -Eq '[[:space:]]IN[[:space:]]A[[:space:]]127\.0\.10\.0$'

echo "==> DNSWL domain provider test point"
query dnswl.test.dwl.dnswl.org A \
  | grep -Eq '[[:space:]]IN[[:space:]]A[[:space:]]127\.0\.10\.0$'

echo "==> DNSWL query-source block check"
query amiblocked.dnswl.org TXT \
  | grep -Eq '[[:space:]]IN[[:space:]]TXT[[:space:]]+"no"$'

echo "DNS reputation resolver smoke passed"
trap - EXIT
