#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
COMPOSE_CMD=(docker compose -f "${COMPOSE_FILE}")

POSTGRES_SERVICE="${POSTGRES_SERVICE:-postgres}"
RABBITMQ_SERVICE="${RABBITMQ_SERVICE:-rabbitmq}"

POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-root}"
POSTGRES_DB="${POSTGRES_DB:-dddd}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_MIGRATION_MODE="${DB_MIGRATION_MODE:-apply}"

RABBITMQ_DEFAULT_USER="${RABBITMQ_DEFAULT_USER:-guest}"
RABBITMQ_DEFAULT_PASS="${RABBITMQ_DEFAULT_PASS:-guest}"

DB_DSN="${DB_DSN:-host=${DB_HOST} user=${POSTGRES_USER} password=${POSTGRES_PASSWORD} dbname=${POSTGRES_DB} port=${DB_PORT} sslmode=disable}"

log() {
  printf '[setup-local] %s\n' "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '[setup-local] missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

wait_for_service() {
  local service="$1"
  local retries="${2:-60}"
  local sleep_seconds="${3:-2}"
  local attempt cid status

  for ((attempt = 1; attempt <= retries; attempt++)); do
    cid="$("${COMPOSE_CMD[@]}" ps -q "${service}" | tr -d '\r')"
    if [[ -n "${cid}" ]]; then
      status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "${cid}" 2>/dev/null || true)"
      case "${status}" in
        healthy|running)
          log "service '${service}' is ${status}"
          return 0
          ;;
      esac
    fi

    log "waiting for service '${service}' (${attempt}/${retries})..."
    sleep "${sleep_seconds}"
  done

  log "service '${service}' did not become ready in time"
  "${COMPOSE_CMD[@]}" ps
  exit 1
}

run_migrate_only() {
  if [[ -x "${ROOT_DIR}/bin/dddd-server" ]]; then
    (
      cd "${ROOT_DIR}"
      ./bin/dddd-server --db "${DB_DSN}" --migrate-only --dev --db-migration-mode "${DB_MIGRATION_MODE}"
    )
    return
  fi

  require_cmd go
  (
    cd "${ROOT_DIR}"
    go run ./server/cmd/dddd-server --db "${DB_DSN}" --migrate-only --dev --db-migration-mode "${DB_MIGRATION_MODE}"
  )
}

require_cmd docker

log "starting local infrastructure: ${RABBITMQ_SERVICE}, ${POSTGRES_SERVICE}"
"${COMPOSE_CMD[@]}" up -d --remove-orphans "${RABBITMQ_SERVICE}" "${POSTGRES_SERVICE}"

wait_for_service "${RABBITMQ_SERVICE}"
wait_for_service "${POSTGRES_SERVICE}"

log "bootstrapping PostgreSQL database and role"
"${COMPOSE_CMD[@]}" exec -T "${POSTGRES_SERVICE}" bash -lc '/docker-entrypoint-initdb.d/000-init-db.sh'

log "applying database migrations"
run_migrate_only

cat <<EOF
[setup-local] local infrastructure is ready
[setup-local] RabbitMQ AMQP: amqp://${RABBITMQ_DEFAULT_USER}:${RABBITMQ_DEFAULT_PASS}@127.0.0.1:5672/
[setup-local] RabbitMQ UI:   http://127.0.0.1:15672
[setup-local] PostgreSQL:    host=${DB_HOST} port=${DB_PORT} dbname=${POSTGRES_DB} user=${POSTGRES_USER}
[setup-local] Next:
[setup-local]   ./bin/dddd-server --db "${DB_DSN}" --dev
[setup-local]   ./bin/dddd-agent --server 127.0.0.1:50051
EOF
