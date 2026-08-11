#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
COMPOSE_CMD=(docker compose -f "${COMPOSE_FILE}")

POSTGRES_SERVICE="${POSTGRES_SERVICE:-postgres}"
RABBITMQ_SERVICE="${RABBITMQ_SERVICE:-rabbitmq}"

POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-argus_dev_pg_S7m9Q4r2L8xP6nV3}"
POSTGRES_DB="${POSTGRES_DB:-argus}"
DB_HOST="${DB_HOST:-127.0.0.1}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
DB_PORT="${DB_PORT:-${POSTGRES_PORT}}"
DB_MIGRATION_MODE="${DB_MIGRATION_MODE:-apply}"

RABBITMQ_HOST="${RABBITMQ_HOST:-127.0.0.1}"
RABBITMQ_PORT="${RABBITMQ_PORT:-5672}"
RABBITMQ_MANAGEMENT_PORT="${RABBITMQ_MANAGEMENT_PORT:-15672}"
RABBITMQ_DEFAULT_USER="${RABBITMQ_DEFAULT_USER:-guest}"
RABBITMQ_DEFAULT_PASS="${RABBITMQ_DEFAULT_PASS:-guest}"

DB_DSN="${DB_DSN:-host=${DB_HOST} user=${POSTGRES_USER} password=${POSTGRES_PASSWORD} dbname=${POSTGRES_DB} port=${DB_PORT} sslmode=disable}"
AMQP_URL="${AMQP_URL:-amqp://${RABBITMQ_DEFAULT_USER}:${RABBITMQ_DEFAULT_PASS}@${RABBITMQ_HOST}:${RABBITMQ_PORT}/}"

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
  (
    cd "${ROOT_DIR}"
    if [[ -x "${ROOT_DIR}/bin/argus-server" ]]; then
      if [[ "${DB_MIGRATION_MODE}" == "dev-auto" ]]; then
        ./bin/argus-server --db "${DB_DSN}" --migrate-only --db-migration-mode "${DB_MIGRATION_MODE}" --dev
      else
        ./bin/argus-server --db "${DB_DSN}" --migrate-only --db-migration-mode "${DB_MIGRATION_MODE}"
      fi
      return
    fi

    require_cmd go
    if [[ "${DB_MIGRATION_MODE}" == "dev-auto" ]]; then
      go run ./server/cmd/argus-server --db "${DB_DSN}" --migrate-only --db-migration-mode "${DB_MIGRATION_MODE}" --dev
    else
      go run ./server/cmd/argus-server --db "${DB_DSN}" --migrate-only --db-migration-mode "${DB_MIGRATION_MODE}"
    fi
  )
}

next_server_command() {
  if [[ -x "${ROOT_DIR}/bin/argus-server" ]]; then
    printf './bin/argus-server --db "%s" --dev' "${DB_DSN}"
    return
  fi

  printf 'make server && ./bin/argus-server --db "%s" --dev' "${DB_DSN}"
}

require_cmd docker

export POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB POSTGRES_PORT
export RABBITMQ_DEFAULT_USER RABBITMQ_DEFAULT_PASS RABBITMQ_PORT RABBITMQ_MANAGEMENT_PORT

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
[setup-local] RabbitMQ AMQP: ${AMQP_URL}
[setup-local] RabbitMQ UI:   http://${RABBITMQ_HOST}:${RABBITMQ_MANAGEMENT_PORT}
[setup-local] PostgreSQL:    host=${DB_HOST} port=${DB_PORT} dbname=${POSTGRES_DB} user=${POSTGRES_USER}
[setup-local] Next:
[setup-local]   $(next_server_command)
[setup-local]   ./bin/argus-agent --server 127.0.0.1:50051
EOF
