#!/usr/bin/env bash
# Rebuild the empty-database baseline from incremental migrations.
# Requires a reachable PostgreSQL (local psql/pg_dump, or the deploy-postgres container).
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
SCHEMA_DIR="${ROOT_DIR}/server/internal/db/schema"
MIGRATIONS_DIR="${ROOT_DIR}/server/internal/db/migrations"
DUMP_DB="${ARGUS_SCHEMA_DUMP_DB:-argus_schema_dump}"

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-${POSTGRES_PORT:-5432}}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-argus_dev_pg_S7m9Q4r2L8xP6nV3}"
POSTGRES_DB="${POSTGRES_DB:-postgres}"

SCHEMA_OUT="${SCHEMA_DIR}/000_current_schema.sql"
VERSIONS_OUT="${SCHEMA_DIR}/000_current_schema.versions"
SEED_OUT="${SCHEMA_DIR}/001_dev_seed.sql"
SEED_SRC="${MIGRATIONS_DIR}/020_seed-admin-and-fix-roles.sql"

CONTAINER="${ARGUS_POSTGRES_CONTAINER:-}"

log() { printf '[db-schema-dump] %s\n' "$*"; }

find_container() {
  if [[ -n "${CONTAINER}" ]]; then
    printf '%s' "${CONTAINER}"
    return 0
  fi
  if ! command -v docker >/dev/null 2>&1; then
    return 1
  fi
  local name
  for name in deploy-postgres-1 argus-postgres postgres; do
    if docker ps --format '{{.Names}}' | grep -qx "${name}"; then
      printf '%s' "${name}"
      return 0
    fi
  done
  return 1
}

have_host_pg() {
  command -v psql >/dev/null 2>&1 && command -v pg_dump >/dev/null 2>&1
}

pg_exec() {
  local db="$1"
  shift
  if have_host_pg; then
    PGPASSWORD="${POSTGRES_PASSWORD}" psql -X -v ON_ERROR_STOP=1 \
      -h "${DB_HOST}" -p "${DB_PORT}" -U "${POSTGRES_USER}" -d "${db}" "$@"
    return
  fi
  local container
  container="$(find_container)" || {
    echo "[db-schema-dump] need psql/pg_dump or a running postgres container" >&2
    exit 1
  }
  docker exec -e PGPASSWORD="${POSTGRES_PASSWORD}" -i "${container}" \
    psql -X -v ON_ERROR_STOP=1 -U "${POSTGRES_USER}" -d "${db}" "$@"
}

pg_dump_schema() {
  local db="$1"
  if have_host_pg; then
    PGPASSWORD="${POSTGRES_PASSWORD}" pg_dump \
      -h "${DB_HOST}" -p "${DB_PORT}" -U "${POSTGRES_USER}" \
      --schema-only --no-owner --no-privileges --no-comments \
      -T schema_migrations "${db}"
    return
  fi
  local container
  container="$(find_container)" || {
    echo "[db-schema-dump] need psql/pg_dump or a running postgres container" >&2
    exit 1
  }
  docker exec -e PGPASSWORD="${POSTGRES_PASSWORD}" "${container}" \
    pg_dump -U "${POSTGRES_USER}" \
      --schema-only --no-owner --no-privileges --no-comments \
      -T schema_migrations "${db}"
}

log "recreating ${DUMP_DB}"
pg_exec "${POSTGRES_DB}" -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${DUMP_DB}' AND pid <> pg_backend_pid();" >/dev/null
pg_exec "${POSTGRES_DB}" -c "DROP DATABASE IF EXISTS ${DUMP_DB};"
pg_exec "${POSTGRES_DB}" -c "CREATE DATABASE ${DUMP_DB};"

DUMP_DSN="host=${DB_HOST} user=${POSTGRES_USER} password=${POSTGRES_PASSWORD} dbname=${DUMP_DB} port=${DB_PORT} sslmode=disable"
log "applying incremental migrations to ${DUMP_DB}"
(
  cd "${ROOT_DIR}"
  ARGUS_DB_FORCE_INCREMENTAL=1 go run ./server/cmd/argus-server \
    --db "${DUMP_DSN}" --migrate-only --db-migration-mode apply
)

log "writing ${SCHEMA_OUT}"
mkdir -p "${SCHEMA_DIR}"
{
  cat <<'EOF'
-- Current-state PostgreSQL schema for empty Argus databases.
-- Generated from an empty database after applying incremental migrations.
-- Do not edit by hand. Regenerate with: make db-schema-dump
-- Existing databases keep using server/internal/db/migrations/*.sql.

EOF
  pg_dump_schema "${DUMP_DB}" | python3 -c '
import sys
wrote = False
pending_blank = False
for raw in sys.stdin:
    line = raw.rstrip("\n")
    if line.startswith("\\") or line.startswith("--"):
        continue
    if line.strip() == "":
        pending_blank = wrote
        continue
    if pending_blank:
        print()
    print(line)
    wrote = True
    pending_blank = False
'
} > "${SCHEMA_OUT}"

log "writing ${VERSIONS_OUT}"
pg_exec "${DUMP_DB}" -Atc "SELECT version FROM schema_migrations ORDER BY version;" > "${VERSIONS_OUT}"

log "syncing ${SEED_OUT} from 020"
{
  cat <<'EOF'
-- Minimal empty-database seed. Keep in sync with
-- server/internal/db/migrations/020_seed-admin-and-fix-roles.sql.
-- Existing databases still apply that incremental file.

EOF
  cat "${SEED_SRC}"
} > "${SEED_OUT}"

log "done: $(wc -l < "${SCHEMA_OUT}" | tr -d ' ') schema lines, $(wc -l < "${VERSIONS_OUT}" | tr -d ' ') stamped versions"
