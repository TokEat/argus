#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SQL_DIR="${SCRIPT_DIR}/sql"
BOOTSTRAP_SQL="${SQL_DIR}/001-bootstrap.sql"

DB_PORT="${DB_PORT:-${PGPORT:-5432}}"
DB_SUPERDB="${DB_SUPERDB:-${PGSUPERDB:-postgres}}"
DB_SUPERUSER="${DB_SUPERUSER:-${PGSUPERUSER:-${POSTGRES_USER:-postgres}}}"
DB_SUPERPASSWORD="${DB_SUPERPASSWORD:-${PGSUPERPASSWORD:-${POSTGRES_PASSWORD:-argus_dev_pg_S7m9Q4r2L8xP6nV3}}}"

APP_DB_NAME="${APP_DB_NAME:-${POSTGRES_DB:-dddd}}"
APP_DB_USER="${APP_DB_USER:-${POSTGRES_USER:-postgres}}"
APP_DB_PASSWORD="${APP_DB_PASSWORD:-${POSTGRES_PASSWORD:-argus_dev_pg_S7m9Q4r2L8xP6nV3}}"

PSQL_COMMON_ARGS=(
  -X
  -v
  ON_ERROR_STOP=1
  -p
  "${DB_PORT}"
)

if [[ -n "${DB_HOST:-${PGHOST:-}}" ]]; then
  PSQL_COMMON_ARGS+=(
    -h
    "${DB_HOST:-${PGHOST}}"
  )
elif [[ -d /var/run/postgresql ]]; then
  PSQL_COMMON_ARGS+=(
    -h
    /var/run/postgresql
  )
else
  PSQL_COMMON_ARGS+=(
    -h
    127.0.0.1
  )
fi

echo "[postgres-init] bootstrap database '${APP_DB_NAME}' for role '${APP_DB_USER}'"
PGPASSWORD="${DB_SUPERPASSWORD}" psql \
  "${PSQL_COMMON_ARGS[@]}" \
  -U "${DB_SUPERUSER}" \
  -d "${DB_SUPERDB}" \
  -v "app_db_name=${APP_DB_NAME}" \
  -v "app_db_user=${APP_DB_USER}" \
  -v "app_db_password=${APP_DB_PASSWORD}" \
  -f "${BOOTSTRAP_SQL}"

echo "[postgres-init] bootstrap complete"
echo "[postgres-init] next step: run dddd-server --migrate-only (or start dddd-server normally) to apply schema migrations"
