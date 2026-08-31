#!/usr/bin/env bash
# db-init.sh --container 负向测试；Docker 可用时再跑一次性 ephemeral Postgres 冒烟。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INIT="${ROOT}/deploy/db-init.sh"
SMOKE_NAME=""

cleanup() {
  if [[ -n "${SMOKE_NAME}" ]]; then
    docker rm -f "${SMOKE_NAME}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

expect_fail_match() {
  local desc="$1"
  local pattern="$2"
  shift 2
  local out rc
  set +e
  out="$("$@" 2>&1)"
  rc=$?
  set -e
  if [[ "${rc}" -eq 0 ]]; then
    echo "FAIL: expected failure (${desc})" >&2
    echo "${out}" >&2
    exit 1
  fi
  if ! grep -Eq -- "${pattern}" <<<"${out}"; then
    echo "FAIL: ${desc}: output did not match /${pattern}/" >&2
    echo "${out}" >&2
    exit 1
  fi
  echo "ok: ${desc}"
}

[[ -x "${INIT}" ]] || chmod +x "${INIT}"

expect_fail_match "illegal container name" "非法容器名" bash "${INIT}" --container '../etc'
expect_fail_match "empty container flag" "--container 需要容器名" bash "${INIT}" --container ""

if ! command -v docker >/dev/null 2>&1; then
  echo "skip: docker 不在 PATH，未跑未知容器/冒烟测试"
  echo "db-init --container checks passed (host-only)"
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  echo "skip: 无法连接 Docker daemon，未跑未知容器/冒烟测试"
  echo "db-init --container checks passed (host-only)"
  exit 0
fi

expect_fail_match "unknown container" "找不到容器" bash "${INIT}" --container argus-db-init-missing-xyz999

SMOKE_NAME="argus-db-init-test-$$"
docker rm -f "${SMOKE_NAME}" >/dev/null 2>&1 || true
docker run -d --name "${SMOKE_NAME}" \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=argus_dev_pg_S7m9Q4r2L8xP6nV3 \
  -e POSTGRES_DB=argus \
  postgres:15-alpine >/dev/null

# 验收：已停止的容器会 docker start 后再初始化。
docker stop "${SMOKE_NAME}" >/dev/null

echo "running container smoke against ${SMOKE_NAME} ..."
bash "${INIT}" --container "${SMOKE_NAME}" --no-backup

ver="$(docker exec "${SMOKE_NAME}" psql -U postgres -d argus -tAc "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1" | tr -d '[:space:]')"
[[ -n "${ver}" ]] || { echo "FAIL: schema_migrations 无版本" >&2; exit 1; }
echo "ok: init schema version ${ver}"

echo "running container topup ..."
bash "${INIT}" --container "${SMOKE_NAME}" --no-backup
ver2="$(docker exec "${SMOKE_NAME}" psql -U postgres -d argus -tAc "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1" | tr -d '[:space:]')"
[[ "${ver2}" == "${ver}" ]] || { echo "FAIL: topup changed version ${ver} -> ${ver2}" >&2; exit 1; }
echo "ok: topup kept schema version ${ver2}"

echo "db-init --container checks passed"
