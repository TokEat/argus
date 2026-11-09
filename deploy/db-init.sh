#!/usr/bin/env bash
# Argus 数据库初始化（纯 SQL，psql 导入，不依赖 argus-server 二进制）。
#
# 职责边界：
#   - 本脚本负责数据库初始化/升级（建角色/建库 + schema 导入 + 种子 + 自检）。
#   - argus-server 启动时仅校验数据库（版本 + 表/列/索引契约），不再执行任何迁移。
#
# 三种库状态的处理：
#   1. 全新空库            -> 依次导入 deploy/db/init/*.sql + seed_admin.sql
#   2. 旧 010..570 终态库  -> 先 pg_dump 备份，执行 legacy/900_cutover，再补导缺失文件
#   3. 其它未知状态        -> 拒绝操作并提示人工处理
#
# 依赖：宿主机 bash；默认还需要本机 psql/pg_dump。指定 --container 时改在
# PostgreSQL 容器内调用配套客户端，宿主机不必安装 PostgreSQL 客户端。
# 用法示例：
#   deploy/db-init.sh                                   # 全默认（本地开发库）
#   POSTGRES_HOST=db POSTGRES_DB=argus POSTGRES_USER=argus \
#     POSTGRES_PASSWORD=xxx ARGUS_ADMIN_POSTGRES_PASSWORD=yyy deploy/db-init.sh
#   deploy/db-init.sh --dsn "host=... dbname=... user=... password=..." \
#                     --admin-dsn "host=... user=postgres password=..." --no-backup
#   deploy/db-init.sh --container argus-postgres         # 在指定容器内执行
#   ARGUS_DB_CONTAINER=argus-postgres deploy/db-init.sh --no-backup
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_DIR="${SCRIPT_DIR}/db"

# ---------- 参数默认值 ----------
POSTGRES_HOST="${POSTGRES_HOST:-127.0.0.1}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-argus}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-argus_dev_pg_S7m9Q4r2L8xP6nV3}"
ARGUS_ADMIN_POSTGRES_PASSWORD="${ARGUS_ADMIN_POSTGRES_PASSWORD:-${POSTGRES_PASSWORD}}"
APP_DSN=""
ADMIN_DSN=""
BOOTSTRAP=1
BACKUP=1
CONTAINER="${ARGUS_DB_CONTAINER:-}"

YELLOW='\033[1;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[db-init]${NC} $*"; }
warn()  { echo -e "${YELLOW}[db-init]${NC} $*" >&2; }
fail()  { echo -e "${RED}[db-init][FAIL]${NC} $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Argus 数据库初始化（纯 SQL，psql 导入，不依赖 argus-server 二进制）。

用法:
  deploy/db-init.sh [选项]

选项:
  --container NAME   在指定 Docker 容器内执行 psql/pg_dump（宿主机无需安装客户端）
  --dsn DSN          应用库连接串；配合 --container 时是容器内地址
  --admin-dsn DSN    管理员连接串（bootstrap 连接 postgres 库）
  --no-bootstrap     跳过建角色/建库
  --no-backup        跳过存量旧库 cutover 前的 pg_dump
  -h, --help         显示本说明

环境变量:
  ARGUS_DB_CONTAINER              等同 --container
  POSTGRES_HOST/PORT/DB/USER/PASSWORD
  ARGUS_ADMIN_POSTGRES_PASSWORD

示例:
  deploy/db-init.sh
  deploy/db-init.sh --container argus-postgres
  make db-setup
  make db-setup POSTGRES_CONTAINER=argus-postgres
EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dsn) APP_DSN="$2"; shift 2 ;;
    --admin-dsn) ADMIN_DSN="$2"; shift 2 ;;
    --container)
      [[ -n "${2:-}" ]] || fail "--container 需要容器名或 ID"
      CONTAINER="$2"
      shift 2
      ;;
    --no-bootstrap) BOOTSTRAP=0; shift ;;
    --no-backup) BACKUP=0; shift ;;
    -h|--help) usage ;;
    *) fail "未知参数: $1（--help 查看用法）" ;;
  esac
done

[[ -f "${DB_DIR}/init/001_init.sql" ]] || fail "未找到 ${DB_DIR}/init/001_init.sql"

if [[ -n "${CONTAINER}" ]]; then
  [[ "${CONTAINER}" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || fail "非法容器名或 ID: ${CONTAINER}"
fi

# 指定容器时，连接的是容器内 Postgres，默认走 loopback:5432，忽略宿主机 POSTGRES_HOST/PORT。
if [[ -n "${CONTAINER}" && -z "${APP_DSN}" ]]; then
  APP_DSN="host=127.0.0.1 port=5432 dbname=${POSTGRES_DB} user=${POSTGRES_USER} password=${POSTGRES_PASSWORD} sslmode=disable"
elif [[ -z "${APP_DSN}" ]]; then
  APP_DSN="host=${POSTGRES_HOST} port=${POSTGRES_PORT} dbname=${POSTGRES_DB} user=${POSTGRES_USER} password=${POSTGRES_PASSWORD} sslmode=disable"
fi

run_psql() {
  local dsn="$1"
  shift
  local -a args=()
  local sql_file=""
  while [[ $# -gt 0 ]]; do
    if [[ "$1" == "-f" ]]; then
      [[ -n "${2:-}" ]] || fail "psql -f 需要文件路径"
      sql_file="$2"
      shift 2
      continue
    fi
    args+=("$1")
    shift
  done
  if [[ -z "${CONTAINER}" ]]; then
    # bash 4.4 之前，set -u 会把空数组视为未绑定变量（args[@]: unbound variable）；
    # 仅在数组非空时展开。
    if [[ -n "${sql_file}" ]]; then
      psql "$dsn" -v ON_ERROR_STOP=1 ${args[@]+"${args[@]}"} -f "${sql_file}"
    else
      psql "$dsn" -v ON_ERROR_STOP=1 ${args[@]+"${args[@]}"}
    fi
    return
  fi
  if [[ -n "${sql_file}" ]]; then
    [[ -f "${sql_file}" ]] || fail "SQL 文件不存在: ${sql_file}"
    docker exec -i "${CONTAINER}" psql "$dsn" -v ON_ERROR_STOP=1 ${args[@]+"${args[@]}"} -f - < "${sql_file}"
    return
  fi
  docker exec "${CONTAINER}" psql "$dsn" -v ON_ERROR_STOP=1 ${args[@]+"${args[@]}"}
}

psql_app()   { run_psql "$APP_DSN" "$@"; }
psql_admin() { run_psql "$ADMIN_DSN" "$@"; }

run_pg_dump() {
  local dsn="$1" out="$2"
  if [[ -z "${CONTAINER}" ]]; then
    command -v pg_dump >/dev/null 2>&1 || fail "未找到 pg_dump，请先安装 PostgreSQL 客户端工具，或改用 --container"
    pg_dump "$dsn" -Fc -f "$out"
    return
  fi
  docker exec "${CONTAINER}" pg_dump "$dsn" -Fc > "$out"
}

ensure_container() {
  command -v docker >/dev/null 2>&1 || fail "未找到 docker，无法使用 --container"
  docker info >/dev/null 2>&1 || fail "无法连接 Docker daemon"
  local status=""
  status="$(docker inspect -f '{{.State.Status}}' "${CONTAINER}" 2>/dev/null || true)"
  if [[ -z "${status}" ]]; then
    fail "找不到容器 ${CONTAINER}。请先 make infra-up 或 docker compose up -d postgres"
  fi
  if [[ "${status}" != "running" ]]; then
    info "容器 ${CONTAINER} 当前为 ${status}，尝试启动 ..."
    docker start "${CONTAINER}" >/dev/null || fail "无法启动容器 ${CONTAINER}"
  fi
  local i
  for i in $(seq 1 30); do
    status="$(docker inspect -f '{{.State.Status}}' "${CONTAINER}" 2>/dev/null || true)"
    if [[ "${status}" == "running" ]]; then
      break
    fi
    sleep 1
  done
  [[ "${status}" == "running" ]] || fail "容器 ${CONTAINER} 未能进入 running"
  docker exec "${CONTAINER}" sh -c 'command -v psql >/dev/null && command -v pg_dump >/dev/null' \
    || fail "容器 ${CONTAINER} 内没有 psql/pg_dump，请指定 PostgreSQL 容器"
}

# ---------- 1. 等待 PostgreSQL 就绪 ----------
wait_for_pg() {
  local dsn="$1" i
  for i in $(seq 1 30); do
    if run_psql "$dsn" -tAc "SELECT 1" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  return 1
}

if [[ -n "${CONTAINER}" ]]; then
  info "使用 Docker 容器 ${CONTAINER} 执行 psql/pg_dump"
  ensure_container
else
  command -v psql >/dev/null 2>&1 || fail "未找到 psql，请先安装 PostgreSQL 客户端工具，或改用 --container <postgres容器>"
fi

# ---------- 2. 建角色/建库（bootstrap，幂等） ----------
if [[ "${BOOTSTRAP}" -eq 1 ]]; then
  if [[ -z "${ADMIN_DSN}" ]]; then
    if [[ -n "${CONTAINER}" ]]; then
      ADMIN_DSN="host=127.0.0.1 port=5432 dbname=postgres user=${POSTGRES_USER} password=${ARGUS_ADMIN_POSTGRES_PASSWORD} sslmode=disable"
    else
      ADMIN_DSN="host=${POSTGRES_HOST} port=${POSTGRES_PORT} dbname=postgres user=${POSTGRES_USER} password=${ARGUS_ADMIN_POSTGRES_PASSWORD} sslmode=disable"
    fi
  fi
  info "等待 PostgreSQL 就绪 ..."
  wait_for_pg "${ADMIN_DSN}" || fail "PostgreSQL 未就绪（30 次重试后仍无法连接），请确认服务已启动"
  info "执行 bootstrap（建角色/建库，幂等）..."
  psql_admin -f "${DB_DIR}/bootstrap/001-bootstrap.sql" \
    -v app_db_name="${POSTGRES_DB}" -v app_db_user="${POSTGRES_USER}" -v app_db_password="${POSTGRES_PASSWORD}" >/dev/null
else
  info "跳过 bootstrap（--no-bootstrap）"
  wait_for_pg "${APP_DSN}" || fail "PostgreSQL 未就绪（30 次重试后仍无法连接），请确认服务已启动"
fi

# ---------- 3. 识别库状态 ----------
has_migrations_table() {
  psql_app -tAc "SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='schema_migrations'" | grep -q 1
}
app_table_count() {
  psql_app -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name <> 'schema_migrations'"
}
applied_versions() {
  psql_app -tAc "SELECT version FROM schema_migrations ORDER BY version" || true
}

MODE="fresh"
if has_migrations_table; then
  # 过滤已退休版本 510：旧引擎允许 DB 保留 510 历史记录（曾两度使用），
  # 视为合法证据而非未知状态。
  APPLIED_STR="$(applied_versions | grep -v '^510$' | tr '\n' ' ' | sed 's/ *$//')"
  # 旧 010..570（无 510）终态集合
  LEGACY_STR="$(sort "${DB_DIR}/legacy/versions.txt" | tr '\n' ' ' | sed 's/ *$//')"
  if [[ "${APPLIED_STR}" == "${LEGACY_STR}" ]]; then
    MODE="cutover"
  else
    # 已在新版本体系内：允许补齐缺失的 init 文件（每个已记录版本都应有对应 init 文件）
    local_ok=1
    while read -r v; do
      [[ -n "${v}" ]] || continue
      ls "${DB_DIR}/init/${v}_"*.sql >/dev/null 2>&1 || local_ok=0
    done <<< "$(applied_versions)"
    [[ ${local_ok} -eq 1 ]] && MODE="topup" || MODE="unknown"
  fi
elif [[ "$(app_table_count)" != "0" ]]; then
  MODE="unknown"
fi

case "${MODE}" in
  fresh)  info "检测到全新空库，导入最小基线 ..." ;;
  topup)  info "检测到新版本体系库（已有: ${APPLIED_STR:-无}），补齐缺失的 init 文件 ..." ;;
  cutover)
    warn "检测到旧 010..570 增量链终态库，将执行一次性切换（cutover）。"
    if [[ "${BACKUP}" -eq 1 ]]; then
      BACKUP_DIR="${SCRIPT_DIR}/backup"
      mkdir -p "${BACKUP_DIR}"
      BACKUP_FILE="${BACKUP_DIR}/db-$(date +%Y%m%d-%H%M%S).dump"
      info "备份当前数据库 -> ${BACKUP_FILE}"
      run_pg_dump "${APP_DSN}" "${BACKUP_FILE}" || fail "备份失败；为安全起见已中止（可 --no-backup 跳过）"
    else
      warn "已指定 --no-backup，跳过升级前备份。"
    fi
    info "执行 legacy/900_cutover_from_010_570.sql ..."
    # cutover 文件自带 BEGIN/COMMIT，不加 -1 避免双重事务
    psql_app -f "${DB_DIR}/legacy/900_cutover_from_010_570.sql" >/dev/null
    ;;
  unknown)
    fail "数据库处于未知状态（schema_migrations 版本无法识别，或存在应用表但无版本记录）。
    请人工核查后处理：pg_dump 备份 -> 重建空库 -> 重新运行本脚本导入，再迁移数据。"
    ;;
esac

# ---------- 4. 按序导入 init 文件（版本未记录的才执行） ----------
shopt -s nullglob
INIT_FILES=("${DB_DIR}"/init/[0-9]*.sql)
shopt -u nullglob
# bash 4.4 之前，set -u 会把空数组视为未绑定变量；仅在数组非空时展开。
for f in ${INIT_FILES[@]+"${INIT_FILES[@]}"}; do
  base="$(basename "$f")"
  ver="${base%%_*}"
  if [[ "${MODE}" != "fresh" ]] && psql_app -tAc "SELECT 1 FROM schema_migrations WHERE version='${ver}'" | grep -q 1; then
    info "跳过 ${base}（版本 ${ver} 已应用）"
    continue
  fi
  info "导入 ${base} ..."
  psql_app -1 -q -f "$f"
done

# ---------- 5. 种子（幂等，总是执行） ----------
info "导入默认管理员种子 ..."
psql_app -1 -q -f "${DB_DIR}/init/seed_admin.sql"

# ---------- 6. 自检 ----------
TABLE_COUNT="$(psql_app -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'")"
VERSION_ROW="$(psql_app -tAc "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1")"
ADMIN_COUNT="$(psql_app -tAc "SELECT count(*) FROM users WHERE username='admin'")"
TABLE_COUNT="$(echo "${TABLE_COUNT}" | tr -d '[:space:]')"
VERSION_ROW="$(echo "${VERSION_ROW}" | tr -d '[:space:]')"
ADMIN_COUNT="$(echo "${ADMIN_COUNT}" | tr -d '[:space:]')"
[[ "${TABLE_COUNT}" -ge 70 ]] || fail "自检失败：表数量异常（${TABLE_COUNT}）"
[[ -n "${VERSION_ROW}" ]]        || fail "自检失败：schema_migrations 无版本记录"
[[ "${ADMIN_COUNT}" -ge 1 ]]     || fail "自检失败：默认管理员缺失"

info "数据库初始化完成：表 ${TABLE_COUNT} 张，schema 版本 ${VERSION_ROW}。"
if [[ -n "${CONTAINER}" ]]; then
  info "下一步：直接启动 argus-server（启动时仅做校验，不再迁移）。容器=${CONTAINER}"
else
  info "下一步：直接启动 argus-server（启动时仅做校验，不再迁移）。"
fi
