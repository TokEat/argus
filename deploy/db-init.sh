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
# 依赖：psql、pg_dump（PostgreSQL 客户端工具）。
# 用法示例：
#   deploy/db-init.sh                                   # 全默认（本地开发库）
#   POSTGRES_HOST=db POSTGRES_DB=argus POSTGRES_USER=argus \
#     POSTGRES_PASSWORD=xxx ARGUS_ADMIN_POSTGRES_PASSWORD=yyy deploy/db-init.sh
#   deploy/db-init.sh --dsn "host=... dbname=... user=... password=..." \
#                     --admin-dsn "host=... user=postgres password=..." --no-backup
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

YELLOW='\033[1;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[db-init]${NC} $*"; }
warn()  { echo -e "${YELLOW}[db-init]${NC} $*" >&2; }
fail()  { echo -e "${RED}[db-init][FAIL]${NC} $*" >&2; exit 1; }

usage() {
  sed -n '2,19p' "${BASH_SOURCE[0]}"; exit 1
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dsn) APP_DSN="$2"; shift 2 ;;
    --admin-dsn) ADMIN_DSN="$2"; shift 2 ;;
    --no-bootstrap) BOOTSTRAP=0; shift ;;
    --no-backup) BACKUP=0; shift ;;
    -h|--help) usage ;;
    *) fail "未知参数: $1（--help 查看用法）" ;;
  esac
done

[[ -f "${DB_DIR}/init/001_init.sql" ]] || fail "未找到 ${DB_DIR}/init/001_init.sql"

if [[ -z "${APP_DSN}" ]]; then
  APP_DSN="host=${POSTGRES_HOST} port=${POSTGRES_PORT} dbname=${POSTGRES_DB} user=${POSTGRES_USER} password=${POSTGRES_PASSWORD} sslmode=disable"
fi
psql_app()     { psql "$APP_DSN" -v ON_ERROR_STOP=1 "$@"; }
psql_admin()   { psql "$ADMIN_DSN" -v ON_ERROR_STOP=1 "$@"; }

# ---------- 1. 等待 PostgreSQL 就绪（不依赖 docker） ----------
wait_for_pg() {
  local dsn="$1" i
  for i in $(seq 1 30); do
    if psql "$dsn" -tAc "SELECT 1" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  return 1
}
command -v psql >/dev/null 2>&1 || fail "未找到 psql，请先安装 PostgreSQL 客户端工具"

# ---------- 2. 建角色/建库（bootstrap，幂等） ----------
if [[ "${BOOTSTRAP}" -eq 1 ]]; then
  if [[ -z "${ADMIN_DSN}" ]]; then
    ADMIN_DSN="host=${POSTGRES_HOST} port=${POSTGRES_PORT} dbname=postgres user=${POSTGRES_USER} password=${ARGUS_ADMIN_POSTGRES_PASSWORD} sslmode=disable"
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
      pg_dump "${APP_DSN}" -Fc -f "${BACKUP_FILE}" || fail "备份失败；为安全起见已中止（可 --no-backup 跳过）"
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
for f in "${INIT_FILES[@]}"; do
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
[[ "${TABLE_COUNT}" -ge 70 ]] || fail "自检失败：表数量异常（${TABLE_COUNT}）"
[[ -n "${VERSION_ROW}" ]]        || fail "自检失败：schema_migrations 无版本记录"
[[ "${ADMIN_COUNT}" -ge 1 ]]     || fail "自检失败：默认管理员缺失"

info "数据库初始化完成：表 ${TABLE_COUNT} 张，schema 版本 ${VERSION_ROW}。"
info "下一步：直接启动 argus-server（启动时仅做校验，不再迁移）。"
