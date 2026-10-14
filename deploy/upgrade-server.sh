#!/bin/bash
# ==============================================================================
# Argus Server 原地升级脚本
#
# 在已安装的生产环境上运行新版发布包中的本脚本，可在不卸载、不删除数据的
# 前提下替换服务端/Agent/前端资源，执行数据库迁移并重启服务。
#
# 用法：
#   tar -xzf argus-release-vX.Y.Z-linux-amd64.tar.gz
#   cd argus-release-vX.Y.Z
#   sudo ./deploy/upgrade-server.sh
#
# 凭据兼容（重点）：
#   全部凭据统一收敛到 ${INSTALL_DIR}/config/secrets.env（0600）。本脚本按
#   "显式参数/env → secrets.env → 旧 service 回退" 的顺序解析；旧环境（密钥
#   明文写在 service / DSN / AMQP URL 里）会自动迁移到新格式并生成 secrets.env。
#   已初始化数据卷的 PostgreSQL/RabbitMQ/MinIO root 凭据以容器实际值为准。
#
# 可选参数：
#   --install-dir <dir>   指定旧安装目录；默认从 argus-server.service 读取
#   --db <dsn>            指定数据库 DSN；默认从 secrets.env / systemd ExecStart 读取
#   --skip-backup         跳过 pg_dump 备份（不推荐）
#   -y, --yes             非交互确认
# ==============================================================================

set -euo pipefail
export LANG="${LANG:-C.UTF-8}"
export LC_ALL="${LC_ALL:-C.UTF-8}"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
    sed -n '2,29s/^# \{0,1\}//p' "$0"
}

die() {
    echo -e "${RED}[!] $*${NC}" >&2
    exit 1
}

# 载入共享库：密钥生成 / secrets.env 写入 / systemd unit 渲染 / 容器与文件读取
# shellcheck source=lib/argus-env.sh
source "${SCRIPT_DIR}/lib/argus-env.sh"

SERVICE_NAME="${ARGUS_SERVICE_NAME:-argus-server}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
INSTALL_DIR="${INSTALL_DIR:-}"
DB_DSN="${ARGUS_DB_DSN:-}"
EGRESS_GATEWAY_LISTEN="${ARGUS_EGRESS_GATEWAY_LISTEN:-}"
EGRESS_GATEWAY_TOKEN="${ARGUS_EGRESS_GATEWAY_TOKEN:-}"
CREDENTIAL_ENCRYPT_KEY="${ARGUS_CREDENTIAL_ENCRYPT_KEY:-}"
GRPC_TLS_PORT="${ARGUS_GRPC_TLS_PORT:-}"
GRPC_TLS_CERT="${ARGUS_GRPC_TLS_CERT:-}"
GRPC_TLS_KEY="${ARGUS_GRPC_TLS_KEY:-}"
MINIO_ROOT_USER="${MINIO_ROOT_USER:-}"
MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-}"
MINIO_API_PORT="${MINIO_API_PORT:-}"
MINIO_CONSOLE_PORT="${MINIO_CONSOLE_PORT:-}"
EXP_MINIO_ACCESS_KEY="${ARGUS_EXP_MINIO_ACCESS_KEY:-}"
EXP_MINIO_SECRET_KEY="${ARGUS_EXP_MINIO_SECRET_KEY:-}"
EXP_MINIO_ENDPOINT="${ARGUS_EXP_MINIO_ENDPOINT:-}"
EXP_MINIO_REGION="${ARGUS_EXP_MINIO_REGION:-}"
EXP_MINIO_BUCKET="${ARGUS_EXP_MINIO_BUCKET:-}"
EXP_MINIO_USE_SSL="${ARGUS_EXP_MINIO_USE_SSL:-}"
EXP_TRACE_RETENTION="${ARGUS_EXP_TRACE_RETENTION:-}"
YAKSHA_URL="${ARGUS_YAKSHA_URL:-}"
RABBITMQ_DEFAULT_USER="${RABBITMQ_DEFAULT_USER:-}"
RABBITMQ_DEFAULT_PASS="${RABBITMQ_DEFAULT_PASS:-}"
RABBITMQ_PORT="${RABBITMQ_PORT:-}"
RABBITMQ_MANAGEMENT_PORT="${RABBITMQ_MANAGEMENT_PORT:-}"
POSTGRES_USER="${POSTGRES_USER:-}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"
POSTGRES_DB="${POSTGRES_DB:-}"
POSTGRES_PORT="${POSTGRES_PORT:-}"
AGENT_PSK="${AGENT_PSK:-}"
JWT_SECRET="${JWT_SECRET:-}"
ENCRYPT_KEY="${ENCRYPT_KEY:-}"
SKIP_BACKUP=false
ASSUME_YES=false

if [[ -n "$EGRESS_GATEWAY_LISTEN" || -n "$EGRESS_GATEWAY_TOKEN" ]]; then
    if [[ -z "$EGRESS_GATEWAY_LISTEN" || -z "$EGRESS_GATEWAY_TOKEN" ]]; then
        die "ARGUS_EGRESS_GATEWAY_LISTEN 与 ARGUS_EGRESS_GATEWAY_TOKEN 必须成对配置"
    fi
fi
if [[ -n "$GRPC_TLS_PORT" || -n "$GRPC_TLS_CERT" || -n "$GRPC_TLS_KEY" ]]; then
    if [[ -z "$GRPC_TLS_PORT" || -z "$GRPC_TLS_CERT" || -z "$GRPC_TLS_KEY" ]]; then
        die "ARGUS_GRPC_TLS_PORT、ARGUS_GRPC_TLS_CERT、ARGUS_GRPC_TLS_KEY 必须成组配置"
    fi
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        --db) DB_DSN="$2"; shift 2 ;;
        --skip-backup) SKIP_BACKUP=true; shift ;;
        -y|--yes) ASSUME_YES=true; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "未知参数: $1" ;;
    esac
done

if [[ "${EUID}" -ne 0 ]]; then
    die "请使用 sudo 运行升级脚本"
fi

if [[ ! -f "$SERVICE_FILE" && -z "$INSTALL_DIR" ]]; then
    die "未找到 ${SERVICE_FILE}，请确认已安装 Argus，或用 --install-dir 指定旧安装目录"
fi

service_execstart() {
    [[ -f "$SERVICE_FILE" ]] || return 0
    awk '
        /^ExecStart=/ {
            line=$0
            sub(/^ExecStart=/, "", line)
            while (line ~ /\\[[:space:]]*$/ && getline nextLine) {
                sub(/\\[[:space:]]*$/, "", line)
                sub(/^[[:space:]]+/, "", nextLine)
                line = line " " nextLine
            }
            print line
            exit
        }
    ' "$SERVICE_FILE"
}

service_workdir() {
    [[ -f "$SERVICE_FILE" ]] || return 0
    awk -F= '/^WorkingDirectory=/{print $2; exit}' "$SERVICE_FILE"
}

service_environment() {
    local key="$1"
    [[ -f "$SERVICE_FILE" ]] || return 0
    sed -nE "s/^Environment=${key}=(.*)$/\1/p" "$SERVICE_FILE" | tail -n 1
}

extract_quoted_arg() {
    local flag="$1"
    local command_line="$2"
    printf '%s\n' "$command_line" | sed -nE "s/.*(^|[[:space:]])${flag}[[:space:]]+\"([^\"]*)\".*/\2/p" | head -n 1
}

extract_plain_arg() {
    local flag="$1"
    local command_line="$2"
    printf '%s\n' "$command_line" | sed -nE "s/.*(^|[[:space:]])${flag}[[:space:]]+\"?([^\"[:space:]]+)\"?.*/\2/p" | head -n 1
}

find_first_file() {
    local candidate
    for candidate in "$@"; do
        if [[ -f "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

# 从 amqp://user:pass@host:port/ 中解析用户名/密码（历史生成的均为 hex，安全）
parse_amqp_user() { sed -nE 's#^amqp://([^:/]+):.*$#\1#p' <<<"$1"; }
parse_amqp_pass() { sed -nE 's#^amqp://[^:/]+:([^@]+)@.*$#\1#p' <<<"$1"; }

# 应用密钥（PSK/JWT/ENCRYPT/CREDENTIAL_ENCRYPT）三级回退：
#   env/CLI → secrets.env → 旧 service 的 Environment 行 / ExecStart 参数
resolve_app_secret() {
    local var="$1" argus_name="$2"; shift 2
    local val="${!var:-}"
    if [[ -z "$val" ]]; then
        val="$(env_file_value "$SECRETS_ENV_FILE" "$argus_name")"
    fi
    if [[ -z "$val" ]]; then
        val="$(service_environment "$argus_name")"
    fi
    if [[ -z "$val" ]]; then
        local flag
        for flag in "$@"; do
            val="$(extract_quoted_arg "$flag" "$SERVICE_CMD" || true)"
            [[ -n "$val" ]] && break
        done
    fi
    # 新格式 service 的 ExecStart 里可能是 "${ARGUS_XXX}" 变量引用，非真实值，剔除后由调用方生成
    if [[ "$val" == '${'* ]]; then
        val=""
    fi
    printf -v "$var" '%s' "$val"
}

SERVICE_CMD="$(service_execstart || true)"

if [[ -z "$INSTALL_DIR" ]]; then
    INSTALL_DIR="$(service_workdir || true)"
fi
INSTALL_DIR="${INSTALL_DIR:-/opt/argus}"

SECRETS_ENV_FILE="${INSTALL_DIR}/config/secrets.env"
MINIO_ENV_FILE="${INSTALL_DIR}/config/minio.env"
EXP_STORAGE_ENV_FILE="${INSTALL_DIR}/config/exp-storage.env"

# ---- 解析安装目录后立即解析全部凭据（顺序：显式 → secrets.env → 旧回退 → 容器权威 → 生成）----

# EGRESS / TLS / PUBLIC_IP：env/CLI → secrets.env → 旧 service Environment 行
# （regenerate service 前必须读到旧值；token 已迁入 secrets.env，LISTEN 仍在 unit 内联）
EGRESS_GATEWAY_LISTEN="${EGRESS_GATEWAY_LISTEN:-$(env_file_value "$SECRETS_ENV_FILE" ARGUS_EGRESS_GATEWAY_LISTEN)}"
EGRESS_GATEWAY_TOKEN="${EGRESS_GATEWAY_TOKEN:-$(env_file_value "$SECRETS_ENV_FILE" ARGUS_EGRESS_GATEWAY_TOKEN)}"
if [[ -z "$EGRESS_GATEWAY_LISTEN" && -z "$EGRESS_GATEWAY_TOKEN" ]]; then
    EGRESS_GATEWAY_LISTEN="$(service_environment ARGUS_EGRESS_GATEWAY_LISTEN || true)"
    EGRESS_GATEWAY_TOKEN="$(service_environment ARGUS_EGRESS_GATEWAY_TOKEN || true)"
fi
if [[ -n "$EGRESS_GATEWAY_LISTEN" || -n "$EGRESS_GATEWAY_TOKEN" ]]; then
    if [[ -z "$EGRESS_GATEWAY_LISTEN" || -z "$EGRESS_GATEWAY_TOKEN" ]]; then
        die "现有 Gateway 配置不完整，请成对设置 ARGUS_EGRESS_GATEWAY_LISTEN/TOKEN"
    fi
fi
if [[ -z "$GRPC_TLS_PORT" && -z "$GRPC_TLS_CERT" && -z "$GRPC_TLS_KEY" ]]; then
    GRPC_TLS_PORT="$(service_environment ARGUS_GRPC_TLS_PORT || true)"
    GRPC_TLS_CERT="$(service_environment ARGUS_GRPC_TLS_CERT || true)"
    GRPC_TLS_KEY="$(service_environment ARGUS_GRPC_TLS_KEY || true)"
fi
PUBLIC_IP="$(service_environment ARGUS_PUBLIC_IP || true)"

# 数据库 DSN：显式 → secrets.env → 旧 ExecStart（新格式 ExecStart 里是变量引用，需剔除）
if [[ -z "$DB_DSN" ]]; then
    DB_DSN="$(env_file_value "$SECRETS_ENV_FILE" ARGUS_DB_DSN)"
fi
if [[ -z "$DB_DSN" && -n "$SERVICE_CMD" ]]; then
    DB_DSN="$(extract_quoted_arg "-db" "$SERVICE_CMD" || true)"
fi
if [[ "$DB_DSN" == '${'* ]]; then
    # 新格式 service 的 -db "${ARGUS_DB_DSN}"，真实值在 secrets.env（上方已读取）
    DB_DSN=""
fi
if [[ -z "$DB_DSN" ]]; then
    die "未能解析数据库 DSN，请使用 --db 或 ARGUS_DB_DSN 显式指定"
fi

dsn_field() {
    local key="$1"
    printf '%s\n' "$DB_DSN" | tr ' ' '\n' | awk -F= -v key="$key" '$1 == key {print substr($0, length(key)+2); exit}'
}

# PostgreSQL：env → DSN 字段 → secrets.env；再按容器实际值锁定
POSTGRES_USER="${POSTGRES_USER:-$(dsn_field user)}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(dsn_field password)}"
POSTGRES_DB="${POSTGRES_DB:-$(dsn_field dbname)}"
POSTGRES_PORT="${POSTGRES_PORT:-$(dsn_field port)}"
POSTGRES_USER="${POSTGRES_USER:-$(env_file_value "$SECRETS_ENV_FILE" POSTGRES_USER)}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(env_file_value "$SECRETS_ENV_FILE" POSTGRES_PASSWORD)}"
POSTGRES_DB="${POSTGRES_DB:-$(env_file_value "$SECRETS_ENV_FILE" POSTGRES_DB)}"
POSTGRES_PORT="${POSTGRES_PORT:-$(env_file_value "$SECRETS_ENV_FILE" POSTGRES_PORT)}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
if [[ -z "${POSTGRES_PASSWORD}" ]]; then
    die "数据库 DSN 缺少 password 字段，请使用 --db 或 ARGUS_DB_DSN 显式指定完整 DSN"
fi
POSTGRES_DB="${POSTGRES_DB:-argus}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
resolve_volume_locked_cred POSTGRES_PASSWORD argus-postgres
# 用锁定后的最终值替换 DSN 中的 password= 字段，确保 ARGUS_DB_DSN 与 POSTGRES_PASSWORD
# 一致（容器权威）。只动 password 字段、保留 DSN 其余部分，显式 --db 指向外部 PG 时
# 的 host/sslmode 等参数不被吞掉（DSN 为 key=value 空格分隔，password 值本身不含空格）。
if [[ "$DB_DSN" == *"password="* ]]; then
    _dsn_before="${DB_DSN%%password=*}"
    _dsn_after="${DB_DSN#*password=}"
    if [[ "$_dsn_after" == *" "* ]]; then
        DB_DSN="${_dsn_before}password=${POSTGRES_PASSWORD} ${_dsn_after#* }"
    else
        DB_DSN="${_dsn_before}password=${POSTGRES_PASSWORD}"
    fi
fi
unset _dsn_before _dsn_after

# RabbitMQ：env → secrets.env → 旧 ExecStart 的 -amqp URL 反解；再按容器实际值锁定
RABBITMQ_DEFAULT_USER="${RABBITMQ_DEFAULT_USER:-$(env_file_value "$SECRETS_ENV_FILE" RABBITMQ_DEFAULT_USER)}"
RABBITMQ_DEFAULT_PASS="${RABBITMQ_DEFAULT_PASS:-$(env_file_value "$SECRETS_ENV_FILE" RABBITMQ_DEFAULT_PASS)}"
RABBITMQ_PORT="${RABBITMQ_PORT:-$(env_file_value "$SECRETS_ENV_FILE" RABBITMQ_PORT)}"
RABBITMQ_MANAGEMENT_PORT="${RABBITMQ_MANAGEMENT_PORT:-$(env_file_value "$SECRETS_ENV_FILE" RABBITMQ_MANAGEMENT_PORT)}"
if [[ -z "$RABBITMQ_DEFAULT_PASS" && -n "$SERVICE_CMD" ]]; then
    AMQP_EXTRACTED="$(extract_quoted_arg "-amqp" "$SERVICE_CMD" || true)"
    if [[ -n "$AMQP_EXTRACTED" && "$AMQP_EXTRACTED" != '${'* ]]; then
        RABBITMQ_DEFAULT_USER="${RABBITMQ_DEFAULT_USER:-$(parse_amqp_user "$AMQP_EXTRACTED")}"
        RABBITMQ_DEFAULT_PASS="${RABBITMQ_DEFAULT_PASS:-$(parse_amqp_pass "$AMQP_EXTRACTED")}"
    fi
fi
RABBITMQ_DEFAULT_USER="${RABBITMQ_DEFAULT_USER:-argus}"
RABBITMQ_PORT="${RABBITMQ_PORT:-5672}"
RABBITMQ_MANAGEMENT_PORT="${RABBITMQ_MANAGEMENT_PORT:-15672}"
if [[ -z "$RABBITMQ_DEFAULT_PASS" ]]; then
    die "未能解析 RabbitMQ 密码（secrets.env 与旧 service 均无），请显式设置 RABBITMQ_DEFAULT_PASS"
fi
resolve_volume_locked_cred RABBITMQ_DEFAULT_PASS argus-rabbitmq
AMQP_URL="amqp://${RABBITMQ_DEFAULT_USER}:${RABBITMQ_DEFAULT_PASS}@127.0.0.1:${RABBITMQ_PORT}/"

# MinIO root：env → secrets.env → 旧 minio.env；再按容器实际值锁定
MINIO_ROOT_USER="${MINIO_ROOT_USER:-$(env_file_value "$SECRETS_ENV_FILE" MINIO_ROOT_USER)}"
MINIO_ROOT_USER="${MINIO_ROOT_USER:-$(env_file_value "$MINIO_ENV_FILE" MINIO_ROOT_USER)}"
MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-$(env_file_value "$SECRETS_ENV_FILE" MINIO_ROOT_PASSWORD)}"
MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-$(env_file_value "$MINIO_ENV_FILE" MINIO_ROOT_PASSWORD)}"
MINIO_API_PORT="${MINIO_API_PORT:-$(env_file_value "$MINIO_ENV_FILE" MINIO_API_PORT)}"
MINIO_CONSOLE_PORT="${MINIO_CONSOLE_PORT:-$(env_file_value "$MINIO_ENV_FILE" MINIO_CONSOLE_PORT)}"
resolve_volume_locked_cred MINIO_ROOT_PASSWORD argus-minio
resolve_volume_locked_cred MINIO_ROOT_USER argus-minio
MINIO_ROOT_USER="${MINIO_ROOT_USER:-argus-minio-root}"
MINIO_API_PORT="${MINIO_API_PORT:-9000}"
MINIO_CONSOLE_PORT="${MINIO_CONSOLE_PORT:-9001}"

# EXP_MINIO 应用用户：env → secrets.env → 旧 exp-storage.env → 生成
EXP_MINIO_ACCESS_KEY="${EXP_MINIO_ACCESS_KEY:-$(env_file_value "$SECRETS_ENV_FILE" ARGUS_EXP_MINIO_ACCESS_KEY)}"
EXP_MINIO_ACCESS_KEY="${EXP_MINIO_ACCESS_KEY:-$(env_file_value "$EXP_STORAGE_ENV_FILE" ARGUS_EXP_MINIO_ACCESS_KEY)}"
EXP_MINIO_SECRET_KEY="${EXP_MINIO_SECRET_KEY:-$(env_file_value "$SECRETS_ENV_FILE" ARGUS_EXP_MINIO_SECRET_KEY)}"
EXP_MINIO_SECRET_KEY="${EXP_MINIO_SECRET_KEY:-$(env_file_value "$EXP_STORAGE_ENV_FILE" ARGUS_EXP_MINIO_SECRET_KEY)}"
EXP_MINIO_ENDPOINT="${EXP_MINIO_ENDPOINT:-$(env_file_value "$EXP_STORAGE_ENV_FILE" ARGUS_EXP_MINIO_ENDPOINT)}"
EXP_MINIO_REGION="${EXP_MINIO_REGION:-$(env_file_value "$EXP_STORAGE_ENV_FILE" ARGUS_EXP_MINIO_REGION)}"
EXP_MINIO_BUCKET="${EXP_MINIO_BUCKET:-$(env_file_value "$EXP_STORAGE_ENV_FILE" ARGUS_EXP_MINIO_BUCKET)}"
EXP_MINIO_USE_SSL="${EXP_MINIO_USE_SSL:-$(env_file_value "$EXP_STORAGE_ENV_FILE" ARGUS_EXP_MINIO_USE_SSL)}"
EXP_TRACE_RETENTION="${EXP_TRACE_RETENTION:-$(env_file_value "$EXP_STORAGE_ENV_FILE" ARGUS_EXP_TRACE_RETENTION)}"
YAKSHA_URL="${YAKSHA_URL:-$(env_file_value "$EXP_STORAGE_ENV_FILE" ARGUS_YAKSHA_URL)}"
EXP_MINIO_ACCESS_KEY="${EXP_MINIO_ACCESS_KEY:-exp$(gen_hex_secret | cut -c1-20)}"
EXP_MINIO_SECRET_KEY="${EXP_MINIO_SECRET_KEY:-$(gen_hex_secret)}"
EXP_MINIO_ENDPOINT="${EXP_MINIO_ENDPOINT:-http://127.0.0.1:${MINIO_API_PORT}}"
EXP_MINIO_REGION="${EXP_MINIO_REGION:-us-east-1}"
EXP_MINIO_BUCKET="${EXP_MINIO_BUCKET:-argus-exp}"
EXP_MINIO_USE_SSL="${EXP_MINIO_USE_SSL:-false}"
EXP_TRACE_RETENTION="${EXP_TRACE_RETENTION:-168h}"
YAKSHA_URL="${YAKSHA_URL:-http://127.0.0.1:8790}"
ARGUS_EXP_MINIO_ACCESS_KEY="$EXP_MINIO_ACCESS_KEY"
ARGUS_EXP_MINIO_SECRET_KEY="$EXP_MINIO_SECRET_KEY"
ARGUS_EXP_MINIO_BUCKET="$EXP_MINIO_BUCKET"

# 应用密钥
resolve_app_secret AGENT_PSK ARGUS_AGENT_PSK "-agent-psk"
AGENT_PSK="${AGENT_PSK:-$(openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | xxd -p)}"
resolve_app_secret JWT_SECRET ARGUS_JWT_SECRET
JWT_SECRET="${JWT_SECRET:-$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p)}"
resolve_app_secret ENCRYPT_KEY ARGUS_ENCRYPT_KEY
ENCRYPT_KEY="${ENCRYPT_KEY:-$(gen_encrypt_key)}"
resolve_app_secret CREDENTIAL_ENCRYPT_KEY ARGUS_CREDENTIAL_ENCRYPT_KEY
CREDENTIAL_ENCRYPT_KEY="${CREDENTIAL_ENCRYPT_KEY:-$(gen_encrypt_key)}"

# API / gRPC 端口（新格式 service 里 -api/-grpc 仍为字面量，可直接解析）
API_ADDR="$(extract_quoted_arg "-api" "$SERVICE_CMD" || true)"
GRPC_PORT="$(extract_plain_arg "-grpc" "$SERVICE_CMD" || true)"
API_ADDR="${API_ADDR:-:8085}"
GRPC_PORT="${GRPC_PORT:-50051}"
API_PORT="${API_ADDR##*:}"

# 统一带 --env-file 调 docker compose：任何子命令都会做 ${VAR:?} 插值，必须能读到凭据。
# 不再 export 密钥变量（shell 环境变量优先于 --env-file，会让文件失去权威）。
dcompose() { docker compose --env-file "${SECRETS_ENV_FILE}" -f "${SCRIPT_DIR}/docker-compose.yml" "$@"; }

# 快照升级前的 secrets.env（确认后即将重写它），供 [2/6] 备份与失败回滚还原旧值，
# 避免备份到的是已重写内容、回滚无法还原旧凭据。
PRE_UPGRADE_SECRETS_ENV=""
if [[ -f "$SECRETS_ENV_FILE" ]]; then
    PRE_UPGRADE_SECRETS_ENV="$(cat "$SECRETS_ENV_FILE")"
fi

shopt -s nullglob
server_candidates=(
    "${ROOT_DIR}/bin/argus-server-linux-amd64"
    "${ROOT_DIR}/bin/argus-server"
    "${ROOT_DIR}/release/argus-server-linux-amd64"
    "${ROOT_DIR}/argus-server-linux-amd64"
    "${ROOT_DIR}"/argus-release-*/bin/argus-server-linux-amd64
)
agent_candidates=(
    "${ROOT_DIR}/bin/argus-agent-linux-amd64"
    "${ROOT_DIR}/release/argus-agent-linux-amd64"
    "${ROOT_DIR}/argus-agent-linux-amd64"
    "${ROOT_DIR}"/argus-release-*/bin/argus-agent-linux-amd64
)
frontend_candidates=(
    "${ROOT_DIR}/server-ui/dist"
    "${ROOT_DIR}"/argus-release-*/server-ui/dist
)
shopt -u nullglob

SERVER_BIN="$(find_first_file "${server_candidates[@]}")" || die "新版发布包中找不到 argus-server 二进制"
AGENT_BIN="$(find_first_file "${agent_candidates[@]}" || true)"
FRONTEND_SRC=""
for candidate in "${frontend_candidates[@]}"; do
    if [[ -d "$candidate" && "$(ls -A "$candidate" 2>/dev/null)" ]]; then
        FRONTEND_SRC="$candidate"
        break
    fi
done

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}       Argus Server 原地升级                    ${NC}"
echo -e "${BLUE}================================================${NC}"
echo -e "  旧安装目录: ${GREEN}${INSTALL_DIR}${NC}"
echo -e "  新 Server:  ${GREEN}${SERVER_BIN}${NC}"
echo -e "  数据库:     ${GREEN}${POSTGRES_USER}:****@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}${NC}"
echo -e "  API/gRPC:   ${GREEN}${API_ADDR} / ${GRPC_PORT}${NC}"
echo -e "  凭据文件:   ${GREEN}${SECRETS_ENV_FILE}${NC}"
echo -e "${BLUE}================================================${NC}"

if [[ "$ASSUME_YES" == "false" ]]; then
    read -r -p "确认执行原地升级？升级会重启 argus-server，但不会删除数据库数据。(输入 yes): " confirm
    [[ "$confirm" == "yes" ]] || die "已取消升级"
fi

# 用户确认后才落盘 secrets.env（取消升级不留副作用）：
# 旧环境由此迁移出新格式；新环境刷新连接串。
mkdir -p "${INSTALL_DIR}/config"
write_secrets_env "${SECRETS_ENV_FILE}"

mkdir -p "$INSTALL_DIR"/{bin,release,server-ui,deploy,logs,backups}
BACKUP_DIR="${INSTALL_DIR}/backups/upgrade-$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"

rollback_ready=false
yaksha_rollback_tag=""
yaksha_had_compose=false
yaksha_had_image_asset=false
yaksha_had_local_image=false
yaksha_was_running=false
rollback_on_error() {
    local exit_code=$?
    trap - ERR
    if [[ "$rollback_ready" == "true" ]]; then
        echo -e "${RED}[!] 升级失败，正在尝试恢复升级前的服务与二进制...${NC}" >&2
        if [[ -f "${BACKUP_DIR}/argus-server" ]]; then
            install -m 0755 "${BACKUP_DIR}/argus-server" "${INSTALL_DIR}/bin/argus-server" || true
        elif [[ -f "${BACKUP_DIR}/argus-server.absent" ]]; then
            rm -f "${INSTALL_DIR}/bin/argus-server" || true
        fi
        if [[ -f "${BACKUP_DIR}/argus-server.service" ]]; then
            cp -a "${BACKUP_DIR}/argus-server.service" "$SERVICE_FILE" || true
        fi
        if [[ -f "${BACKUP_DIR}/minio.env" ]]; then
            cp -a "${BACKUP_DIR}/minio.env" "$MINIO_ENV_FILE" || true
        elif [[ -f "${BACKUP_DIR}/minio.env.absent" ]]; then
            rm -f "$MINIO_ENV_FILE" || true
        fi
        if [[ -f "${BACKUP_DIR}/exp-storage.env" ]]; then
            cp -a "${BACKUP_DIR}/exp-storage.env" "$EXP_STORAGE_ENV_FILE" || true
        elif [[ -f "${BACKUP_DIR}/exp-storage.env.absent" ]]; then
            rm -f "$EXP_STORAGE_ENV_FILE" || true
        fi
        if [[ -f "${BACKUP_DIR}/secrets.env" ]]; then
            cp -a "${BACKUP_DIR}/secrets.env" "$SECRETS_ENV_FILE" || true
        elif [[ -f "${BACKUP_DIR}/secrets.env.absent" ]]; then
            rm -f "$SECRETS_ENV_FILE" || true
        fi
        current_yaksha_compose="${INSTALL_DIR}/deploy/yaksha-compose.yaml"
        if [[ -f "$current_yaksha_compose" ]]; then
            docker compose -f "$current_yaksha_compose" down --remove-orphans 2>/dev/null || true
        fi
        if [[ "$yaksha_had_compose" == "true" ]]; then
            cp -a "${BACKUP_DIR}/yaksha-compose.yaml" "$current_yaksha_compose" || true
        else
            rm -f "$current_yaksha_compose" || true
        fi
        if [[ "$yaksha_had_image_asset" == "true" ]]; then
            mkdir -p "${INSTALL_DIR}/deploy/images"
            cp -a "${BACKUP_DIR}/argus-yaksha-linux-amd64.tar" "${INSTALL_DIR}/deploy/images/" || true
        else
            rm -f "${INSTALL_DIR}/deploy/images/argus-yaksha-linux-amd64.tar" || true
        fi
        if [[ -n "$yaksha_rollback_tag" ]]; then
            docker tag "$yaksha_rollback_tag" argus-yaksha:local 2>/dev/null || true
        elif [[ "$yaksha_had_local_image" != "true" ]]; then
            docker image rm argus-yaksha:local >/dev/null 2>&1 || true
        fi
        if [[ "$yaksha_was_running" == "true" && -f "$current_yaksha_compose" ]]; then
            # 优先用本次已解析的 shell 变量（新格式 token 在 secrets.env、不在旧 unit 内联），
            # 兜底再 grep 备份 unit 的内联值（旧格式）。备份 unit 可能不存在，禁 set -e/pipefail 中断。
            export YAKSHA_RELAY_ADDR="${EGRESS_GATEWAY_LISTEN:-$(sed -nE 's/^Environment=ARGUS_EGRESS_GATEWAY_LISTEN=(.*)$/\1/p' "${BACKUP_DIR}/argus-server.service" 2>/dev/null | tail -n 1 || true)}"
            export YAKSHA_RELAY_TOKEN="${EGRESS_GATEWAY_TOKEN:-$(sed -nE 's/^Environment=ARGUS_EGRESS_GATEWAY_TOKEN=(.*)$/\1/p' "${BACKUP_DIR}/argus-server.service" 2>/dev/null | tail -n 1 || true)}"
            docker compose -f "$current_yaksha_compose" up -d --no-build 2>/dev/null || true
        fi
        systemctl daemon-reload 2>/dev/null || true
        systemctl start "$SERVICE_NAME" 2>/dev/null || true
        echo -e "${YELLOW}    备份目录: ${BACKUP_DIR}${NC}" >&2
    fi
    exit "$exit_code"
}
trap rollback_on_error ERR

echo -e "${YELLOW}[1/6] 检查并启动基础设施...${NC}"
if command -v docker &>/dev/null; then
    if docker ps -a --format '{{.Names}}' | grep -qx "argus-postgres"; then
        docker start argus-postgres >/dev/null 2>&1 || true
    elif [[ -f "${SCRIPT_DIR}/docker-compose.yml" ]]; then
        dcompose up -d postgres
    else
        die "找不到 argus-postgres 容器，也找不到 docker-compose.yml"
    fi

    echo -ne "  等待 PostgreSQL 就绪..."
    postgres_ready=false
    for _ in $(seq 1 30); do
        if docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" argus-postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" &>/dev/null; then
            echo -e " ${GREEN}OK${NC}"
            postgres_ready=true
            break
        fi
        echo -n "."
        sleep 2
    done
    [[ "$postgres_ready" == "true" ]] || die "PostgreSQL 未在预期时间内就绪"

    dcompose up -d minio
    minio_ready=false
    for _ in $(seq 1 30); do
        if dcompose exec -T minio curl -fsS http://127.0.0.1:9000/minio/health/ready &>/dev/null; then
            minio_ready=true
            break
        fi
        sleep 2
    done
    [[ "$minio_ready" == "true" ]] || die "MinIO 未在预期时间内就绪"
    dcompose up --no-deps minio-init
    [[ "$(docker inspect -f '{{.State.ExitCode}}' argus-minio-init 2>/dev/null || echo 1)" == "0" ]] || die "MinIO 私有 Bucket 或应用用户初始化失败"
else
    echo -e "${YELLOW}  [!] 未找到 docker，跳过基础设施检查${NC}"
fi

echo -e "${YELLOW}[2/6] 创建升级备份...${NC}"
if [[ -f "${INSTALL_DIR}/bin/argus-server" ]]; then
    cp -a "${INSTALL_DIR}/bin/argus-server" "${BACKUP_DIR}/argus-server"
else
    touch "${BACKUP_DIR}/argus-server.absent"
fi
if [[ -f "${INSTALL_DIR}/release/argus-agent-linux-amd64" ]]; then
    cp -a "${INSTALL_DIR}/release/argus-agent-linux-amd64" "${BACKUP_DIR}/argus-agent-linux-amd64"
fi
if [[ -d "${INSTALL_DIR}/server-ui/dist" ]]; then
    cp -a "${INSTALL_DIR}/server-ui/dist" "${BACKUP_DIR}/server-ui-dist"
fi
if [[ -f "$SERVICE_FILE" ]]; then
    cp -a "$SERVICE_FILE" "${BACKUP_DIR}/argus-server.service"
fi
if [[ -f "$MINIO_ENV_FILE" ]]; then
    cp -a "$MINIO_ENV_FILE" "${BACKUP_DIR}/minio.env"
else
    touch "${BACKUP_DIR}/minio.env.absent"
fi
if [[ -f "$EXP_STORAGE_ENV_FILE" ]]; then
    cp -a "$EXP_STORAGE_ENV_FILE" "${BACKUP_DIR}/exp-storage.env"
else
    touch "${BACKUP_DIR}/exp-storage.env.absent"
fi
# secrets.env 用升级前的快照（当前文件在确认后已被本脚本重写，直接 cp 备份不到旧值）
if [[ -n "$PRE_UPGRADE_SECRETS_ENV" ]]; then
    printf '%s\n' "$PRE_UPGRADE_SECRETS_ENV" > "${BACKUP_DIR}/secrets.env"
    chmod 0600 "${BACKUP_DIR}/secrets.env"
else
    touch "${BACKUP_DIR}/secrets.env.absent"
fi
if [[ -f "${INSTALL_DIR}/deploy/yaksha-compose.yaml" ]]; then
    yaksha_had_compose=true
    cp -a "${INSTALL_DIR}/deploy/yaksha-compose.yaml" "${BACKUP_DIR}/yaksha-compose.yaml"
    export YAKSHA_RELAY_ADDR="${EGRESS_GATEWAY_LISTEN}"
    export YAKSHA_RELAY_TOKEN="${EGRESS_GATEWAY_TOKEN}"
    if [[ -n "$(docker compose -f "${INSTALL_DIR}/deploy/yaksha-compose.yaml" ps --status running -q yaksha 2>/dev/null || true)" ]]; then
        yaksha_was_running=true
    fi
fi
if [[ -f "${INSTALL_DIR}/deploy/images/argus-yaksha-linux-amd64.tar" ]]; then
    yaksha_had_image_asset=true
    cp -a "${INSTALL_DIR}/deploy/images/argus-yaksha-linux-amd64.tar" "${BACKUP_DIR}/argus-yaksha-linux-amd64.tar"
fi
if docker image inspect argus-yaksha:local >/dev/null 2>&1; then
    yaksha_had_local_image=true
    yaksha_rollback_tag="argus-yaksha:rollback-$(date +%Y%m%d%H%M%S)"
    docker tag argus-yaksha:local "$yaksha_rollback_tag"
fi

if [[ "$SKIP_BACKUP" == "false" ]]; then
    if command -v docker &>/dev/null && docker ps --format '{{.Names}}' | grep -qx "argus-postgres"; then
        dump_name="/tmp/argus-upgrade-$(date +%Y%m%d%H%M%S).dump"
        docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" argus-postgres \
            pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc -f "$dump_name"
        docker cp "argus-postgres:${dump_name}" "${BACKUP_DIR}/postgres.dump"
        docker exec argus-postgres rm -f "$dump_name" >/dev/null 2>&1 || true
        echo -e "  数据库备份: ${GREEN}${BACKUP_DIR}/postgres.dump${NC}"
    else
        echo -e "${YELLOW}  [!] 未找到运行中的 argus-postgres 容器，跳过 pg_dump 备份${NC}"
    fi
else
    echo -e "${YELLOW}  [!] 已按参数跳过数据库备份${NC}"
fi
rollback_ready=true

echo -e "${YELLOW}[3/6] 停止应用服务...${NC}"
systemctl stop "$SERVICE_NAME" 2>/dev/null || true

echo -e "${YELLOW}[4/6] 替换应用文件...${NC}"
install -m 0755 "$SERVER_BIN" "${INSTALL_DIR}/bin/argus-server"
echo -e "  Server: ${GREEN}${SERVER_BIN} -> ${INSTALL_DIR}/bin/argus-server${NC}"
mkdir -p "${INSTALL_DIR}/config"
umask 077
cat > "$MINIO_ENV_FILE" <<EOF
MINIO_ROOT_USER=${MINIO_ROOT_USER}
MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}
MINIO_API_PORT=${MINIO_API_PORT}
MINIO_CONSOLE_PORT=${MINIO_CONSOLE_PORT}
EOF
cat > "$EXP_STORAGE_ENV_FILE" <<EOF
ARGUS_EXP_STORE_MODE=minio
ARGUS_EXP_MINIO_ENDPOINT=${EXP_MINIO_ENDPOINT}
ARGUS_EXP_MINIO_REGION=${EXP_MINIO_REGION}
ARGUS_EXP_MINIO_BUCKET=${EXP_MINIO_BUCKET}
ARGUS_EXP_MINIO_ACCESS_KEY=${EXP_MINIO_ACCESS_KEY}
ARGUS_EXP_MINIO_SECRET_KEY=${EXP_MINIO_SECRET_KEY}
ARGUS_EXP_MINIO_USE_SSL=${EXP_MINIO_USE_SSL}
ARGUS_EXP_TRACE_RETENTION=${EXP_TRACE_RETENTION}
ARGUS_YAKSHA_URL=${YAKSHA_URL}
EOF
chmod 0600 "$MINIO_ENV_FILE" "$EXP_STORAGE_ENV_FILE"
# 密钥统一进 secrets.env（Credential Encrypt Key 等不再写 service 的 Environment 行，避免遮蔽 env 文件）
write_secrets_env "$SECRETS_ENV_FILE"

# 用共享模板重建 systemd unit：旧格式（明文密钥/内嵌 DSN）→ 新格式（EnvironmentFile + ${VAR}）。
# PUBLIC_IP/EGRESS/TLS 已在上文从旧 service 解析，此处一并保留。
render_argus_service_unit "$SERVICE_FILE"

if [[ -n "$AGENT_BIN" ]]; then
    install -m 0755 "$AGENT_BIN" "${INSTALL_DIR}/release/argus-agent-linux-amd64"
    echo -e "  Agent:  ${GREEN}${AGENT_BIN} -> ${INSTALL_DIR}/release/argus-agent-linux-amd64${NC}"
fi

if [[ -n "$FRONTEND_SRC" ]]; then
    rm -rf "${INSTALL_DIR}/server-ui/dist.new"
    mkdir -p "${INSTALL_DIR}/server-ui/dist.new"
    cp -a "${FRONTEND_SRC}/." "${INSTALL_DIR}/server-ui/dist.new/"
    rm -rf "${INSTALL_DIR}/server-ui/dist"
    mv "${INSTALL_DIR}/server-ui/dist.new" "${INSTALL_DIR}/server-ui/dist"
    echo -e "  Frontend: ${GREEN}${FRONTEND_SRC} -> ${INSTALL_DIR}/server-ui/dist${NC}"
fi

if [[ -f "${SCRIPT_DIR}/docker-compose.yml" ]]; then
    cp -a "${SCRIPT_DIR}/docker-compose.yml" "${INSTALL_DIR}/deploy/docker-compose.yml"
fi
if [[ -f "${SCRIPT_DIR}/setup-server.sh" ]]; then
    cp -a "${SCRIPT_DIR}/setup-server.sh" "${INSTALL_DIR}/deploy/setup-server.sh"
fi
if [[ -f "${SCRIPT_DIR}/upgrade-server.sh" ]]; then
    cp -a "${SCRIPT_DIR}/upgrade-server.sh" "${INSTALL_DIR}/deploy/upgrade-server.sh"
fi
if [[ -f "${SCRIPT_DIR}/uninstall-server.sh" ]]; then
    cp -a "${SCRIPT_DIR}/uninstall-server.sh" "${INSTALL_DIR}/deploy/uninstall-server.sh"
fi
if [[ -f "${SCRIPT_DIR}/show-secrets.sh" ]]; then
    cp -a "${SCRIPT_DIR}/show-secrets.sh" "${INSTALL_DIR}/deploy/show-secrets.sh"
fi
if [[ -d "${SCRIPT_DIR}/lib" ]]; then
    mkdir -p "${INSTALL_DIR}/deploy/lib"
    cp -a "${SCRIPT_DIR}/lib/." "${INSTALL_DIR}/deploy/lib/"
fi
if [[ -f "${SCRIPT_DIR}/yaksha-compose.yaml" ]]; then
    cp -a "${SCRIPT_DIR}/yaksha-compose.yaml" "${INSTALL_DIR}/deploy/yaksha-compose.yaml"
fi
if [[ -f "${SCRIPT_DIR}/images/argus-yaksha-linux-amd64.tar" ]]; then
    mkdir -p "${INSTALL_DIR}/deploy/images"
    cp -a "${SCRIPT_DIR}/images/argus-yaksha-linux-amd64.tar" "${INSTALL_DIR}/deploy/images/"
fi
if [[ -d "${SCRIPT_DIR}/postgres" ]]; then
    mkdir -p "${INSTALL_DIR}/deploy/postgres"
    cp -a "${SCRIPT_DIR}/postgres/." "${INSTALL_DIR}/deploy/postgres/"
fi

echo -e "${YELLOW}[5/6] 执行数据库迁移与规则同步...${NC}"
"${INSTALL_DIR}/bin/argus-server" --db "$DB_DSN" --migrate-only --db-migration-mode apply --config-dir "${INSTALL_DIR}/config"

if [[ -f "${SCRIPT_DIR}/arsenal_seed.db" ]]; then
    "${INSTALL_DIR}/bin/argus-server" --db "$DB_DSN" --seed-from-db "${SCRIPT_DIR}/arsenal_seed.db"
else
    echo -e "${YELLOW}  [!] 未找到 deploy/arsenal_seed.db，跳过规则资产同步${NC}"
fi

echo -e "${YELLOW}[6/6] 重启应用服务并检查状态...${NC}"
systemctl daemon-reload
YAKSHA_COMPOSE="${INSTALL_DIR}/deploy/yaksha-compose.yaml"
YAKSHA_IMAGE="${INSTALL_DIR}/deploy/images/argus-yaksha-linux-amd64.tar"
if [[ -f "$YAKSHA_COMPOSE" && -f "$YAKSHA_IMAGE" ]]; then
    docker load -i "$YAKSHA_IMAGE" >/dev/null
    export YAKSHA_RELAY_ADDR="${EGRESS_GATEWAY_LISTEN}"
    export YAKSHA_RELAY_TOKEN="${EGRESS_GATEWAY_TOKEN}"
    docker compose -f "$YAKSHA_COMPOSE" up -d --no-build
    yaksha_ready=false
    for _ in $(seq 1 30); do
        if docker compose -f "$YAKSHA_COMPOSE" exec -T yaksha /usr/local/bin/yaksha healthcheck >/dev/null 2>&1; then
            yaksha_ready=true
            break
        fi
        sleep 2
    done
    [[ "$yaksha_ready" == "true" ]] || die "Yaksha Runtime 未就绪"
fi

# The production Server deliberately refuses to start without ready MinIO and
# Yaksha dependencies. Start Yaksha first, then bring up the Server.
systemctl start "$SERVICE_NAME"
sleep 3
if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "${RED}[!] 服务启动失败，请查看 ${INSTALL_DIR}/logs/server.log${NC}" >&2
    false
fi

rollback_ready=false
trap - ERR
if [[ -n "$yaksha_rollback_tag" ]]; then
    docker image rm "$yaksha_rollback_tag" >/dev/null 2>&1 || true
fi

echo ""
echo -e "${BLUE}================================================${NC}"
echo -e "${GREEN}  ✅ Argus Server 原地升级完成${NC}"
echo -e "${BLUE}================================================${NC}"
echo -e "  备份目录: ${GREEN}${BACKUP_DIR}${NC}"
echo -e "  凭据文件: ${GREEN}${SECRETS_ENV_FILE}${NC}  ${YELLOW}(sudo ${INSTALL_DIR}/deploy/show-secrets.sh 查看)${NC}"
echo -e "  查看日志: ${YELLOW}tail -f ${INSTALL_DIR}/logs/server.log${NC}"
echo -e "  服务状态: ${YELLOW}systemctl status ${SERVICE_NAME}${NC}"
echo ""
