#!/bin/bash
# ==============================================================================
# Argus 部署凭据查看工具
#
# 部署/升级后，全部随机生成的密码与密钥统一保存在:
#     ${INSTALL_DIR}/config/secrets.env   (权限 0600)
# 本脚本解析该文件并分类展示，同时给出常用运维命令，解决"密码只存在容器 env
# 里、后续 down/exec 找不到"的痛点。
#
# 用法：
#   sudo ./deploy/show-secrets.sh                # 完整展示
#   sudo ./deploy/show-secrets.sh --mask         # 脱敏（仅显示首尾各 4 位）
#   sudo ./deploy/show-secrets.sh --install-dir /path/to/argus-release
#
# 安装目录定位顺序：--install-dir → systemd argus-server.service 的
# WorkingDirectory → 本脚本所在发布包根目录（deploy/ 的父目录）。
# ==============================================================================

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SERVICE_NAME="argus-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# shellcheck source=lib/argus-env.sh
source "${SCRIPT_DIR}/lib/argus-env.sh"

MASK=false
EXPLICIT_INSTALL_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mask) MASK=true; shift ;;
        --install-dir) EXPLICIT_INSTALL_DIR="$2"; shift 2 ;;
        -h|--help) sed -n '2,21s/^# \{0,1\}//p' "$0"; exit 0 ;;
        *) echo -e "${RED}未知参数: $1${NC}" >&2; exit 1 ;;
    esac
done

service_workdir() {
    local value=""
    if command -v systemctl &>/dev/null; then
        value="$(systemctl show "${SERVICE_NAME}.service" --property=WorkingDirectory --value 2>/dev/null | head -n 1 || true)"
    fi
    if [[ -z "$value" && -f "$SERVICE_FILE" ]]; then
        value="$(sed -nE 's/^[[:space:]]*WorkingDirectory[[:space:]]*=[[:space:]]*(.*)$/\1/p' "$SERVICE_FILE" | head -n 1)"
    fi
    value="${value%\"}"; value="${value#\"}"
    printf '%s\n' "$value"
}

resolve_install_dir() {
    if [[ -n "$EXPLICIT_INSTALL_DIR" ]]; then
        printf '%s\n' "$EXPLICIT_INSTALL_DIR"
        return 0
    fi
    local dir
    dir="$(service_workdir || true)"
    if [[ -n "$dir" ]]; then
        printf '%s\n' "$dir"
        return 0
    fi
    # 发布包内运行：deploy/ 的父目录即安装目录
    (cd "${SCRIPT_DIR}/.." && pwd -P)
}

INSTALL_DIR="$(resolve_install_dir)"
SECRETS_ENV_FILE="${INSTALL_DIR}/config/secrets.env"
COMPOSE_FILE="${INSTALL_DIR}/deploy/docker-compose.yml"

if [[ ! -f "$SECRETS_ENV_FILE" ]]; then
    echo -e "${RED}[!] 未找到凭据文件: ${SECRETS_ENV_FILE}${NC}" >&2
    echo -e "    请用 --install-dir 指定正确的安装目录。" >&2
    echo -e "    若这是旧版本环境（升级前），请先运行 ${YELLOW}sudo ${SCRIPT_DIR}/upgrade-server.sh${NC} 完成凭据迁移。" >&2
    exit 1
fi

# 按 key 读取（不 source/eval，避免注入）
v() { env_file_value "$SECRETS_ENV_FILE" "$1"; }

# 展示值（可选脱敏：首尾各留 4 位，中间打码；过短则全打码）
display() {
    local val="$1"
    if [[ "$MASK" != "true" ]]; then
        printf '%s\n' "$val"
        return 0
    fi
    local len=${#val}
    if (( len <= 8 )); then
        printf '%*s\n' "$len" '' | tr ' ' '*'
    else
        printf '%s%s%s\n' "${val:0:4}" "***" "${val:len-4}"
    fi
}

line()  { printf '  %-16s %s\n' "$1" "$2"; }
cline() { printf "  ${YELLOW}%-16s${NC} %s\n" "$1" "$2"; }

PG_USER="$(v POSTGRES_USER)"
PG_DB="$(v POSTGRES_DB)"
PG_PORT="$(v POSTGRES_PORT)"
RMQ_PORT="$(v RABBITMQ_PORT)"
RMQ_MGMT="$(v RABBITMQ_MANAGEMENT_PORT)"

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}   Argus 部署凭据  (${SECRETS_ENV_FILE})${NC}"
echo -e "${BLUE}================================================${NC}"

echo -e "${GREEN}-- PostgreSQL ----------------------------------${NC}"
line "User:      " "$(display "$(v POSTGRES_USER)")"
line "Password:  " "$(display "$(v POSTGRES_PASSWORD)")"
line "Database:  " "${PG_DB}"
line "Port:      " "${PG_PORT}"

echo -e "${GREEN}-- RabbitMQ ------------------------------------${NC}"
line "User:      " "$(display "$(v RABBITMQ_DEFAULT_USER)")"
line "Password:  " "$(display "$(v RABBITMQ_DEFAULT_PASS)")"
line "AMQP Port: " "${RMQ_PORT}"
line "Mgmt Port: " "${RMQ_MGMT}"

echo -e "${GREEN}-- MinIO (root) --------------------------------${NC}"
line "Root User: " "$(display "$(v MINIO_ROOT_USER)")"
line "Root Pass: " "$(display "$(v MINIO_ROOT_PASSWORD)")"
line "API Port:  " "$(v MINIO_API_PORT)"
line "Console:   " "$(v MINIO_CONSOLE_PORT)"

echo -e "${GREEN}-- 应用密钥 -------------------------------------${NC}"
line "Agent PSK: " "$(display "$(v ARGUS_AGENT_PSK)")"
line "JWT Secret:" "$(display "$(v ARGUS_JWT_SECRET)")"
line "EncryptKey:" "$(display "$(v ARGUS_ENCRYPT_KEY)")"
line "Cred Key:  " "$(display "$(v ARGUS_CREDENTIAL_ENCRYPT_KEY)")"

echo -e "${GREEN}-- EXP MinIO (应用用户) -------------------------${NC}"
line "Access Key:" "$(display "$(v ARGUS_EXP_MINIO_ACCESS_KEY)")"
line "Secret Key:" "$(display "$(v ARGUS_EXP_MINIO_SECRET_KEY)")"
line "Bucket:    " "$(v ARGUS_EXP_MINIO_BUCKET)"

GATEWAY_TOKEN="$(v ARGUS_EGRESS_GATEWAY_TOKEN)"
if [[ -n "$GATEWAY_TOKEN" ]]; then
    echo -e "${GREEN}-- Egress Gateway -------------------------------${NC}"
    line "Listen:    " "$(v ARGUS_EGRESS_GATEWAY_LISTEN)"
    line "Token:     " "$(display "$GATEWAY_TOKEN")"
fi

echo -e "${GREEN}-- 连接串 ---------------------------------------${NC}"
line "DB DSN:    " "$(display "$(v ARGUS_DB_DSN)")"
line "AMQP URL:  " "$(display "$(v ARGUS_AMQP_URL)")"

echo ""
echo -e "${GREEN}-- 常用运维命令 ---------------------------------${NC}"
if [[ -f "$COMPOSE_FILE" ]]; then
    echo -e "  ${YELLOW}# 进入数据库 (psql)${NC}"
    cline "" "docker compose --env-file ${SECRETS_ENV_FILE} -f ${COMPOSE_FILE} exec postgres psql -U ${PG_USER} -d ${PG_DB}"
    echo -e "  ${YELLOW}# 查看 / 重启基础设施${NC}"
    cline "" "docker compose --env-file ${SECRETS_ENV_FILE} -f ${COMPOSE_FILE} ps"
    cline "" "docker compose --env-file ${SECRETS_ENV_FILE} -f ${COMPOSE_FILE} restart"
else
    echo -e "  ${YELLOW}# 未找到 ${COMPOSE_FILE}，compose 命令请自行指定 -f 路径${NC}"
fi
echo ""
