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
# 可选参数：
#   --install-dir <dir>   指定旧安装目录；默认从 argus-server.service 读取
#   --db <dsn>            指定数据库 DSN；默认从 systemd ExecStart 读取
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

SERVICE_NAME="${ARGUS_SERVICE_NAME:-argus-server}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
INSTALL_DIR="${INSTALL_DIR:-}"
DB_DSN="${ARGUS_DB_DSN:-}"
EGRESS_GATEWAY_LISTEN="${ARGUS_EGRESS_GATEWAY_LISTEN:-}"
EGRESS_GATEWAY_TOKEN="${ARGUS_EGRESS_GATEWAY_TOKEN:-}"
SKIP_BACKUP=false
ASSUME_YES=false

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
    sed -n '2,28s/^# \{0,1\}//p' "$0"
}

die() {
    echo -e "${RED}[!] $*${NC}" >&2
    exit 1
}

if [[ -n "$EGRESS_GATEWAY_LISTEN" || -n "$EGRESS_GATEWAY_TOKEN" ]]; then
    if [[ -z "$EGRESS_GATEWAY_LISTEN" || -z "$EGRESS_GATEWAY_TOKEN" ]]; then
        die "ARGUS_EGRESS_GATEWAY_LISTEN 与 ARGUS_EGRESS_GATEWAY_TOKEN 必须成对配置"
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

# Migration-only compatibility boundary. A pre-Argus service can keep its
# legacy executable path in ExecStart; normalize that reference only after the
# newly packaged Argus binary is installed. The old executable stays in place,
# so restoring the saved unit reactivates it on failure. No legacy artifact is
# accepted from the release bundle and no legacy binary is installed.
migrate_legacy_service_identity() {
    if [[ -f "$SERVICE_FILE" ]] && grep -q '/bin/dddd-server' "$SERVICE_FILE"; then
        sed -i 's#/bin/dddd-server#/bin/argus-server#g' "$SERVICE_FILE"
    fi
}

set_service_environment() {
    local key="$1"
    local value="$2"
    local temporary="${SERVICE_FILE}.tmp.$$"
    awk -v key="$key" -v value="$value" '
        BEGIN { replaced=0 }
        $0 ~ "^Environment=" key "=" {
            if (!replaced) print "Environment=" key "=" value
            replaced=1
            next
        }
        /^ExecStart=/ && !replaced {
            print "Environment=" key "=" value
            replaced=1
        }
        { print }
        END {
            if (!replaced) print "Environment=" key "=" value
        }
    ' "$SERVICE_FILE" > "$temporary"
    chmod --reference="$SERVICE_FILE" "$temporary"
    chown --reference="$SERVICE_FILE" "$temporary"
    mv "$temporary" "$SERVICE_FILE"
}

SERVICE_CMD="$(service_execstart || true)"
if [[ -z "$EGRESS_GATEWAY_LISTEN" && -z "$EGRESS_GATEWAY_TOKEN" ]]; then
    EGRESS_GATEWAY_LISTEN="$(service_environment ARGUS_EGRESS_GATEWAY_LISTEN || true)"
    EGRESS_GATEWAY_TOKEN="$(service_environment ARGUS_EGRESS_GATEWAY_TOKEN || true)"
fi
if [[ -n "$EGRESS_GATEWAY_LISTEN" || -n "$EGRESS_GATEWAY_TOKEN" ]]; then
    if [[ -z "$EGRESS_GATEWAY_LISTEN" || -z "$EGRESS_GATEWAY_TOKEN" ]]; then
        die "现有 Gateway 配置不完整，请成对设置 ARGUS_EGRESS_GATEWAY_LISTEN/TOKEN"
    fi
fi
if [[ -z "$INSTALL_DIR" ]]; then
    INSTALL_DIR="$(service_workdir || true)"
fi
INSTALL_DIR="${INSTALL_DIR:-/opt/argus}"

if [[ -z "$DB_DSN" && -n "$SERVICE_CMD" ]]; then
    DB_DSN="$(extract_quoted_arg "-db" "$SERVICE_CMD" || true)"
fi
if [[ -z "$DB_DSN" ]]; then
    die "未能从 ${SERVICE_FILE} 读取数据库 DSN，请使用 --db 或 ARGUS_DB_DSN 显式指定"
fi

API_ADDR="$(extract_quoted_arg "-api" "$SERVICE_CMD" || true)"
GRPC_PORT="$(extract_plain_arg "-grpc" "$SERVICE_CMD" || true)"
API_ADDR="${API_ADDR:-:8085}"
GRPC_PORT="${GRPC_PORT:-50051}"

dsn_field() {
    local key="$1"
    printf '%s\n' "$DB_DSN" | tr ' ' '\n' | awk -F= -v key="$key" '$1 == key {print substr($0, length(key)+2); exit}'
}

POSTGRES_USER="${POSTGRES_USER:-$(dsn_field user)}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(dsn_field password)}"
POSTGRES_DB="${POSTGRES_DB:-$(dsn_field dbname)}"
POSTGRES_PORT="${POSTGRES_PORT:-$(dsn_field port)}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
if [[ -z "${POSTGRES_PASSWORD}" ]]; then
    die "数据库 DSN 缺少 password 字段，请使用 --db 或 ARGUS_DB_DSN 显式指定完整 DSN"
fi
POSTGRES_DB="${POSTGRES_DB:-argus}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"

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
echo -e "${BLUE}================================================${NC}"

if [[ "$ASSUME_YES" == "false" ]]; then
    read -r -p "确认执行原地升级？升级会重启 argus-server，但不会删除数据库数据。(输入 yes): " confirm
    [[ "$confirm" == "yes" ]] || die "已取消升级"
fi

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
            export YAKSHA_RELAY_ADDR="$(sed -nE 's/^Environment=ARGUS_EGRESS_GATEWAY_LISTEN=(.*)$/\1/p' "${BACKUP_DIR}/argus-server.service" | tail -n 1)"
            export YAKSHA_RELAY_TOKEN="$(sed -nE 's/^Environment=ARGUS_EGRESS_GATEWAY_TOKEN=(.*)$/\1/p' "${BACKUP_DIR}/argus-server.service" | tail -n 1)"
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
        export INSTALL_DIR POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB POSTGRES_PORT
        docker compose -f "${SCRIPT_DIR}/docker-compose.yml" up -d postgres
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
migrate_legacy_service_identity
if [[ -n "$EGRESS_GATEWAY_LISTEN" ]]; then
    set_service_environment ARGUS_EGRESS_GATEWAY_LISTEN "$EGRESS_GATEWAY_LISTEN"
    set_service_environment ARGUS_EGRESS_GATEWAY_TOKEN "$EGRESS_GATEWAY_TOKEN"
fi

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
systemctl start "$SERVICE_NAME"
sleep 3

if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "${RED}[!] 服务启动失败，请查看 ${INSTALL_DIR}/logs/server.log${NC}" >&2
    false
fi

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
echo -e "  查看日志: ${YELLOW}tail -f ${INSTALL_DIR}/logs/server.log${NC}"
echo -e "  服务状态: ${YELLOW}systemctl status ${SERVICE_NAME}${NC}"
echo ""
