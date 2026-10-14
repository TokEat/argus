#!/bin/bash
# ==============================================================================
# Argus Server 卸载清理脚本
#
# 该脚本将完全卸载 Argus Server，包含：
# 1. 停止并移除 argus-server systemd 服务
# 2. 停止并移除 Docker 基础设施 (RabbitMQ, PostgreSQL)
# 3. 删除所有的二进制文件、日志、配置与数据库数据
#
# 警告：此操作不可逆！
#
# 用法：
#   sudo ./deploy/uninstall-server.sh
#   sudo ./deploy/uninstall-server.sh --install-dir /path/to/argus-release-vX.Y.Z
#
# 安装目录默认从 argus-server.service 的 WorkingDirectory 读取。仅当服务文件
# 不可用时，才使用经 Argus 安装结构校验的 --install-dir；无法确认时拒绝卸载。
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
SYSTEMCTL_BIN="systemctl"

usage() {
    sed -n '2,23s/^# \{0,1\}//p' "$0"
}

die() {
    echo -e "${RED}[!] $*${NC}" >&2
    exit 1
}

canonical_install_dir() {
    local candidate="$1"

    [[ -n "$candidate" ]] || return 1
    [[ "$candidate" == /* ]] || return 1
    [[ "$candidate" != *$'\n'* && "$candidate" != *$'\r'* ]] || return 1

    if command -v realpath &>/dev/null; then
        realpath -m -- "$candidate"
    elif command -v readlink &>/dev/null; then
        readlink -m -- "$candidate"
    else
        return 1
    fi
}

validate_install_dir_safety() {
    local install_dir="$1"

    [[ "$install_dir" == /* ]] || die "安装目录必须是绝对路径: ${install_dir}"
    case "$install_dir" in
        /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
            die "拒绝删除高风险系统目录: ${install_dir}"
            ;;
    esac
}

service_working_directory() {
    local value=""

    if command -v "$SYSTEMCTL_BIN" &>/dev/null; then
        value="$($SYSTEMCTL_BIN show "${SERVICE_NAME}.service" --property=WorkingDirectory --value 2>/dev/null | head -n 1 || true)"
    fi
    if [[ -z "$value" && -f "$SERVICE_FILE" ]]; then
        value="$(sed -nE 's/^[[:space:]]*WorkingDirectory[[:space:]]*=[[:space:]]*(.*)$/\1/p' "$SERVICE_FILE" | head -n 1)"
    fi

    if [[ "$value" == \"*\" && "$value" == *\" ]]; then
        value="${value:1:${#value}-2}"
    fi
    printf '%s\n' "$value"
}

service_exec_definition() {
    local value=""

    if command -v "$SYSTEMCTL_BIN" &>/dev/null; then
        value="$($SYSTEMCTL_BIN show "${SERVICE_NAME}.service" --property=ExecStart --value 2>/dev/null || true)"
    fi
    if [[ -z "$value" && -f "$SERVICE_FILE" ]]; then
        value="$(sed -n '/^[[:space:]]*ExecStart[[:space:]]*=/,/^[^[:space:]]/p' "$SERVICE_FILE")"
    fi
    printf '%s\n' "$value"
}

validate_service_contract() {
    local install_dir="$1"
    local exec_definition

    exec_definition="$(service_exec_definition)"
    [[ -n "$exec_definition" ]] || die "无法确认 ${SERVICE_NAME}.service 的 ExecStart，拒绝删除目录"
    [[ "$exec_definition" == *"${install_dir}/bin/argus-server"* ]] || \
        die "${SERVICE_NAME}.service 的 ExecStart 不属于 ${install_dir}，拒绝删除目录"
}

validate_explicit_install_evidence() {
    local install_dir="$1"

    [[ -f "${install_dir}/bin/argus-server" ]] || \
        die "${install_dir} 缺少 bin/argus-server，无法确认是 Argus 安装目录"
    [[ -f "${install_dir}/deploy/docker-compose.yml" ]] || \
        die "${install_dir} 缺少 deploy/docker-compose.yml，无法确认是 Argus 安装目录"
}

resolve_install_dir() {
    local explicit_dir="${1:-}"
    local service_dir_raw service_dir="" resolved_explicit=""

    service_dir_raw="$(service_working_directory)"
    if [[ -n "$service_dir_raw" ]]; then
        service_dir="$(canonical_install_dir "$service_dir_raw")" || \
            die "${SERVICE_NAME}.service 的 WorkingDirectory 不是安全的绝对路径"
        validate_install_dir_safety "$service_dir"
        validate_service_contract "$service_dir"
    fi

    if [[ -n "$explicit_dir" ]]; then
        resolved_explicit="$(canonical_install_dir "$explicit_dir")" || \
            die "--install-dir 必须是可规范化的绝对路径"
        validate_install_dir_safety "$resolved_explicit"

        if [[ -n "$service_dir" ]]; then
            [[ "$resolved_explicit" == "$service_dir" ]] || \
                die "--install-dir (${resolved_explicit}) 与 service WorkingDirectory (${service_dir}) 不一致"
        else
            validate_explicit_install_evidence "$resolved_explicit"
        fi
        printf '%s\n' "$resolved_explicit"
        return 0
    fi

    [[ -n "$service_dir" ]] || \
        die "无法从 ${SERVICE_NAME}.service 确认安装目录；请用 --install-dir 指定并校验真实目录"
    printf '%s\n' "$service_dir"
}

service_is_installed() {
    [[ -f "$SERVICE_FILE" ]] && return 0
    command -v "$SYSTEMCTL_BIN" &>/dev/null && "$SYSTEMCTL_BIN" cat "${SERVICE_NAME}.service" &>/dev/null
}

main() {
    local force=false
    local explicit_install_dir=""
    local confirm
    local install_dir compose_file yaksha_compose_file

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install-dir)
                [[ $# -ge 2 ]] || die "--install-dir 缺少目录参数"
                explicit_install_dir="$2"
                shift 2
                ;;
            -y|--force) force=true; shift ;;
            -h|--help) usage; exit 0 ;;
            *) die "未知参数: $1" ;;
        esac
    done

    [[ "${EUID}" -eq 0 ]] || die "请使用 sudo 运行卸载脚本"

    # 所有破坏性操作之前先解析并校验目录。没有可验证来源时绝不使用默认路径。
    install_dir="$(resolve_install_dir "$explicit_install_dir")"
    compose_file="${install_dir}/deploy/docker-compose.yml"
    yaksha_compose_file="${install_dir}/deploy/yaksha-compose.yaml"

    echo -e "${RED}================================================${NC}"
    echo -e "${RED}       ⚠️  Argus Server 卸载向导  ⚠️              ${NC}"
    echo -e "${RED}================================================${NC}"
    echo -e "此脚本将永久删除以下内容："
    echo -e "  - ${YELLOW}${SERVICE_NAME} systemd 服务${NC}"
    echo -e "  - ${YELLOW}Docker 基础设施 (RabbitMQ, PostgreSQL)${NC}"
    echo -e "  - ${YELLOW}已验证的安装目录及所有数据: ${install_dir}${NC}"
    echo ""

    if [[ "$force" == "false" ]]; then
        read -r -p "确认要执行完全卸载吗？此操作不可逆！(输入 'yes' 确认): " confirm
        if [[ "$confirm" != "yes" ]]; then
            echo -e "${BLUE}已取消卸载操作。${NC}"
            exit 0
        fi
    fi

    echo -e "\n${YELLOW}[1/4] 停止并移除 systemd 服务...${NC}"
    if service_is_installed; then
        "$SYSTEMCTL_BIN" stop "$SERVICE_NAME" 2>/dev/null || true
        "$SYSTEMCTL_BIN" disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f -- "$SERVICE_FILE"
        "$SYSTEMCTL_BIN" daemon-reload
        echo -e "${GREEN}[✔] 已移除 systemd 服务${NC}"
    else
        echo -e "${GREEN}[✔] systemd 服务未安装，已跳过${NC}"
    fi

    echo -e "\n${YELLOW}[2/4] 停止并清理 Docker 容器...${NC}"
    if [[ -f "$yaksha_compose_file" ]]; then
        docker compose -f "$yaksha_compose_file" down --remove-orphans 2>/dev/null || true
    fi
    if [[ -f "$compose_file" ]]; then
        secrets_env_file="${install_dir}/config/secrets.env"
        if [[ -f "$secrets_env_file" ]]; then
            # 以 secrets.env 为权威（含 INSTALL_DIR 与全部凭据），完整解析 compose 后清理所有基础设施容器。
            docker compose --env-file "$secrets_env_file" -f "$compose_file" down -v --remove-orphans 2>/dev/null || true
        else
            # 无 secrets.env（旧环境）：提供假变量避免 compose 插值报错；bind mount 必须使用已验证安装目录。
            export POSTGRES_USER=postgres POSTGRES_PASSWORD=unused-uninstall-password POSTGRES_DB=argus POSTGRES_PORT=5432
            export RABBITMQ_DEFAULT_USER=argus RABBITMQ_DEFAULT_PASS=unused-uninstall-password RABBITMQ_PORT=5672 RABBITMQ_MANAGEMENT_PORT=15672
            export MINIO_ROOT_USER=unused MINIO_ROOT_PASSWORD=unused-uninstall-password
            export ARGUS_EXP_MINIO_ACCESS_KEY=unused ARGUS_EXP_MINIO_SECRET_KEY=unused-uninstall-password
            export INSTALL_DIR="$install_dir"
            docker compose -f "$compose_file" down -v --remove-orphans 2>/dev/null || true
        fi
        echo -e "${GREEN}[✔] 容器已清理${NC}"
    else
        # 尝试直接通过 Argus 专用容器名称清理。
        docker rm -f argus-minio-init argus-minio argus-rabbitmq argus-postgres 2>/dev/null || true
        echo -e "${GREEN}[✔] 容器清理完成 (备用模式)${NC}"
    fi

    echo -e "\n${YELLOW}[3/4] 删除安装目录和持久化数据...${NC}"
    if [[ -d "$install_dir" ]]; then
        rm -rf --one-file-system -- "$install_dir"
        echo -e "${GREEN}[✔] 已删除 ${install_dir}${NC}"
    else
        echo -e "${GREEN}[✔] 目录 ${install_dir} 不存在，已跳过${NC}"
    fi

    echo -e "\n${YELLOW}[4/4] 清理防火墙规则...${NC}"
    if command -v ufw &>/dev/null; then
        # 由于安装时通过端口添加了规则，卸载时较难精确匹配（不知道当初用了什么端口）。
        echo -e "${YELLOW}  提示: 安装程序曾可能在 ufw 开放过 API 和 gRPC 端口，请按需手动删除规则:${NC}"
        echo -e "        sudo ufw status numbered"
        echo -e "        sudo ufw delete <规则编号>"
    fi
    echo -e "${GREEN}[✔] 防火墙检查完成${NC}"

    echo -e "\n${BLUE}================================================${NC}"
    echo -e "${GREEN}  ✅ Argus Server 已成功卸载！${NC}"
    echo -e "${BLUE}================================================${NC}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
