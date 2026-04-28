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
# ==============================================================================

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/argus"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

FORCE=false

# 解析参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--force) FORCE=true; shift ;;
        -h|--help)  head -15 "$0" | grep '^#' | sed 's/^# //'; exit 0 ;;
        *)          echo -e "${RED}未知参数: $1${NC}"; exit 1 ;;
    esac
done

echo -e "${RED}================================================${NC}"
echo -e "${RED}       ⚠️  Argus Server 卸载向导  ⚠️              ${NC}"
echo -e "${RED}================================================${NC}"
echo -e "此脚本将永久删除以下内容："
echo -e "  - ${YELLOW}argus-server systemd 服务${NC}"
echo -e "  - ${YELLOW}Docker 基础设施 (RabbitMQ, PostgreSQL)${NC}"
echo -e "  - ${YELLOW}安装目录及所有数据: ${INSTALL_DIR}${NC}"
echo ""

if [[ "$FORCE" == "false" ]]; then
    read -p "确认要执行完全卸载吗？此操作不可逆！(输入 'yes' 确认): " confirm
    if [[ "$confirm" != "yes" ]]; then
        echo -e "${BLUE}已取消卸载操作。${NC}"
        exit 0
    fi
fi

echo -e "\n${YELLOW}[1/4] 停止并移除 systemd 服务...${NC}"
if systemctl list-unit-files | grep -q "argus-server.service"; then
    systemctl stop argus-server 2>/dev/null || true
    systemctl disable argus-server 2>/dev/null || true
    rm -f /etc/systemd/system/argus-server.service
    systemctl daemon-reload
    echo -e "${GREEN}[✔] 已移除 systemd 服务${NC}"
else
    echo -e "${GREEN}[✔] systemd 服务未安装，已跳过${NC}"
fi

echo -e "\n${YELLOW}[2/4] 停止并清理 Docker 容器...${NC}"
if [[ -f "$COMPOSE_FILE" ]]; then
    # 提供假变量避免 docker compose 警告
    export POSTGRES_USER=postgres POSTGRES_PASSWORD=root POSTGRES_DB=dddd POSTGRES_PORT=5432
    export RABBITMQ_DEFAULT_USER=guest RABBITMQ_DEFAULT_PASS=guest RABBITMQ_PORT=5672 RABBITMQ_MANAGEMENT_PORT=15672
    export INSTALL_DIR
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
    echo -e "${GREEN}[✔] 容器已清理${NC}"
else
    # 尝试直接通过容器名称清理
    docker rm -f argus-rabbitmq argus-postgres 2>/dev/null || true
    echo -e "${GREEN}[✔] 容器清理完成 (备用模式)${NC}"
fi

echo -e "\n${YELLOW}[3/4] 删除安装目录和持久化数据...${NC}"
if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    echo -e "${GREEN}[✔] 已删除 ${INSTALL_DIR}${NC}"
else
    echo -e "${GREEN}[✔] 目录 ${INSTALL_DIR} 不存在，已跳过${NC}"
fi

echo -e "\n${YELLOW}[4/4] 清理防火墙规则...${NC}"
if command -v ufw &>/dev/null; then
    # 由于安装时通过端口添加了规则，卸载时较难精确匹配（不知道当初用了什么端口）
    echo -e "${YELLOW}  提示: 安装程序曾可能在 ufw 开放过 API 和 gRPC 端口，请按需手动删除规则:${NC}"
    echo -e "        sudo ufw status numbered"
    echo -e "        sudo ufw delete <规则编号>"
fi
echo -e "${GREEN}[✔] 防火墙检查完成${NC}"

echo -e "\n${BLUE}================================================${NC}"
echo -e "${GREEN}  ✅ Argus Server 已成功卸载！${NC}"
echo -e "${BLUE}================================================${NC}"
