#!/bin/bash
# ==============================================================================
# Argus Server 一键云端部署脚本
#
# 在一台全新的 Ubuntu 22.04/24.04 云实例上运行此脚本，将自动：
# 1. 安装 PostgreSQL 和 RabbitMQ
# 2. 下载/部署 dddd-server 二进制
# 3. 构建前端 UI
# 4. 注册为 systemd 服务并启动
#
# 用法：
#   # 方式1：直接在云实例上执行（需要先上传 release 产物）
#   curl -fsSL <your-url>/setup-server.sh | bash -s -- --public-ip <公网IP>
#
#   # 方式2：手动执行
#   chmod +x setup-server.sh
#   ./setup-server.sh --public-ip <公网IP>
#
# 环境变量（可选）：
#   ARGUS_DB_PASSWORD   PostgreSQL 密码（默认: argus2026）
#   ARGUS_AGENT_PSK     Agent 认证预共享密钥（默认: 自动生成）
#   ARGUS_API_PORT      HTTP API 端口（默认: 8085）
#   ARGUS_GRPC_PORT     gRPC 端口（默认: 50051）
# ==============================================================================

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# 默认值
DB_PASSWORD="${ARGUS_DB_PASSWORD:-argus2026}"
API_PORT="${ARGUS_API_PORT:-8085}"
GRPC_PORT="${ARGUS_GRPC_PORT:-50051}"
AGENT_PSK="${ARGUS_AGENT_PSK:-$(openssl rand -hex 16)}"
PUBLIC_IP=""
SERVER_BIN=""
UI_DIR=""

# 解析参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        --public-ip)
            PUBLIC_IP="$2"
            shift 2
            ;;
        --server-bin)
            SERVER_BIN="$2"
            shift 2
            ;;
        --ui-dir)
            UI_DIR="$2"
            shift 2
            ;;
        --db-password)
            DB_PASSWORD="$2"
            shift 2
            ;;
        --psk)
            AGENT_PSK="$2"
            shift 2
            ;;
        -h|--help)
            head -30 "$0" | grep '^#' | sed 's/^# //'
            exit 0
            ;;
        *)
            echo -e "${RED}未知参数: $1${NC}"
            exit 1
            ;;
    esac
done

# 自动检测公网 IP
if [[ -z "$PUBLIC_IP" ]]; then
    PUBLIC_IP=$(curl -4 -s --connect-timeout 5 ifconfig.me || curl -4 -s --connect-timeout 5 icanhazip.com || echo "")
    if [[ -z "$PUBLIC_IP" ]]; then
        echo -e "${RED}[!] 无法自动检测公网 IP，请使用 --public-ip 参数指定${NC}"
        exit 1
    fi
    echo -e "${YELLOW}[*] 自动检测到公网 IP: ${PUBLIC_IP}${NC}"
fi

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}       Argus Server 一键部署                    ${NC}"
echo -e "${BLUE}================================================${NC}"
echo -e "  公网 IP:    ${GREEN}${PUBLIC_IP}${NC}"
echo -e "  API 端口:   ${GREEN}${API_PORT}${NC}"
echo -e "  gRPC 端口:  ${GREEN}${GRPC_PORT}${NC}"
echo -e "  Agent PSK:  ${GREEN}${AGENT_PSK}${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# ============================================================
# Step 1: 系统依赖
# ============================================================
echo -e "${YELLOW}[1/6] 安装系统依赖...${NC}"

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq
sudo apt-get install -y -qq curl wget gnupg2 lsb-release ca-certificates

# ============================================================
# Step 2: PostgreSQL
# ============================================================
echo -e "${YELLOW}[2/6] 安装 PostgreSQL...${NC}"

if ! command -v psql &>/dev/null; then
    sudo apt-get install -y -qq postgresql postgresql-contrib
fi

sudo systemctl enable --now postgresql

# 创建数据库和用户
sudo -u postgres psql -c "SELECT 1 FROM pg_roles WHERE rolname='argus'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER argus WITH PASSWORD '${DB_PASSWORD}';"
sudo -u postgres psql -c "SELECT 1 FROM pg_database WHERE datname='argus'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE argus OWNER argus;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE argus TO argus;"

echo -e "${GREEN}[✔] PostgreSQL 就绪${NC}"

# ============================================================
# Step 3: RabbitMQ
# ============================================================
echo -e "${YELLOW}[3/6] 安装 RabbitMQ...${NC}"

if ! command -v rabbitmqctl &>/dev/null; then
    sudo apt-get install -y -qq rabbitmq-server
fi

sudo systemctl enable --now rabbitmq-server

echo -e "${GREEN}[✔] RabbitMQ 就绪${NC}"

# ============================================================
# Step 4: 部署 Server 二进制
# ============================================================
echo -e "${YELLOW}[4/6] 部署 Server 二进制...${NC}"

INSTALL_DIR="/opt/argus"
sudo mkdir -p "$INSTALL_DIR"/{bin,data,logs,config,ui}

# 查找 server 二进制
if [[ -n "$SERVER_BIN" && -f "$SERVER_BIN" ]]; then
    sudo cp "$SERVER_BIN" "$INSTALL_DIR/bin/dddd-server"
elif [[ -f "./dddd-server-linux-amd64" ]]; then
    sudo cp ./dddd-server-linux-amd64 "$INSTALL_DIR/bin/dddd-server"
elif [[ -f "./release/dddd-server-linux-amd64" ]]; then
    sudo cp ./release/dddd-server-linux-amd64 "$INSTALL_DIR/bin/dddd-server"
else
    echo -e "${RED}[!] 找不到 dddd-server 二进制文件${NC}"
    echo -e "    请先编译: ./build.sh --component dddd-server --target linux/amd64"
    echo -e "    然后将 release/dddd-server-linux-amd64 上传到当前目录"
    exit 1
fi

sudo chmod +x "$INSTALL_DIR/bin/dddd-server"

# 部署前端 UI（如果有）
if [[ -n "$UI_DIR" && -d "$UI_DIR" ]]; then
    sudo cp -r "$UI_DIR"/* "$INSTALL_DIR/ui/"
elif [[ -d "./server-ui/dist" ]]; then
    sudo cp -r ./server-ui/dist/* "$INSTALL_DIR/ui/"
fi

# 部署 Agent 二进制（用于 OSS 上传或 HTTP 分发）
if [[ -f "./dddd-agent-linux-amd64" ]]; then
    sudo mkdir -p "$INSTALL_DIR/release"
    sudo cp ./dddd-agent-linux-amd64 "$INSTALL_DIR/release/"
elif [[ -f "./release/dddd-agent-linux-amd64" ]]; then
    sudo mkdir -p "$INSTALL_DIR/release"
    sudo cp ./release/dddd-agent-linux-amd64 "$INSTALL_DIR/release/"
fi

echo -e "${GREEN}[✔] Server 二进制部署完成${NC}"

# ============================================================
# Step 5: 创建 systemd 服务
# ============================================================
echo -e "${YELLOW}[5/6] 配置 systemd 服务...${NC}"

DB_DSN="host=localhost port=5432 user=argus password=${DB_PASSWORD} dbname=argus sslmode=disable"

sudo tee /etc/systemd/system/argus-server.service > /dev/null <<EOF
[Unit]
Description=Argus Security Platform Server
After=network-online.target postgresql.service rabbitmq-server.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment=ARGUS_PUBLIC_IP=${PUBLIC_IP}
Environment=ARGUS_AGENT_PSK=${AGENT_PSK}
ExecStart=${INSTALL_DIR}/bin/dddd-server \\
    -db "${DB_DSN}" \\
    -amqp "amqp://guest:guest@localhost:5672/" \\
    -api ":${API_PORT}" \\
    -grpc ${GRPC_PORT} \\
    -agent-psk "${AGENT_PSK}" \\
    -dev
Restart=always
RestartSec=5
StandardOutput=append:${INSTALL_DIR}/logs/server.log
StandardError=append:${INSTALL_DIR}/logs/server.log
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable argus-server

echo -e "${GREEN}[✔] systemd 服务配置完成${NC}"

# ============================================================
# Step 6: 防火墙 & 启动
# ============================================================
echo -e "${YELLOW}[6/6] 配置防火墙并启动服务...${NC}"

# UFW 防火墙（如果存在）
if command -v ufw &>/dev/null; then
    sudo ufw allow ${API_PORT}/tcp comment "Argus API" 2>/dev/null || true
    sudo ufw allow ${GRPC_PORT}/tcp comment "Argus gRPC" 2>/dev/null || true
fi

sudo systemctl restart argus-server
sleep 3

# 检查状态
if sudo systemctl is-active --quiet argus-server; then
    echo -e "${GREEN}[✔] Argus Server 启动成功！${NC}"
else
    echo -e "${RED}[!] 启动失败，查看日志:${NC}"
    sudo tail -20 "$INSTALL_DIR/logs/server.log"
    exit 1
fi

echo ""
echo -e "${BLUE}================================================${NC}"
echo -e "${GREEN}  ✅ Argus Server 部署完成！${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""
echo -e "  🌐 管理面板:  ${GREEN}http://${PUBLIC_IP}:${API_PORT}${NC}"
echo -e "  🔌 gRPC:      ${GREEN}${PUBLIC_IP}:${GRPC_PORT}${NC}"
echo -e "  🔑 Agent PSK: ${GREEN}${AGENT_PSK}${NC}"
echo ""
echo -e "  📋 常用命令:"
echo -e "     查看日志:   ${YELLOW}tail -f /opt/argus/logs/server.log${NC}"
echo -e "     重启服务:   ${YELLOW}sudo systemctl restart argus-server${NC}"
echo -e "     查看状态:   ${YELLOW}sudo systemctl status argus-server${NC}"
echo ""
echo -e "  ⚠️  请确保阿里云安全组已开放以下端口:"
echo -e "     - ${YELLOW}${API_PORT}${NC} (TCP) — HTTP API / 管理面板"
echo -e "     - ${YELLOW}${GRPC_PORT}${NC} (TCP) — Agent gRPC 通信"
echo ""
echo -e "  📦 部署 Agent 到扫描节点:"
echo -e "     ${YELLOW}./dddd-agent --server ${PUBLIC_IP}:${GRPC_PORT} --api http://${PUBLIC_IP}:${API_PORT} --psk ${AGENT_PSK}${NC}"
echo ""
