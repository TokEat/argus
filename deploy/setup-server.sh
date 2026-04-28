#!/bin/bash
# ==============================================================================
# Argus Server 一键云端部署脚本
#
# 在一台全新的 Ubuntu 22.04/24.04 云实例上运行此脚本，将自动：
# 1. 安装 Docker 并通过 docker-compose 启动 PostgreSQL + RabbitMQ
# 2. 部署 dddd-server 二进制并执行数据库迁移
# 3. 注册为 systemd 服务并启动
#
# 用法：
#   # 将 release 产物和项目上传到云实例后执行
#   chmod +x deploy/setup-server.sh
#   ./deploy/setup-server.sh --public-ip <公网IP>
#
# 环境变量（可选，与 Makefile 保持一致）：
#   POSTGRES_USER       PostgreSQL 用户（默认: postgres）
#   POSTGRES_PASSWORD    PostgreSQL 密码（默认: root）
#   POSTGRES_DB          数据库名（默认: dddd）
#   POSTGRES_PORT        PostgreSQL 端口（默认: 5432）
#   RABBITMQ_PORT        RabbitMQ 端口（默认: 5672）
#   ARGUS_AGENT_PSK      Agent 认证预共享密钥（默认: 自动生成）
#   ARGUS_JWT_SECRET     API JWT 签名密钥（默认: 自动生成）
#   ARGUS_ENCRYPT_KEY    凭证加密密钥（默认: 自动生成，Base64 32字节）
#   ARGUS_API_PORT       HTTP API 端口（默认: 8085）
#   ARGUS_GRPC_PORT      gRPC 端口（默认: 50051）
# ==============================================================================

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# ---- 默认值（与 Makefile / docker-compose.yml 保持一致）----
# 生成 Base64 编码的 32 字节密钥（用于 ARGUS_ENCRYPT_KEY）
gen_encrypt_key() {
    openssl rand -base64 32 2>/dev/null | tr -d '\n' || \
    head -c 32 /dev/urandom | base64 | tr -d '\n'
}
POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-root}"
POSTGRES_DB="${POSTGRES_DB:-dddd}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
RABBITMQ_PORT="${RABBITMQ_PORT:-5672}"
RABBITMQ_MANAGEMENT_PORT="${RABBITMQ_MANAGEMENT_PORT:-15672}"
RABBITMQ_DEFAULT_USER="${RABBITMQ_DEFAULT_USER:-guest}"
RABBITMQ_DEFAULT_PASS="${RABBITMQ_DEFAULT_PASS:-guest}"

API_PORT="${ARGUS_API_PORT:-8085}"
GRPC_PORT="${ARGUS_GRPC_PORT:-50051}"
AGENT_PSK="${ARGUS_AGENT_PSK:-$(openssl rand -hex 16 2>/dev/null || head -c 16 /dev/urandom | xxd -p)}"
JWT_SECRET="${ARGUS_JWT_SECRET:-$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p)}"
ENCRYPT_KEY="${ARGUS_ENCRYPT_KEY:-$(gen_encrypt_key)}"
PUBLIC_IP=""

# 自动定位项目根目录（脚本在 deploy/ 目录下）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

# 解析参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        --public-ip)  PUBLIC_IP="$2";           shift 2 ;;
        --db-password) POSTGRES_PASSWORD="$2";  shift 2 ;;
        --psk)        AGENT_PSK="$2";           shift 2 ;;
        --jwt-secret) JWT_SECRET="$2";          shift 2 ;;
        --encrypt-key) ENCRYPT_KEY="$2";        shift 2 ;;
        -h|--help)    head -25 "$0" | grep '^#' | sed 's/^# //'; exit 0 ;;
        *)            echo -e "${RED}未知参数: $1${NC}"; exit 1 ;;
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

# DSN（与 Makefile 格式一致）
DB_DSN="host=127.0.0.1 user=${POSTGRES_USER} password=${POSTGRES_PASSWORD} dbname=${POSTGRES_DB} port=${POSTGRES_PORT} sslmode=disable"
AMQP_URL="amqp://${RABBITMQ_DEFAULT_USER}:${RABBITMQ_DEFAULT_PASS}@127.0.0.1:${RABBITMQ_PORT}/"
INSTALL_DIR="${ROOT_DIR}"

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}       Argus Server 一键部署                    ${NC}"
echo -e "${BLUE}================================================${NC}"
echo -e "  公网 IP:    ${GREEN}${PUBLIC_IP}${NC}"
echo -e "  API 端口:   ${GREEN}${API_PORT}${NC}"
echo -e "  gRPC 端口:  ${GREEN}${GRPC_PORT}${NC}"
echo -e "  Agent PSK:  ${GREEN}${AGENT_PSK}${NC}"
echo -e "  JWT Secret: ${GREEN}已生成/已加载${NC}"
echo -e "  EncryptKey: ${GREEN}已生成/已加载 (base64, 32-byte)${NC}"
echo -e "  PostgreSQL: ${GREEN}${POSTGRES_USER}:****@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}${NC}"
echo -e "  RabbitMQ:   ${GREEN}${RABBITMQ_DEFAULT_USER}:****@127.0.0.1:${RABBITMQ_PORT}${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""
# ============================================================
# Step 1: 安装 Docker
# ============================================================
echo -e "${YELLOW}[1/6] 检查 Docker 环境...${NC}"

if ! command -v docker &>/dev/null; then
    echo -e "${YELLOW}  安装 Docker...${NC}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi

# 确保 Docker 在运行
systemctl enable --now docker
echo -e "${GREEN}[✔] Docker 就绪$(docker --version | grep -oP 'Docker version \K[^,]+')${NC}"

# ============================================================
# Step 2: 通过 docker-compose 启动 PostgreSQL + RabbitMQ
# ============================================================
echo -e "${YELLOW}[2/6] 启动基础设施 (PostgreSQL + RabbitMQ)...${NC}"

if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo -e "${RED}[!] 找不到 ${COMPOSE_FILE}${NC}"
    echo -e "    请确保项目完整上传到云实例"
    exit 1
fi

# 导出环境变量供 docker-compose 使用
export POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB POSTGRES_PORT
export RABBITMQ_DEFAULT_USER RABBITMQ_DEFAULT_PASS RABBITMQ_PORT RABBITMQ_MANAGEMENT_PORT
export INSTALL_DIR

docker compose -f "$COMPOSE_FILE" up -d --remove-orphans rabbitmq postgres

# 等待服务健康
echo -ne "  等待 PostgreSQL 就绪..."
for i in $(seq 1 30); do
    if docker compose -f "$COMPOSE_FILE" exec -T postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" &>/dev/null; then
        echo -e " ${GREEN}OK${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

echo -ne "  等待 RabbitMQ 就绪..."
for i in $(seq 1 30); do
    if docker compose -f "$COMPOSE_FILE" exec -T rabbitmq rabbitmq-diagnostics -q ping &>/dev/null; then
        echo -e " ${GREEN}OK${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

# 初始化数据库（执行 init 脚本）
echo -e "  初始化数据库..."
docker compose -f "$COMPOSE_FILE" exec -T postgres bash -lc '/docker-entrypoint-initdb.d/000-init-db.sh' 2>/dev/null || true

echo -e "${GREEN}[✔] 基础设施就绪${NC}"

# ============================================================
# Step 3: 部署 Server 二进制
# ============================================================
echo -e "${YELLOW}[3/6] 部署 Server 二进制...${NC}"

mkdir -p "$INSTALL_DIR"/{bin,data,logs,config,release}
mkdir -p "$INSTALL_DIR/server-ui/dist"

# 查找 server 二进制（按优先级）
SERVER_BIN=""
for candidate in \
    "${ROOT_DIR}/bin/dddd-server-linux-amd64" \
    "${ROOT_DIR}/bin/dddd-server" \
    "${ROOT_DIR}/release/dddd-server-linux-amd64" \
    "${ROOT_DIR}/dddd-server-linux-amd64" \
    "./dddd-server-linux-amd64"; do
    if [[ -f "$candidate" ]]; then
        SERVER_BIN="$candidate"
        break
    fi
done

if [[ -z "$SERVER_BIN" ]]; then
    shopt -s nullglob
    tar_files=("${SCRIPT_DIR}"/argus-release-*.tar.gz "${ROOT_DIR}"/argus-release-*.tar.gz)
    shopt -u nullglob

    if [[ ${#tar_files[@]} -gt 0 ]]; then
        TAR_FILE="${tar_files[0]}"
        echo -e "${YELLOW}  检测到安装包: ${TAR_FILE}，正在自动解压...${NC}"
        tar -xzf "$TAR_FILE" -C "${ROOT_DIR}"
        # 解压后通常会有一个 argus-release-xxx 目录，再次尝试查找
        for candidate in \
            "${ROOT_DIR}"/argus-release-*/bin/dddd-server-linux-amd64 \
            "${ROOT_DIR}/bin/dddd-server-linux-amd64" \
            "${ROOT_DIR}/bin/dddd-server"; do
            if [[ -f "$candidate" ]]; then
                SERVER_BIN="$candidate"
                break
            fi
        done
    fi
fi

if [[ -z "$SERVER_BIN" ]]; then
    echo -e "${RED}[!] 找不到 dddd-server 二进制文件${NC}"
    echo -e "    请先在开发机编译:"
    echo -e "      ${YELLOW}./build.sh --component dddd-server --target linux/amd64${NC}"
    echo -e "    或者: ${YELLOW}make server GOOS=linux GOARCH=amd64${NC}"
    exit 1
fi

if [[ "$SERVER_BIN" != "$INSTALL_DIR/bin/dddd-server" ]]; then
    rm -f "$INSTALL_DIR/bin/dddd-server"
    cp "$SERVER_BIN" "$INSTALL_DIR/bin/dddd-server"
fi
chmod +x "$INSTALL_DIR/bin/dddd-server"
echo -e "  Server: ${GREEN}${SERVER_BIN} → ${INSTALL_DIR}/bin/dddd-server${NC}"

# 部署 Agent 二进制（用于 HTTP 分发给云实例）
AGENT_BIN=""
for candidate in \
    "${ROOT_DIR}/bin/dddd-agent-linux-amd64" \
    "${ROOT_DIR}/release/dddd-agent-linux-amd64" \
    "${ROOT_DIR}/dddd-agent-linux-amd64" \
    "./dddd-agent-linux-amd64" \
    "${ROOT_DIR}"/argus-release-*/bin/dddd-agent-linux-amd64; do
    if [[ -f "$candidate" ]]; then
        AGENT_BIN="$candidate"
        break
    fi
done

if [[ -n "$AGENT_BIN" ]]; then
    if [[ "$AGENT_BIN" != "$INSTALL_DIR/release/dddd-agent-linux-amd64" ]]; then
        rm -f "$INSTALL_DIR/release/dddd-agent-linux-amd64"
        cp "$AGENT_BIN" "$INSTALL_DIR/release/dddd-agent-linux-amd64"
    fi
    echo -e "  Agent:  ${GREEN}${AGENT_BIN} → ${INSTALL_DIR}/release/dddd-agent-linux-amd64${NC}"
fi

# 部署组件配置
CONFIG_SRC=""
for candidate in \
    "${ROOT_DIR}/config" \
    "${ROOT_DIR}"/argus-release-*/config; do
    if [[ -d "$candidate" && "$(ls -A "$candidate" 2>/dev/null)" ]]; then
        CONFIG_SRC="$candidate"
        break
    fi
done

if [[ -n "$CONFIG_SRC" ]]; then
    if [[ "$CONFIG_SRC" != "$INSTALL_DIR/config" ]]; then
        cp -r "$CONFIG_SRC/"* "$INSTALL_DIR/config/" 2>/dev/null || true
    fi
    echo -e "  Config: ${GREEN}${CONFIG_SRC} → ${INSTALL_DIR}/config/${NC}"
fi

echo -e "${GREEN}[✔] 二进制及配置部署完成${NC}"

# ============================================================
# Step 4: 数据库迁移
# ============================================================
echo -e "${YELLOW}[4/6] 执行数据库迁移...${NC}"

"$INSTALL_DIR/bin/dddd-server" --db "$DB_DSN" --migrate-only --db-migration-mode apply --config-dir "$INSTALL_DIR/config"
echo -e "${GREEN}[✔] 数据库迁移完成${NC}"

# ============================================================
# Step 4.5: 导入规则资产库
# ============================================================
echo -e "${YELLOW}[4.5/6] 导入安全规则资产库 (从预编译 DB 中恢复)...${NC}"

if [[ -f "${SCRIPT_DIR}/arsenal_seed.db" ]]; then
    "$INSTALL_DIR/bin/dddd-server" --db "$DB_DSN" --seed-from-db "${SCRIPT_DIR}/arsenal_seed.db"
    echo -e "${GREEN}[✔] 规则资产导入完成${NC}"
else
    echo -e "${YELLOW}[!] 未找到预编译的 arsenal_seed.db，跳过规则导入${NC}"
fi

# 部署前端静态资源
FRONTEND_SRC=""
for candidate in \
    "${ROOT_DIR}/server-ui/dist" \
    "${SCRIPT_DIR}/../server-ui/dist" \
    "${ROOT_DIR}"/argus-release-*/server-ui/dist; do
    if [[ -d "$candidate" && "$(ls -A "$candidate" 2>/dev/null)" ]]; then
        FRONTEND_SRC="$candidate"
        break
    fi
done

if [[ -n "$FRONTEND_SRC" ]]; then
    if [[ "$FRONTEND_SRC" != "$INSTALL_DIR/server-ui/dist" ]]; then
        cp -r "$FRONTEND_SRC/"* "$INSTALL_DIR/server-ui/dist/" 2>/dev/null || true
    fi
    echo -e "  Frontend: ${GREEN}${FRONTEND_SRC} → ${INSTALL_DIR}/server-ui/dist${NC}"
else
    echo -e "${YELLOW}  [!] 未找到前端静态资源 (server-ui/dist)，控制台界面可能无法访问。${NC}"
fi

# ============================================================
# Step 5: 创建 systemd 服务
# ============================================================
echo -e "${YELLOW}[5/6] 配置 systemd 服务...${NC}"

cat > /etc/systemd/system/argus-server.service <<EOF
[Unit]
Description=Argus Security Platform Server
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment=ARGUS_PUBLIC_IP=${PUBLIC_IP}
Environment=ARGUS_AGENT_PSK=${AGENT_PSK}
Environment=ARGUS_JWT_SECRET=${JWT_SECRET}
Environment=ARGUS_ENCRYPT_KEY=${ENCRYPT_KEY}
ExecStart=${INSTALL_DIR}/bin/dddd-server \\
    -db "${DB_DSN}" \\
    -amqp "${AMQP_URL}" \\
    -api ":${API_PORT}" \\
    -grpc ${GRPC_PORT} \\
    -agent-psk "${AGENT_PSK}" \\
    -config-dir "${INSTALL_DIR}/config"
Restart=always
RestartSec=5
StandardOutput=append:${INSTALL_DIR}/logs/server.log
StandardError=append:${INSTALL_DIR}/logs/server.log
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable argus-server
echo -e "${GREEN}[✔] systemd 服务配置完成${NC}"

# ============================================================
# Step 6: 防火墙 & 启动
# ============================================================
echo -e "${YELLOW}[6/6] 启动服务...${NC}"

# UFW 防火墙（如果存在）
if command -v ufw &>/dev/null; then
    ufw allow "${API_PORT}/tcp" comment "Argus API" 2>/dev/null || true
    ufw allow "${GRPC_PORT}/tcp" comment "Argus gRPC" 2>/dev/null || true
fi

systemctl restart argus-server
sleep 3

# 检查状态
if systemctl is-active --quiet argus-server; then
    echo -e "${GREEN}[✔] Argus Server 启动成功！${NC}"
else
    echo -e "${RED}[!] 启动失败，查看日志:${NC}"
    tail -30 "$INSTALL_DIR/logs/server.log"
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
echo -e "  🐰 RabbitMQ:  ${GREEN}http://${PUBLIC_IP}:${RABBITMQ_MANAGEMENT_PORT}${NC}"
echo ""
echo -e "  📋 常用命令:"
echo -e "     查看日志:       ${YELLOW}tail -f ${INSTALL_DIR}/logs/server.log${NC}"
echo -e "     重启服务:       ${YELLOW}systemctl restart argus-server${NC}"
echo -e "     查看状态:       ${YELLOW}systemctl status argus-server${NC}"
echo -e "     查看基础设施:   ${YELLOW}docker compose -f ${COMPOSE_FILE} ps${NC}"
echo -e "     重启基础设施:   ${YELLOW}docker compose -f ${COMPOSE_FILE} restart${NC}"
echo ""
echo -e "  ⚠️  请确保云安全组已开放以下端口:"
echo -e "     - ${YELLOW}${API_PORT}${NC} (TCP) — HTTP API / 管理面板"
echo -e "     - ${YELLOW}${GRPC_PORT}${NC} (TCP) — Agent gRPC 通信"
echo ""
echo -e "  📦 部署 Agent 到扫描节点:"
echo -e "     ${YELLOW}./dddd-agent --server ${PUBLIC_IP}:${GRPC_PORT} --api http://${PUBLIC_IP}:${API_PORT} --psk ${AGENT_PSK}${NC}"
echo ""
