#!/bin/bash
# ==============================================================================
# Argus 生产环境打包脚本
#
# 该脚本用于将 Argus 项目打包为一键部署的产物 (tar.gz)
# 默认版本: v0.1.0
# 产物包含：
# 1. 预编译的 server 和 agent 二进制文件、Yaksha OCI 镜像
# 2. server-ui/dist 前端静态资源
# 3. docker-compose.yml、生产配置模板和部署/卸载脚本
# 4. 必需规则资产库 deploy/arsenal_seed.db
#
# 用法: 
#   ./deploy/build-bundle.sh [版本号]
# 示例:
#   ./deploy/build-bundle.sh v0.1.0
# ==============================================================================

set -euo pipefail

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION=${1:-"v0.1.0"}
if [[ ! "${VERSION}" =~ ^v[0-9]+(\.[0-9]+){2}([-.][0-9A-Za-z.-]+)?$ ]]; then
    echo "Invalid release version: ${VERSION}; expected vMAJOR.MINOR.PATCH" >&2
    exit 2
fi
BUNDLE_NAME="argus-release-${VERSION}"
BUNDLE_DIR="${ROOT_DIR}/${BUNDLE_NAME}"
ARCHIVE_NAME="${BUNDLE_NAME}-linux-amd64.tar.gz"

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}       Argus 生产环境打包工具                   ${NC}"
echo -e "${BLUE}================================================${NC}"
echo -e "  版本号: ${GREEN}${VERSION}${NC}"
echo -e "  产物名: ${GREEN}${ARCHIVE_NAME}${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# 1. 编译 Linux/amd64 二进制文件
echo -e "${YELLOW}[1/3] 编译项目二进制文件...${NC}"
cd "${ROOT_DIR}"
# 调用全平台构建脚本，只构建服务端和Agent的 linux/amd64 架构
./build.sh --pack --require-upx --component argus-server,argus-agent --target linux/amd64

if [[ ! -f "${ROOT_DIR}/release/argus-server-linux-amd64" ]] || [[ ! -f "${ROOT_DIR}/release/argus-agent-linux-amd64" ]]; then
    echo -e "${RED}[!] 编译失败或未找到产物，请检查构建日志。${NC}"
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}[!] 构建 Yaksha 生产镜像需要 Docker${NC}"
    exit 1
fi
docker build --platform linux/amd64 -f "${ROOT_DIR}/yaksha/Dockerfile" -t argus-yaksha:local "${ROOT_DIR}"

# 1.5 编译前端控制台
echo -e "${YELLOW}[1.5/3] 编译前端页面...${NC}"
cd "${ROOT_DIR}/server-ui"
npm ci
npm run build
cd "${ROOT_DIR}"

# 2. 准备打包目录结构
echo -e "${YELLOW}[2/3] 整理部署文件与资源...${NC}"
rm -rf "${BUNDLE_DIR}"
mkdir -p "${BUNDLE_DIR}/bin"
mkdir -p "${BUNDLE_DIR}/deploy/db"
mkdir -p "${BUNDLE_DIR}/deploy/images"

# 拷贝二进制
echo "  -> 拷贝服务端和 Agent..."
cp "${ROOT_DIR}/release/argus-server-linux-amd64" "${BUNDLE_DIR}/bin/"
cp "${ROOT_DIR}/release/argus-agent-linux-amd64" "${BUNDLE_DIR}/bin/"
docker save -o "${BUNDLE_DIR}/deploy/images/argus-yaksha-linux-amd64.tar" argus-yaksha:local

# 拷贝前端产物
echo "  -> 拷贝前端控制台..."
mkdir -p "${BUNDLE_DIR}/server-ui"
if [[ -d "${ROOT_DIR}/server-ui/dist" ]]; then
    cp -r "${ROOT_DIR}/server-ui/dist" "${BUNDLE_DIR}/server-ui/"
else
    echo -e "${YELLOW}[!] 警告: 未找到前端产物 server-ui/dist${NC}"
fi

# 拷贝部署脚本和配置
echo "  -> 拷贝环境部署脚本和 Docker 编排文件..."
cp "${SCRIPT_DIR}/setup-server.sh" "${BUNDLE_DIR}/deploy/"
cp "${SCRIPT_DIR}/upgrade-server.sh" "${BUNDLE_DIR}/deploy/"
cp "${SCRIPT_DIR}/uninstall-server.sh" "${BUNDLE_DIR}/deploy/"
cp "${SCRIPT_DIR}/docker-compose.yml" "${BUNDLE_DIR}/deploy/"
cp "${SCRIPT_DIR}/production.env.example" "${BUNDLE_DIR}/deploy/"
cp "${ROOT_DIR}/yaksha/compose.yaml" "${BUNDLE_DIR}/deploy/yaksha-compose.yaml"

# 生成并拷贝预编译的规则数据库
echo "  -> 编译规则资产库为单文件 DB..."
cd "${ROOT_DIR}/server"
go build -o build_seed_db scripts/build_seed_db.go
cd "${ROOT_DIR}"
./server/build_seed_db
if [[ -f "${ROOT_DIR}/deploy/arsenal_seed.db" ]]; then
    cp "${ROOT_DIR}/deploy/arsenal_seed.db" "${BUNDLE_DIR}/deploy/"
else
    echo -e "${RED}[!] 规则资产库生成失败: ${ROOT_DIR}/deploy/arsenal_seed.db 不存在${NC}"
    exit 1
fi

# 拷贝数据库初始化脚本
# 数据库初始化 SQL 与脚本是部署必需品，缺失即失败（不得静默跳过）
if [[ ! -f "${ROOT_DIR}/deploy/db/init/001_init.sql" || ! -f "${ROOT_DIR}/deploy/db-init.sh" ]]; then
    echo -e "${RED}[!] 缺少数据库初始化文件 deploy/db/ 或 deploy/db-init.sh${NC}"
    exit 1
fi
cp -r "${ROOT_DIR}/deploy/db/"* "${BUNDLE_DIR}/deploy/db/"

required_paths=(
    "bin/argus-server-linux-amd64"
    "bin/argus-agent-linux-amd64"
    "server-ui/dist"
    "deploy/docker-compose.yml"
    "deploy/setup-server.sh"
    "deploy/upgrade-server.sh"
    "deploy/uninstall-server.sh"
    "deploy/production.env.example"
    "deploy/yaksha-compose.yaml"
    "deploy/images/argus-yaksha-linux-amd64.tar"
    "deploy/arsenal_seed.db"
)

for required_path in "${required_paths[@]}"; do
    if [[ ! -e "${BUNDLE_DIR}/${required_path}" ]]; then
        echo -e "${RED}[!] 发行包缺少必需文件: ${required_path}${NC}"
        exit 1
    fi
done

# 3. 压缩打包
echo -e "${YELLOW}[3/3] 生成发行包...${NC}"
cd "${ROOT_DIR}"
tar -czf "${SCRIPT_DIR}/${ARCHIVE_NAME}" "${BUNDLE_NAME}"
rm -rf "${BUNDLE_DIR}"

echo -e "${GREEN}[✔] 打包完成: ${SCRIPT_DIR}/${ARCHIVE_NAME}${NC}"
echo -e "部署说明:"
echo -e "  1. 将 ${ARCHIVE_NAME} 上传到目标云实例。"
echo -e "  2. 执行解压: tar -xzf ${ARCHIVE_NAME}"
echo -e "  3. 进入解压后的目录并运行部署脚本: cd ${BUNDLE_NAME} && sudo ./deploy/setup-server.sh"
echo ""
