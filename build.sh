#!/bin/bash

# ==============================================================================
# dddd 全平台自动构建脚本
# 支持交叉编译：Linux (amd64/arm64), macOS (amd64/arm64), Windows (amd64/386)
# 包含自动获取纯Go SQLite依赖、UPX极限压缩等功能
# usage: ./build.sh [pack] (加上 pack 参数表示使用 upx 压缩当前机器平台支持的二进制文件)
# ==============================================================================

set -e

# 配置产物输出目录
OUTPUT_DIR="release"

# 定义需要编译的组件数组。格式: "组件名:main文件路径:是否加EXE后缀(Windows专属)"
declare -a COMPONENTS=(
    "dddd:./scanner/cmd/cli:true"
    "dddd-agent:./scanner/cmd/agent:true"
    "dddd-server:./server/cmd/dddd-server:true"
)

# 定义要编译的目标平台数组。格式: "GOOS:GOARCH"
declare -a TARGETS=(
    "darwin:amd64"
    "darwin:arm64"
    "linux:amd64"
    "linux:arm64"
    "windows:amd64"
    "windows:386"
)

# 设置控制台颜色
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}       dddd 全平台交叉编译构建         ${NC}"
echo -e "${BLUE}=======================================${NC}"

# 判断是否需要压缩
USE_UPX=false
if [ "$1" == "pack" ]; then
    if command -v upx &> /dev/null; then
        USE_UPX=true
        echo -e "${GREEN}[✔] 检测到 UPX，将开启二进制压缩模式。${NC}"
    else
        echo -e "${RED}[!] 收到 pack 参数，但未安装 upx。跳过压缩。${NC}"
        echo -e "${YELLOW}    提示: macOS 请使用 'brew install upx' 安装${NC}"
    fi
fi

# 清理或创建输出目录
if [ -d "$OUTPUT_DIR" ]; then
    echo -e "清理旧的 release 目录..."
    rm -rf "${OUTPUT_DIR:?}"/*
else
    mkdir -p "$OUTPUT_DIR"
fi

# 检查依赖状态（不改动 go.mod/go.sum）
echo -e "\n${YELLOW}检查依赖状态...${NC}"
go mod verify >/dev/null
echo -e "${GREEN}[✔] 依赖校验通过${NC}"

# 开始编译循环
echo -e "\n${YELLOW}开始交叉编译各平台版本...${NC}"

for target in "${TARGETS[@]}"; do
    IFS=":" read -r os arch <<< "$target"
    
    echo -e "\n${BLUE}➤ 目标平台: [${os}/${arch}]${NC}"

    for component in "${COMPONENTS[@]}"; do
        IFS=":" read -r name path win_exe <<< "$component"

        # 设置输出文件名
        OUT_FILE="${OUTPUT_DIR}/${name}-${os}-${arch}"
        if [ "$os" == "windows" ] && [ "$win_exe" == "true" ]; then
            OUT_FILE="${OUT_FILE}.exe"
        fi

        echo -n "  编译 [${name}] ... "

        # 编译命令 (CGO_ENABLED=0 保障跨平台通过，去除符号表缩减体积)
        CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" go build \
            -ldflags="-s -w" \
            -trimpath \
            -o "${OUT_FILE}" "${path}"

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}成功${NC}"
            
            # 执行 UPX 压缩
            if [ "$USE_UPX" == "true" ]; then
                # UPX 对于某些 macOS 二进制文件和早期版本支持不完善
                # 这里我们执行压缩，并压制冗长的标准输出
                upx_args="-9 --quiet"
                if [ "$os" == "darwin" ]; then
                    upx_args="$upx_args --force-macos"
                fi

                # 捕获压缩错误，避免由于某平台不支持 upx 导致整个脚本停止
                set +e
                upx $upx_args "${OUT_FILE}" >/dev/null 2>&1
                UPX_STATUS=$?
                set -e
                
                if [ $UPX_STATUS -eq 0 ]; then
                    echo -e "    ${YELLOW}↳ UPX 压缩成功${NC}"
                else
                    echo -e "    ${RED}↳ UPX 跳过该架构 (暂不支持或失败)${NC}"
                fi
            fi
        else
            echo -e "${RED}失败${NC}"
        fi
    done
done

echo -e "\n${GREEN}=======================================${NC}"
echo -e "${GREEN}  🎉 所有版本编译完成！产物已存入 ${OUTPUT_DIR}/ 目录 ${NC}"
echo -e "${GREEN}=======================================${NC}"
ls -lh "$OUTPUT_DIR"
