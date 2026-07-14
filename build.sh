#!/bin/bash

# ==============================================================================
# dddd 全平台自动构建脚本
# 支持交叉编译：Linux (amd64/arm64), macOS (amd64/arm64), Windows (amd64/386)
#
# 新增能力：
# 1) 可按组件类型编译（dddd / dddd-agent / dddd-server）
# 2) 可按平台版本编译（darwin/arm64, linux:amd64, windows-amd64 等）
#
# 用法示例：
#   ./build.sh
#   ./build.sh pack
#   ./build.sh --component dddd-agent --target darwin/arm64
#   ./build.sh --component dddd,dddd-server --target linux/amd64,linux/arm64
#   ./build.sh --list
# ==============================================================================

set -euo pipefail

OUTPUT_DIR="release"

# 格式: "name:main_path:windows_has_exe"
declare -a COMPONENTS=(
    "dddd:./scanner/cmd/cli:true"
    "dddd-agent:./scanner/cmd/agent:true"
    "dddd-server:./server/cmd/dddd-server:true"
)

# 格式: "goos:goarch"
declare -a TARGETS=(
    "darwin:amd64"
    "darwin:arm64"
    "linux:amd64"
    "linux:arm64"
    "windows:amd64"
    "windows:386"
)

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

show_help() {
    cat <<'EOF'
dddd build script

Usage:
  ./build.sh [pack] [--require-upx] [--component <name[,name...]>] [--target <os/arch[,os/arch...]>]
  ./build.sh --list

Options:
  pack, --pack            启用 UPX 压缩（需本机安装 upx）
  --require-upx           UPX 缺失、压缩失败或压缩后自检失败时直接终止
  -c, --component         指定组件类型，支持多个逗号分隔：
                          dddd, dddd-agent, dddd-server
  -t, --target            指定平台版本，支持多个逗号分隔：
                          darwin/arm64, linux:amd64, windows-amd64
  --list                  仅展示可用组件和平台
  -h, --help              显示帮助

Notes:
  1) 未指定 component/target 时，默认全量构建并清空 release 目录
  2) 指定了筛选条件时，执行增量构建，不会清空 release 目录
EOF
}

list_supported() {
    echo -e "${BLUE}可用组件:${NC}"
    for component in "${COMPONENTS[@]}"; do
        IFS=":" read -r name _path _win_exe <<< "$component"
        echo "  - ${name}"
    done
    echo -e "${BLUE}可用平台:${NC}"
    for target in "${TARGETS[@]}"; do
        IFS=":" read -r os arch <<< "$target"
        echo "  - ${os}/${arch}"
    done
}

normalize_target() {
    local raw="$1"
    raw="${raw//-/:}"
    raw="${raw//\//:}"
    echo "$raw"
}

contains_component() {
    local wanted="$1"
    local component
    for component in "${COMPONENTS[@]}"; do
        IFS=":" read -r name _path _win_exe <<< "$component"
        if [[ "$name" == "$wanted" ]]; then
            return 0
        fi
    done
    return 1
}

contains_target() {
    local wanted="$1"
    local target
    for target in "${TARGETS[@]}"; do
        if [[ "$target" == "$wanted" ]]; then
            return 0
        fi
    done
    return 1
}

USE_UPX_REQUESTED=false
REQUIRE_UPX=false
LIST_ONLY=false
COMPONENT_FILTER=""
TARGET_FILTER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        pack|--pack)
            USE_UPX_REQUESTED=true
            shift
            ;;
        --require-upx)
            REQUIRE_UPX=true
            USE_UPX_REQUESTED=true
            shift
            ;;
        -c|--component)
            if [[ $# -lt 2 ]]; then
                echo -e "${RED}[!] --component 需要参数${NC}"
                exit 1
            fi
            COMPONENT_FILTER="$2"
            shift 2
            ;;
        -t|--target)
            if [[ $# -lt 2 ]]; then
                echo -e "${RED}[!] --target 需要参数${NC}"
                exit 1
            fi
            TARGET_FILTER="$2"
            shift 2
            ;;
        --list)
            LIST_ONLY=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}[!] 未知参数: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

if [[ "$LIST_ONLY" == "true" ]]; then
    list_supported
    exit 0
fi

echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}       dddd 全平台交叉编译构建         ${NC}"
echo -e "${BLUE}=======================================${NC}"

USE_UPX=false
if [[ "$USE_UPX_REQUESTED" == "true" ]]; then
    if command -v upx >/dev/null 2>&1; then
        USE_UPX=true
        echo -e "${GREEN}[✔] 检测到 UPX，将开启二进制压缩模式。${NC}"
    else
        echo -e "${RED}[!] 收到 pack 参数，但未安装 upx。跳过压缩。${NC}"
        echo -e "${YELLOW}    提示: macOS 请使用 'brew install upx' 安装${NC}"
        if [[ "$REQUIRE_UPX" == "true" ]]; then
            echo -e "${RED}[!] 当前构建要求 UPX，无法继续。${NC}"
            exit 1
        fi
    fi
fi

declare -a SELECTED_COMPONENTS=()
declare -a SELECTED_TARGETS=()

if [[ -z "$COMPONENT_FILTER" ]]; then
    SELECTED_COMPONENTS=("${COMPONENTS[@]}")
else
    IFS=',' read -r -a requested_components <<< "$COMPONENT_FILTER"
    for requested in "${requested_components[@]}"; do
        requested="$(echo "$requested" | xargs)"
        if [[ -z "$requested" ]]; then
            continue
        fi
        if ! contains_component "$requested"; then
            echo -e "${RED}[!] 未知组件: ${requested}${NC}"
            list_supported
            exit 1
        fi
        for component in "${COMPONENTS[@]}"; do
            IFS=":" read -r name _path _win_exe <<< "$component"
            if [[ "$name" == "$requested" ]]; then
                SELECTED_COMPONENTS+=("$component")
            fi
        done
    done
fi

if [[ -z "$TARGET_FILTER" ]]; then
    SELECTED_TARGETS=("${TARGETS[@]}")
else
    IFS=',' read -r -a requested_targets <<< "$TARGET_FILTER"
    for requested in "${requested_targets[@]}"; do
        requested="$(echo "$requested" | xargs)"
        if [[ -z "$requested" ]]; then
            continue
        fi
        normalized="$(normalize_target "$requested")"
        if ! contains_target "$normalized"; then
            echo -e "${RED}[!] 未知平台: ${requested}${NC}"
            list_supported
            exit 1
        fi
        SELECTED_TARGETS+=("$normalized")
    done
fi

if [[ ${#SELECTED_COMPONENTS[@]} -eq 0 ]]; then
    echo -e "${RED}[!] 未匹配到任何组件，请检查 --component 参数${NC}"
    exit 1
fi

if [[ ${#SELECTED_TARGETS[@]} -eq 0 ]]; then
    echo -e "${RED}[!] 未匹配到任何平台，请检查 --target 参数${NC}"
    exit 1
fi

full_build=false
if [[ -z "$COMPONENT_FILTER" && -z "$TARGET_FILTER" ]]; then
    full_build=true
fi

if [[ ! -d "$OUTPUT_DIR" ]]; then
    mkdir -p "$OUTPUT_DIR"
elif [[ "$full_build" == "true" ]]; then
    echo -e "清理旧的 release 目录..."
    rm -rf "${OUTPUT_DIR:?}"/*
else
    echo -e "${YELLOW}增量构建模式：保留现有 release 产物，仅覆盖目标文件${NC}"
fi

echo -e "\n${YELLOW}检查依赖状态...${NC}"
go mod verify >/dev/null
echo -e "${GREEN}[✔] 依赖校验通过${NC}"

echo -e "\n${YELLOW}开始编译...${NC}"
echo -e "${BLUE}组件数量: ${#SELECTED_COMPONENTS[@]}，平台数量: ${#SELECTED_TARGETS[@]}${NC}"

for target in "${SELECTED_TARGETS[@]}"; do
    IFS=":" read -r os arch <<< "$target"
    echo -e "\n${BLUE}➤ 目标平台: [${os}/${arch}]${NC}"

    for component in "${SELECTED_COMPONENTS[@]}"; do
        IFS=":" read -r name path win_exe <<< "$component"

        out_file="${OUTPUT_DIR}/${name}-${os}-${arch}"
        if [[ "$os" == "windows" && "$win_exe" == "true" ]]; then
            out_file="${out_file}.exe"
        fi

        echo -n "  编译 [${name}] ... "

        # 增量构建时，Go 可能保留已被 UPX 压缩且源码未变化的旧产物。
        # 先移除目标文件，确保本轮从未压缩二进制开始，再执行 UPX 和自检。
        if [[ "$USE_UPX" == "true" && -f "$out_file" ]]; then
            rm -f "$out_file"
        fi

        if [[ "$name" == "dddd-agent" ]]; then
            if CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" go build \
                -tags noembed \
                -ldflags="-s -w" \
                -trimpath \
                -o "${out_file}" "${path}"; then
                echo -e "${GREEN}成功${NC}"
            else
                echo -e "${RED}失败${NC}"
                exit 1
            fi
        elif CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" go build \
            -ldflags="-s -w" \
            -trimpath \
            -o "${out_file}" "${path}"; then
            echo -e "${GREEN}成功${NC}"
        else
            echo -e "${RED}失败${NC}"
            exit 1
        fi

        if [[ "$USE_UPX" == "true" ]]; then
            upx_args="-9 --quiet"
            if [[ "$os" == "darwin" ]]; then
                upx_args="$upx_args --force-macos"
            fi

            set +e
            upx $upx_args "${out_file}" >/dev/null 2>&1
            upx_status=$?
            set -e

            if [[ $upx_status -eq 0 ]]; then
                set +e
                upx -t "${out_file}" >/dev/null 2>&1
                test_status=$?
                set -e
                if [[ $test_status -eq 0 ]]; then
                    echo -e "    ${YELLOW}↳ UPX 压缩并自检成功${NC}"
                elif [[ "$REQUIRE_UPX" == "true" ]]; then
                    echo -e "    ${RED}↳ UPX 自检失败，终止构建${NC}"
                    exit 1
                else
                    echo -e "    ${RED}↳ UPX 自检失败，保留未验证产物${NC}"
                fi
            elif [[ "$REQUIRE_UPX" == "true" ]]; then
                echo -e "    ${RED}↳ UPX 压缩失败，终止构建${NC}"
                exit 1
            else
                echo -e "    ${RED}↳ UPX 跳过该架构 (暂不支持或失败)${NC}"
            fi
        fi
    done
done

echo -e "\n${GREEN}=======================================${NC}"
echo -e "${GREEN}  编译完成！产物位于 ${OUTPUT_DIR}/ 目录 ${NC}"
echo -e "${GREEN}=======================================${NC}"
ls -lh "$OUTPUT_DIR"
