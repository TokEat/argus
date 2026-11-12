#!/bin/bash

# ==============================================================================
# Argus 构建脚本
#
# 本机当前架构 → bin/（日常开发）
# 交叉编译     → release/（发行、多平台）
#
#   ./build.sh agent
#   ./build.sh cli
#   ./build.sh server
#   ./build.sh                 # cli + agent + server，当前机器
#   ./build.sh agent --target linux/amd64
#   ./build.sh cross           # 全平台交叉编译
#   ./build.sh --component argus-agent --target darwin/arm64
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${ROOT_DIR}"

BIN_DIR="bin"
RELEASE_DIR="release"

# 格式: "name:main_path:windows_has_exe:noembed"
declare -a COMPONENTS=(
    "argus:./scanner/cmd/cli:true:noembed"
    "argus-agent:./scanner/cmd/agent:true:noembed"
    "argus-server:./server/cmd/argus-server:true:"
)

# 格式: "goos:goarch"
declare -a TARGETS=(
    "darwin:amd64"
    "darwin:arm64"
    "linux:amd64"
    "linux:arm64"
    "windows:amd64"
    "windows:arm64"
    "windows:386"
)

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

show_help() {
    cat <<'EOF'
Argus build script

本机当前架构（输出 bin/）:
  ./build.sh                 cli + agent + server
  ./build.sh agent
  ./build.sh cli
  ./build.sh server
  ./build.sh mcp
  ./build.sh yaksha

交叉编译（输出 release/）:
  ./build.sh cross
  ./build.sh agent --target linux/amd64
  ./build.sh --component argus-agent --target darwin/arm64
  ./build.sh pack --all-targets

Options:
  pack, --pack            启用 UPX 压缩（需本机安装 upx；darwin 会跳过）
  --require-upx           UPX 缺失或失败时直接终止
  -c, --component         组件：argus, argus-agent, argus-server（可逗号分隔）
  -t, --target            平台：darwin/arm64, linux:amd64, windows-amd64
  --all-targets, cross    编译全部支持的 OS/Arch 到 release/
  --list                  展示可用组件、平台和当前机器
  -h, --help              显示帮助

产物约定:
  bin/      当前机器可执行文件（无架构后缀），供本地直接运行
  release/  交叉编译产物，文件名带 <os>-<arch>
EOF
}

host_target() {
    local os arch
    os="$(go env GOOS)"
    arch="$(go env GOARCH)"
    if [[ -z "$os" || -z "$arch" ]]; then
        echo -e "${RED}[!] 无法识别当前机器架构（go env GOOS/GOARCH 为空）${NC}" >&2
        exit 1
    fi
    echo "${os}:${arch}"
}

list_supported() {
    local host
    host="$(host_target)"
    echo -e "${BLUE}当前机器:${NC} ${host//://}"
    echo -e "${BLUE}可用组件:${NC}"
    echo "  - cli          (argus)"
    echo "  - agent        (argus-agent)"
    echo "  - server       (argus-server)"
    echo "  - mcp          (argus-mcp)"
    echo "  - yaksha"
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

alias_to_component() {
    case "$1" in
        cli|argus) echo "argus" ;;
        agent|argus-agent) echo "argus-agent" ;;
        server|argus-server) echo "argus-server" ;;
        mcp|argus-mcp) echo "argus-mcp" ;;
        yaksha) echo "yaksha" ;;
        *) echo "" ;;
    esac
}

contains_component() {
    local wanted="$1"
    local component
    for component in "${COMPONENTS[@]}"; do
        IFS=":" read -r name _path _win_exe _tags <<< "$component"
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

component_record() {
    local wanted="$1"
    local component
    for component in "${COMPONENTS[@]}"; do
        IFS=":" read -r name _path _win_exe _tags <<< "$component"
        if [[ "$name" == "$wanted" ]]; then
            echo "$component"
            return 0
        fi
    done
    return 1
}

output_name() {
    local name="$1" os="$2" arch="$3" win_exe="$4" local_mode="$5"
    local out
    if [[ "$local_mode" == "true" ]]; then
        out="${BIN_DIR}/${name}"
    else
        out="${RELEASE_DIR}/${name}-${os}-${arch}"
    fi
    if [[ "$os" == "windows" && "$win_exe" == "true" ]]; then
        out="${out}.exe"
    fi
    echo "$out"
}

build_go_binary() {
    local name="$1" path="$2" os="$3" arch="$4" out_file="$5" tags="$6"
    local extra=()
    if [[ -n "$tags" ]]; then
        extra+=(-tags "$tags")
    fi
    CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" go build \
        ${extra[@]+"${extra[@]}"} \
        -ldflags="-s -w" \
        -trimpath \
        -o "${out_file}" \
        "${path}"
}

build_nested() {
    local dir="$1" out_file="$2" package="$3" os="$4" arch="$5"
    local disable_gowork="${6:-}"
    (
        cd "$dir"
        if [[ "$disable_gowork" == "gowork-off" ]]; then
            CGO_ENABLED=0 GOWORK=off GOOS="${os}" GOARCH="${arch}" go build \
                -ldflags="-s -w" \
                -trimpath \
                -o "${ROOT_DIR}/${out_file}" \
                "${package}"
        else
            CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" go build \
                -ldflags="-s -w" \
                -trimpath \
                -o "${ROOT_DIR}/${out_file}" \
                "${package}"
        fi
    )
}

compress_upx() {
    local out_file="$1" os="$2"
    if [[ "$os" == "darwin" ]]; then
        echo -e "    ${YELLOW}↳ UPX 跳过 darwin (Mach-O 压缩产物无法在 macOS 运行)${NC}"
        return 0
    fi
    local upx_args="-9 --quiet" upx_status test_status
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
}

USE_UPX_REQUESTED=false
REQUIRE_UPX=false
LIST_ONLY=false
ALL_TARGETS=false
COMPONENT_FILTER=""
TARGET_FILTER=""
declare -a POSITIONAL=()

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
        --all-targets|cross)
            ALL_TARGETS=true
            shift
            ;;
        --list)
            LIST_ONLY=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        cli|agent|server|mcp|yaksha|all|argus|argus-agent|argus-server|argus-mcp)
            POSITIONAL+=("$1")
            shift
            ;;
        *)
            echo -e "${RED}[!] 未知参数: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

if ! command -v go >/dev/null 2>&1; then
    echo -e "${RED}[!] 未找到 go，无法编译${NC}"
    exit 1
fi

if [[ "$LIST_ONLY" == "true" ]]; then
    list_supported
    exit 0
fi

# 无筛选的 pack 保持旧行为：全平台发行压缩
if [[ "$USE_UPX_REQUESTED" == "true" && ${#POSITIONAL[@]} -eq 0 && -z "$COMPONENT_FILTER" && -z "$TARGET_FILTER" ]]; then
    ALL_TARGETS=true
fi

HOST="$(host_target)"
IFS=":" read -r HOST_OS HOST_ARCH <<< "$HOST"

declare -a SELECTED_NAMES=()
declare -a SELECTED_TARGETS=()

append_name() {
    local name="$1" existing
    for existing in "${SELECTED_NAMES[@]+"${SELECTED_NAMES[@]}"}"; do
        if [[ "$existing" == "$name" ]]; then
            return 0
        fi
    done
    SELECTED_NAMES+=("$name")
}

if [[ ${#POSITIONAL[@]} -gt 0 ]]; then
    for item in "${POSITIONAL[@]}"; do
        if [[ "$item" == "all" ]]; then
            append_name "argus"
            append_name "argus-agent"
            append_name "argus-server"
            continue
        fi
        mapped="$(alias_to_component "$item")"
        if [[ -z "$mapped" ]]; then
            echo -e "${RED}[!] 未知组件: ${item}${NC}"
            list_supported
            exit 1
        fi
        append_name "$mapped"
    done
fi

if [[ -n "$COMPONENT_FILTER" ]]; then
    IFS=',' read -r -a requested_components <<< "$COMPONENT_FILTER"
    # bash 4.4 之前，set -u 会把空数组视为未绑定变量；
    # 过滤串只含换行时 read -r -a 会得到 0 个元素，仅在数组非空时展开。
    for requested in ${requested_components[@]+"${requested_components[@]}"}; do
        requested="$(echo "$requested" | xargs)"
        if [[ -z "$requested" ]]; then
            continue
        fi
        mapped="$(alias_to_component "$requested")"
        if [[ -n "$mapped" ]]; then
            requested="$mapped"
        fi
        if [[ "$requested" != "argus-mcp" && "$requested" != "yaksha" ]] && ! contains_component "$requested"; then
            echo -e "${RED}[!] 未知组件: ${requested}${NC}"
            list_supported
            exit 1
        fi
        append_name "$requested"
    done
fi

if [[ ${#SELECTED_NAMES[@]} -eq 0 ]]; then
    append_name "argus"
    append_name "argus-agent"
    append_name "argus-server"
fi

if [[ -n "$TARGET_FILTER" ]]; then
    IFS=',' read -r -a requested_targets <<< "$TARGET_FILTER"
    # bash 4.4 之前，set -u 会把空数组视为未绑定变量；
    # 过滤串只含换行时 read -r -a 会得到 0 个元素，仅在数组非空时展开。
    for requested in ${requested_targets[@]+"${requested_targets[@]}"}; do
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
elif [[ "$ALL_TARGETS" == "true" ]]; then
    SELECTED_TARGETS=("${TARGETS[@]}")
elif [[ -n "$COMPONENT_FILTER" && ${#POSITIONAL[@]} -eq 0 ]]; then
    # 兼容旧用法：只写 --component 时交叉编译全部平台
    SELECTED_TARGETS=("${TARGETS[@]}")
else
    SELECTED_TARGETS=("$HOST")
fi

if [[ ${#SELECTED_TARGETS[@]} -eq 0 ]]; then
    echo -e "${RED}[!] 未匹配到任何平台，请检查 --target 参数${NC}"
    exit 1
fi

LOCAL_MODE=true
if [[ -n "$TARGET_FILTER" || "$ALL_TARGETS" == "true" ]]; then
    LOCAL_MODE=false
elif [[ -n "$COMPONENT_FILTER" && ${#POSITIONAL[@]} -eq 0 ]]; then
    LOCAL_MODE=false
fi

OUTPUT_DIR="$RELEASE_DIR"
if [[ "$LOCAL_MODE" == "true" ]]; then
    OUTPUT_DIR="$BIN_DIR"
fi
mkdir -p "$OUTPUT_DIR"

if [[ "$LOCAL_MODE" == "false" && -z "$COMPONENT_FILTER" && -z "$TARGET_FILTER" && "$ALL_TARGETS" == "true" && ${#POSITIONAL[@]} -eq 0 ]]; then
    echo -e "清理旧的 release 目录..."
    rm -rf "${RELEASE_DIR:?}"/*
    mkdir -p "$RELEASE_DIR"
fi

echo -e "${BLUE}=======================================${NC}"
if [[ "$LOCAL_MODE" == "true" ]]; then
    echo -e "${BLUE}  Argus 本机构建  ${HOST_OS}/${HOST_ARCH}${NC}"
else
    echo -e "${BLUE}  Argus 交叉编译${NC}"
fi
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

NEED_CLI_PACKAGE=false
for name in "${SELECTED_NAMES[@]}"; do
    if [[ "$name" == "argus" && "$LOCAL_MODE" == "false" ]]; then
        NEED_CLI_PACKAGE=true
        break
    fi
done

CLI_PACKAGE_DB=""
if [[ "$NEED_CLI_PACKAGE" == "true" ]]; then
    echo -e "\n${YELLOW}检查依赖状态...${NC}"
    go mod verify >/dev/null
    echo -e "${GREEN}[✔] 依赖校验通过${NC}"
    CLI_PACKAGE_DB="${RELEASE_DIR}/.arsenal-package/arsenal.db"
    mkdir -p "$(dirname "$CLI_PACKAGE_DB")"
    rm -f "$CLI_PACKAGE_DB"
    echo -e "\n${YELLOW}生成 CLI 离线弹药库...${NC}"
    go run ./scanner/cmd/arsenal-package \
        --config scanner/common/config \
        --output "$CLI_PACKAGE_DB"
fi

echo -e "\n${YELLOW}开始编译...${NC}"
echo -e "${BLUE}组件: ${SELECTED_NAMES[*]}，平台: ${SELECTED_TARGETS[*]//://}${NC}"

BUILT_FILES=()

for target in "${SELECTED_TARGETS[@]}"; do
    IFS=":" read -r os arch <<< "$target"
    echo -e "\n${BLUE}➤ 目标平台: [${os}/${arch}]${NC}"

    for name in "${SELECTED_NAMES[@]}"; do
        win_exe="true"
        tags=""
        path=""
        out_file=""

        case "$name" in
            argus-mcp)
                out_file="$(output_name "$name" "$os" "$arch" true "$LOCAL_MODE")"
                echo -n "  编译 [${name}] ... "
                if [[ "$USE_UPX" == "true" && -f "$out_file" ]]; then
                    rm -f "$out_file"
                fi
                if build_nested mcp "$out_file" ./cmd/argus-mcp "$os" "$arch"; then
                    echo -e "${GREEN}成功${NC}"
                else
                    echo -e "${RED}失败${NC}"
                    exit 1
                fi
                ;;
            yaksha)
                out_file="$(output_name "$name" "$os" "$arch" true "$LOCAL_MODE")"
                echo -n "  编译 [${name}] ... "
                if [[ "$USE_UPX" == "true" && -f "$out_file" ]]; then
                    rm -f "$out_file"
                fi
                if build_nested yaksha "$out_file" ./cmd/yaksha "$os" "$arch" gowork-off; then
                    echo -e "${GREEN}成功${NC}"
                else
                    echo -e "${RED}失败${NC}"
                    exit 1
                fi
                ;;
            *)
                record="$(component_record "$name")"
                IFS=":" read -r _name path win_exe tags <<< "$record"
                tags="${tags:-}"
                win_exe="${win_exe:-true}"
                out_file="$(output_name "$name" "$os" "$arch" "$win_exe" "$LOCAL_MODE")"
                # 本机 CLI 使用内嵌规则，交叉编译 CLI 使用 noembed + 离线包
                if [[ "$name" == "argus" && "$LOCAL_MODE" == "true" ]]; then
                    tags=""
                fi
                echo -n "  编译 [${name}] ... "
                if [[ "$USE_UPX" == "true" && -f "$out_file" ]]; then
                    rm -f "$out_file"
                fi
                if build_go_binary "$name" "$path" "$os" "$arch" "$out_file" "$tags"; then
                    echo -e "${GREEN}成功${NC}"
                else
                    echo -e "${RED}失败${NC}"
                    exit 1
                fi
                ;;
        esac

        if [[ "$USE_UPX" == "true" ]]; then
            compress_upx "$out_file" "$os"
        fi

        if [[ "$name" == "argus" && "$LOCAL_MODE" == "false" ]]; then
            package_stage="$(mktemp -d "${RELEASE_DIR}/.argus-${os}-${arch}.XXXXXX")"
            cp "$out_file" "$package_stage/"
            mkdir -p "$package_stage/argus-data/arsenal"
            cp "$CLI_PACKAGE_DB" "$package_stage/argus-data/arsenal/arsenal.db"
            package_file="${RELEASE_DIR}/argus-${os}-${arch}.tar.gz"
            rm -f "$package_file"
            tar -czf "$package_file" -C "$package_stage" .
            rm -rf "$package_stage"
            echo -e "    ${GREEN}↳ CLI 离线包: ${package_file}${NC}"
            BUILT_FILES+=("$package_file")
        fi

        BUILT_FILES+=("$out_file")
    done
done

echo -e "\n${GREEN}=======================================${NC}"
echo -e "${GREEN}  编译完成  ${HOST_OS}/${HOST_ARCH}${NC}"
echo -e "${GREEN}=======================================${NC}"
for file in "${BUILT_FILES[@]}"; do
    ls -lh "$file"
done
