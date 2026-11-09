#!/usr/bin/env bash
# shell 脚本空数组展开回归测试（bash < 4.4 + set -u）。
#
# 背景：带 `set -euo pipefail` 的脚本若用裸 "${arr[@]}" 展开数组，bash 4.4 之前
# 会把空数组视为未绑定变量，抛 `arr[@]: unbound variable` 并以非零码中断脚本。
# macOS 自带 bash 3.2、CentOS 7 的 bash 4.2 都受影响。
#
# 本测试分两层：
#   1) 静态契约检查：变量名无关地找出所有裸 "${IDENT[@]}" / "${IDENT[*]}" 展开。
#      bash >= 4.4 运行期不再报错，宿主 bash 单靠运行期断言抓不到回归，
#      静态检查是唯一能在所有 bash 版本上发现回归的手段。
#   2) 运行期断言：抽取被测脚本的函数体，用假 psql/docker/rsync 替身记录实参，
#      验证参数拼装在 bash 3.2 下不中断且完全正确。
#
# 用法：bash deploy/tests/shell-empty-array.sh [被检查的文件...]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

TMP_DIR="$(mktemp -d)"
# ---- 成功哨兵 ----
# bash 3.2 的 EXIT trap 会把致命展开错误（unbound variable）的退出码吞成 0：
# 实测顶层报错后 trap 收到的 $? 是 0，trap 内 exit "${rc}" 于是返回 0，
# 造成「打印了错误但 CI 显示绿色」的假绿窗口。
# 因此用 ok=0/ok=1 哨兵表示「是否走完全部断言」：
#   ok=1  -> 全部断言通过，正常退出 0
#   ok=0  -> 断言失败或中途被致命错误打断，一律非零退出
ok=0
trap 'rc=$?; rm -rf -- "${TMP_DIR}"; if [[ "${ok}" -eq 1 ]]; then exit 0; fi; if [[ "${rc}" -ne 0 ]]; then exit "${rc}"; fi; exit 1' EXIT

# ---- 静态契约检查：变量名无关 ----
# 步骤 1：剔除所有受保护写法（允许变量名不同、允许空格变体、允许内层不加引号）。
#   形如 ${IDENT[@]+"${IDENT[@]}"} / ${IDENT[@] + "${IDENT[@]}"} / ${IDENT[@]+${IDENT[@]}}
# 步骤 2：剩余的 ${IDENT[@]} / ${IDENT[*]} 即为裸展开。
# 注意 ${arr[@]:1} 这类切片写法在 bash 3.2 下不会报错，故不计入。
#
# 豁免名单：某些数组在展开点上恒非空（如硬编码常量列表、已判空后赋默认值的数组），
# 这些展开不会触发 unbound variable。豁免按「文件 + 数组变量名」精确匹配，
# 不使用通配 —— 这样新增的、尚未证明恒非空的数组名仍会被拦下。
#
# check_no_bare_expansion <文件> <标签> [豁免的数组变量名...]
check_no_bare_expansion() {
    local file="$1"
    local label="$2"
    shift 2
    local stripped hits
    stripped="$(sed -E \
        's/\$\{[A-Za-z_][A-Za-z0-9_]*\[(@|\*)\][[:space:]]*\+"?[^"]*"?\}//g' \
        "${file}")"
    hits="$(grep -nE '\$\{[A-Za-z_][A-Za-z0-9_]*\[(@|\*)\]\}' <<<"${stripped}" || true)"
    if [[ -n "${hits}" ]]; then
        local line hit name
        while IFS= read -r hit; do
            [[ -n "${hit}" ]] || continue
            line="${hit%%:*}"
            name="$(sed -E 's/.*\$\{([A-Za-z_][A-Za-z0-9_]*)\[(@|\*)\]\}.*/\1/' <<<"${hit}")"
            local exempted=0
            local allowed
            for allowed in "$@"; do
                if [[ "${name}" == "${allowed}" ]]; then
                    exempted=1
                    break
                fi
            done
            if [[ "${exempted}" -eq 0 ]]; then
                echo "FAIL: ${label}: 存在裸数组展开 \${${name}[@]}，在 bash < 4.4 下会 unbound variable" >&2
                echo "  ${file}:${line}" >&2
                exit 1
            fi
        done <<<"${hits}"
    fi
    echo "ok: ${label}: 无裸数组展开"
}

# ---- 运行期断言工具 ----
CALLS="${TMP_DIR}/calls.txt"
export ARGUS_TEST_CALLS="${CALLS}"

reset_calls() {
    : >"${CALLS}"
}

# 在子 shell 中执行被测函数，并同时断言返回码与输出。
# assert_case <描述> <期望实参(以 | 分隔)> <命令...>
assert_case() {
    local desc="$1"
    local expected="$2"
    shift 2
    local out rc actual

    reset_calls
    out="$( { "$@"; } 2>&1 )" && rc=0 || rc=$?

    if [[ "${rc}" -ne 0 ]]; then
        echo "FAIL: ${desc}: 调用返回非零码 ${rc}" >&2
        echo "${out}" >&2
        exit 1
    fi
    if [[ "${out}" == *"unbound variable"* ]]; then
        echo "FAIL: ${desc}: 出现 unbound variable" >&2
        echo "${out}" >&2
        exit 1
    fi

    actual="$(tr '\n' '|' <"${CALLS}")"
    if [[ "${actual}" != "${expected}" ]]; then
        echo "FAIL: ${desc}: 实参不符" >&2
        echo "  expected: ${expected}" >&2
        echo "  actual:   ${actual}" >&2
        exit 1
    fi
    echo "ok: ${desc}"
}

# 抽取 shell 文件中某个函数的定义体。
# 形如 extract_function <文件> <函数名>
# 匹配函数名后紧跟可选空白与 "{"，到行首 "}" 结束。
extract_function() {
    local file="$1"
    local fn="$2"
    awk -v fn="${fn}" '
        $0 ~ "^" fn "[ \t]*\\(\\) *[ \t]*\\{ *$" { inside = 1 }
        inside { print }
        inside && /^\} *$/ { exit }
    ' "${file}"
}

# ==============================================================================
# 0) 全量静态检查：所有带 set -u 的 shell 脚本
# ==============================================================================
# 这些脚本在 bash < 4.4 上都可能因空数组展开而中断，逐个检查。
# 豁免的数组均已确认在展开点上恒非空，依据写在注释里。
check_no_bare_expansion "${ROOT}/build.sh" "build.sh" \
    TARGETS COMPONENTS POSITIONAL requested_components requested_targets \
    SELECTED_NAMES SELECTED_TARGETS BUILT_FILES
# required_paths 是硬编码常量列表，恒非空。
check_no_bare_expansion "${ROOT}/deploy/build-bundle.sh" "deploy/build-bundle.sh" \
    required_paths
check_no_bare_expansion "${ROOT}/deploy/db-init.sh" "deploy/db-init.sh"
check_no_bare_expansion "${ROOT}/deploy/setup-server.sh" "deploy/setup-server.sh"
check_no_bare_expansion "${ROOT}/deploy/show-secrets.sh" "deploy/show-secrets.sh"
# server_candidates / agent_candidates / frontend_candidates 在 nullglob 下可能为空。
# 但三者的首项都是带引号的字面量路径（非 glob），nullglob 只剔除未匹配的 glob 项，
# 字面量项恒保留，故数组恒非空。
check_no_bare_expansion "${ROOT}/deploy/upgrade-server.sh" "deploy/upgrade-server.sh" \
    server_candidates agent_candidates frontend_candidates
# agent_args / server_args 在函数内始终至少含 --server 等固定项，恒非空。
check_no_bare_expansion "${ROOT}/scripts/start-agent.sh" "scripts/start-agent.sh" \
    agent_args
check_no_bare_expansion "${ROOT}/scripts/start-server.sh" "scripts/start-server.sh" \
    server_args
check_no_bare_expansion "${ROOT}/scripts/sync-aliyun.sh" "scripts/sync-aliyun.sh"

# ==============================================================================
# 1) deploy/db-init.sh —— run_psql 的 psql 参数拼装
# ==============================================================================
DB_INIT="${ROOT}/deploy/db-init.sh"

if [[ -f "${DB_INIT}" ]]; then
    # 假 psql / docker：把实参逐行落到 CALLS 文件
    cat >"${TMP_DIR}/psql" <<'EOS'
#!/usr/bin/env bash
printf '%s\n' "$@" >>"${ARGUS_TEST_CALLS}"
exit 0
EOS
    cat >"${TMP_DIR}/docker" <<'EOS'
#!/usr/bin/env bash
printf '%s\n' "$@" >>"${ARGUS_TEST_CALLS}"
cat >/dev/null
exit 0
EOS
    chmod +x "${TMP_DIR}/psql" "${TMP_DIR}/docker"
    export PATH="${TMP_DIR}:${PATH}"

    RUN_PSQL_SRC="$(extract_function "${DB_INIT}" "run_psql")"
    if [[ -z "${RUN_PSQL_SRC}" ]]; then
        echo "FAIL: 未能从 ${DB_INIT} 抽取 run_psql 函数" >&2
        exit 1
    fi

    # ---- 被测实现 ----
    CONTAINER=""
    fail() {
        echo "FAIL: $*" >&2
        exit 1
    }
    eval "${RUN_PSQL_SRC}"

    SQL_FILE="${TMP_DIR}/seed.sql"
    echo "-- seed" >"${SQL_FILE}"

    # 场景 1：只有 -f，args 为空（bootstrap / legacy cutover 路径）
    assert_case "db-init 空 args 时 psql 参数正确" \
        "host=localhost dbname=argus|-v|ON_ERROR_STOP=1|-f|${SQL_FILE}|" \
        run_psql "host=localhost dbname=argus" -f "${SQL_FILE}"

    # 场景 2：args 非空时参数必须原样透传
    assert_case "db-init 非空 args 时 psql 参数透传" \
        "host=localhost dbname=argus|-v|ON_ERROR_STOP=1|-1|-q|-f|${SQL_FILE}|" \
        run_psql "host=localhost dbname=argus" -1 -q -f "${SQL_FILE}"

    # 场景 3：既无 -f 也无额外参数
    assert_case "db-init 空 args 且无 -f 时 psql 参数正确" \
        "host=localhost dbname=argus|-v|ON_ERROR_STOP=1|" \
        run_psql "host=localhost dbname=argus"

    # 场景 4：含空格的参数必须作为单个参数原样透传（不分词、不 glob 展开）
    assert_case "db-init 含空格参数原样透传" \
        "host=localhost dbname=argus|-v|ON_ERROR_STOP=1|-tAc|SELECT count(*) FROM users WHERE name = 'a b'|" \
        run_psql "host=localhost dbname=argus" -tAc "SELECT count(*) FROM users WHERE name = 'a b'"

    # 场景 5：--container 路径下同样不能因空 args 中断
    # shellcheck disable=SC2034  # CONTAINER 由 eval 进来的 run_psql 读取
    CONTAINER="argus-test-pg"
    assert_case "db-init 容器路径下空 args 时 docker 参数正确" \
        "exec|-i|argus-test-pg|psql|host=127.0.0.1 dbname=argus|-v|ON_ERROR_STOP=1|-f|-|" \
        run_psql "host=127.0.0.1 dbname=argus" -f "${SQL_FILE}"
    # shellcheck disable=SC2034
    CONTAINER=""
fi

# ==============================================================================
# 2) scripts/sync-aliyun.sh —— run_rsync 的 rsync 参数拼装
# ==============================================================================
SYNC_ALIYUN="${ROOT}/scripts/sync-aliyun.sh"

if [[ -f "${SYNC_ALIYUN}" ]]; then
    cat >"${TMP_DIR}/rsync" <<'EOS'
#!/usr/bin/env bash
printf '%s\n' "$@" >>"${ARGUS_TEST_CALLS}"
exit 0
EOS
    chmod +x "${TMP_DIR}/rsync"
    export PATH="${TMP_DIR}:${PATH}"

    RUN_RSYNC_SRC="$(extract_function "${SYNC_ALIYUN}" "run_rsync")"
    if [[ -z "${RUN_RSYNC_SRC}" ]]; then
        echo "FAIL: 未能从 ${SYNC_ALIYUN} 抽取 run_rsync 函数" >&2
        exit 1
    fi

    DRY_RUN=0
    EXCLUDES="/tmp/argus-sync.excludes"
    RSYNC_PATH="sudo -u claudex rsync"
    eval "${RUN_RSYNC_SRC}"

    # 场景 1：非 dry-run 时 dry 为空数组，不能中断，也不能多出空参数
    DRY_RUN=0
    assert_case "sync-aliyun 非 dry-run 时 rsync 参数正确" \
        "-aHz|--delete|--exclude-from=${EXCLUDES}|-e|ssh -o BatchMode=yes -o ConnectTimeout=15|--rsync-path=${RSYNC_PATH}|/src/|/dst:|" \
        run_rsync "/src/" "/dst:"

    # 场景 2：dry-run 时必须带上 --dry-run
    # shellcheck disable=SC2034  # DRY_RUN 由 eval 进来的 run_rsync 读取
    DRY_RUN=1
    assert_case "sync-aliyun dry-run 时 rsync 带 --dry-run" \
        "-aHz|--delete|--exclude-from=${EXCLUDES}|-e|ssh -o BatchMode=yes -o ConnectTimeout=15|--rsync-path=${RSYNC_PATH}|--dry-run|/src/|/dst:|" \
        run_rsync "/src/" "/dst:"
fi

ok=1
echo "shell empty-array checks passed (bash ${BASH_VERSION})"
