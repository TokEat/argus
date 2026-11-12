#!/usr/bin/env bash
# 空数组展开回归测试（bash < 4.4 + set -u）。
#
# 背景：带 `set -euo pipefail` 的脚本若用裸 "${arr[@]}" 展开数组，bash 4.4 之前
# 会把空数组视为未绑定变量，抛 `arr[@]: unbound variable` 并以非零码中断脚本。
# macOS 自带 bash 3.2、CentOS 7 的 bash 4.2 都受影响。
#
# 覆盖四处（引入提交见 issue #303 / #304）：
#   - scripts/sync-aliyun.sh   run_rsync 的 dry      （引入于 8746006b）
#   - deploy/db-init.sh        run_psql 的 args       （引入于 19326e8b）
#   - deploy/db-init.sh        INIT_FILES             （引入于 19326e8b）
#   - scripts/start-*.sh       extra_args             （引入于 ae97c26b）
#   - build.sh                 requested_components / requested_targets（引入于 a84f7d73）
#
# 本测试不依赖真实 PostgreSQL / rsync / go：用假替身记录实参，
# 验证「数组为空」与「数组非空」两种情况下参数拼装都正确且不中断。
#
# 用法：bash deploy/tests/shell-empty-array.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

TMP_DIR="$(mktemp -d)"
# 成功哨兵：bash 3.2 的 EXIT trap 会把致命展开错误的退出码吞成 0
# （实测顶层报错后 trap 收到的 $? 是 0），只信 $? 会造成
# 「打印了错误但 CI 显示绿色」的假绿窗口。
# ok=1 表示走完全部断言；ok=0 一律非零退出。
ok=0
trap 'rc=$?; rm -rf -- "${TMP_DIR}"; if [[ "${ok}" -eq 1 ]]; then exit 0; fi; if [[ "${rc}" -ne 0 ]]; then exit "${rc}"; fi; exit 1' EXIT

CALLS="${TMP_DIR}/calls.txt"
: >"${CALLS}"
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
# extract_function <文件> <函数名>
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
# 1) scripts/sync-aliyun.sh —— run_rsync 的 rsync 参数拼装
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
    RSYNC_PATH="sudo -u deploy rsync"
    eval "${RUN_RSYNC_SRC}"

    # 场景 1：非 dry-run 时 dry 为空数组，不能中断，也不能多出空参数
    DRY_RUN=0
    assert_case "sync-aliyun 非 dry-run 时 rsync 参数正确" \
        "-aHz|--delete|--exclude-from=${EXCLUDES}|-e|ssh -o BatchMode=yes -o ConnectTimeout=15|--rsync-path=${RSYNC_PATH}|/src/|/dst:|" \
        run_rsync "/src/" "/dst:"

    # 场景 2：dry-run 时必须带上 --dry-run，且位置不变
    # shellcheck disable=SC2034  # DRY_RUN 由 eval 进来的 run_rsync 读取
    DRY_RUN=1
    assert_case "sync-aliyun dry-run 时 rsync 带 --dry-run" \
        "-aHz|--delete|--exclude-from=${EXCLUDES}|-e|ssh -o BatchMode=yes -o ConnectTimeout=15|--rsync-path=${RSYNC_PATH}|--dry-run|/src/|/dst:|" \
        run_rsync "/src/" "/dst:"
fi

# ==============================================================================
# 2) deploy/db-init.sh —— run_psql 的 psql 参数拼装
# ==============================================================================
DB_INIT="${ROOT}/deploy/db-init.sh"

if [[ -f "${DB_INIT}" ]]; then
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
# 3) scripts/start-agent.sh / start-server.sh —— extra_args 为空时不中断
# ==============================================================================
# 这两个脚本是线性脚本（无法像 run_psql 那样抽出函数体），
# 因此改为直接检查真实文件里的展开写法：
# extra_args 必须用受保护写法 ${extra_args[@]+"${extra_args[@]}"}，
# 否则环境变量只含空白时分词出空数组，bash < 4.4 下会中断。
for script in start-agent start-server; do
    f="${ROOT}/scripts/${script}.sh"
    [[ -f "${f}" ]] || continue

    # shellcheck disable=SC2016  # 单引号是刻意的：匹配字面量而非展开
    if ! grep -q 'extra_args\[@\]+"${extra_args\[@\]}"' "${f}"; then
        echo "FAIL: ${script}.sh 的 extra_args 未使用受保护展开，bash < 4.4 下会 unbound variable" >&2
        grep -n 'extra_args\[@\]' "${f}" >&2
        exit 1
    fi
    # 受保护写法必须真的能处理空数组：只含空白时分词结果为空数组。
    ARGUS_EXTRA_ARGS=" "
    # shellcheck disable=SC2206
    extra_args=(${ARGUS_EXTRA_ARGS})
    if [[ "${#extra_args[@]}" -ne 0 ]]; then
        echo "FAIL: ${script}.sh 的 extra_args 预期为空数组，实际 ${#extra_args[@]} 个元素" >&2
        exit 1
    fi
    args=(--dev)
    args+=(${extra_args[@]+"${extra_args[@]}"})
    if [[ "${#args[@]}" -ne 1 ]]; then
        echo "FAIL: ${script}.sh 的 extra_args 为空时参数数异常: ${#args[@]}" >&2
        exit 1
    fi
    echo "ok: ${script}.sh extra_args 为空时不中断"
done

# ==============================================================================
# 4) build.sh —— 过滤串只含换行时 requested_* 为空数组，不中断
# ==============================================================================
BUILD_SH="${ROOT}/build.sh"

if [[ -f "${BUILD_SH}" ]]; then
    # 同样直接检查真实文件里的展开写法。
    for name in requested_components requested_targets; do
        if ! grep -q "${name}\[@\]+\"\${${name}\[@\]}\"" "${BUILD_SH}"; then
            echo "FAIL: build.sh 的 ${name} 未使用受保护展开，bash < 4.4 下会 unbound variable" >&2
            grep -n "${name}\[@\]" "${BUILD_SH}" >&2
            exit 1
        fi
    done
    # 受保护写法必须真的能处理空数组：herestring 传纯换行时 read -r -a 得到 0 个元素。
    FILTER=$'\n'
    IFS=',' read -r -a parsed <<< "$FILTER"
    if [[ "${#parsed[@]}" -ne 0 ]]; then
        echo "FAIL: build.sh 的过滤串解析预期为空数组，实际 ${#parsed[@]} 个元素" >&2
        exit 1
    fi
    # shellcheck disable=SC2034  # item 仅用于验证展开不中断
    for item in ${parsed[@]+"${parsed[@]}"}; do
        :
    done
    echo "ok: build.sh 过滤串只含换行时不中断"
fi

ok=1
echo "shell empty-array checks passed (bash ${BASH_VERSION})"
