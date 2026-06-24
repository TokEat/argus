#!/usr/bin/env bash
set -euo pipefail

ARGUS_ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARGUS_RUNTIME_DIR="${ARGUS_RUNTIME_DIR:-"${ARGUS_ROOT_DIR}/runtime"}"
ARGUS_LOG_DIR="${ARGUS_LOG_DIR:-"${ARGUS_RUNTIME_DIR}/logs"}"
ARGUS_PID_DIR="${ARGUS_PID_DIR:-"${ARGUS_RUNTIME_DIR}/pids"}"

ARGUS_API_URL="${ARGUS_API_URL:-http://127.0.0.1:8085}"
ARGUS_GRPC_ADDR="${ARGUS_GRPC_ADDR:-127.0.0.1:50051}"
ARGUS_AGENT_ID="${ARGUS_AGENT_ID:-agent-mcp-dev}"
ARGUS_AGENT_WORKERS="${ARGUS_AGENT_WORKERS:-1}"
ARGUS_MCP_HTTP_ADDR="${ARGUS_MCP_HTTP_ADDR:-127.0.0.1:8787}"

mkdir -p "${ARGUS_LOG_DIR}" "${ARGUS_PID_DIR}"

argus_pid_file() {
    printf '%s/%s.pid' "${ARGUS_PID_DIR}" "$1"
}

argus_log_file() {
    printf '%s/%s.log' "${ARGUS_LOG_DIR}" "$1"
}

argus_is_running() {
    local pid="$1"
    [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1
}

argus_pid_from_file() {
    local file="$1"
    [[ -f "${file}" ]] && tr -d '[:space:]' < "${file}" || true
}

argus_require_binary() {
    local name="$1"
    local make_target="$2"
    local bin_path="${ARGUS_ROOT_DIR}/bin/${name}"

    if [[ ! -x "${bin_path}" || "${ARGUS_REBUILD:-0}" == "1" ]]; then
        echo "[argus-dev] building ${name} via make ${make_target}"
        (cd "${ARGUS_ROOT_DIR}" && make "${make_target}")
    fi

    if [[ ! -x "${bin_path}" ]]; then
        echo "[argus-dev] missing binary: ${bin_path}" >&2
        exit 1
    fi
    printf '%s' "${bin_path}"
}

argus_start_process() {
    local name="$1"
    shift
    local pid_file log_file existing_pid
    pid_file="$(argus_pid_file "${name}")"
    log_file="$(argus_log_file "${name}")"
    existing_pid="$(argus_pid_from_file "${pid_file}")"

    if argus_is_running "${existing_pid}"; then
        echo "[argus-dev] ${name} already running: pid=${existing_pid}"
        echo "[argus-dev] log: ${log_file}"
        return 0
    fi

    rm -f "${pid_file}"
    echo "[argus-dev] starting ${name}"
    echo "[argus-dev] log: ${log_file}"
    (
        cd "${ARGUS_ROOT_DIR}"
        nohup "$@" >> "${log_file}" 2>&1 &
        echo "$!" > "${pid_file}"
    )

    sleep 0.2
    existing_pid="$(argus_pid_from_file "${pid_file}")"
    if argus_is_running "${existing_pid}"; then
        echo "[argus-dev] ${name} started: pid=${existing_pid}"
    else
        echo "[argus-dev] ${name} failed to start, see ${log_file}" >&2
        exit 1
    fi
}

argus_stop_process() {
    local name="$1"
    local pid_file pid
    pid_file="$(argus_pid_file "${name}")"
    pid="$(argus_pid_from_file "${pid_file}")"

    if ! argus_is_running "${pid}"; then
        echo "[argus-dev] ${name} not running"
        rm -f "${pid_file}"
        return 0
    fi

    echo "[argus-dev] stopping ${name}: pid=${pid}"
    kill "${pid}" >/dev/null 2>&1 || true
    for _ in {1..30}; do
        if ! argus_is_running "${pid}"; then
            rm -f "${pid_file}"
            echo "[argus-dev] ${name} stopped"
            return 0
        fi
        sleep 0.2
    done

    echo "[argus-dev] ${name} still running after SIGTERM; use kill -9 ${pid} if needed" >&2
    return 1
}

argus_print_status() {
    local name="$1"
    local pid_file pid log_file
    pid_file="$(argus_pid_file "${name}")"
    log_file="$(argus_log_file "${name}")"
    pid="$(argus_pid_from_file "${pid_file}")"

    if argus_is_running "${pid}"; then
        printf '%-12s running pid=%s log=%s\n' "${name}" "${pid}" "${log_file}"
    else
        printf '%-12s stopped log=%s\n' "${name}" "${log_file}"
    fi
}
