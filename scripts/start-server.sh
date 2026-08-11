#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dev-env.sh"

server_bin="$(argus_require_binary argus-server server)"

server_args=(--dev)
if [[ -n "${ARGUS_DB_DSN:-}" ]]; then
    server_args+=(--db "${ARGUS_DB_DSN}")
fi
if [[ -n "${ARGUS_AMQP_URL:-}" ]]; then
    server_args+=(--amqp "${ARGUS_AMQP_URL}")
fi
if [[ -n "${ARGUS_AGENT_PSK:-}" ]]; then
    server_args+=(--agent-psk "${ARGUS_AGENT_PSK}")
fi
if [[ -n "${ARGUS_SERVER_EXTRA_ARGS:-}" ]]; then
    # shellcheck disable=SC2206
    extra_args=(${ARGUS_SERVER_EXTRA_ARGS})
    server_args+=("${extra_args[@]}")
fi

argus_start_process server "${server_bin}" "${server_args[@]}"

