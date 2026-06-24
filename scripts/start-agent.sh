#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dev-env.sh"

agent_bin="$(argus_require_binary dddd-agent agent)"

agent_args=(
    --server "${ARGUS_GRPC_ADDR}"
    --api "${ARGUS_API_URL}"
    --id "${ARGUS_AGENT_ID}"
    --workers "${ARGUS_AGENT_WORKERS}"
)
if [[ -n "${ARGUS_AGENT_TAGS:-}" ]]; then
    agent_args+=(--tags "${ARGUS_AGENT_TAGS}")
fi
if [[ -n "${ARGUS_AGENT_PSK:-}" ]]; then
    agent_args+=(--psk "${ARGUS_AGENT_PSK}")
fi
if [[ -n "${ARGUS_AGENT_EXTRA_ARGS:-}" ]]; then
    # shellcheck disable=SC2206
    extra_args=(${ARGUS_AGENT_EXTRA_ARGS})
    agent_args+=("${extra_args[@]}")
fi

argus_start_process agent "${agent_bin}" "${agent_args[@]}"

