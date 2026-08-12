#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dev-env.sh"

mcp_bin="$(argus_require_binary argus-mcp mcp)"
token_file="${ARGUS_TOKEN_FILE:-"${ARGUS_RUNTIME_DIR}/argus-token.jwt"}"

argus_fetch_dev_token() {
    local username password tenant response
    username="${ARGUS_LOGIN_USERNAME:-admin}"
    password="${ARGUS_LOGIN_PASSWORD:-admin123}"
    tenant="${ARGUS_LOGIN_TENANT:-default}"

    response="$(curl -fsS \
        -H 'Content-Type: application/json' \
        -d "{\"tenant_id\":\"${tenant}\",\"username\":\"${username}\",\"password\":\"${password}\"}" \
        "${ARGUS_API_URL}/api/v1/auth/login")"

    python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])' <<< "${response}"
}

if [[ -z "${ARGUS_TOKEN:-}" && -z "${ARGUS_TOKEN_FILE:-}" && "${ARGUS_MCP_AUTO_LOGIN:-1}" == "1" ]]; then
    echo "[argus-dev] ARGUS_TOKEN not set; attempting dev login at ${ARGUS_API_URL}"
    if token="$(argus_fetch_dev_token)"; then
        printf '%s\n' "${token}" > "${token_file}"
        chmod 0600 "${token_file}"
        export ARGUS_TOKEN_FILE="${token_file}"
        echo "[argus-dev] wrote MCP token to ${token_file}"
    else
        echo "[argus-dev] dev login failed; set ARGUS_TOKEN or ARGUS_TOKEN_FILE before starting MCP" >&2
        exit 1
    fi
fi

export ARGUS_BASE_URL="${ARGUS_BASE_URL:-"${ARGUS_API_URL}"}"
export ARGUS_YAKSHA_URL="${ARGUS_YAKSHA_URL:-http://127.0.0.1:8790}"
if ! curl -fsS --max-time 3 "${ARGUS_YAKSHA_URL}/readyz" >/dev/null; then
    echo "[argus-dev] Yaksha runtime unavailable at ${ARGUS_YAKSHA_URL}; run ./scripts/start-yaksha.sh first" >&2
    exit 1
fi
export ARGUS_MCP_TRANSPORT="${ARGUS_MCP_TRANSPORT:-http}"
export ARGUS_MCP_HTTP_ADDR

argus_start_process mcp "${mcp_bin}"
