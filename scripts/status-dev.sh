#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dev-env.sh"

echo "Argus dev runtime"
echo "  root:       ${ARGUS_ROOT_DIR}"
echo "  api:        ${ARGUS_API_URL}"
echo "  grpc:       ${ARGUS_GRPC_ADDR}"
echo "  mcp:        http://${ARGUS_MCP_HTTP_ADDR}"
echo "  logs:       ${ARGUS_LOG_DIR}"
echo "  pids:       ${ARGUS_PID_DIR}"
echo
argus_print_status server
argus_print_status agent
argus_print_status mcp
