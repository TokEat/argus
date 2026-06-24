#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dev-env.sh"

argus_stop_process mcp || true
argus_stop_process agent || true
argus_stop_process server || true

