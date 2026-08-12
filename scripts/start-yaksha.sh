#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
compose_file="${repo_root}/yaksha/compose.yaml"

docker compose -f "${compose_file}" up -d --build
echo "[argus-dev] waiting for Yaksha at http://127.0.0.1:8790"
for _ in $(seq 1 60); do
    if curl -fsS --max-time 2 http://127.0.0.1:8790/readyz >/dev/null; then
        echo "[argus-dev] Yaksha is ready"
        exit 0
    fi
    sleep 1
done

echo "[argus-dev] Yaksha did not become ready; inspect: docker compose -f yaksha/compose.yaml logs" >&2
exit 1
