#!/usr/bin/env bash
# 本地 Mac <-> 阿里云 Argus 按需 rsync（只走现有 SSH Host: aliyun，不开新端口）
# 用法:
#   ./scripts/sync-aliyun.sh push [--dry-run]   # 本地 -> 服务器
#   ./scripts/sync-aliyun.sh pull [--dry-run]   # 服务器 -> 本地
#   ./scripts/sync-aliyun.sh diff              # 两边差异预览（双向 dry-run）
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXCLUDES="$ROOT/scripts/sync-aliyun.excludes"
SSH_HOST="${ARGUS_SYNC_SSH:-aliyun}"
REMOTE_PATH="${ARGUS_SYNC_REMOTE:-/home/claudex/workspace/project/argus-main}"
# 远端以 claudex 身份写文件，避免 root 属主污染
RSYNC_PATH="${ARGUS_SYNC_RSYNC_PATH:-sudo -u claudex rsync}"

DRY_RUN=0
ACTION="${1:-}"
if [[ $# -gt 0 ]]; then shift; fi
for arg in "$@"; do
  case "$arg" in
    --dry-run|-n) DRY_RUN=1 ;;
    -h|--help) ACTION=help ;;
    *) echo "未知参数: $arg" >&2; exit 2 ;;
  esac
done

usage() {
  cat <<'USAGE'
本地 Mac <-> 阿里云 Argus 按需 rsync（只走现有 SSH Host: aliyun，不开新端口）
用法:
  ./scripts/sync-aliyun.sh push [--dry-run]   # 本地 -> 服务器
  ./scripts/sync-aliyun.sh pull [--dry-run]   # 服务器 -> 本地
  ./scripts/sync-aliyun.sh diff              # 两边差异预览（双向 dry-run）
USAGE
}

if [[ -z "$ACTION" || "$ACTION" == help ]]; then
  usage
  exit 0
fi

if [[ ! -f "$EXCLUDES" ]]; then
  echo "缺少排除列表: $EXCLUDES" >&2
  exit 1
fi

run_rsync() {
  local dry=()
  if [[ "$DRY_RUN" -eq 1 ]]; then
    dry=(--dry-run)
  fi
  rsync -aHz --delete \
    --exclude-from="$EXCLUDES" \
    -e "ssh -o BatchMode=yes -o ConnectTimeout=15" \
    --rsync-path="$RSYNC_PATH" \
    "${dry[@]}" \
    "$@"
}

case "$ACTION" in
  push)
    echo "==> push: $ROOT/  ->  ${SSH_HOST}:${REMOTE_PATH}/"
    run_rsync "$ROOT/" "${SSH_HOST}:${REMOTE_PATH}/"
    if [[ "$DRY_RUN" -eq 1 ]]; then echo "完成: dry-run（未写入）"; else echo "完成: 本地 -> 服务器"; fi
    ;;
  pull)
    echo "==> pull: ${SSH_HOST}:${REMOTE_PATH}/  ->  $ROOT/"
    run_rsync "${SSH_HOST}:${REMOTE_PATH}/" "$ROOT/"
    if [[ "$DRY_RUN" -eq 1 ]]; then echo "完成: dry-run（未写入）"; else echo "完成: 服务器 -> 本地"; fi
    ;;
  diff)
    DRY_RUN=1
    export LC_ALL=C
    echo "---- 若 push，服务器将变更的文件 ----"
    run_rsync --out-format='%n' "$ROOT/" "${SSH_HOST}:${REMOTE_PATH}/" 2>/dev/null | sed '/\/$/d' | head -200 || true
    echo
    echo "---- 若 pull，本地将变更的文件 ----"
    run_rsync --out-format='%n' "${SSH_HOST}:${REMOTE_PATH}/" "$ROOT/" 2>/dev/null | sed '/\/$/d' | head -200 || true
    echo
    echo "提示: 真正同步请显式 push 或 pull；两边都改同一文件时先备份再选一侧覆盖。"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
