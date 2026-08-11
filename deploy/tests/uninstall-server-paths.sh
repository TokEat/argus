#!/usr/bin/env bash

set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
UNINSTALL_SCRIPT="${TEST_DIR}/../uninstall-server.sh"

# shellcheck source=../uninstall-server.sh
source "$UNINSTALL_SCRIPT"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT

SYSTEMCTL_BIN="${TMP_DIR}/missing-systemctl"
SERVICE_FILE="${TMP_DIR}/argus-server.service"
INSTALL_ROOT="${TMP_DIR}/argus-release-v1.2.3"
OTHER_ROOT="${TMP_DIR}/argus-release-other"

mkdir -p "${INSTALL_ROOT}/bin" "${INSTALL_ROOT}/deploy"
touch "${INSTALL_ROOT}/bin/argus-server" "${INSTALL_ROOT}/deploy/docker-compose.yml"

cat > "$SERVICE_FILE" <<EOF
[Service]
WorkingDirectory=${INSTALL_ROOT}
ExecStart=${INSTALL_ROOT}/bin/argus-server -api ":8085"
EOF

expected="$(realpath -m -- "$INSTALL_ROOT")"
actual="$(resolve_install_dir "")"
[[ "$actual" == "$expected" ]] || {
    echo "service WorkingDirectory resolution failed: expected ${expected}, got ${actual}" >&2
    exit 1
}

actual="$(resolve_install_dir "$INSTALL_ROOT")"
[[ "$actual" == "$expected" ]] || {
    echo "matching explicit install directory was rejected" >&2
    exit 1
}

mkdir -p "${OTHER_ROOT}/bin" "${OTHER_ROOT}/deploy"
touch "${OTHER_ROOT}/bin/argus-server" "${OTHER_ROOT}/deploy/docker-compose.yml"
if (resolve_install_dir "$OTHER_ROOT" >/dev/null 2>&1); then
    echo "service/explicit directory mismatch was accepted" >&2
    exit 1
fi

rm -f -- "$SERVICE_FILE"
actual="$(resolve_install_dir "$INSTALL_ROOT")"
[[ "$actual" == "$expected" ]] || {
    echo "validated explicit install directory was rejected" >&2
    exit 1
}

if (resolve_install_dir "" >/dev/null 2>&1); then
    echo "missing service and explicit directory did not fail closed" >&2
    exit 1
fi

if (resolve_install_dir "/" >/dev/null 2>&1); then
    echo "filesystem root was accepted as an install directory" >&2
    exit 1
fi

if grep -Eq 'INSTALL_DIR=.*(/opt/argus|:-/opt/argus)' "$UNINSTALL_SCRIPT"; then
    echo "uninstall script contains a hard-coded /opt/argus fallback" >&2
    exit 1
fi

echo "uninstall install-directory safety checks passed"
