#!/usr/bin/env bash
# 锁定 write_secrets_env 生成的 secrets.env 格式，防止回归导致
# docker compose (godotenv) 或 systemd (EnvironmentFile) 解析不一致。
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=../lib/argus-env.sh
source "${TEST_DIR}/../lib/argus-env.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TMP_DIR"' EXIT
OUT="${TMP_DIR}/secrets.env"

# 构造"难缠但合法"的取值：base64(含 + / =)、含空格 DSN、hex 密码
INSTALL_DIR="/opt/argus"
POSTGRES_USER="postgres"
POSTGRES_PASSWORD="abc123+/=XYZ"
POSTGRES_DB="argus"
POSTGRES_PORT="5432"
RABBITMQ_DEFAULT_USER="argus"
RABBITMQ_DEFAULT_PASS="deadbeef0011"
RABBITMQ_PORT="5672"
RABBITMQ_MANAGEMENT_PORT="15672"
MINIO_ROOT_USER="argus-minio-root"
MINIO_ROOT_PASSWORD="feed4242cafe"
MINIO_API_PORT="9000"
MINIO_CONSOLE_PORT="9001"
ARGUS_EXP_MINIO_ACCESS_KEY="expabc123"
ARGUS_EXP_MINIO_SECRET_KEY="secRET+/=9900"
ARGUS_EXP_MINIO_BUCKET="argus-exp"
AGENT_PSK="psk112233"
JWT_SECRET="jwt334455"
ENCRYPT_KEY="ZW5jRr+yeKey9/x=="
CREDENTIAL_ENCRYPT_KEY="Y3JlZEtleXK0PQ=="
DB_DSN="host=127.0.0.1 user=postgres password=abc123+/=XYZ dbname=argus port=5432 sslmode=disable"
AMQP_URL="amqp://argus:deadbeef0011@127.0.0.1:5672/"

write_secrets_env "$OUT"

# 1) 每个 key 都能被 env_file_value 精确还原（含特殊字符与空格）
check_roundtrip() {
    local key="$1" expected="$2" actual
    actual="$(env_file_value "$OUT" "$key")"
    [[ "$actual" == "$expected" ]] || {
        echo "roundtrip failed for ${key}: expected [${expected}] got [${actual}]" >&2
        exit 1
    }
}
check_roundtrip INSTALL_DIR "$INSTALL_DIR"
check_roundtrip POSTGRES_PASSWORD "$POSTGRES_PASSWORD"
check_roundtrip ARGUS_ENCRYPT_KEY "$ENCRYPT_KEY"
check_roundtrip ARGUS_CREDENTIAL_ENCRYPT_KEY "$CREDENTIAL_ENCRYPT_KEY"
check_roundtrip ARGUS_EXP_MINIO_SECRET_KEY "$ARGUS_EXP_MINIO_SECRET_KEY"
check_roundtrip ARGUS_DB_DSN "$DB_DSN"
check_roundtrip ARGUS_AMQP_URL "$AMQP_URL"

# 2) 格式约束：无 export 前缀、值不被引号包裹、KEY=VALUE 行的值内无 '#' 行内注释
if grep -nE '^[[:space:]]*export ' "$OUT" >/dev/null; then
    echo "env file must not use 'export' prefix" >&2
    exit 1
fi
if grep -nE '^[A-Z_]+=".*"$' "$OUT" >/dev/null; then
    echo "env file values must not be wrapped in quotes" >&2
    exit 1
fi
if grep -E '^[A-Z_]+=' "$OUT" | grep -q '#'; then
    echo "env file values must not contain inline '#' comments" >&2
    exit 1
fi

# 3) 权限必须为 0600
perm="$(stat -c '%a' "$OUT")"
[[ "$perm" == "600" ]] || {
    echo "secrets.env must be chmod 0600, got ${perm}" >&2
    exit 1
}

# 4) set -e 安全：复用不到值时函数必须返回 0，否则部署脚本会被 set -e 中断
SECRETS_ENV_FILE="${TMP_DIR}/nonexistent-secrets.env"   # 故意指向不存在的文件
SOME_KEY=""
reuse_secret SOME_KEY ARGUS_ENCRYPT_KEY
[[ -z "$SOME_KEY" ]] || { echo "reuse_secret should leave var empty when no source" >&2; exit 1; }

MISSING_LOCKED=""
resolve_volume_locked_cred MISSING_LOCKED argus-definitely-not-exist
[[ -z "$MISSING_LOCKED" ]] || { echo "resolve_volume_locked_cred should leave var empty without container/file" >&2; exit 1; }

# 5) 生成的 secrets.env 必须包含全部预期键且值非空。
#    曾发生 upgrade 漏赋值 ARGUS_EXP_MINIO_BUCKET 导致 set -u 崩溃的回归，
#    这类"漏了一个键"由本循环兜底拦住。
EXPECTED_KEYS=(
    INSTALL_DIR
    POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB POSTGRES_PORT
    RABBITMQ_DEFAULT_USER RABBITMQ_DEFAULT_PASS RABBITMQ_PORT RABBITMQ_MANAGEMENT_PORT
    MINIO_ROOT_USER MINIO_ROOT_PASSWORD MINIO_API_PORT MINIO_CONSOLE_PORT
    ARGUS_EXP_MINIO_ACCESS_KEY ARGUS_EXP_MINIO_SECRET_KEY ARGUS_EXP_MINIO_BUCKET
    ARGUS_AGENT_PSK ARGUS_JWT_SECRET ARGUS_ENCRYPT_KEY ARGUS_CREDENTIAL_ENCRYPT_KEY
    ARGUS_DB_DSN ARGUS_AMQP_URL
)
for key in "${EXPECTED_KEYS[@]}"; do
    val="$(env_file_value "$OUT" "$key")"
    [[ -n "$val" ]] || { echo "secrets.env missing or empty key: ${key}" >&2; exit 1; }
done

# 6) render_argus_service_unit 转义/结构约束：
#    - EnvironmentFile 两个（exp-storage.env 可选带 - 前缀在前、secrets.env 必填在后）
#    - ExecStart 中 \${VAR} 被保留为字面 ${VAR} 留给 systemd 运行时展开
#    - ${INSTALL_DIR} 在生成期被 bash 展开成绝对路径（不得残留字面量）
#    - 为空的 EGRESS/TLS 项不得输出 Environment 行；非空 PUBLIC_IP 必须输出
#    - 明文密钥绝不写成 Environment= 行
UNIT="${TMP_DIR}/argus-server.service"
PUBLIC_IP="203.0.113.10"
API_PORT="8085"
GRPC_PORT="50051"
EGRESS_GATEWAY_LISTEN=""
EGRESS_GATEWAY_TOKEN=""
GRPC_TLS_PORT=""
GRPC_TLS_CERT=""
GRPC_TLS_KEY=""
render_argus_service_unit "$UNIT"

grep -qF 'EnvironmentFile=-/opt/argus/config/exp-storage.env' "$UNIT" \
    || { echo "unit missing optional exp-storage.env EnvironmentFile" >&2; exit 1; }
grep -qF 'EnvironmentFile=/opt/argus/config/secrets.env' "$UNIT" \
    || { echo "unit missing required secrets.env EnvironmentFile" >&2; exit 1; }
grep -qF 'WorkingDirectory=/opt/argus' "$UNIT" \
    || { echo "unit did not expand \${INSTALL_DIR} at render time" >&2; exit 1; }
if grep -qF '${INSTALL_DIR}' "$UNIT"; then
    echo "unit leaked literal \${INSTALL_DIR}" >&2; exit 1
fi
for ref in '${ARGUS_DB_DSN}' '${ARGUS_AMQP_URL}' '${ARGUS_AGENT_PSK}'; do
    grep -qF "$ref" "$UNIT" || { echo "unit missing runtime expansion ${ref}" >&2; exit 1; }
done
if grep -qF '\${' "$UNIT"; then
    echo "unit leaked escaped backslash-dollar (heredoc escaping broken)" >&2; exit 1
fi
grep -qF 'Environment=ARGUS_PUBLIC_IP=203.0.113.10' "$UNIT" \
    || { echo "unit missing PUBLIC_IP Environment line" >&2; exit 1; }
# 注意：ARGUS_EGRESS_GATEWAY_TOKEN 已迁入 secrets.env，无论是否为空 render 都不再内联，
# 因此不在"为空则省略"清单内，而是由第 7 节专项断言。
for omitted in ARGUS_EGRESS_GATEWAY_LISTEN \
               ARGUS_GRPC_TLS_PORT ARGUS_GRPC_TLS_CERT ARGUS_GRPC_TLS_KEY; do
    if grep -qE "^Environment=${omitted}=" "$UNIT"; then
        echo "unit emitted Environment line for empty ${omitted}" >&2; exit 1
    fi
done
for plaintext in ARGUS_AGENT_PSK ARGUS_JWT_SECRET ARGUS_ENCRYPT_KEY ARGUS_CREDENTIAL_ENCRYPT_KEY \
                 ARGUS_EGRESS_GATEWAY_TOKEN; do
    if grep -qE "^Environment=${plaintext}=" "$UNIT"; then
        echo "unit must not carry plaintext secret as Environment: ${plaintext}" >&2; exit 1
    fi
done

# 7) Egress Gateway 成对配置：TOKEN（密钥）须进 secrets.env 且 unit 不得内联；
#    LISTEN（非密钥）仍内联。值含 +/= 以验证特殊字符往返。
EGRESS_GATEWAY_LISTEN="10.0.0.1:8790"
EGRESS_GATEWAY_TOKEN="gw-tok-en-9911+/="
write_secrets_env "$OUT"
[[ "$(env_file_value "$OUT" ARGUS_EGRESS_GATEWAY_LISTEN)" == "$EGRESS_GATEWAY_LISTEN" ]] \
    || { echo "secrets.env lost ARGUS_EGRESS_GATEWAY_LISTEN" >&2; exit 1; }
[[ "$(env_file_value "$OUT" ARGUS_EGRESS_GATEWAY_TOKEN)" == "$EGRESS_GATEWAY_TOKEN" ]] \
    || { echo "secrets.env lost ARGUS_EGRESS_GATEWAY_TOKEN" >&2; exit 1; }
# 追加写入后权限仍须 0600
[[ "$(stat -c '%a' "$OUT")" == "600" ]] \
    || { echo "secrets.env must stay 0600 after conditional append" >&2; exit 1; }
render_argus_service_unit "$UNIT"
grep -qF 'Environment=ARGUS_EGRESS_GATEWAY_LISTEN=10.0.0.1:8790' "$UNIT" \
    || { echo "unit missing inline LISTEN (non-secret should stay inline)" >&2; exit 1; }
if grep -qE '^Environment=ARGUS_EGRESS_GATEWAY_TOKEN=' "$UNIT"; then
    echo "unit must not inline ARGUS_EGRESS_GATEWAY_TOKEN (belongs in secrets.env)" >&2; exit 1
fi

echo "secrets-env-format checks passed"
