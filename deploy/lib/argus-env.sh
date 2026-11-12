#!/bin/bash
# ==============================================================================
# Argus 部署共享库 —— 被 setup-server.sh / upgrade-server.sh / show-secrets.sh source
#
# 职责：
#   gen_hex_secret / gen_encrypt_key   生成随机密钥
#   env_file_value                     从 env 文件安全读取单个值（不 source/eval）
#   container_env_value                读取容器内某个环境变量的实际值
#   reuse_secret                       非卷锁定凭据：复用已有 secrets.env 里的值
#   resolve_volume_locked_cred         卷锁定凭据：以已存在容器实际值为最高权威
#   write_secrets_env                  将全部凭据写入统一 secrets.env（0600）
#   render_argus_service_unit          渲染无明文密钥的 systemd unit
#
# 约定：本库只定义函数，source 时不执行副作用。
#   reuse_secret / resolve_volume_locked_cred / write_secrets_env 依赖调用方
#   预先设置 SECRETS_ENV_FILE；render_argus_service_unit 依赖 INSTALL_DIR 及
#   PUBLIC_IP/API_PORT/GRPC_PORT/EGRESS_*/GRPC_TLS_* 等变量。
# ==============================================================================

# 生成 Base64 编码的 32 字节密钥（用于 ARGUS_ENCRYPT_KEY）
gen_encrypt_key() {
    openssl rand -base64 32 2>/dev/null | tr -d '\n' || \
    head -c 32 /dev/urandom | base64 | tr -d '\n'
}

# 生成 hex 编码的随机密钥
gen_hex_secret() {
    openssl rand -hex 24 2>/dev/null || head -c 24 /dev/urandom | xxd -p
}

# 从 env 文件读取指定 key 的值（不 source/eval，避免注入；取最后一次出现）。
# 用法: env_file_value <file> <key>
env_file_value() {
    local file_path="$1" key="$2"
    [[ -f "$file_path" ]] || return 0
    sed -nE "s/^${key}=(.*)$/\1/p" "$file_path" | tail -n 1
}

# 读取容器（无论运行或停止）内某个环境变量的实际值。
# 这是"卷锁定"凭据的最高权威来源：数据目录首次初始化后，容器实际在用的
# 密码可能与后来 env/CLI 指定的值不一致，此时必须沿用容器值。
# 用法: container_env_value <container> <key>
container_env_value() {
    local container="$1" key="$2"
    docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$container" 2>/dev/null \
        | sed -nE "s/^${key}=(.*)$/\1/p" | tail -n 1
}

# 非卷锁定凭据（应用密钥、EXP_MINIO 应用用户等）的复用：
# 若调用方尚未给该变量赋值（未通过 env/CLI 显式指定），则尝试复用已有
# secrets.env 中的同名字段，实现重复部署时密码稳定（幂等）。
# 注意：secrets.env 中应用密钥以 ARGUS_ 前缀存储，与内部变量名可能不同，
#   需用第二个参数显式指定键名（缺省与变量名相同）。
# 用法: reuse_secret <VAR_NAME> [SECRETS_ENV_KEY]
reuse_secret() {
    local var="$1" key="${2:-$1}"
    if [[ -z "${!var:-}" ]]; then
        local reused
        reused="$(env_file_value "$SECRETS_ENV_FILE" "$key")"
        if [[ -n "$reused" ]]; then
            printf -v "$var" '%s' "$reused"
        fi
    fi
    return 0
}

# 卷锁定凭据（POSTGRES_PASSWORD / RABBITMQ_DEFAULT_PASS / MINIO_ROOT_PASSWORD /
# MINIO_ROOT_USER）的解析：这些凭据只在数据目录首次初始化时生效。
#   - 容器已存在：以容器实际值为权威；若调用方通过 env/CLI 显式指定了不同值，
#     告警并沿用容器值（避免数据卷用旧密、连接串记新密导致连不上）。
#   - 容器不存在：保持 env/CLI 值 → 否则复用 secrets.env → 否则留空由调用方生成。
# 用法: resolve_volume_locked_cred <VAR_NAME> <CONTAINER_NAME>
resolve_volume_locked_cred() {
    local var="$1" container="$2"
    local explicit="${!var:-}"
    if docker inspect "$container" >/dev/null 2>&1; then
        local actual
        actual="$(container_env_value "$container" "$var")"
        if [[ -n "$actual" ]]; then
            if [[ -n "$explicit" && "$explicit" != "$actual" ]]; then
                echo -e "${YELLOW}[!] 已存在 ${container} 容器，指定的 ${var} 与其数据卷实际值不一致；${NC}" >&2
                echo -e "${YELLOW}    数据目录初始化后该凭据不再生效，已自动沿用容器实际值。${NC}" >&2
            fi
            printf -v "$var" '%s' "$actual"
            return 0
        fi
    fi
    if [[ -z "${!var:-}" ]]; then
        local reused
        reused="$(env_file_value "$SECRETS_ENV_FILE" "$var")"
        if [[ -n "$reused" ]]; then
            printf -v "$var" '%s' "$reused"
        fi
    fi
    return 0
}

# 将全部凭据与连接串写入统一 secrets.env（0600）。该文件是唯一事实来源：
# 同时供 docker compose (--env-file)、systemd (EnvironmentFile) 与运维查看使用。
# 依赖调用方已就位的变量：
#   INSTALL_DIR POSTGRES_USER/POSTGRES_PASSWORD/POSTGRES_DB/POSTGRES_PORT
#   RABBITMQ_DEFAULT_USER/RABBITMQ_DEFAULT_PASS/RABBITMQ_PORT/RABBITMQ_MANAGEMENT_PORT
#   MINIO_ROOT_USER/MINIO_ROOT_PASSWORD/MINIO_API_PORT/MINIO_CONSOLE_PORT
#   ARGUS_EXP_MINIO_ACCESS_KEY/ARGUS_EXP_MINIO_SECRET_KEY/ARGUS_EXP_MINIO_BUCKET
#   AGENT_PSK JWT_SECRET ENCRYPT_KEY CREDENTIAL_ENCRYPT_KEY DB_DSN AMQP_URL
#   EGRESS_GATEWAY_LISTEN/TOKEN（可选，成对配置时才追加写入，见函数尾）
# 用法: write_secrets_env <output-file>
write_secrets_env() {
    local out="$1"
    umask 077
    cat > "$out" <<EOF
# Argus 部署凭据文件 —— 由部署脚本自动生成并维护，请勿手工编辑或提交版本库。
# 同时供 docker compose (--env-file)、systemd (EnvironmentFile) 使用，也是运维查看的唯一入口。
# 格式约定：值为原始字符串，不含引号、不含行内注释，KEY 与 = 之间无空格。
INSTALL_DIR=${INSTALL_DIR}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_PORT=${POSTGRES_PORT}
RABBITMQ_DEFAULT_USER=${RABBITMQ_DEFAULT_USER}
RABBITMQ_DEFAULT_PASS=${RABBITMQ_DEFAULT_PASS}
RABBITMQ_PORT=${RABBITMQ_PORT}
RABBITMQ_MANAGEMENT_PORT=${RABBITMQ_MANAGEMENT_PORT}
MINIO_ROOT_USER=${MINIO_ROOT_USER}
MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}
MINIO_API_PORT=${MINIO_API_PORT}
MINIO_CONSOLE_PORT=${MINIO_CONSOLE_PORT}
ARGUS_EXP_MINIO_ACCESS_KEY=${ARGUS_EXP_MINIO_ACCESS_KEY}
ARGUS_EXP_MINIO_SECRET_KEY=${ARGUS_EXP_MINIO_SECRET_KEY}
ARGUS_EXP_MINIO_BUCKET=${ARGUS_EXP_MINIO_BUCKET}
ARGUS_AGENT_PSK=${AGENT_PSK}
ARGUS_JWT_SECRET=${JWT_SECRET}
ARGUS_ENCRYPT_KEY=${ENCRYPT_KEY}
ARGUS_CREDENTIAL_ENCRYPT_KEY=${CREDENTIAL_ENCRYPT_KEY}
ARGUS_DB_DSN=${DB_DSN}
ARGUS_AMQP_URL=${AMQP_URL}
EOF
    # Egress Gateway 配置非必填：仅成对配置时存在。TOKEN 是密钥必须进本文件；
    # LISTEN 虽非密钥，但与 TOKEN 成对存取可保证重复部署时 Gateway 配置稳定（幂等）。
    # 空值均不写入，避免进程 env 出现空串。
    if [[ -n "${EGRESS_GATEWAY_LISTEN:-}" ]]; then
        printf 'ARGUS_EGRESS_GATEWAY_LISTEN=%s\n' "${EGRESS_GATEWAY_LISTEN}" >> "$out"
    fi
    if [[ -n "${EGRESS_GATEWAY_TOKEN:-}" ]]; then
        printf 'ARGUS_EGRESS_GATEWAY_TOKEN=%s\n' "${EGRESS_GATEWAY_TOKEN}" >> "$out"
    fi
    chmod 0600 "$out"
}

# 渲染不含明文密钥的 argus-server systemd unit。
# 密钥统一经 EnvironmentFile=secrets.env 注入；ExecStart 用 \${VAR} 引用（由 systemd
# 在运行时展开，生成时保留字面量）。EGRESS_GATEWAY_TOKEN 也属密钥，已移入 secrets.env，
# 不再内联。PUBLIC_IP/EGRESS_GATEWAY_LISTEN/GRPC_TLS_* 等非密钥项仍内联为
# Environment=。exp-storage.env 在前、secrets.env 在后，使凭据以 secrets.env 为准。
# 依赖调用方变量：INSTALL_DIR PUBLIC_IP API_PORT GRPC_PORT
#   EGRESS_GATEWAY_LISTEN GRPC_TLS_PORT/CERT/KEY
# 用法: render_argus_service_unit <output-file>
render_argus_service_unit() {
    local out="$1"
    local exp_env_file="${INSTALL_DIR}/config/exp-storage.env"
    local secrets_env_file="${INSTALL_DIR}/config/secrets.env"
    {
        cat <<EOF
[Unit]
Description=Argus Security Platform Server
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
EOF
        if [[ -n "${PUBLIC_IP}" ]]; then
            printf 'Environment=ARGUS_PUBLIC_IP=%s\n' "${PUBLIC_IP}"
        fi
        if [[ -n "${EGRESS_GATEWAY_LISTEN}" ]]; then
            printf 'Environment=ARGUS_EGRESS_GATEWAY_LISTEN=%s\n' "${EGRESS_GATEWAY_LISTEN}"
        fi
        if [[ -n "${GRPC_TLS_PORT}" ]]; then
            printf 'Environment=ARGUS_GRPC_TLS_PORT=%s\n' "${GRPC_TLS_PORT}"
        fi
        if [[ -n "${GRPC_TLS_CERT}" ]]; then
            printf 'Environment=ARGUS_GRPC_TLS_CERT=%s\n' "${GRPC_TLS_CERT}"
        fi
        if [[ -n "${GRPC_TLS_KEY}" ]]; then
            printf 'Environment=ARGUS_GRPC_TLS_KEY=%s\n' "${GRPC_TLS_KEY}"
        fi
        cat <<EOF
EnvironmentFile=-${exp_env_file}
EnvironmentFile=${secrets_env_file}
ExecStart=${INSTALL_DIR}/bin/argus-server \\
    -db "\${ARGUS_DB_DSN}" \\
    -amqp "\${ARGUS_AMQP_URL}" \\
    -api ":${API_PORT}" \\
    -grpc ${GRPC_PORT} \\
    -agent-psk "\${ARGUS_AGENT_PSK}" \\
    -config-dir "${INSTALL_DIR}/config"
Restart=always
RestartSec=5
StandardOutput=append:${INSTALL_DIR}/logs/server.log
StandardError=append:${INSTALL_DIR}/logs/server.log
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    } > "$out"
}
