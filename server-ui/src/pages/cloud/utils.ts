export const extractErrorMsg = (err: unknown): string | null => {
    if (!err) return null;
    if (typeof err === 'string') return err;
    if (err instanceof Error) return err.message;
    if (typeof err === 'object') {
        const obj = err as Record<string, unknown>;
        if (obj.errorFields) return null;
        if (obj.error) return String(obj.error);
        if (obj.message) return String(obj.message);
    }
    return String(err);
};

export const DEFAULT_CLOUD_INIT_TEMPLATE = `#!/bin/bash
set -ex

echo "[Argus] Starting agent provisioning..."

# 下载 Agent 二进制（通过 OSS 预签名 URL 内网高速分发）
DOWNLOAD_URL="{{.DownloadURL}}"
AGENT_BIN="/usr/local/bin/dddd-agent"

for i in 1 2 3 4 5; do
    if curl -fsSL "$DOWNLOAD_URL" -o "$AGENT_BIN"; then
        chmod +x "$AGENT_BIN"
        echo "[Argus] Agent binary downloaded successfully"
        break
    fi
    echo "[Argus] Download attempt $i failed, retrying in 10s..."
    sleep 10
done

if [ ! -x "$AGENT_BIN" ]; then
    echo "[Argus] FATAL: Failed to download agent binary after 5 attempts"
    exit 1
fi

mkdir -p /var/log/argus

cat > /etc/systemd/system/argus-agent.service <<EOF
[Unit]
Description=Argus Scanning Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$AGENT_BIN \\
    --server "{{.ServerAddr}}" \\
    --id "{{.AgentID}}" \\
    --api "{{.APIURL}}" \\
    --tags "cloud=true,auto_scaled=true,target_type=all"{{if .PSK}} \\
    --psk "{{.PSK}}"{{end}}
Restart=always
RestartSec=5
StandardOutput=append:/var/log/argus/agent.log
StandardError=append:/var/log/argus/agent.log
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable argus-agent
systemctl start argus-agent

echo "[Argus] Agent registered as systemd service and started"
`;
