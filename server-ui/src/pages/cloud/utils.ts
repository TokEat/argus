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

export interface CloudPolicyFormValues {
    name: string;
    cloud_account_id?: string;
    min_instances: number;
    max_instances: number;
    scale_up_threshold: number;
    scale_down_threshold: number;
    cooldown_seconds: number;
    instance_ttl_minutes: number;
    spot_strategy: string;
    spot_duration_hours: number;
    max_spot_price?: number;
}

export const buildDefaultPolicyFormValues = (accounts: API.CloudAccount[]): CloudPolicyFormValues => ({
    name: '经济型弹性扫描策略',
    min_instances: 0,
    max_instances: 5,
    scale_up_threshold: 50,
    scale_down_threshold: 0,
    cooldown_seconds: 180,
    instance_ttl_minutes: 60,
    spot_strategy: 'SpotAsPriceGo',
    spot_duration_hours: 1,
    ...(accounts.length === 1 ? { cloud_account_id: accounts[0].id } : {}),
});

export const buildPolicyFormValues = (
    defaults: CloudPolicyFormValues,
    policy?: API.CloudScalingPolicy | null,
): CloudPolicyFormValues => {
    if (!policy) return { ...defaults, max_spot_price: undefined };
    return {
        ...defaults,
        name: policy.name ?? defaults.name,
        cloud_account_id: policy.cloud_account_id ?? defaults.cloud_account_id,
        min_instances: policy.min_instances ?? defaults.min_instances,
        max_instances: policy.max_instances ?? defaults.max_instances,
        scale_up_threshold: policy.scale_up_threshold ?? defaults.scale_up_threshold,
        scale_down_threshold: policy.scale_down_threshold ?? defaults.scale_down_threshold,
        cooldown_seconds: policy.cooldown_seconds ?? defaults.cooldown_seconds,
        instance_ttl_minutes: policy.instance_ttl_minutes ?? defaults.instance_ttl_minutes,
        spot_strategy: policy.spot_strategy ?? defaults.spot_strategy,
        spot_duration_hours: policy.spot_duration_hours ?? defaults.spot_duration_hours,
        max_spot_price: policy.max_spot_price ?? undefined,
    };
};

export const DEFAULT_CLOUD_INIT_TEMPLATE = `#!/bin/bash
set -ex

echo "[Argus] Starting agent provisioning..."

# 下载 Agent 二进制（通过 OSS 预签名 URL 内网高速分发）
DOWNLOAD_URL="{{.DownloadURL}}"
AGENT_BIN="/usr/local/bin/argus-agent"

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
