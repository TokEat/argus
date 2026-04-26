-- Cloud resource orchestration tables
-- Supports automatic scaling of scanner agents via cloud providers (Alibaba Cloud ECS, etc.)

-- 云厂商凭证存储
CREATE TABLE IF NOT EXISTS cloud_accounts (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    name            TEXT NOT NULL DEFAULT '',
    provider        TEXT NOT NULL DEFAULT 'aliyun',
    access_key_id   TEXT NOT NULL DEFAULT '',
    access_key_secret TEXT NOT NULL DEFAULT '',
    region          TEXT NOT NULL DEFAULT '',
    default_image_id TEXT NOT NULL DEFAULT '',
    default_instance_type TEXT NOT NULL DEFAULT '',
    default_security_group TEXT NOT NULL DEFAULT '',
    default_v_switch TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_tenant ON cloud_accounts (tenant_id);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_provider ON cloud_accounts (provider);
CREATE INDEX IF NOT EXISTS idx_cloud_accounts_status ON cloud_accounts (status);

-- 自动伸缩策略
CREATE TABLE IF NOT EXISTS cloud_scaling_policies (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL DEFAULT 'default',
    cloud_account_id     TEXT NOT NULL DEFAULT '',
    name                 TEXT NOT NULL DEFAULT '',
    enabled              BOOLEAN NOT NULL DEFAULT FALSE,
    min_instances        INTEGER NOT NULL DEFAULT 0,
    max_instances        INTEGER NOT NULL DEFAULT 5,
    scale_up_threshold   INTEGER NOT NULL DEFAULT 50,
    scale_down_threshold INTEGER NOT NULL DEFAULT 3,
    cooldown_seconds     INTEGER NOT NULL DEFAULT 300,
    instance_ttl_minutes INTEGER NOT NULL DEFAULT 120,
    spot_strategy        TEXT NOT NULL DEFAULT 'NoSpot',
    max_spot_price       DOUBLE PRECISION NOT NULL DEFAULT 0,
    user_data_template   TEXT NOT NULL DEFAULT '',
    last_scale_action    TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cloud_policies_tenant ON cloud_scaling_policies (tenant_id);
CREATE INDEX IF NOT EXISTS idx_cloud_policies_account ON cloud_scaling_policies (cloud_account_id);
CREATE INDEX IF NOT EXISTS idx_cloud_policies_enabled ON cloud_scaling_policies (enabled);

-- 实例生命周期追踪
CREATE TABLE IF NOT EXISTS cloud_instances (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL DEFAULT 'default',
    cloud_account_id     TEXT NOT NULL DEFAULT '',
    policy_id            TEXT NOT NULL DEFAULT '',
    provider_instance_id TEXT NOT NULL DEFAULT '',
    agent_id             TEXT NOT NULL DEFAULT '',
    ip                   TEXT NOT NULL DEFAULT '',
    region               TEXT NOT NULL DEFAULT '',
    status               TEXT NOT NULL DEFAULT 'Provisioning',
    spot                 BOOLEAN NOT NULL DEFAULT FALSE,
    error_message        TEXT NOT NULL DEFAULT '',
    launched_at          TIMESTAMPTZ,
    ready_at             TIMESTAMPTZ,
    terminated_at        TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at           TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_cloud_instances_tenant ON cloud_instances (tenant_id);
CREATE INDEX IF NOT EXISTS idx_cloud_instances_account ON cloud_instances (cloud_account_id);
CREATE INDEX IF NOT EXISTS idx_cloud_instances_policy ON cloud_instances (policy_id);
CREATE INDEX IF NOT EXISTS idx_cloud_instances_agent ON cloud_instances (agent_id);
CREATE INDEX IF NOT EXISTS idx_cloud_instances_provider_id ON cloud_instances (provider_instance_id);
CREATE INDEX IF NOT EXISTS idx_cloud_instances_status ON cloud_instances (status);
CREATE INDEX IF NOT EXISTS idx_cloud_instances_deleted ON cloud_instances (deleted_at);
