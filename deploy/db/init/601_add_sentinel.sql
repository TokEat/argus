ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS taint_status TEXT NOT NULL DEFAULT '';
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS taint_reason TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_taint_status ON vulnerabilities (taint_status);

-- 扫描安全设备对抗哨兵：规则引擎检测到的封禁/拦截/覆盖度异常事件，AI 分类后给出处置建议。
CREATE TABLE IF NOT EXISTS egress_ban_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    root_task_id TEXT NOT NULL DEFAULT '',
    sub_task_id TEXT NOT NULL DEFAULT '',
    batch_id TEXT NOT NULL DEFAULT '',
    project_id TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    agent_id TEXT NOT NULL DEFAULT '',
    signal_type TEXT NOT NULL,              -- http_streak | homogeneity | success_drop
    evidence JSONB NOT NULL DEFAULT '{}',   -- 规则引擎采集的样本/计数/片段
    classification TEXT NOT NULL DEFAULT 'pending', -- pending | banned | rate_limited | waf_challenge | target_down | scanner_bug | false_positive
    recommended_action TEXT NOT NULL DEFAULT '',    -- '' | backoff | rescan_other_node | halt | flag_findings | none
    action_reason TEXT NOT NULL DEFAULT '',
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'open',    -- open | executed | dismissed | expired
    executed_at TIMESTAMPTZ,
    executed_by TEXT NOT NULL DEFAULT '',
    cooldown_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_egress_ban_events_tenant_status ON egress_ban_events (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_egress_ban_events_target ON egress_ban_events (target);
CREATE INDEX IF NOT EXISTS idx_egress_ban_events_root_task ON egress_ban_events (root_task_id);
CREATE INDEX IF NOT EXISTS idx_egress_ban_events_created ON egress_ban_events (created_at);

-- 封禁记忆：按 (tenant, target, agent) 记录被封节点与冷却时间，防止换节点死循环。
CREATE TABLE IF NOT EXISTS node_bans (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    target TEXT NOT NULL DEFAULT '',
    agent_id TEXT NOT NULL DEFAULT '',
    egress_ip TEXT NOT NULL DEFAULT '',
    hit_count INTEGER NOT NULL DEFAULT 1,
    banned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cooldown_until TIMESTAMPTZ,
    UNIQUE (tenant_id, target, agent_id)
);

CREATE INDEX IF NOT EXISTS idx_node_bans_target ON node_bans (tenant_id, target);
