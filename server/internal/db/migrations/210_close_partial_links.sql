-- Close v0.1.0 partial-link gaps without breaking existing /api/v1 payloads.

ALTER TABLE nodes ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS token_revoked_at TIMESTAMPTZ;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS last_token_rotated_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS agent_session_audits (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    agent_id TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT,
    operator_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_session_audits_tenant_id ON agent_session_audits (tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_session_audits_agent_id ON agent_session_audits (agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_session_audits_action ON agent_session_audits (action);
CREATE INDEX IF NOT EXISTS idx_agent_session_audits_operator_id ON agent_session_audits (operator_id);
CREATE INDEX IF NOT EXISTS idx_agent_session_audits_created_at ON agent_session_audits (created_at);

ALTER TABLE sub_tasks ADD COLUMN IF NOT EXISTS agent_selector_rules TEXT;

CREATE TABLE IF NOT EXISTS ws_event_logs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ws_event_logs_tenant_id ON ws_event_logs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_ws_event_logs_project_id ON ws_event_logs (project_id);
CREATE INDEX IF NOT EXISTS idx_ws_event_logs_occurred_at ON ws_event_logs (occurred_at);

CREATE TABLE IF NOT EXISTS agent_log_alert_rules (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    agent_id TEXT,
    level TEXT,
    keyword TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_log_alert_rules_tenant_id ON agent_log_alert_rules (tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_log_alert_rules_name ON agent_log_alert_rules (name);
CREATE INDEX IF NOT EXISTS idx_agent_log_alert_rules_agent_id ON agent_log_alert_rules (agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_log_alert_rules_level ON agent_log_alert_rules (level);

CREATE TABLE IF NOT EXISTS agent_log_alert_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    rule_id BIGINT NOT NULL,
    agent_id TEXT NOT NULL,
    level TEXT,
    message TEXT,
    log_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_log_alert_events_tenant_id ON agent_log_alert_events (tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_log_alert_events_rule_id ON agent_log_alert_events (rule_id);
CREATE INDEX IF NOT EXISTS idx_agent_log_alert_events_agent_id ON agent_log_alert_events (agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_log_alert_events_level ON agent_log_alert_events (level);
CREATE INDEX IF NOT EXISTS idx_agent_log_alert_events_log_id ON agent_log_alert_events (log_id);
CREATE INDEX IF NOT EXISTS idx_agent_log_alert_events_created_at ON agent_log_alert_events (created_at);

CREATE TABLE IF NOT EXISTS agent_log_archives (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    day TEXT NOT NULL,
    storage_key TEXT,
    log_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'success',
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_agent_log_archives_tenant_id ON agent_log_archives (tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_log_archives_day ON agent_log_archives (day);
CREATE INDEX IF NOT EXISTS idx_agent_log_archives_status ON agent_log_archives (status);

ALTER TABLE build_jobs ADD COLUMN IF NOT EXISTS components TEXT;
ALTER TABLE build_jobs ADD COLUMN IF NOT EXISTS artifacts TEXT;
