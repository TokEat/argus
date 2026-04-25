CREATE TABLE IF NOT EXISTS ai_tool_invocations (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    user_id TEXT,
    module TEXT,
    tool_name TEXT NOT NULL,
    args_summary JSONB,
    agent_id TEXT,
    target_url TEXT,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    error_summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_tool_invocations_tenant_id ON ai_tool_invocations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_ai_tool_invocations_user_id ON ai_tool_invocations (user_id);
CREATE INDEX IF NOT EXISTS idx_ai_tool_invocations_module ON ai_tool_invocations (module);
CREATE INDEX IF NOT EXISTS idx_ai_tool_invocations_tool_name ON ai_tool_invocations (tool_name);
CREATE INDEX IF NOT EXISTS idx_ai_tool_invocations_agent_id ON ai_tool_invocations (agent_id);
CREATE INDEX IF NOT EXISTS idx_ai_tool_invocations_status ON ai_tool_invocations (status);
CREATE INDEX IF NOT EXISTS idx_ai_tool_invocations_created_at ON ai_tool_invocations (created_at);
