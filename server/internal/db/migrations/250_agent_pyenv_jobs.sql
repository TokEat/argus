CREATE TABLE IF NOT EXISTS agent_pyenv_jobs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    agent_id TEXT NOT NULL,
    operator_id TEXT,
    exploit_rule_id BIGINT,
    requirements JSONB,
    requirements_hash TEXT,
    status TEXT,
    logs TEXT,
    error TEXT,
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_agent_pyenv_jobs_tenant_id ON agent_pyenv_jobs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_pyenv_jobs_agent_id ON agent_pyenv_jobs (agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_pyenv_jobs_operator_id ON agent_pyenv_jobs (operator_id);
CREATE INDEX IF NOT EXISTS idx_agent_pyenv_jobs_exploit_rule_id ON agent_pyenv_jobs (exploit_rule_id);
CREATE INDEX IF NOT EXISTS idx_agent_pyenv_jobs_requirements_hash ON agent_pyenv_jobs (requirements_hash);
CREATE INDEX IF NOT EXISTS idx_agent_pyenv_jobs_status ON agent_pyenv_jobs (status);
