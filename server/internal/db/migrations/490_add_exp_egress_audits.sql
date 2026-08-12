CREATE TABLE IF NOT EXISTS exp_egress_audits (
    id BIGSERIAL PRIMARY KEY,
    route_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    operator_id VARCHAR(128) NOT NULL,
    agent_id VARCHAR(255) NOT NULL,
    targets JSONB NOT NULL DEFAULT '[]'::jsonb,
    resolved_ips JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(32) NOT NULL,
    error_code VARCHAR(64) NOT NULL DEFAULT '',
    connection_count INTEGER NOT NULL DEFAULT 0,
    bytes_to_agent BIGINT NOT NULL DEFAULT 0,
    bytes_from_agent BIGINT NOT NULL DEFAULT 0,
    issued_at TIMESTAMPTZ NOT NULL,
    claimed_at TIMESTAMPTZ NULL,
    finished_at TIMESTAMPTZ NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_exp_egress_audits_route_id ON exp_egress_audits (route_id);
CREATE INDEX IF NOT EXISTS idx_exp_egress_audits_tenant_id ON exp_egress_audits (tenant_id);
CREATE INDEX IF NOT EXISTS idx_exp_egress_audits_operator_id ON exp_egress_audits (operator_id);
CREATE INDEX IF NOT EXISTS idx_exp_egress_audits_agent_id ON exp_egress_audits (agent_id);
CREATE INDEX IF NOT EXISTS idx_exp_egress_audits_status ON exp_egress_audits (status);
CREATE INDEX IF NOT EXISTS idx_exp_egress_audits_error_code ON exp_egress_audits (error_code);
CREATE INDEX IF NOT EXISTS idx_exp_egress_audits_issued_at ON exp_egress_audits (issued_at);
CREATE INDEX IF NOT EXISTS idx_exp_egress_audits_finished_at ON exp_egress_audits (finished_at);
CREATE INDEX IF NOT EXISTS idx_exp_egress_audits_expires_at ON exp_egress_audits (expires_at);
