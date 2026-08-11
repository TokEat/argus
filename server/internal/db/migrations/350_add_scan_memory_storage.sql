CREATE TABLE IF NOT EXISTS scan_observations (
    id BIGSERIAL PRIMARY KEY,
    schema_version VARCHAR(32) NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    network_zone VARCHAR(255) NOT NULL,
    normalized_target TEXT NOT NULL,
    target_hash VARCHAR(64) NOT NULL,
    stage VARCHAR(64) NOT NULL,
    work_key_hash VARCHAR(64) NOT NULL,
    scope_hash VARCHAR(64) NOT NULL,
    config_hash VARCHAR(64) NOT NULL,
    rule_version TEXT NOT NULL,
    poc_set_hash VARCHAR(64) NOT NULL DEFAULT '',
    endpoint_content_hash VARCHAR(64) NOT NULL DEFAULT '',
    source_event_id VARCHAR(128),
    root_task_id TEXT NOT NULL DEFAULT '',
    batch_id TEXT NOT NULL DEFAULT '',
    attempt_id TEXT NOT NULL DEFAULT '',
    agent_id TEXT NOT NULL DEFAULT '',
    outcome VARCHAR(32) NOT NULL,
    content_hash VARCHAR(64) NOT NULL DEFAULT '',
    evidence_hash VARCHAR(64) NOT NULL DEFAULT '',
    error_code VARCHAR(128) NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_observations_tenant_event ON scan_observations (tenant_id, source_event_id) WHERE source_event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_observations_tenant_id ON scan_observations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scan_observations_project_id ON scan_observations (project_id);
CREATE INDEX IF NOT EXISTS idx_scan_observations_target_hash ON scan_observations (target_hash);
CREATE INDEX IF NOT EXISTS idx_scan_observations_stage ON scan_observations (stage);
CREATE INDEX IF NOT EXISTS idx_scan_observations_work_key_hash ON scan_observations (work_key_hash);
CREATE INDEX IF NOT EXISTS idx_scan_observations_rule_version ON scan_observations (rule_version);
CREATE INDEX IF NOT EXISTS idx_scan_observations_root_task_id ON scan_observations (root_task_id);
CREATE INDEX IF NOT EXISTS idx_scan_observations_batch_id ON scan_observations (batch_id);
CREATE INDEX IF NOT EXISTS idx_scan_observations_attempt_id ON scan_observations (attempt_id);
CREATE INDEX IF NOT EXISTS idx_scan_observations_agent_id ON scan_observations (agent_id);
CREATE INDEX IF NOT EXISTS idx_scan_observations_outcome ON scan_observations (outcome);
CREATE INDEX IF NOT EXISTS idx_scan_observations_observed_at ON scan_observations (observed_at);
CREATE INDEX IF NOT EXISTS idx_scan_observations_scope ON scan_observations (tenant_id, project_id, network_zone, stage, observed_at DESC);

CREATE TABLE IF NOT EXISTS scan_coverages (
    id BIGSERIAL PRIMARY KEY,
    schema_version VARCHAR(32) NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    network_zone VARCHAR(255) NOT NULL,
    normalized_target TEXT NOT NULL,
    target_hash VARCHAR(64) NOT NULL,
    stage VARCHAR(64) NOT NULL,
    work_key_hash VARCHAR(64) NOT NULL,
    scope_hash VARCHAR(64) NOT NULL,
    config_hash VARCHAR(64) NOT NULL,
    rule_version TEXT NOT NULL,
    poc_set_hash VARCHAR(64) NOT NULL DEFAULT '',
    endpoint_content_hash VARCHAR(64) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    observation_hash VARCHAR(64) NOT NULL DEFAULT '',
    source_observation_id BIGINT NOT NULL DEFAULT 0,
    source_task_id TEXT NOT NULL DEFAULT '',
    source_batch_id TEXT NOT NULL DEFAULT '',
    source_attempt_id TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL DEFAULT 1,
    invalid_reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_coverages_tenant_project_work ON scan_coverages (tenant_id, project_id, work_key_hash);
CREATE INDEX IF NOT EXISTS idx_scan_coverages_tenant_id ON scan_coverages (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scan_coverages_project_id ON scan_coverages (project_id);
CREATE INDEX IF NOT EXISTS idx_scan_coverages_stage ON scan_coverages (stage);
CREATE INDEX IF NOT EXISTS idx_scan_coverages_rule_version ON scan_coverages (rule_version);
CREATE INDEX IF NOT EXISTS idx_scan_coverages_status ON scan_coverages (status);
CREATE INDEX IF NOT EXISTS idx_scan_coverages_outcome ON scan_coverages (outcome);
CREATE INDEX IF NOT EXISTS idx_scan_coverages_finished_at ON scan_coverages (finished_at);
CREATE INDEX IF NOT EXISTS idx_scan_coverages_valid_until ON scan_coverages (valid_until);
CREATE INDEX IF NOT EXISTS idx_scan_coverages_source_observation_id ON scan_coverages (source_observation_id);
CREATE INDEX IF NOT EXISTS idx_scan_coverages_source_task_id ON scan_coverages (source_task_id);
CREATE INDEX IF NOT EXISTS idx_scan_coverages_source_batch_id ON scan_coverages (source_batch_id);
CREATE INDEX IF NOT EXISTS idx_scan_coverages_source_attempt_id ON scan_coverages (source_attempt_id);
CREATE INDEX IF NOT EXISTS idx_scan_coverages_lookup ON scan_coverages (tenant_id, project_id, network_zone, target_hash, stage);

CREATE TABLE IF NOT EXISTS scan_work_claims (
    id BIGSERIAL PRIMARY KEY,
    schema_version VARCHAR(32) NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    network_zone VARCHAR(255) NOT NULL,
    normalized_target TEXT NOT NULL,
    target_hash VARCHAR(64) NOT NULL,
    stage VARCHAR(64) NOT NULL,
    work_key_hash VARCHAR(64) NOT NULL,
    scope_hash VARCHAR(64) NOT NULL,
    config_hash VARCHAR(64) NOT NULL,
    rule_version TEXT NOT NULL,
    poc_set_hash VARCHAR(64) NOT NULL DEFAULT '',
    endpoint_content_hash VARCHAR(64) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL,
    owner_task_id TEXT NOT NULL DEFAULT '',
    owner_batch_id TEXT NOT NULL DEFAULT '',
    owner_attempt_id TEXT NOT NULL DEFAULT '',
    owner_agent_id TEXT NOT NULL DEFAULT '',
    lease_token_hash VARCHAR(64) NOT NULL DEFAULT '',
    lease_expires_at TIMESTAMPTZ,
    claimed_at TIMESTAMPTZ NOT NULL,
    released_at TIMESTAMPTZ,
    revision INTEGER NOT NULL DEFAULT 1,
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_work_claims_tenant_project_work ON scan_work_claims (tenant_id, project_id, work_key_hash);
CREATE INDEX IF NOT EXISTS idx_scan_work_claims_tenant_id ON scan_work_claims (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scan_work_claims_project_id ON scan_work_claims (project_id);
CREATE INDEX IF NOT EXISTS idx_scan_work_claims_network_zone ON scan_work_claims (network_zone);
CREATE INDEX IF NOT EXISTS idx_scan_work_claims_target_hash ON scan_work_claims (target_hash);
CREATE INDEX IF NOT EXISTS idx_scan_work_claims_stage ON scan_work_claims (stage);
CREATE INDEX IF NOT EXISTS idx_scan_work_claims_rule_version ON scan_work_claims (rule_version);
CREATE INDEX IF NOT EXISTS idx_scan_work_claims_status ON scan_work_claims (status);
CREATE INDEX IF NOT EXISTS idx_scan_work_claims_owner_task_id ON scan_work_claims (owner_task_id);
CREATE INDEX IF NOT EXISTS idx_scan_work_claims_owner_batch_id ON scan_work_claims (owner_batch_id);
CREATE INDEX IF NOT EXISTS idx_scan_work_claims_owner_attempt_id ON scan_work_claims (owner_attempt_id);
CREATE INDEX IF NOT EXISTS idx_scan_work_claims_owner_agent_id ON scan_work_claims (owner_agent_id);
CREATE INDEX IF NOT EXISTS idx_scan_work_claims_lease_expires_at ON scan_work_claims (lease_expires_at);

CREATE TABLE IF NOT EXISTS task_coverage_links (
    id BIGSERIAL PRIMARY KEY,
    schema_version VARCHAR(32) NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    root_task_id TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL DEFAULT '',
    work_key_hash VARCHAR(64) NOT NULL,
    link_type VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    coverage_id BIGINT NOT NULL DEFAULT 0,
    claim_id BIGINT NOT NULL DEFAULT 0,
    source_task_id TEXT NOT NULL DEFAULT '',
    source_batch_id TEXT NOT NULL DEFAULT '',
    source_attempt_id TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_task_coverage_links_destination_work ON task_coverage_links (tenant_id, project_id, root_task_id, batch_id, attempt_id, work_key_hash, link_type);
CREATE INDEX IF NOT EXISTS idx_task_coverage_links_tenant_id ON task_coverage_links (tenant_id);
CREATE INDEX IF NOT EXISTS idx_task_coverage_links_project_id ON task_coverage_links (project_id);
CREATE INDEX IF NOT EXISTS idx_task_coverage_links_root_task_id ON task_coverage_links (root_task_id);
CREATE INDEX IF NOT EXISTS idx_task_coverage_links_batch_id ON task_coverage_links (batch_id);
CREATE INDEX IF NOT EXISTS idx_task_coverage_links_attempt_id ON task_coverage_links (attempt_id);
CREATE INDEX IF NOT EXISTS idx_task_coverage_links_work_key_hash ON task_coverage_links (work_key_hash);
CREATE INDEX IF NOT EXISTS idx_task_coverage_links_link_type ON task_coverage_links (link_type);
CREATE INDEX IF NOT EXISTS idx_task_coverage_links_status ON task_coverage_links (status);
CREATE INDEX IF NOT EXISTS idx_task_coverage_links_coverage_id ON task_coverage_links (coverage_id);
CREATE INDEX IF NOT EXISTS idx_task_coverage_links_claim_id ON task_coverage_links (claim_id);
CREATE INDEX IF NOT EXISTS idx_task_coverage_links_source_task_id ON task_coverage_links (source_task_id);
CREATE INDEX IF NOT EXISTS idx_task_coverage_links_source_batch_id ON task_coverage_links (source_batch_id);
CREATE INDEX IF NOT EXISTS idx_task_coverage_links_source_attempt_id ON task_coverage_links (source_attempt_id);
