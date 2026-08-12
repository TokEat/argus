CREATE TABLE IF NOT EXISTS exps (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    name VARCHAR(160) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    risk_level VARCHAR(24) NOT NULL,
    status VARCHAR(24) NOT NULL,
    active_revision INTEGER NULL,
    created_by VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deprecated_at TIMESTAMPTZ NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_exps_tenant_name ON exps (tenant_id, name);
CREATE INDEX IF NOT EXISTS idx_exps_tenant_id ON exps (tenant_id);
CREATE INDEX IF NOT EXISTS idx_exps_status ON exps (status);

CREATE TABLE IF NOT EXISTS exp_revisions (
    id BIGSERIAL PRIMARY KEY,
    exp_id VARCHAR(36) NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    status VARCHAR(24) NOT NULL,
    source_object_key VARCHAR(768) NOT NULL,
    source_sha256 VARCHAR(64) NOT NULL,
    source_size BIGINT NOT NULL CHECK (source_size >= 0),
    cli_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
    inspect_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    validate_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    tests_passed_at TIMESTAMPTZ NULL,
    test_cases_sha256 VARCHAR(64) NOT NULL DEFAULT '',
    created_by VARCHAR(128) NOT NULL,
    published_by VARCHAR(128) NOT NULL DEFAULT '',
    published_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_exp_revisions_exp FOREIGN KEY (exp_id) REFERENCES exps(id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_exp_revision ON exp_revisions (exp_id, revision);
CREATE INDEX IF NOT EXISTS idx_exp_revisions_tenant_id ON exp_revisions (tenant_id);
CREATE INDEX IF NOT EXISTS idx_exp_revisions_source_sha256 ON exp_revisions (source_sha256);

CREATE TABLE IF NOT EXISTS exp_dependencies (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    parent_exp_id VARCHAR(36) NOT NULL,
    parent_revision INTEGER NOT NULL,
    dependency_exp_id VARCHAR(36) NOT NULL,
    dependency_revision INTEGER NOT NULL CHECK (dependency_revision > 0),
    source_sha256 VARCHAR(64) NOT NULL,
    CONSTRAINT fk_exp_dependency_parent FOREIGN KEY (parent_exp_id, parent_revision) REFERENCES exp_revisions(exp_id, revision) ON DELETE RESTRICT,
    CONSTRAINT fk_exp_dependency_child FOREIGN KEY (dependency_exp_id, dependency_revision) REFERENCES exp_revisions(exp_id, revision) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_exp_dependency ON exp_dependencies (parent_exp_id, parent_revision, dependency_exp_id, dependency_revision);
CREATE INDEX IF NOT EXISTS idx_exp_dependencies_tenant_id ON exp_dependencies (tenant_id);

CREATE TABLE IF NOT EXISTS exp_assets (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    asset_id VARCHAR(128) NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    object_key VARCHAR(768) NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    size BIGINT NOT NULL CHECK (size >= 0),
    media_type VARCHAR(160) NOT NULL,
    created_by VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_exp_asset_identity ON exp_assets (tenant_id, asset_id, version);
CREATE INDEX IF NOT EXISTS idx_exp_assets_tenant_id ON exp_assets (tenant_id);
CREATE INDEX IF NOT EXISTS idx_exp_assets_sha256 ON exp_assets (sha256);

CREATE TABLE IF NOT EXISTS exp_asset_refs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    exp_id VARCHAR(36) NOT NULL,
    revision INTEGER NOT NULL,
    asset_id VARCHAR(128) NOT NULL,
    asset_version INTEGER NOT NULL CHECK (asset_version > 0),
    sha256 VARCHAR(64) NOT NULL,
    CONSTRAINT fk_exp_asset_ref_revision FOREIGN KEY (exp_id, revision) REFERENCES exp_revisions(exp_id, revision) ON DELETE RESTRICT,
    CONSTRAINT fk_exp_asset_ref_asset FOREIGN KEY (tenant_id, asset_id, asset_version) REFERENCES exp_assets(tenant_id, asset_id, version) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_exp_asset_ref ON exp_asset_refs (exp_id, revision, asset_id);
CREATE INDEX IF NOT EXISTS idx_exp_asset_refs_tenant_id ON exp_asset_refs (tenant_id);

CREATE TABLE IF NOT EXISTS exp_test_cases (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    exp_id VARCHAR(36) NOT NULL,
    revision INTEGER NOT NULL,
    name VARCHAR(160) NOT NULL,
    params JSONB NOT NULL DEFAULT '{}'::jsonb,
    fixtures JSONB NOT NULL DEFAULT '[]'::jsonb,
    assertions JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_by VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_exp_test_case_revision FOREIGN KEY (exp_id, revision) REFERENCES exp_revisions(exp_id, revision) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_exp_test_case_revision ON exp_test_cases (exp_id, revision);
CREATE INDEX IF NOT EXISTS idx_exp_test_cases_tenant_id ON exp_test_cases (tenant_id);

CREATE TABLE IF NOT EXISTS exp_runs (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    exp_id VARCHAR(36) NOT NULL,
    revision INTEGER NOT NULL,
    source_sha256 VARCHAR(64) NOT NULL,
    action VARCHAR(16) NOT NULL,
    operator_id VARCHAR(128) NOT NULL,
    egress_mode VARCHAR(16) NOT NULL,
    agent_id VARCHAR(255) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL,
    provenance VARCHAR(32) NOT NULL,
    attested BOOLEAN NOT NULL DEFAULT FALSE,
    result_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    artifact_object_key VARCHAR(768) NOT NULL DEFAULT '',
    artifact_sha256 VARCHAR(64) NOT NULL DEFAULT '',
    artifact_expires_at TIMESTAMPTZ NULL,
    error_code VARCHAR(64) NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_exp_run_revision FOREIGN KEY (exp_id, revision) REFERENCES exp_revisions(exp_id, revision) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS idx_exp_runs_tenant_id ON exp_runs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_exp_runs_exp_id ON exp_runs (exp_id);
CREATE INDEX IF NOT EXISTS idx_exp_runs_status ON exp_runs (status);
CREATE INDEX IF NOT EXISTS idx_exp_runs_artifact_expires_at ON exp_runs (artifact_expires_at);

CREATE TABLE IF NOT EXISTS exp_audits (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    exp_id VARCHAR(36) NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    actor_id VARCHAR(128) NOT NULL,
    action VARCHAR(32) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_exp_audits_tenant_id ON exp_audits (tenant_id);
CREATE INDEX IF NOT EXISTS idx_exp_audits_exp_id ON exp_audits (exp_id);
CREATE INDEX IF NOT EXISTS idx_exp_audits_actor_id ON exp_audits (actor_id);
CREATE INDEX IF NOT EXISTS idx_exp_audits_action ON exp_audits (action);

CREATE TABLE IF NOT EXISTS exp_risk_waivers (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    exp_id VARCHAR(36) NOT NULL,
    reason TEXT NOT NULL,
    granted_by VARCHAR(128) NOT NULL,
    expires_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT fk_exp_risk_waiver_exp FOREIGN KEY (exp_id) REFERENCES exps(id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_exp_risk_waiver ON exp_risk_waivers (tenant_id, exp_id);
