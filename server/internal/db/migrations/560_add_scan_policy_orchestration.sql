-- Version 510 is permanently retired because two different migrations used it
-- during development releases. Keep this migration at 560 for compatibility
-- with databases that recorded either historical 510 checksum.
CREATE TABLE IF NOT EXISTS scan_policy_intents (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    project_id VARCHAR(255) NOT NULL,
    root_task_id VARCHAR(255) NOT NULL,
    schema_version VARCHAR(64) NOT NULL,
    policy_json JSONB NOT NULL,
    policy_hash VARCHAR(64) NOT NULL,
    plan_hash VARCHAR(64) NOT NULL,
    risk_status VARCHAR(24) NOT NULL,
    credential_status VARCHAR(24) NOT NULL,
    authorization_actor_id VARCHAR(255) NOT NULL DEFAULT '',
    authorized_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_policy_intent_root ON scan_policy_intents (tenant_id, root_task_id);
CREATE INDEX IF NOT EXISTS idx_scan_policy_intents_project_id ON scan_policy_intents (project_id);
CREATE INDEX IF NOT EXISTS idx_scan_policy_intents_policy_hash ON scan_policy_intents (policy_hash);
CREATE INDEX IF NOT EXISTS idx_scan_policy_intents_plan_hash ON scan_policy_intents (plan_hash);

CREATE TABLE IF NOT EXISTS scan_stage_derivations (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    project_id VARCHAR(255) NOT NULL,
    root_task_id VARCHAR(255) NOT NULL,
    stage VARCHAR(32) NOT NULL,
    status VARCHAR(24) NOT NULL,
    plan_hash VARCHAR(64) NOT NULL,
    observation_hash VARCHAR(64) NOT NULL DEFAULT '',
    batch_id VARCHAR(255) NOT NULL DEFAULT '',
    attempt_id VARCHAR(255) NOT NULL DEFAULT '',
    item_count INTEGER NOT NULL DEFAULT 0,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_stage_derivation ON scan_stage_derivations (tenant_id, root_task_id, stage);
CREATE INDEX IF NOT EXISTS idx_scan_stage_derivations_batch_id ON scan_stage_derivations (batch_id);

CREATE TABLE IF NOT EXISTS credential_dictionaries (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    project_id VARCHAR(255) NOT NULL,
    kind VARCHAR(16) NOT NULL CHECK (kind IN ('username', 'password')),
    name VARCHAR(160) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_credential_dictionary_name ON credential_dictionaries (tenant_id, project_id, kind, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_credential_dictionaries_project_id ON credential_dictionaries (project_id);

CREATE TABLE IF NOT EXISTS credential_dictionary_revisions (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    project_id VARCHAR(255) NOT NULL,
    dictionary_id VARCHAR(36) NOT NULL REFERENCES credential_dictionaries(id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK (revision > 0),
    sha256 VARCHAR(64) NOT NULL,
    item_count INTEGER NOT NULL CHECK (item_count >= 0),
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_credential_dictionary_revision ON credential_dictionary_revisions (dictionary_id, revision);
CREATE INDEX IF NOT EXISTS idx_credential_dictionary_revisions_tenant_id ON credential_dictionary_revisions (tenant_id);

CREATE TABLE IF NOT EXISTS credential_bundles (
    ref VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    project_id VARCHAR(255) NOT NULL,
    root_task_id VARCHAR(255) NOT NULL,
    batch_id VARCHAR(255) NOT NULL,
    attempt_id VARCHAR(255) NOT NULL,
    agent_id VARCHAR(255) NOT NULL DEFAULT '',
    sha256 VARCHAR(64) NOT NULL,
    pair_count INTEGER NOT NULL CHECK (pair_count >= 0),
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    claimed_at TIMESTAMPTZ NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_credential_bundles_attempt_id ON credential_bundles (attempt_id);
CREATE INDEX IF NOT EXISTS idx_credential_bundles_expires_at ON credential_bundles (expires_at);

CREATE TABLE IF NOT EXISTS credential_finding_secrets (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    project_id VARCHAR(255) NOT NULL,
    root_task_id VARCHAR(255) NOT NULL,
    attempt_id VARCHAR(255) NOT NULL,
    endpoint VARCHAR(512) NOT NULL,
    service VARCHAR(64) NOT NULL,
    plugin VARCHAR(128) NOT NULL,
    masked_username VARCHAR(256) NOT NULL,
    ciphertext BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_credential_finding_secrets_tenant_id ON credential_finding_secrets (tenant_id);
CREATE INDEX IF NOT EXISTS idx_credential_finding_secrets_root_task_id ON credential_finding_secrets (root_task_id);

CREATE TABLE IF NOT EXISTS credential_reveal_audits (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    project_id VARCHAR(255) NOT NULL,
    finding_id VARCHAR(36) NOT NULL,
    actor_id VARCHAR(255) NOT NULL,
    action VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_credential_reveal_audits_tenant_id ON credential_reveal_audits (tenant_id);
CREATE INDEX IF NOT EXISTS idx_credential_reveal_audits_finding_id ON credential_reveal_audits (finding_id);
