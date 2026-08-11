CREATE UNIQUE INDEX IF NOT EXISTS idx_root_tasks_scope_id
    ON root_tasks (tenant_id, project_id, id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_task_config_revisions_scope_version
    ON task_config_revisions (tenant_id, project_id, root_task_id, version);

CREATE TABLE IF NOT EXISTS asset_discovery_notebook_distribution_intents (
    id BIGSERIAL PRIMARY KEY,
    schema_version VARCHAR(64) NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    root_task_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    operation VARCHAR(32) NOT NULL,
    idempotency_key_hash VARCHAR(64) NOT NULL,
    request_hash VARCHAR(64) NOT NULL,
    plan_hash VARCHAR(64) NOT NULL,
    config_hash VARCHAR(64) NOT NULL,
    preview_schema_version VARCHAR(64) NOT NULL,
    task_status VARCHAR(64) NOT NULL,
    config_version INTEGER NOT NULL,
    rule_version TEXT NOT NULL,
    selected INTEGER NOT NULL,
    fresh INTEGER NOT NULL,
    duplicate INTEGER NOT NULL,
    scope_added INTEGER NOT NULL,
    seed_targets_added INTEGER NOT NULL,
    batch_count INTEGER NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_addi_ids CHECK (
        octet_length(tenant_id) BETWEEN 1 AND 1024
        AND octet_length(project_id) BETWEEN 1 AND 1024
        AND octet_length(root_task_id) BETWEEN 1 AND 1024
        AND octet_length(operator_id) BETWEEN 1 AND 1024
    ),
    CONSTRAINT chk_addi_operation CHECK (operation = 'materialize'),
    CONSTRAINT chk_addi_hashes CHECK (
        idempotency_key_hash ~ '^[0-9a-f]{64}$'
        AND request_hash ~ '^[0-9a-f]{64}$'
        AND plan_hash ~ '^[0-9a-f]{64}$'
        AND config_hash ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT chk_addi_versions CHECK (
        octet_length(schema_version) BETWEEN 1 AND 64
        AND octet_length(preview_schema_version) BETWEEN 1 AND 64
        AND octet_length(task_status) BETWEEN 1 AND 64
        AND octet_length(rule_version) BETWEEN 0 AND 8192
        AND config_version >= 1
    ),
    CONSTRAINT chk_addi_counts CHECK (
        selected BETWEEN 1 AND 100
        AND fresh >= 0
        AND duplicate >= 0
        AND fresh + duplicate = selected
        AND scope_added BETWEEN 0 AND fresh
        AND seed_targets_added BETWEEN 0 AND fresh
        AND batch_count BETWEEN 0 AND fresh
    ),
    CONSTRAINT chk_addi_status CHECK (status = 'recorded'),
    CONSTRAINT fk_addi_root_task FOREIGN KEY (tenant_id, project_id, root_task_id)
        REFERENCES root_tasks (tenant_id, project_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_addi_config_revision FOREIGN KEY (tenant_id, project_id, root_task_id, config_version)
        REFERENCES task_config_revisions (tenant_id, project_id, root_task_id, version) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_addi_scope_id
    ON asset_discovery_notebook_distribution_intents (tenant_id, project_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_addi_idempotency
    ON asset_discovery_notebook_distribution_intents (tenant_id, project_id, operator_id, operation, idempotency_key_hash);
CREATE INDEX IF NOT EXISTS idx_addi_task_created
    ON asset_discovery_notebook_distribution_intents (tenant_id, project_id, root_task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_addi_operator_created
    ON asset_discovery_notebook_distribution_intents (tenant_id, project_id, operator_id, created_at);
CREATE INDEX IF NOT EXISTS idx_addi_status_created
    ON asset_discovery_notebook_distribution_intents (tenant_id, project_id, status, created_at);

CREATE TABLE IF NOT EXISTS asset_discovery_notebook_distribution_intent_items (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    project_id TEXT NOT NULL,
    intent_id BIGINT NOT NULL,
    position INTEGER NOT NULL,
    notebook_item_id BIGINT NOT NULL,
    normalized_target TEXT NOT NULL,
    target_hash VARCHAR(64) NOT NULL,
    disposition VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_addii_ids CHECK (
        octet_length(tenant_id) BETWEEN 1 AND 1024
        AND octet_length(project_id) BETWEEN 1 AND 1024
    ),
    CONSTRAINT chk_addii_position CHECK (position BETWEEN 0 AND 99),
    CONSTRAINT chk_addii_target CHECK (
        octet_length(normalized_target) BETWEEN 1 AND 8192
        AND target_hash ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT chk_addii_disposition CHECK (disposition IN ('new', 'duplicate')),
    CONSTRAINT fk_addii_intent FOREIGN KEY (tenant_id, project_id, intent_id)
        REFERENCES asset_discovery_notebook_distribution_intents (tenant_id, project_id, id) ON DELETE RESTRICT,
    CONSTRAINT fk_addii_notebook_item FOREIGN KEY (tenant_id, project_id, notebook_item_id)
        REFERENCES asset_discovery_notebook_items (tenant_id, project_id, id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_addii_scope_id
    ON asset_discovery_notebook_distribution_intent_items (tenant_id, project_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_addii_intent_position
    ON asset_discovery_notebook_distribution_intent_items (tenant_id, project_id, intent_id, position);
CREATE UNIQUE INDEX IF NOT EXISTS idx_addii_intent_notebook_item
    ON asset_discovery_notebook_distribution_intent_items (tenant_id, project_id, intent_id, notebook_item_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_addii_intent_target_hash
    ON asset_discovery_notebook_distribution_intent_items (tenant_id, project_id, intent_id, target_hash);
CREATE INDEX IF NOT EXISTS idx_addii_notebook_item
    ON asset_discovery_notebook_distribution_intent_items (tenant_id, project_id, notebook_item_id);
CREATE INDEX IF NOT EXISTS idx_addii_target_hash
    ON asset_discovery_notebook_distribution_intent_items (tenant_id, project_id, target_hash);
