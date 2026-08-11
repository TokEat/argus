ALTER TABLE asset_discovery_notebook_items ADD COLUMN IF NOT EXISTS note TEXT NOT NULL DEFAULT '';
ALTER TABLE asset_discovery_notebook_items ADD COLUMN IF NOT EXISTS removed_at TIMESTAMPTZ NULL;
ALTER TABLE asset_discovery_notebook_items ADD COLUMN IF NOT EXISTS removed_by TEXT NOT NULL DEFAULT '';
ALTER TABLE asset_discovery_notebook_items ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_scope_id ON projects (tenant_id, id);
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM asset_discovery_notebook_items AS notebook_item
        LEFT JOIN projects AS project
          ON project.tenant_id = notebook_item.tenant_id
         AND project.id = notebook_item.project_id
        WHERE project.id IS NULL
    ) THEN
        RAISE EXCEPTION 'cannot add notebook project scope: orphan notebook items exist';
    END IF;
END $$;
ALTER TABLE asset_discovery_notebook_items ADD CONSTRAINT fk_adn_item_project FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id) ON DELETE RESTRICT;
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_items_updated_by ON asset_discovery_notebook_items (updated_by);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_items_removed_at ON asset_discovery_notebook_items (removed_at);
CREATE INDEX IF NOT EXISTS idx_asset_discovery_notebook_items_removed_by ON asset_discovery_notebook_items (removed_by);
CREATE INDEX IF NOT EXISTS idx_adn_items_active_updated ON asset_discovery_notebook_items (tenant_id, project_id, removed_at, updated_at DESC, id DESC);
ALTER TABLE asset_discovery_audits ADD COLUMN IF NOT EXISTS notebook_item_id BIGINT NULL;
CREATE INDEX IF NOT EXISTS idx_asset_discovery_audits_notebook_item_id ON asset_discovery_audits (notebook_item_id);
ALTER TABLE asset_discovery_audits ADD CONSTRAINT fk_asset_discovery_audit_notebook_item FOREIGN KEY (tenant_id, project_id, notebook_item_id) REFERENCES asset_discovery_notebook_items (tenant_id, project_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE IF NOT EXISTS asset_discovery_notebook_tags (id BIGSERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, project_id TEXT NOT NULL, name VARCHAR(64) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), CONSTRAINT chk_adn_tag_name CHECK (octet_length(name) BETWEEN 1 AND 64), CONSTRAINT fk_adn_tag_project FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id) ON DELETE RESTRICT);
CREATE UNIQUE INDEX IF NOT EXISTS idx_adn_tag ON asset_discovery_notebook_tags (tenant_id, project_id, name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_adn_tag_scope ON asset_discovery_notebook_tags (tenant_id, project_id, id);
CREATE TABLE IF NOT EXISTS asset_discovery_notebook_item_tags (id BIGSERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, project_id TEXT NOT NULL, notebook_item_id BIGINT NOT NULL, tag_id BIGINT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), CONSTRAINT fk_adn_item_tag_item FOREIGN KEY (tenant_id, project_id, notebook_item_id) REFERENCES asset_discovery_notebook_items (tenant_id, project_id, id) ON DELETE RESTRICT, CONSTRAINT fk_adn_item_tag_tag FOREIGN KEY (tenant_id, project_id, tag_id) REFERENCES asset_discovery_notebook_tags (tenant_id, project_id, id) ON DELETE RESTRICT);
CREATE UNIQUE INDEX IF NOT EXISTS idx_adn_item_tag ON asset_discovery_notebook_item_tags (tenant_id, project_id, notebook_item_id, tag_id);
