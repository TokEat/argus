CREATE TABLE IF NOT EXISTS subdomain_dictionaries (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    project_id VARCHAR(255) NOT NULL,
    name VARCHAR(160) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_subdomain_dictionary_name ON subdomain_dictionaries (tenant_id, project_id, name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_subdomain_dictionaries_project_id ON subdomain_dictionaries (project_id);

CREATE TABLE IF NOT EXISTS subdomain_dictionary_revisions (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    project_id VARCHAR(255) NOT NULL,
    dictionary_id VARCHAR(36) NOT NULL REFERENCES subdomain_dictionaries(id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK (revision > 0),
    sha256 VARCHAR(64) NOT NULL,
    item_count INTEGER NOT NULL CHECK (item_count > 0),
    values_json JSONB NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_subdomain_dictionary_revision ON subdomain_dictionary_revisions (dictionary_id, revision);
CREATE INDEX IF NOT EXISTS idx_subdomain_dictionary_revisions_tenant_id ON subdomain_dictionary_revisions (tenant_id);
