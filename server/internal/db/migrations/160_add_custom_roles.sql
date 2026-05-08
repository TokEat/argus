-- 160_add_custom_roles.sql
-- Tenant-scoped custom roles. Runtime authorization maps each custom role to
-- one built-in base role while preserving a display/audit permission snapshot.

CREATE TABLE IF NOT EXISTS custom_roles (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    label TEXT,
    description TEXT,
    base_role TEXT NOT NULL DEFAULT 'viewer',
    permissions JSONB,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_custom_roles_tenant_name
    ON custom_roles (tenant_id, name);

CREATE INDEX IF NOT EXISTS idx_custom_roles_base_role
    ON custom_roles (base_role);
