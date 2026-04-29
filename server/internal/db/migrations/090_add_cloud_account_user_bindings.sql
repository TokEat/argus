-- Cloud account ownership and per-user bindings.

ALTER TABLE cloud_accounts
    ADD COLUMN IF NOT EXISTS owner_user_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_cloud_accounts_owner_user_id ON cloud_accounts (owner_user_id);

CREATE TABLE IF NOT EXISTS cloud_account_bindings (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    cloud_account_id TEXT NOT NULL DEFAULT '',
    user_id TEXT NOT NULL DEFAULT '',
    access_type TEXT NOT NULL DEFAULT 'bound',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_account_binding_unique
    ON cloud_account_bindings (tenant_id, cloud_account_id, user_id);
CREATE INDEX IF NOT EXISTS idx_cloud_account_bindings_tenant_id
    ON cloud_account_bindings (tenant_id);
CREATE INDEX IF NOT EXISTS idx_cloud_account_bindings_cloud_account_id
    ON cloud_account_bindings (cloud_account_id);
CREATE INDEX IF NOT EXISTS idx_cloud_account_bindings_user_id
    ON cloud_account_bindings (user_id);

UPDATE cloud_accounts ca
SET owner_user_id = COALESCE(
    (
        SELECT u.id::TEXT
        FROM users u
        WHERE u.tenant_id = ca.tenant_id
          AND u.status = 'active'
          AND u.role = 'admin'
        ORDER BY u.id
        LIMIT 1
    ),
    (
        SELECT u.id::TEXT
        FROM users u
        WHERE u.tenant_id = ca.tenant_id
          AND u.status = 'active'
        ORDER BY u.id
        LIMIT 1
    ),
    ca.owner_user_id
)
WHERE ca.owner_user_id = '';

INSERT INTO cloud_account_bindings (tenant_id, cloud_account_id, user_id, access_type, created_at, updated_at)
SELECT tenant_id, id, owner_user_id, 'owner', NOW(), NOW()
FROM cloud_accounts
WHERE owner_user_id <> ''
ON CONFLICT (tenant_id, cloud_account_id, user_id) DO NOTHING;
