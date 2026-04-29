ALTER TABLE projects ADD COLUMN IF NOT EXISTS owner_user_id TEXT;
ALTER TABLE project_members ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE project_members ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

WITH fallback_owner AS (
    SELECT DISTINCT ON (tenant_id)
        tenant_id,
        id AS user_id
    FROM users
    WHERE status = 'active'
    ORDER BY tenant_id, CASE WHEN role = 'admin' THEN 0 ELSE 1 END, created_at ASC, id ASC
)
UPDATE projects p
SET owner_user_id = f.user_id
FROM fallback_owner f
WHERE p.tenant_id = f.tenant_id
  AND (p.owner_user_id IS NULL OR p.owner_user_id = '');

UPDATE project_members pm
SET tenant_id = COALESCE(NULLIF(p.tenant_id, ''), 'default')
FROM projects p
WHERE pm.project_id = p.id
  AND (pm.tenant_id IS NULL OR pm.tenant_id = '' OR pm.tenant_id = 'default');

INSERT INTO project_members (tenant_id, project_id, user_id, role, created_at, updated_at)
SELECT p.tenant_id, p.id, p.owner_user_id, 'owner', NOW(), NOW()
FROM projects p
WHERE p.owner_user_id IS NOT NULL
  AND p.owner_user_id <> ''
ON CONFLICT (project_id, user_id) DO UPDATE
SET tenant_id = EXCLUDED.tenant_id,
    role = EXCLUDED.role,
    updated_at = NOW();

CREATE INDEX IF NOT EXISTS idx_projects_owner_user_id ON projects (owner_user_id);
CREATE INDEX IF NOT EXISTS idx_project_members_tenant_user ON project_members (tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_project_members_tenant_project ON project_members (tenant_id, project_id);
