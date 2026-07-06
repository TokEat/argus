ALTER TABLE agent_logs ADD COLUMN IF NOT EXISTS tenant_id TEXT;

UPDATE agent_logs AS logs
SET tenant_id = COALESCE(NULLIF(nodes.tenant_id, ''), 'default')
FROM nodes
WHERE logs.agent_id = nodes.agent_id
  AND (logs.tenant_id IS NULL OR logs.tenant_id = '');

UPDATE agent_logs
SET tenant_id = 'default'
WHERE tenant_id IS NULL OR tenant_id = '';

ALTER TABLE agent_logs ALTER COLUMN tenant_id SET DEFAULT 'default';
ALTER TABLE agent_logs ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_agent_logs_tenant_id ON agent_logs (tenant_id);
