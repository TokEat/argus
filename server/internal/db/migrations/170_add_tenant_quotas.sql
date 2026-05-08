-- 170_add_tenant_quotas.sql
-- Tenant task quota limits. A value of 0 means unlimited for backward compatibility.

CREATE TABLE IF NOT EXISTS tenant_quotas (
    tenant_id TEXT PRIMARY KEY DEFAULT 'default',
    max_concurrent_tasks INTEGER NOT NULL DEFAULT 0,
    max_running_sub_tasks INTEGER NOT NULL DEFAULT 0,
    daily_task_limit INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);
