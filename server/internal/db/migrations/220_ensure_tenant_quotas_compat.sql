-- 220_ensure_tenant_quotas_compat.sql
-- Production hardening for tenant quota table naming.
-- The canonical table is tenant_quotas. A tenant_quota compatibility view keeps
-- rolling deployments safe if an older process still queries the singular name.

DO $$
BEGIN
    IF to_regclass('public.tenant_quotas') IS NULL
       AND to_regclass('public.tenant_quota') IS NOT NULL
       AND EXISTS (
           SELECT 1
           FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public'
             AND c.relname = 'tenant_quota'
             AND c.relkind = 'r'
       ) THEN
        ALTER TABLE public.tenant_quota RENAME TO tenant_quotas;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS tenant_quotas (
    tenant_id TEXT PRIMARY KEY DEFAULT 'default',
    max_concurrent_tasks INTEGER NOT NULL DEFAULT 0,
    max_running_sub_tasks INTEGER NOT NULL DEFAULT 0,
    daily_task_limit INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);

ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS tenant_id TEXT;
ALTER TABLE tenant_quotas ALTER COLUMN tenant_id SET DEFAULT 'default';
UPDATE tenant_quotas SET tenant_id = 'default' WHERE tenant_id IS NULL OR tenant_id = '';
ALTER TABLE tenant_quotas ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS max_concurrent_tasks INTEGER;
UPDATE tenant_quotas SET max_concurrent_tasks = 0 WHERE max_concurrent_tasks IS NULL;
ALTER TABLE tenant_quotas ALTER COLUMN max_concurrent_tasks SET DEFAULT 0;
ALTER TABLE tenant_quotas ALTER COLUMN max_concurrent_tasks SET NOT NULL;

ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS max_running_sub_tasks INTEGER;
UPDATE tenant_quotas SET max_running_sub_tasks = 0 WHERE max_running_sub_tasks IS NULL;
ALTER TABLE tenant_quotas ALTER COLUMN max_running_sub_tasks SET DEFAULT 0;
ALTER TABLE tenant_quotas ALTER COLUMN max_running_sub_tasks SET NOT NULL;

ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS daily_task_limit INTEGER;
UPDATE tenant_quotas SET daily_task_limit = 0 WHERE daily_task_limit IS NULL;
ALTER TABLE tenant_quotas ALTER COLUMN daily_task_limit SET DEFAULT 0;
ALTER TABLE tenant_quotas ALTER COLUMN daily_task_limit SET NOT NULL;

ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;
ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.tenant_quotas'::regclass
          AND contype = 'p'
    ) THEN
        ALTER TABLE public.tenant_quotas ADD PRIMARY KEY (tenant_id);
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.tenant_quota') IS NOT NULL
       AND EXISTS (
           SELECT 1
           FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'public'
             AND c.relname = 'tenant_quota'
             AND c.relkind = 'r'
       ) THEN
        INSERT INTO public.tenant_quotas (
            tenant_id,
            max_concurrent_tasks,
            max_running_sub_tasks,
            daily_task_limit,
            created_at,
            updated_at
        )
        SELECT
            COALESCE(NULLIF(tenant_id, ''), 'default'),
            COALESCE(max_concurrent_tasks, 0),
            COALESCE(max_running_sub_tasks, 0),
            COALESCE(daily_task_limit, 0),
            created_at,
            updated_at
        FROM public.tenant_quota
        ON CONFLICT (tenant_id) DO UPDATE SET
            max_concurrent_tasks = EXCLUDED.max_concurrent_tasks,
            max_running_sub_tasks = EXCLUDED.max_running_sub_tasks,
            daily_task_limit = EXCLUDED.daily_task_limit,
            created_at = COALESCE(public.tenant_quotas.created_at, EXCLUDED.created_at),
            updated_at = EXCLUDED.updated_at;
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.tenant_quota') IS NULL THEN
        CREATE VIEW public.tenant_quota AS
        SELECT
            tenant_id,
            max_concurrent_tasks,
            max_running_sub_tasks,
            daily_task_limit,
            created_at,
            updated_at
        FROM public.tenant_quotas;
    END IF;
END $$;
