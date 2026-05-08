-- 230_canonicalize_tenant_quota_view.sql
-- Ensure tenant_quota remains only a compatibility view after any legacy table
-- data has been merged into the canonical tenant_quotas table.

CREATE TABLE IF NOT EXISTS tenant_quotas (
    tenant_id TEXT PRIMARY KEY DEFAULT 'default',
    max_concurrent_tasks INTEGER NOT NULL DEFAULT 0,
    max_running_sub_tasks INTEGER NOT NULL DEFAULT 0,
    daily_task_limit INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);

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

        EXECUTE format(
            'ALTER TABLE public.tenant_quota RENAME TO %I',
            'tenant_quota_legacy_' || to_char(clock_timestamp(), 'YYYYMMDDHH24MISS')
        );
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
