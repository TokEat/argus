--
-- Restore ai_tool_invocations (schema v604).
-- The fork merge keeps the Copilot AI tool-invocation audit feature (GET /ai/tool-invocations,
-- db.AIToolInvocation, schema_verify requirement), but upstream migration 006_mcp_tool_invocations.sql
-- dropped this table as "retired". Local lineage still reads/writes it, so recreate it here.
-- Idempotent: safe for fresh installs (001 creates it, 006 drops it, 604 recreates it) and for
-- databases that already applied 006. Column/sequence/PK/index DDL mirrors 001_init.sql exactly.
--

CREATE SEQUENCE IF NOT EXISTS public.ai_tool_invocations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

CREATE TABLE IF NOT EXISTS public.ai_tool_invocations (
    id bigint NOT NULL DEFAULT nextval('public.ai_tool_invocations_id_seq'::regclass),
    tenant_id text DEFAULT 'default'::text NOT NULL,
    user_id text,
    module text,
    tool_name text NOT NULL,
    args_summary jsonb,
    agent_id text,
    target_url text,
    duration_ms bigint DEFAULT 0 NOT NULL,
    status text NOT NULL,
    error_summary text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ai_tool_invocations_pkey PRIMARY KEY (id)
);

ALTER SEQUENCE public.ai_tool_invocations_id_seq OWNED BY public.ai_tool_invocations.id;

CREATE INDEX IF NOT EXISTS idx_ai_tool_invocations_agent_id ON public.ai_tool_invocations USING btree (agent_id);
CREATE INDEX IF NOT EXISTS idx_ai_tool_invocations_created_at ON public.ai_tool_invocations USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_ai_tool_invocations_module ON public.ai_tool_invocations USING btree (module);
CREATE INDEX IF NOT EXISTS idx_ai_tool_invocations_status ON public.ai_tool_invocations USING btree (status);
CREATE INDEX IF NOT EXISTS idx_ai_tool_invocations_tenant_id ON public.ai_tool_invocations USING btree (tenant_id);
CREATE INDEX IF NOT EXISTS idx_ai_tool_invocations_tool_name ON public.ai_tool_invocations USING btree (tool_name);
CREATE INDEX IF NOT EXISTS idx_ai_tool_invocations_user_id ON public.ai_tool_invocations USING btree (user_id);

INSERT INTO public.schema_migrations (version, name, checksum, applied_at)
VALUES ('604', 'add_ai_tool_invocations', 'psql-managed', now())
ON CONFLICT (version) DO NOTHING;
