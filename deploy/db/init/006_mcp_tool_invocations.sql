--
-- MCP tools/call audit (schema v006).
-- High-risk MCP invocations only. Copilot ai_tool_invocations is retired.
--

CREATE TABLE public.mcp_tool_invocations (
    id character varying(64) NOT NULL,
    tenant_id character varying(128) NOT NULL,
    user_id character varying(64) NOT NULL DEFAULT '',
    role character varying(32) NOT NULL DEFAULT '',
    client_id character varying(128) NOT NULL DEFAULT '',
    tool_name character varying(128) NOT NULL,
    action character varying(32) NOT NULL DEFAULT '',
    args jsonb NOT NULL DEFAULT '{}'::jsonb,
    agent_id character varying(255) NOT NULL DEFAULT '',
    target text NOT NULL DEFAULT '',
    duration_ms bigint NOT NULL DEFAULT 0,
    status character varying(32) NOT NULL,
    error_summary text NOT NULL DEFAULT '',
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mcp_tool_invocations_pkey PRIMARY KEY (id),
    CONSTRAINT mcp_tool_invocations_tenant_id_check CHECK (btrim(tenant_id) <> ''),
    CONSTRAINT mcp_tool_invocations_tool_name_check CHECK (btrim(tool_name) <> ''),
    CONSTRAINT mcp_tool_invocations_status_check CHECK (btrim(status) <> ''),
    CONSTRAINT mcp_tool_invocations_args_check CHECK (jsonb_typeof(args) = 'object')
);

CREATE INDEX idx_mcp_tool_invocations_tenant_id ON public.mcp_tool_invocations USING btree (tenant_id);
CREATE INDEX idx_mcp_tool_invocations_user_id ON public.mcp_tool_invocations USING btree (user_id);
CREATE INDEX idx_mcp_tool_invocations_client_id ON public.mcp_tool_invocations USING btree (client_id);
CREATE INDEX idx_mcp_tool_invocations_tool_name ON public.mcp_tool_invocations USING btree (tool_name);
CREATE INDEX idx_mcp_tool_invocations_status ON public.mcp_tool_invocations USING btree (status);
CREATE INDEX idx_mcp_tool_invocations_created_at ON public.mcp_tool_invocations USING btree (created_at);

DROP TABLE IF EXISTS public.ai_tool_invocations;
DROP SEQUENCE IF EXISTS public.ai_tool_invocations_id_seq;

INSERT INTO public.schema_migrations (version, name, checksum, applied_at)
VALUES ('006', 'mcp_tool_invocations', 'psql-managed', now())
ON CONFLICT (version) DO NOTHING;
