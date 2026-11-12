--
-- MCP admin governance tables (schema v005).
-- Tenant-scoped enable flag, per-tenant OAuth client blocks, and admin action audit.
-- Authorization codes and refresh tokens stay hashed in v004 tables.
--

CREATE TABLE public.tenant_mcp_settings (
    tenant_id character varying(128) NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by character varying(64) NOT NULL DEFAULT '',
    CONSTRAINT tenant_mcp_settings_pkey PRIMARY KEY (tenant_id),
    CONSTRAINT tenant_mcp_settings_tenant_id_check CHECK (btrim(tenant_id) <> '')
);

CREATE TABLE public.oauth_tenant_client_blocks (
    tenant_id character varying(128) NOT NULL,
    client_id character varying(128) NOT NULL,
    blocked_at timestamp with time zone DEFAULT now() NOT NULL,
    actor_id character varying(64) NOT NULL DEFAULT '',
    CONSTRAINT oauth_tenant_client_blocks_pkey PRIMARY KEY (tenant_id, client_id),
    CONSTRAINT oauth_tenant_client_blocks_tenant_id_check CHECK (btrim(tenant_id) <> ''),
    CONSTRAINT oauth_tenant_client_blocks_client_id_check CHECK (btrim(client_id) <> '')
);

CREATE INDEX idx_oauth_tenant_client_blocks_client_id ON public.oauth_tenant_client_blocks USING btree (client_id);

CREATE TABLE public.mcp_admin_events (
    id character varying(64) NOT NULL,
    tenant_id character varying(128) NOT NULL,
    actor_id character varying(64) NOT NULL DEFAULT '',
    action character varying(64) NOT NULL,
    client_id character varying(128) NOT NULL DEFAULT '',
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mcp_admin_events_pkey PRIMARY KEY (id),
    CONSTRAINT mcp_admin_events_tenant_id_check CHECK (btrim(tenant_id) <> ''),
    CONSTRAINT mcp_admin_events_action_check CHECK (btrim(action) <> ''),
    CONSTRAINT mcp_admin_events_details_check CHECK (jsonb_typeof(details) = 'object')
);

CREATE INDEX idx_mcp_admin_events_tenant_id ON public.mcp_admin_events USING btree (tenant_id);
CREATE INDEX idx_mcp_admin_events_actor_id ON public.mcp_admin_events USING btree (actor_id);
CREATE INDEX idx_mcp_admin_events_action ON public.mcp_admin_events USING btree (action);
CREATE INDEX idx_mcp_admin_events_created_at ON public.mcp_admin_events USING btree (created_at);

INSERT INTO public.schema_migrations (version, name, checksum, applied_at)
VALUES ('005', 'mcp_admin', 'psql-managed', now())
ON CONFLICT (version) DO NOTHING;
