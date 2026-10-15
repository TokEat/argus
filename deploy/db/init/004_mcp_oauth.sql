--
-- MCP OAuth 2.1 authorization server tables (schema v004).
-- Authorization codes and refresh tokens store SHA-256 hashes only.
--

CREATE TABLE public.oauth_clients (
    client_id character varying(128) NOT NULL,
    redirect_uris jsonb NOT NULL,
    public boolean NOT NULL DEFAULT true,
    tenant_id character varying(128) NOT NULL DEFAULT '',
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth_clients_pkey PRIMARY KEY (client_id),
    CONSTRAINT oauth_clients_redirect_uris_check CHECK ((jsonb_typeof(redirect_uris) = 'array'))
);

CREATE INDEX idx_oauth_clients_tenant_id ON public.oauth_clients USING btree (tenant_id);

CREATE TABLE public.oauth_authorization_codes (
    code_hash character varying(64) NOT NULL,
    client_id character varying(128) NOT NULL,
    redirect_uri text NOT NULL,
    resource text NOT NULL,
    code_challenge text NOT NULL,
    user_id character varying(64) NOT NULL,
    tenant_id character varying(128) NOT NULL,
    role character varying(64) NOT NULL,
    role_base character varying(64) NOT NULL DEFAULT '',
    exp_authorized boolean NOT NULL DEFAULT false,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth_authorization_codes_pkey PRIMARY KEY (code_hash)
);

CREATE INDEX idx_oauth_authorization_codes_client_id ON public.oauth_authorization_codes USING btree (client_id);
CREATE INDEX idx_oauth_authorization_codes_tenant_id ON public.oauth_authorization_codes USING btree (tenant_id);
CREATE INDEX idx_oauth_authorization_codes_expires_at ON public.oauth_authorization_codes USING btree (expires_at);

CREATE TABLE public.oauth_refresh_tokens (
    token_hash character varying(64) NOT NULL,
    client_id character varying(128) NOT NULL,
    user_id character varying(64) NOT NULL,
    tenant_id character varying(128) NOT NULL,
    role character varying(64) NOT NULL,
    role_base character varying(64) NOT NULL DEFAULT '',
    exp_authorized boolean NOT NULL DEFAULT false,
    resource text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth_refresh_tokens_pkey PRIMARY KEY (token_hash)
);

CREATE INDEX idx_oauth_refresh_tokens_client_id ON public.oauth_refresh_tokens USING btree (client_id);
CREATE INDEX idx_oauth_refresh_tokens_user_id ON public.oauth_refresh_tokens USING btree (user_id);
CREATE INDEX idx_oauth_refresh_tokens_tenant_id ON public.oauth_refresh_tokens USING btree (tenant_id);
CREATE INDEX idx_oauth_refresh_tokens_expires_at ON public.oauth_refresh_tokens USING btree (expires_at);
CREATE INDEX idx_oauth_refresh_tokens_revoked_at ON public.oauth_refresh_tokens USING btree (revoked_at);

INSERT INTO public.oauth_clients (client_id, redirect_uris, public, tenant_id, created_at)
VALUES (
    'cursor',
    '["http://127.0.0.1:8787/callback","http://localhost:8787/callback","https://www.cursor.com/agents/mcp/oauth/callback","cursor://anysphere.cursor-mcp/oauth/callback"]'::jsonb,
    true,
    '',
    now()
)
ON CONFLICT (client_id) DO NOTHING;

INSERT INTO public.schema_migrations (version, name, checksum, applied_at)
VALUES ('004', 'mcp_oauth', 'psql-managed', now())
ON CONFLICT (version) DO NOTHING;
