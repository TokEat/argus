--
-- Name: subdomain_passive_cache; Type: TABLE; Schema: public; Owner: -
--
-- 按域缓存 Server 端被动子域收集结果。CT/被动 DNS 数据为公共历史数据，
-- 缓存全局共享（不含租户语义），按 expires_at 判定新鲜度。
--

CREATE TABLE public.subdomain_passive_cache (
    domain character varying(255) NOT NULL,
    subdomains jsonb NOT NULL,
    sources jsonb NOT NULL,
    collected_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    CONSTRAINT subdomain_passive_cache_pkey PRIMARY KEY (domain),
    CONSTRAINT subdomain_passive_cache_subdomains_check CHECK ((jsonb_typeof(subdomains) = 'array')),
    CONSTRAINT subdomain_passive_cache_sources_check CHECK ((jsonb_typeof(sources) = 'array')),
    CONSTRAINT subdomain_passive_cache_domain_check CHECK ((btrim(domain) <> '' AND domain = lower(domain)))
);


--
-- Name: subdomain_passive_cache expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_subdomain_passive_cache_expires ON public.subdomain_passive_cache USING btree (expires_at);


--
-- Name: subdomain_passive_jobs; Type: TABLE; Schema: public; Owner: -
--
-- 派发前 Server 端被动收集任务。持有中的域名批次停留在 Queued 状态，
-- 收集完成（或超时兜底）后由 collector 释放并入队。
--

CREATE TABLE public.subdomain_passive_jobs (
    id character varying(64) NOT NULL,
    tenant_id character varying(128) NOT NULL DEFAULT 'default',
    project_id character varying(255) NOT NULL,
    root_task_id character varying(64) NOT NULL,
    batch_id character varying(64) NOT NULL,
    attempt_id character varying(64) NOT NULL,
    domains jsonb NOT NULL,
    domains_done integer NOT NULL DEFAULT 0,
    state character varying(16) NOT NULL,
    note text NOT NULL DEFAULT '',
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT subdomain_passive_jobs_pkey PRIMARY KEY (id),
    CONSTRAINT subdomain_passive_jobs_state_check CHECK ((state IN ('pending', 'running', 'released', 'skipped', 'failed'))),
    CONSTRAINT subdomain_passive_jobs_domains_check CHECK ((jsonb_typeof(domains) = 'array')),
    CONSTRAINT subdomain_passive_jobs_domains_done_check CHECK ((domains_done >= 0))
);


--
-- Name: subdomain_passive_jobs indexes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_subdomain_passive_jobs_state ON public.subdomain_passive_jobs USING btree (state);
CREATE INDEX idx_subdomain_passive_jobs_attempt ON public.subdomain_passive_jobs USING btree (attempt_id);
CREATE INDEX idx_subdomain_passive_jobs_root ON public.subdomain_passive_jobs USING btree (root_task_id);
CREATE INDEX idx_subdomain_passive_jobs_tenant ON public.subdomain_passive_jobs USING btree (tenant_id);


INSERT INTO public.schema_migrations (version, name, checksum, applied_at)
VALUES ('002', 'passive_subdomain_collection', 'psql-managed', now())
ON CONFLICT (version) DO NOTHING;
