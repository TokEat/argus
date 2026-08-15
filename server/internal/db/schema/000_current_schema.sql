-- Current-state PostgreSQL schema for empty Argus databases.
-- Generated from an empty database after applying incremental migrations.
-- Do not edit by hand. Regenerate with: make db-schema-dump
-- Existing databases keep using server/internal/db/migrations/*.sql.

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

SET default_tablespace = '';

SET default_table_access_method = heap;

CREATE TABLE public.active_fingerprint_rules (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    artifact_id text,
    source_file text NOT NULL,
    name text NOT NULL,
    product_name text NOT NULL,
    content_hash text NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    state text,
    enabled boolean DEFAULT true NOT NULL,
    declared_auto_profile text,
    computed_auto_profile text NOT NULL,
    auto_eligible boolean DEFAULT false NOT NULL,
    max_requests integer DEFAULT 1 NOT NULL,
    classification_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.active_fingerprint_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.active_fingerprint_rules_id_seq OWNED BY public.active_fingerprint_rules.id;

CREATE TABLE public.agent_log_alert_events (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    rule_id bigint NOT NULL,
    agent_id text NOT NULL,
    level text,
    message text,
    log_id bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.agent_log_alert_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.agent_log_alert_events_id_seq OWNED BY public.agent_log_alert_events.id;

CREATE TABLE public.agent_log_alert_rules (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    name text NOT NULL,
    agent_id text,
    level text,
    keyword text,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.agent_log_alert_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.agent_log_alert_rules_id_seq OWNED BY public.agent_log_alert_rules.id;

CREATE TABLE public.agent_log_archives (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    day text NOT NULL,
    storage_key text,
    log_count integer DEFAULT 0 NOT NULL,
    status text DEFAULT 'success'::text NOT NULL,
    error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.agent_log_archives_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.agent_log_archives_id_seq OWNED BY public.agent_log_archives.id;

CREATE TABLE public.agent_logs (
    id bigint NOT NULL,
    agent_id text,
    level text,
    message text,
    "timestamp" bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL
);

CREATE SEQUENCE public.agent_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.agent_logs_id_seq OWNED BY public.agent_logs.id;

CREATE TABLE public.agent_session_audits (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    agent_id text NOT NULL,
    action text NOT NULL,
    reason text,
    operator_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.agent_session_audits_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.agent_session_audits_id_seq OWNED BY public.agent_session_audits.id;

CREATE TABLE public.ai_tool_invocations (
    id bigint NOT NULL,
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
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.ai_tool_invocations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.ai_tool_invocations_id_seq OWNED BY public.ai_tool_invocations.id;

CREATE TABLE public.arsenal_ai_reviews (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    type text NOT NULL,
    file_name text,
    content_hash text NOT NULL,
    suggestion text NOT NULL,
    confidence double precision DEFAULT 0 NOT NULL,
    summary text,
    reason text,
    issues jsonb,
    duplicate_candidates jsonb,
    raw_response jsonb,
    provider text,
    model text,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.arsenal_ai_reviews_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.arsenal_ai_reviews_id_seq OWNED BY public.arsenal_ai_reviews.id;

CREATE TABLE public.arsenal_events (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    artifact_id text NOT NULL,
    type text NOT NULL,
    file_name text NOT NULL,
    version integer NOT NULL,
    hash text NOT NULL,
    state text NOT NULL,
    action text NOT NULL,
    actor_id text,
    content text,
    details jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.arsenal_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.arsenal_events_id_seq OWNED BY public.arsenal_events.id;

CREATE TABLE public.arsenals (
    id text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    type text,
    file_name text,
    content text,
    hash text,
    previous_hash text,
    version integer DEFAULT 1 NOT NULL,
    state text DEFAULT 'Draft'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    previous_content text
);

CREATE TABLE public.asset_change_logs (
    id bigint NOT NULL,
    project_id text,
    task_id text,
    entity_type text,
    entity_id bigint,
    change_type text,
    details jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.asset_change_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.asset_change_logs_id_seq OWNED BY public.asset_change_logs.id;

CREATE TABLE public.asset_discovery_audits (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    provider character varying(32) NOT NULL,
    action character varying(64) NOT NULL,
    operator_id text NOT NULL,
    query_hash character varying(64) NOT NULL,
    config_version integer DEFAULT 0 NOT NULL,
    config_hash character varying(64) DEFAULT ''::character varying NOT NULL,
    requested_limit integer DEFAULT 0 NOT NULL,
    provider_total integer DEFAULT 0 NOT NULL,
    returned_count integer DEFAULT 0 NOT NULL,
    skipped_rows integer DEFAULT 0 NOT NULL,
    truncated boolean DEFAULT false NOT NULL,
    status character varying(32) NOT NULL,
    error_code character varying(64) DEFAULT ''::character varying NOT NULL,
    duration_ms bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    notebook_item_id bigint
);

CREATE SEQUENCE public.asset_discovery_audits_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.asset_discovery_audits_id_seq OWNED BY public.asset_discovery_audits.id;

CREATE TABLE public.asset_discovery_notebook_distribution_intent_items (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    intent_id bigint NOT NULL,
    "position" integer NOT NULL,
    notebook_item_id bigint NOT NULL,
    normalized_target text NOT NULL,
    target_hash character varying(64) NOT NULL,
    disposition character varying(32) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_addii_disposition CHECK (((disposition)::text = ANY ((ARRAY['new'::character varying, 'duplicate'::character varying])::text[]))),
    CONSTRAINT chk_addii_ids CHECK ((((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 1024)) AND ((octet_length(project_id) >= 1) AND (octet_length(project_id) <= 1024)))),
    CONSTRAINT chk_addii_position CHECK ((("position" >= 0) AND ("position" <= 99))),
    CONSTRAINT chk_addii_target CHECK ((((octet_length(normalized_target) >= 1) AND (octet_length(normalized_target) <= 8192)) AND ((target_hash)::text ~ '^[0-9a-f]{64}$'::text)))
);

CREATE SEQUENCE public.asset_discovery_notebook_distribution_intent_items_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.asset_discovery_notebook_distribution_intent_items_id_seq OWNED BY public.asset_discovery_notebook_distribution_intent_items.id;

CREATE TABLE public.asset_discovery_notebook_distribution_intents (
    id bigint NOT NULL,
    schema_version character varying(64) NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    root_task_id text NOT NULL,
    operator_id text NOT NULL,
    operation character varying(32) NOT NULL,
    idempotency_key_hash character varying(64) NOT NULL,
    request_hash character varying(64) NOT NULL,
    plan_hash character varying(64) NOT NULL,
    config_hash character varying(64) NOT NULL,
    preview_schema_version character varying(64) NOT NULL,
    task_status character varying(64) NOT NULL,
    config_version integer NOT NULL,
    rule_version text NOT NULL,
    selected integer NOT NULL,
    fresh integer NOT NULL,
    duplicate integer NOT NULL,
    scope_added integer NOT NULL,
    seed_targets_added integer NOT NULL,
    batch_count integer NOT NULL,
    status character varying(32) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_addi_counts CHECK ((((selected >= 1) AND (selected <= 100)) AND (fresh >= 0) AND (duplicate >= 0) AND ((fresh + duplicate) = selected) AND ((scope_added >= 0) AND (scope_added <= fresh)) AND ((seed_targets_added >= 0) AND (seed_targets_added <= fresh)) AND ((batch_count >= 0) AND (batch_count <= fresh)))),
    CONSTRAINT chk_addi_hashes CHECK ((((idempotency_key_hash)::text ~ '^[0-9a-f]{64}$'::text) AND ((request_hash)::text ~ '^[0-9a-f]{64}$'::text) AND ((plan_hash)::text ~ '^[0-9a-f]{64}$'::text) AND ((config_hash)::text ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chk_addi_ids CHECK ((((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 1024)) AND ((octet_length(project_id) >= 1) AND (octet_length(project_id) <= 1024)) AND ((octet_length(root_task_id) >= 1) AND (octet_length(root_task_id) <= 1024)) AND ((octet_length(operator_id) >= 1) AND (octet_length(operator_id) <= 1024)))),
    CONSTRAINT chk_addi_operation CHECK (((operation)::text = 'materialize'::text)),
    CONSTRAINT chk_addi_status CHECK (((status)::text = 'recorded'::text)),
    CONSTRAINT chk_addi_versions CHECK ((((octet_length((schema_version)::text) >= 1) AND (octet_length((schema_version)::text) <= 64)) AND ((octet_length((preview_schema_version)::text) >= 1) AND (octet_length((preview_schema_version)::text) <= 64)) AND ((octet_length((task_status)::text) >= 1) AND (octet_length((task_status)::text) <= 64)) AND ((octet_length(rule_version) >= 0) AND (octet_length(rule_version) <= 8192)) AND (config_version >= 1)))
);

CREATE SEQUENCE public.asset_discovery_notebook_distribution_intents_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.asset_discovery_notebook_distribution_intents_id_seq OWNED BY public.asset_discovery_notebook_distribution_intents.id;

CREATE TABLE public.asset_discovery_notebook_distribution_materializations (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    intent_id bigint NOT NULL,
    root_task_id text NOT NULL,
    status character varying(32) NOT NULL,
    task_status character varying(64) NOT NULL,
    batch_ids jsonb NOT NULL,
    attempt_ids jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_addm_arrays CHECK (((jsonb_typeof(batch_ids) = 'array'::text) AND (jsonb_typeof(attempt_ids) = 'array'::text) AND (jsonb_array_length(batch_ids) = jsonb_array_length(attempt_ids)) AND (jsonb_array_length(batch_ids) <= 100) AND (((status)::text <> 'unchanged'::text) OR (jsonb_array_length(batch_ids) = 0)))),
    CONSTRAINT chk_addm_ids CHECK ((((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 1024)) AND ((octet_length(project_id) >= 1) AND (octet_length(project_id) <= 1024)) AND ((octet_length(root_task_id) >= 1) AND (octet_length(root_task_id) <= 1024)))),
    CONSTRAINT chk_addm_status CHECK (((status)::text = ANY ((ARRAY['materialized'::character varying, 'unchanged'::character varying])::text[])))
);

CREATE SEQUENCE public.asset_discovery_notebook_distribution_materializations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.asset_discovery_notebook_distribution_materializations_id_seq OWNED BY public.asset_discovery_notebook_distribution_materializations.id;

CREATE TABLE public.asset_discovery_notebook_item_tags (
    id bigint NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    notebook_item_id bigint NOT NULL,
    tag_id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.asset_discovery_notebook_item_tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.asset_discovery_notebook_item_tags_id_seq OWNED BY public.asset_discovery_notebook_item_tags.id;

CREATE TABLE public.asset_discovery_notebook_items (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    normalized_target text NOT NULL,
    target_hash character varying(64) NOT NULL,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    note text DEFAULT ''::text NOT NULL,
    removed_at timestamp with time zone,
    removed_by text DEFAULT ''::text NOT NULL,
    updated_by text DEFAULT ''::text NOT NULL,
    CONSTRAINT chk_asset_discovery_notebook_items_target CHECK (((octet_length(normalized_target) >= 1) AND (octet_length(normalized_target) <= 8192))),
    CONSTRAINT chk_asset_discovery_notebook_items_target_hash CHECK ((char_length((target_hash)::text) = 64))
);

CREATE SEQUENCE public.asset_discovery_notebook_items_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.asset_discovery_notebook_items_id_seq OWNED BY public.asset_discovery_notebook_items.id;

CREATE TABLE public.asset_discovery_notebook_sources (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    notebook_item_id bigint NOT NULL,
    snapshot_id bigint NOT NULL,
    snapshot_item_id bigint NOT NULL,
    audit_id bigint NOT NULL,
    archived_by text NOT NULL,
    archived_at timestamp with time zone NOT NULL,
    CONSTRAINT chk_asset_discovery_notebook_sources_archive CHECK (((octet_length(archived_by) >= 1) AND (octet_length(archived_by) <= 1024)))
);

CREATE SEQUENCE public.asset_discovery_notebook_sources_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.asset_discovery_notebook_sources_id_seq OWNED BY public.asset_discovery_notebook_sources.id;

CREATE TABLE public.asset_discovery_notebook_tags (
    id bigint NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    name character varying(64) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_adn_tag_name CHECK (((octet_length((name)::text) >= 1) AND (octet_length((name)::text) <= 64)))
);

CREATE SEQUENCE public.asset_discovery_notebook_tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.asset_discovery_notebook_tags_id_seq OWNED BY public.asset_discovery_notebook_tags.id;

CREATE TABLE public.asset_discovery_snapshot_items (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    snapshot_id bigint NOT NULL,
    "position" integer DEFAULT 0 NOT NULL,
    normalized_target text NOT NULL,
    target_hash character varying(64) NOT NULL,
    ip character varying(64) DEFAULT ''::character varying NOT NULL,
    port integer DEFAULT 0 NOT NULL,
    domain character varying(255) DEFAULT ''::character varying NOT NULL,
    protocol character varying(32) DEFAULT ''::character varying NOT NULL,
    title text DEFAULT ''::text NOT NULL,
    icp text DEFAULT ''::text NOT NULL,
    country character varying(128) DEFAULT ''::character varying NOT NULL,
    city character varying(128) DEFAULT ''::character varying NOT NULL,
    company text DEFAULT ''::text NOT NULL,
    status_code integer DEFAULT 0 NOT NULL,
    source character varying(32) NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_asset_discovery_snapshot_items_port CHECK (((port >= 0) AND (port <= 65535))),
    CONSTRAINT chk_asset_discovery_snapshot_items_position CHECK (("position" >= 0)),
    CONSTRAINT chk_asset_discovery_snapshot_items_status_code CHECK (((status_code >= 0) AND (status_code <= 999))),
    CONSTRAINT chk_asset_discovery_snapshot_items_target CHECK (((octet_length(normalized_target) >= 1) AND (octet_length(normalized_target) <= 8192)))
);

CREATE SEQUENCE public.asset_discovery_snapshot_items_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.asset_discovery_snapshot_items_id_seq OWNED BY public.asset_discovery_snapshot_items.id;

CREATE TABLE public.asset_discovery_snapshots (
    id bigint NOT NULL,
    schema_version character varying(64) NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    audit_id bigint NOT NULL,
    provider character varying(32) NOT NULL,
    expression text NOT NULL,
    query_hash character varying(64) NOT NULL,
    config_version integer DEFAULT 0 NOT NULL,
    config_hash character varying(64) DEFAULT ''::character varying NOT NULL,
    requested_limit integer DEFAULT 0 NOT NULL,
    provider_total integer DEFAULT 0 NOT NULL,
    returned_count integer DEFAULT 0 NOT NULL,
    skipped_rows integer DEFAULT 0 NOT NULL,
    truncated boolean DEFAULT false NOT NULL,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_asset_discovery_snapshots_counts CHECK (((requested_limit >= 0) AND (provider_total >= 0) AND (returned_count >= 0) AND (skipped_rows >= 0))),
    CONSTRAINT chk_asset_discovery_snapshots_expression CHECK (((octet_length(expression) >= 1) AND (octet_length(expression) <= 4096)))
);

CREATE SEQUENCE public.asset_discovery_snapshots_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.asset_discovery_snapshots_id_seq OWNED BY public.asset_discovery_snapshots.id;

CREATE TABLE public.assets (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    task_id text,
    target text,
    protocol text,
    port integer,
    url text,
    title text,
    service text,
    cert_subject text,
    cert_expiry timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    project_id text,
    tags jsonb,
    status text DEFAULT 'alive'::text NOT NULL,
    owner_id text,
    cred_id text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    root_task_id text
);

CREATE SEQUENCE public.assets_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.assets_id_seq OWNED BY public.assets.id;

CREATE TABLE public.build_jobs (
    id bigint NOT NULL,
    platform text NOT NULL,
    arch text NOT NULL,
    pack boolean DEFAULT false NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    artifact text,
    log_tail text,
    log_text text,
    error text,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    components text,
    artifacts text
);

CREATE SEQUENCE public.build_jobs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.build_jobs_id_seq OWNED BY public.build_jobs.id;

CREATE TABLE public.cloud_account_bindings (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    cloud_account_id text DEFAULT ''::text NOT NULL,
    user_id text DEFAULT ''::text NOT NULL,
    access_type text DEFAULT 'bound'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.cloud_account_bindings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cloud_account_bindings_id_seq OWNED BY public.cloud_account_bindings.id;

CREATE TABLE public.cloud_accounts (
    id text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    provider text DEFAULT 'aliyun'::text NOT NULL,
    access_key_id text DEFAULT ''::text NOT NULL,
    access_key_secret text DEFAULT ''::text NOT NULL,
    region text DEFAULT ''::text NOT NULL,
    default_image_id text DEFAULT ''::text NOT NULL,
    default_instance_type text DEFAULT ''::text NOT NULL,
    default_security_group text DEFAULT ''::text NOT NULL,
    default_v_switch text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    oss_bucket text DEFAULT ''::text NOT NULL,
    oss_endpoint text DEFAULT ''::text NOT NULL,
    owner_user_id text DEFAULT ''::text NOT NULL
);

CREATE TABLE public.cloud_instances (
    id text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    cloud_account_id text DEFAULT ''::text NOT NULL,
    policy_id text DEFAULT ''::text NOT NULL,
    provider_instance_id text DEFAULT ''::text NOT NULL,
    agent_id text DEFAULT ''::text NOT NULL,
    ip text DEFAULT ''::text NOT NULL,
    region text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'Provisioning'::text NOT NULL,
    spot boolean DEFAULT false NOT NULL,
    error_message text DEFAULT ''::text NOT NULL,
    launched_at timestamp with time zone,
    ready_at timestamp with time zone,
    terminated_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    reboot_count integer DEFAULT 0 NOT NULL
);

CREATE TABLE public.cloud_scaling_policies (
    id text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    cloud_account_id text DEFAULT ''::text NOT NULL,
    name text DEFAULT ''::text NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    min_instances integer DEFAULT 0 NOT NULL,
    max_instances integer DEFAULT 5 NOT NULL,
    scale_up_threshold integer DEFAULT 50 NOT NULL,
    scale_down_threshold integer DEFAULT 3 NOT NULL,
    cooldown_seconds integer DEFAULT 300 NOT NULL,
    instance_ttl_minutes integer DEFAULT 120 NOT NULL,
    spot_strategy text DEFAULT 'NoSpot'::text NOT NULL,
    max_spot_price double precision DEFAULT 0 NOT NULL,
    user_data_template text DEFAULT ''::text NOT NULL,
    last_scale_action timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    spot_duration_hours integer DEFAULT 1 NOT NULL
);

CREATE TABLE public.credential_bundles (
    ref character varying(36) NOT NULL,
    tenant_id character varying(128) NOT NULL,
    project_id character varying(255) NOT NULL,
    root_task_id character varying(255) NOT NULL,
    batch_id character varying(255) NOT NULL,
    attempt_id character varying(255) NOT NULL,
    agent_id character varying(255) DEFAULT ''::character varying NOT NULL,
    sha256 character varying(64) NOT NULL,
    pair_count integer NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    claimed_at timestamp with time zone,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT credential_bundles_pair_count_check CHECK ((pair_count >= 0))
);

CREATE TABLE public.credential_dictionaries (
    id character varying(36) NOT NULL,
    tenant_id character varying(128) NOT NULL,
    project_id character varying(255) NOT NULL,
    kind character varying(16) NOT NULL,
    name character varying(160) NOT NULL,
    created_by character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone,
    CONSTRAINT credential_dictionaries_kind_check CHECK (((kind)::text = ANY ((ARRAY['username'::character varying, 'password'::character varying])::text[])))
);

CREATE TABLE public.credential_dictionary_revisions (
    id bigint NOT NULL,
    tenant_id character varying(128) NOT NULL,
    project_id character varying(255) NOT NULL,
    dictionary_id character varying(36) NOT NULL,
    revision integer NOT NULL,
    sha256 character varying(64) NOT NULL,
    item_count integer NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    created_by character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT credential_dictionary_revisions_item_count_check CHECK ((item_count >= 0)),
    CONSTRAINT credential_dictionary_revisions_revision_check CHECK ((revision > 0))
);

CREATE SEQUENCE public.credential_dictionary_revisions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.credential_dictionary_revisions_id_seq OWNED BY public.credential_dictionary_revisions.id;

CREATE TABLE public.credential_finding_secrets (
    id character varying(36) NOT NULL,
    tenant_id character varying(128) NOT NULL,
    project_id character varying(255) NOT NULL,
    root_task_id character varying(255) NOT NULL,
    attempt_id character varying(255) NOT NULL,
    endpoint character varying(512) NOT NULL,
    service character varying(64) NOT NULL,
    plugin character varying(128) NOT NULL,
    masked_username character varying(256) NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.credential_reveal_audits (
    id bigint NOT NULL,
    tenant_id character varying(128) NOT NULL,
    project_id character varying(255) NOT NULL,
    finding_id character varying(36) NOT NULL,
    actor_id character varying(255) NOT NULL,
    action character varying(32) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.credential_reveal_audits_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.credential_reveal_audits_id_seq OWNED BY public.credential_reveal_audits.id;

CREATE TABLE public.credentials (
    id text NOT NULL,
    project_id text,
    name text,
    type text,
    content text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE public.cron_tasks (
    id text NOT NULL,
    project_id text,
    name text,
    cron_expr text,
    targets jsonb,
    config jsonb,
    next_run_at timestamp with time zone,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE public.custom_roles (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    name text NOT NULL,
    label text,
    description text,
    base_role text DEFAULT 'viewer'::text NOT NULL,
    permissions jsonb,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);

CREATE SEQUENCE public.custom_roles_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.custom_roles_id_seq OWNED BY public.custom_roles.id;

CREATE TABLE public.dir_rules (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    artifact_id text,
    source_file text,
    path text NOT NULL,
    product_name text NOT NULL,
    content_hash text,
    version integer DEFAULT 1 NOT NULL,
    state text,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.dir_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.dir_rules_id_seq OWNED BY public.dir_rules.id;

CREATE TABLE public.domains (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text,
    name text,
    task_id text,
    tags jsonb,
    records jsonb,
    icp text,
    whois jsonb,
    status text DEFAULT 'alive'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.domains_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.domains_id_seq OWNED BY public.domains.id;

CREATE TABLE public.exp_asset_refs (
    id bigint NOT NULL,
    tenant_id character varying(128) NOT NULL,
    exp_id character varying(36) NOT NULL,
    revision integer NOT NULL,
    asset_id character varying(128) NOT NULL,
    asset_version integer NOT NULL,
    sha256 character varying(64) NOT NULL,
    CONSTRAINT exp_asset_refs_asset_version_check CHECK ((asset_version > 0))
);

CREATE SEQUENCE public.exp_asset_refs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.exp_asset_refs_id_seq OWNED BY public.exp_asset_refs.id;

CREATE TABLE public.exp_assets (
    id bigint NOT NULL,
    tenant_id character varying(128) NOT NULL,
    asset_id character varying(128) NOT NULL,
    version integer NOT NULL,
    object_key character varying(768) NOT NULL,
    sha256 character varying(64) NOT NULL,
    size bigint NOT NULL,
    media_type character varying(160) NOT NULL,
    created_by character varying(128) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT exp_assets_size_check CHECK ((size >= 0)),
    CONSTRAINT exp_assets_version_check CHECK ((version > 0))
);

CREATE SEQUENCE public.exp_assets_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.exp_assets_id_seq OWNED BY public.exp_assets.id;

CREATE TABLE public.exp_audits (
    id bigint NOT NULL,
    tenant_id character varying(128) NOT NULL,
    exp_id character varying(36) NOT NULL,
    revision integer DEFAULT 0 NOT NULL,
    actor_id character varying(128) NOT NULL,
    action character varying(32) NOT NULL,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.exp_audits_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.exp_audits_id_seq OWNED BY public.exp_audits.id;

CREATE TABLE public.exp_dependencies (
    id bigint NOT NULL,
    tenant_id character varying(128) NOT NULL,
    parent_exp_id character varying(36) NOT NULL,
    parent_revision integer NOT NULL,
    dependency_exp_id character varying(36) NOT NULL,
    dependency_revision integer NOT NULL,
    source_sha256 character varying(64) NOT NULL,
    CONSTRAINT exp_dependencies_dependency_revision_check CHECK ((dependency_revision > 0))
);

CREATE SEQUENCE public.exp_dependencies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.exp_dependencies_id_seq OWNED BY public.exp_dependencies.id;

CREATE TABLE public.exp_egress_audits (
    id bigint NOT NULL,
    route_id character varying(64) NOT NULL,
    tenant_id character varying(128) NOT NULL,
    operator_id character varying(128) NOT NULL,
    agent_id character varying(255) NOT NULL,
    targets jsonb DEFAULT '[]'::jsonb NOT NULL,
    resolved_ips jsonb DEFAULT '[]'::jsonb NOT NULL,
    status character varying(32) NOT NULL,
    error_code character varying(64) DEFAULT ''::character varying NOT NULL,
    connection_count integer DEFAULT 0 NOT NULL,
    bytes_to_agent bigint DEFAULT 0 NOT NULL,
    bytes_from_agent bigint DEFAULT 0 NOT NULL,
    issued_at timestamp with time zone NOT NULL,
    claimed_at timestamp with time zone,
    finished_at timestamp with time zone,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.exp_egress_audits_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.exp_egress_audits_id_seq OWNED BY public.exp_egress_audits.id;

CREATE TABLE public.exp_revisions (
    id bigint NOT NULL,
    exp_id character varying(36) NOT NULL,
    tenant_id character varying(128) NOT NULL,
    revision integer NOT NULL,
    status character varying(24) NOT NULL,
    source_object_key character varying(768) NOT NULL,
    source_sha256 character varying(64) NOT NULL,
    source_size bigint NOT NULL,
    cli_schema jsonb DEFAULT '{}'::jsonb NOT NULL,
    inspect_summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    validate_summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    tests_passed_at timestamp with time zone,
    test_cases_sha256 character varying(64) DEFAULT ''::character varying NOT NULL,
    created_by character varying(128) NOT NULL,
    published_by character varying(128) DEFAULT ''::character varying NOT NULL,
    published_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT exp_revisions_revision_check CHECK ((revision > 0)),
    CONSTRAINT exp_revisions_source_size_check CHECK ((source_size >= 0))
);

CREATE SEQUENCE public.exp_revisions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.exp_revisions_id_seq OWNED BY public.exp_revisions.id;

CREATE TABLE public.exp_risk_waivers (
    id bigint NOT NULL,
    tenant_id character varying(128) NOT NULL,
    exp_id character varying(36) NOT NULL,
    reason text NOT NULL,
    granted_by character varying(128) NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.exp_risk_waivers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.exp_risk_waivers_id_seq OWNED BY public.exp_risk_waivers.id;

CREATE TABLE public.exp_runs (
    id character varying(36) NOT NULL,
    tenant_id character varying(128) NOT NULL,
    exp_id character varying(36) NOT NULL,
    revision integer NOT NULL,
    source_sha256 character varying(64) NOT NULL,
    action character varying(16) NOT NULL,
    operator_id character varying(128) NOT NULL,
    egress_mode character varying(16) NOT NULL,
    agent_id character varying(255) DEFAULT ''::character varying NOT NULL,
    status character varying(32) NOT NULL,
    provenance character varying(32) NOT NULL,
    attested boolean DEFAULT false NOT NULL,
    result_summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    artifact_object_key character varying(768) DEFAULT ''::character varying NOT NULL,
    artifact_sha256 character varying(64) DEFAULT ''::character varying NOT NULL,
    artifact_expires_at timestamp with time zone,
    error_code character varying(64) DEFAULT ''::character varying NOT NULL,
    started_at timestamp with time zone NOT NULL,
    finished_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.exp_test_cases (
    id character varying(36) NOT NULL,
    tenant_id character varying(128) NOT NULL,
    exp_id character varying(36) NOT NULL,
    revision integer NOT NULL,
    name character varying(160) NOT NULL,
    params jsonb DEFAULT '{}'::jsonb NOT NULL,
    fixtures jsonb DEFAULT '[]'::jsonb NOT NULL,
    assertions jsonb DEFAULT '[]'::jsonb NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_by character varying(128) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.exps (
    id character varying(36) NOT NULL,
    tenant_id character varying(128) NOT NULL,
    name character varying(160) NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    risk_level character varying(24) NOT NULL,
    status character varying(24) NOT NULL,
    active_revision integer,
    created_by character varying(128) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deprecated_at timestamp with time zone,
    product_name character varying(160) DEFAULT '未分类'::character varying NOT NULL,
    parent_exp_id character varying(36),
    variant_key character varying(64) DEFAULT ''::character varying NOT NULL,
    CONSTRAINT chk_exps_family_shape CHECK ((((parent_exp_id IS NULL) AND ((variant_key)::text = ''::text)) OR ((parent_exp_id IS NOT NULL) AND ((variant_key)::text ~ '^[a-z0-9][a-z0-9._-]{0,63}$'::text))))
);

CREATE TABLE public.fingerprint_hits (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    task_id text,
    target text,
    product_name text,
    rule_name text,
    evidence text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    project_id text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    root_task_id text
);

CREATE SEQUENCE public.fingerprint_hits_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.fingerprint_hits_id_seq OWNED BY public.fingerprint_hits.id;

CREATE TABLE public.fingerprint_rules (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    artifact_id text,
    source_file text,
    product_name text NOT NULL,
    rule_expr text NOT NULL,
    category text DEFAULT 'web'::text NOT NULL,
    content_hash text,
    version integer DEFAULT 1 NOT NULL,
    state text,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.fingerprint_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.fingerprint_rules_id_seq OWNED BY public.fingerprint_rules.id;

CREATE TABLE public.nodes (
    agent_id text NOT NULL,
    ip text,
    status text,
    token text,
    tags text,
    version text,
    capacity integer DEFAULT 1 NOT NULL,
    running_tasks integer DEFAULT 0 NOT NULL,
    rule_version text,
    last_beat bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    running_task_ids text DEFAULT '[]'::text NOT NULL,
    os text,
    arch text,
    cpu_usage real,
    mem_usage real,
    token_expires_at timestamp with time zone,
    token_revoked_at timestamp with time zone,
    last_token_rotated_at timestamp with time zone
);

CREATE TABLE public.notification_rules (
    id bigint NOT NULL,
    project_id text,
    event text,
    channel text,
    config jsonb,
    status text DEFAULT 'enabled'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.notification_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.notification_rules_id_seq OWNED BY public.notification_rules.id;

CREATE TABLE public.poc_rules (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    artifact_id text,
    source_file text,
    name text NOT NULL,
    content_hash text,
    severity text DEFAULT 'info'::text NOT NULL,
    tags text,
    author text,
    description text,
    version integer DEFAULT 1 NOT NULL,
    state text,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    target_product text,
    cve text,
    compatibility_status text DEFAULT 'unknown'::text,
    source_version text,
    execution_class text DEFAULT 'detection'::text NOT NULL,
    risk_level text DEFAULT 'unknown'::text NOT NULL
);

CREATE SEQUENCE public.poc_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.poc_rules_id_seq OWNED BY public.poc_rules.id;

CREATE TABLE public.project_members (
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    user_id text NOT NULL,
    role text DEFAULT 'operator'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.projects (
    id text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    owner_user_id text,
    name text,
    description text,
    tags jsonb,
    seed_targets jsonb,
    scope jsonb,
    default_config jsonb,
    node_affinity jsonb,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE public.reports (
    id text NOT NULL,
    project_id text,
    name text,
    type text,
    format text,
    file_url text,
    status text DEFAULT 'pending'::text NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.risk_validation_execution_idempotencies (
    id bigint NOT NULL,
    schema_version character varying(64) NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    root_task_id text NOT NULL,
    operator_id text NOT NULL,
    operation character varying(64) NOT NULL,
    idempotency_key_hash character varying(64) NOT NULL,
    request_hash character varying(64) NOT NULL,
    plan_hash character varying(64) NOT NULL,
    poc_set_hash character varying(64) NOT NULL,
    config_version integer NOT NULL,
    config_hash character varying(64) NOT NULL,
    rule_version text NOT NULL,
    batch_id text NOT NULL,
    batch_sequence integer NOT NULL,
    attempt_id text NOT NULL,
    attempt_no integer NOT NULL,
    candidate_count integer NOT NULL,
    target_count integer NOT NULL,
    poc_count integer NOT NULL,
    estimated_requests bigint NOT NULL,
    second_confirmation_required boolean NOT NULL,
    before_status character varying(64) NOT NULL,
    after_status character varying(64) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_rvei_hashes CHECK ((((idempotency_key_hash)::text ~ '^[0-9a-f]{64}$'::text) AND ((request_hash)::text ~ '^[0-9a-f]{64}$'::text) AND ((plan_hash)::text ~ '^[0-9a-f]{64}$'::text) AND ((poc_set_hash)::text ~ '^[0-9a-f]{64}$'::text) AND ((config_hash)::text ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chk_rvei_ids CHECK ((((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 1024)) AND ((octet_length(project_id) >= 1) AND (octet_length(project_id) <= 1024)) AND ((octet_length(root_task_id) >= 1) AND (octet_length(root_task_id) <= 1024)) AND ((octet_length(operator_id) >= 1) AND (octet_length(operator_id) <= 1024)) AND ((octet_length(batch_id) >= 1) AND (octet_length(batch_id) <= 1024)) AND ((octet_length(attempt_id) >= 1) AND (octet_length(attempt_id) <= 1024)))),
    CONSTRAINT chk_rvei_outcome CHECK (((config_version >= 1) AND (batch_sequence >= 0) AND (attempt_no >= 1) AND (candidate_count >= 1) AND (target_count >= 1) AND (poc_count >= 1) AND (estimated_requests >= 0) AND ((octet_length(rule_version) >= 1) AND (octet_length(rule_version) <= 1024)) AND ((octet_length((before_status)::text) >= 1) AND (octet_length((before_status)::text) <= 64)) AND ((octet_length((after_status)::text) >= 1) AND (octet_length((after_status)::text) <= 64))))
);

CREATE SEQUENCE public.risk_validation_execution_idempotencies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.risk_validation_execution_idempotencies_id_seq OWNED BY public.risk_validation_execution_idempotencies.id;

CREATE TABLE public.root_tasks (
    id text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    user_id text,
    name text,
    original_targets text,
    status text,
    total_chunks integer,
    completed_chunks integer,
    config text,
    priority integer,
    timeout_sec integer,
    rule_version text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    project_id text,
    cron_task_id text,
    total_targets integer DEFAULT 0 NOT NULL,
    completed_targets integer DEFAULT 0 NOT NULL,
    archived_at timestamp with time zone,
    current_config_version integer DEFAULT 1 NOT NULL
);

CREATE TABLE public.rule_catalog_bootstraps (
    key text NOT NULL,
    schema_version integer,
    source text,
    status text,
    aggregate_hash text,
    arsenal_count integer,
    fingerprint_count integer,
    workflow_count integer,
    dir_probe_count integer,
    poc_count integer,
    last_error text,
    last_seeded_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    active_finger_count integer
);

CREATE TABLE public.scan_coverages (
    id bigint NOT NULL,
    schema_version character varying(32) NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    network_zone character varying(255) NOT NULL,
    normalized_target text NOT NULL,
    target_hash character varying(64) NOT NULL,
    stage character varying(64) NOT NULL,
    work_key_hash character varying(64) NOT NULL,
    scope_hash character varying(64) NOT NULL,
    config_hash character varying(64) NOT NULL,
    rule_version text NOT NULL,
    poc_set_hash character varying(64) DEFAULT ''::character varying NOT NULL,
    endpoint_content_hash character varying(64) DEFAULT ''::character varying NOT NULL,
    status character varying(32) NOT NULL,
    outcome character varying(32) NOT NULL,
    started_at timestamp with time zone NOT NULL,
    finished_at timestamp with time zone NOT NULL,
    valid_until timestamp with time zone,
    observation_hash character varying(64) DEFAULT ''::character varying NOT NULL,
    source_observation_id bigint DEFAULT 0 NOT NULL,
    source_task_id text DEFAULT ''::text NOT NULL,
    source_batch_id text DEFAULT ''::text NOT NULL,
    source_attempt_id text DEFAULT ''::text NOT NULL,
    revision integer DEFAULT 1 NOT NULL,
    invalid_reason text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.scan_coverages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.scan_coverages_id_seq OWNED BY public.scan_coverages.id;

CREATE TABLE public.scan_observations (
    id bigint NOT NULL,
    schema_version character varying(32) NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    network_zone character varying(255) NOT NULL,
    normalized_target text NOT NULL,
    target_hash character varying(64) NOT NULL,
    stage character varying(64) NOT NULL,
    work_key_hash character varying(64) NOT NULL,
    scope_hash character varying(64) NOT NULL,
    config_hash character varying(64) NOT NULL,
    rule_version text NOT NULL,
    poc_set_hash character varying(64) DEFAULT ''::character varying NOT NULL,
    endpoint_content_hash character varying(64) DEFAULT ''::character varying NOT NULL,
    source_event_id character varying(128),
    root_task_id text DEFAULT ''::text NOT NULL,
    batch_id text DEFAULT ''::text NOT NULL,
    attempt_id text DEFAULT ''::text NOT NULL,
    agent_id text DEFAULT ''::text NOT NULL,
    outcome character varying(32) NOT NULL,
    content_hash character varying(64) DEFAULT ''::character varying NOT NULL,
    evidence_hash character varying(64) DEFAULT ''::character varying NOT NULL,
    error_code character varying(128) DEFAULT ''::character varying NOT NULL,
    error_message text DEFAULT ''::text NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    checkpoint jsonb DEFAULT '{}'::jsonb NOT NULL,
    checkpoint_hash character varying(64) DEFAULT ''::character varying NOT NULL
);

CREATE SEQUENCE public.scan_observations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.scan_observations_id_seq OWNED BY public.scan_observations.id;

CREATE TABLE public.scan_policy_intents (
    id bigint NOT NULL,
    tenant_id character varying(128) NOT NULL,
    project_id character varying(255) NOT NULL,
    root_task_id character varying(255) NOT NULL,
    schema_version character varying(64) NOT NULL,
    policy_json jsonb NOT NULL,
    policy_hash character varying(64) NOT NULL,
    plan_hash character varying(64) NOT NULL,
    risk_status character varying(24) NOT NULL,
    credential_status character varying(24) NOT NULL,
    authorization_actor_id character varying(255) DEFAULT ''::character varying NOT NULL,
    authorized_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.scan_policy_intents_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.scan_policy_intents_id_seq OWNED BY public.scan_policy_intents.id;

CREATE TABLE public.scan_stage_derivations (
    id bigint NOT NULL,
    tenant_id character varying(128) NOT NULL,
    project_id character varying(255) NOT NULL,
    root_task_id character varying(255) NOT NULL,
    stage character varying(32) NOT NULL,
    status character varying(24) NOT NULL,
    plan_hash character varying(64) NOT NULL,
    observation_hash character varying(64) DEFAULT ''::character varying NOT NULL,
    batch_id character varying(255) DEFAULT ''::character varying NOT NULL,
    attempt_id character varying(255) DEFAULT ''::character varying NOT NULL,
    item_count integer DEFAULT 0 NOT NULL,
    summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.scan_stage_derivations_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.scan_stage_derivations_id_seq OWNED BY public.scan_stage_derivations.id;

CREATE TABLE public.scan_timing_events (
    id bigint NOT NULL,
    schema_version character varying(64) NOT NULL,
    tenant_id text NOT NULL,
    project_id text NOT NULL,
    root_task_id text NOT NULL,
    batch_id text NOT NULL,
    attempt_id text NOT NULL,
    agent_id text NOT NULL,
    source_event_id text NOT NULL,
    kind character varying(32) NOT NULL,
    stage character varying(64) DEFAULT ''::character varying NOT NULL,
    outcome character varying(32) NOT NULL,
    started_at timestamp with time zone NOT NULL,
    finished_at timestamp with time zone NOT NULL,
    duration_ns bigint NOT NULL,
    config_version integer NOT NULL,
    rule_version text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_scan_timing_event_contract CHECK ((((schema_version)::text = 'argus.timing/v1'::text) AND ((kind)::text = ANY ((ARRAY['process_startup'::character varying, 'rule_prepare'::character varying, 'context_init'::character varying, 'stage'::character varying])::text[])) AND ((outcome)::text = ANY ((ARRAY['success'::character varying, 'negative'::character varying, 'failed'::character varying, 'skipped'::character varying])::text[])) AND ((((kind)::text = 'stage'::text) AND ((octet_length((stage)::text) >= 1) AND (octet_length((stage)::text) <= 64))) OR (((kind)::text <> 'stage'::text) AND ((stage)::text = ''::text))) AND (config_version >= 1) AND ((octet_length(rule_version) >= 1) AND (octet_length(rule_version) <= 8192)))),
    CONSTRAINT chk_scan_timing_event_ids CHECK ((((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 1024)) AND ((octet_length(project_id) >= 1) AND (octet_length(project_id) <= 1024)) AND ((octet_length(root_task_id) >= 1) AND (octet_length(root_task_id) <= 1024)) AND ((octet_length(batch_id) >= 1) AND (octet_length(batch_id) <= 1024)) AND ((octet_length(attempt_id) >= 1) AND (octet_length(attempt_id) <= 1024)) AND ((octet_length(agent_id) >= 1) AND (octet_length(agent_id) <= 1024)) AND (source_event_id ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chk_scan_timing_event_interval CHECK (((duration_ns >= 0) AND (duration_ns <= '86400000000000'::bigint) AND (finished_at >= started_at) AND ((finished_at - started_at) <= '24:00:00'::interval)))
);

CREATE SEQUENCE public.scan_timing_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.scan_timing_events_id_seq OWNED BY public.scan_timing_events.id;

CREATE TABLE public.scan_work_claims (
    id bigint NOT NULL,
    schema_version character varying(32) NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    network_zone character varying(255) NOT NULL,
    normalized_target text NOT NULL,
    target_hash character varying(64) NOT NULL,
    stage character varying(64) NOT NULL,
    work_key_hash character varying(64) NOT NULL,
    scope_hash character varying(64) NOT NULL,
    config_hash character varying(64) NOT NULL,
    rule_version text NOT NULL,
    poc_set_hash character varying(64) DEFAULT ''::character varying NOT NULL,
    endpoint_content_hash character varying(64) DEFAULT ''::character varying NOT NULL,
    status character varying(32) NOT NULL,
    owner_task_id text DEFAULT ''::text NOT NULL,
    owner_batch_id text DEFAULT ''::text NOT NULL,
    owner_attempt_id text DEFAULT ''::text NOT NULL,
    owner_agent_id text DEFAULT ''::text NOT NULL,
    lease_token_hash character varying(64) DEFAULT ''::character varying NOT NULL,
    lease_expires_at timestamp with time zone,
    claimed_at timestamp with time zone NOT NULL,
    released_at timestamp with time zone,
    revision integer DEFAULT 1 NOT NULL,
    last_error text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.scan_work_claims_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.scan_work_claims_id_seq OWNED BY public.scan_work_claims.id;

CREATE TABLE public.sub_tasks (
    id text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    root_task_id text,
    chunk_targets text,
    status text,
    agent_id text,
    config text,
    stream_msg_id text,
    priority integer DEFAULT 1 NOT NULL,
    agent_selector text,
    timeout_sec integer,
    retry_count integer,
    max_retry integer DEFAULT 3 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    project_id text,
    agent_selector_rules text,
    config_version integer DEFAULT 1 NOT NULL,
    batch_id text DEFAULT ''::text NOT NULL,
    attempt_no integer DEFAULT 1 NOT NULL,
    rule_version text DEFAULT ''::text NOT NULL,
    parent_attempt_id text DEFAULT ''::text NOT NULL,
    trigger text DEFAULT 'initial'::text NOT NULL,
    failure_reason text DEFAULT ''::text NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone
);

CREATE TABLE public.subdomain_dictionaries (
    id character varying(36) NOT NULL,
    tenant_id character varying(128) NOT NULL,
    project_id character varying(255) NOT NULL,
    name character varying(160) NOT NULL,
    created_by character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    deleted_at timestamp with time zone
);

CREATE TABLE public.subdomain_dictionary_revisions (
    id bigint NOT NULL,
    tenant_id character varying(128) NOT NULL,
    project_id character varying(255) NOT NULL,
    dictionary_id character varying(36) NOT NULL,
    revision integer NOT NULL,
    sha256 character varying(64) NOT NULL,
    item_count integer NOT NULL,
    values_json jsonb NOT NULL,
    created_by character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT subdomain_dictionary_revisions_item_count_check CHECK ((item_count > 0)),
    CONSTRAINT subdomain_dictionary_revisions_revision_check CHECK ((revision > 0))
);

CREATE SEQUENCE public.subdomain_dictionary_revisions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.subdomain_dictionary_revisions_id_seq OWNED BY public.subdomain_dictionary_revisions.id;

CREATE TABLE public.system_configs (
    key text NOT NULL,
    value text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.task_append_idempotencies (
    id bigint NOT NULL,
    schema_version character varying(64) NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    root_task_id text NOT NULL,
    operator_id text NOT NULL,
    operation character varying(64) NOT NULL,
    idempotency_key_hash character varying(64) NOT NULL,
    request_hash character varying(64) NOT NULL,
    outcome character varying(16) NOT NULL,
    config_version integer NOT NULL,
    config_hash character varying(64) NOT NULL,
    rule_version text NOT NULL,
    before_status character varying(64) NOT NULL,
    after_status character varying(64) NOT NULL,
    batch_ids jsonb NOT NULL,
    attempt_ids jsonb NOT NULL,
    requested_targets integer NOT NULL,
    new_targets integer NOT NULL,
    duplicate_targets integer NOT NULL,
    project_scope_added integer NOT NULL,
    project_seeds_added integer NOT NULL,
    total_chunks integer NOT NULL,
    total_targets integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_tai_counts CHECK (((config_version > 0) AND (requested_targets >= 0) AND (new_targets >= 0) AND (duplicate_targets >= 0) AND (requested_targets = (new_targets + duplicate_targets)) AND (project_scope_added >= 0) AND (project_seeds_added >= 0) AND (total_chunks >= 0) AND (total_targets >= 0))),
    CONSTRAINT chk_tai_hashes CHECK ((((idempotency_key_hash)::text ~ '^[0-9a-f]{64}$'::text) AND ((request_hash)::text ~ '^[0-9a-f]{64}$'::text) AND ((config_hash)::text ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chk_tai_ids CHECK ((((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 1024)) AND ((octet_length(project_id) >= 1) AND (octet_length(project_id) <= 1024)) AND ((octet_length(root_task_id) >= 1) AND (octet_length(root_task_id) <= 1024)) AND ((octet_length(operator_id) >= 1) AND (octet_length(operator_id) <= 1024)))),
    CONSTRAINT chk_tai_ids_json CHECK (((jsonb_typeof(batch_ids) = 'array'::text) AND (jsonb_typeof(attempt_ids) = 'array'::text))),
    CONSTRAINT chk_tai_outcome CHECK (((outcome)::text = ANY ((ARRAY['appended'::character varying, 'unchanged'::character varying])::text[]))),
    CONSTRAINT chk_tai_outcome_ids CHECK (((((outcome)::text = 'unchanged'::text) AND (new_targets = 0) AND (jsonb_array_length(batch_ids) = 0) AND (jsonb_array_length(attempt_ids) = 0)) OR (((outcome)::text = 'appended'::text) AND (new_targets > 0) AND (jsonb_array_length(batch_ids) > 0) AND (jsonb_array_length(batch_ids) = jsonb_array_length(attempt_ids))))),
    CONSTRAINT chk_tai_schema_operation CHECK ((((octet_length((schema_version)::text) >= 1) AND (octet_length((schema_version)::text) <= 64)) AND ((octet_length((operation)::text) >= 1) AND (octet_length((operation)::text) <= 64)))),
    CONSTRAINT chk_tai_statuses CHECK ((((octet_length((before_status)::text) >= 1) AND (octet_length((before_status)::text) <= 64)) AND ((octet_length((after_status)::text) >= 1) AND (octet_length((after_status)::text) <= 64)) AND ((octet_length(rule_version) >= 1) AND (octet_length(rule_version) <= 1024))))
);

CREATE SEQUENCE public.task_append_idempotencies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.task_append_idempotencies_id_seq OWNED BY public.task_append_idempotencies.id;

CREATE TABLE public.task_audits (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    root_task_id text NOT NULL,
    batch_id text DEFAULT ''::text NOT NULL,
    attempt_id text DEFAULT ''::text NOT NULL,
    operator_id text NOT NULL,
    action text NOT NULL,
    before_status text DEFAULT ''::text NOT NULL,
    after_status text DEFAULT ''::text NOT NULL,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.task_audits_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.task_audits_id_seq OWNED BY public.task_audits.id;

CREATE TABLE public.task_batch_retry_idempotencies (
    id bigint NOT NULL,
    schema_version character varying(64) NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    root_task_id text NOT NULL,
    batch_id text NOT NULL,
    operator_id text NOT NULL,
    operation character varying(64) NOT NULL,
    idempotency_key_hash character varying(64) NOT NULL,
    request_hash character varying(64) NOT NULL,
    attempt_id text NOT NULL,
    attempt_no integer NOT NULL,
    config_version integer NOT NULL,
    config_hash character varying(64) NOT NULL,
    rule_version text NOT NULL,
    before_status character varying(64) NOT NULL,
    after_status character varying(64) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_tbri_hashes CHECK ((((idempotency_key_hash)::text ~ '^[0-9a-f]{64}$'::text) AND ((request_hash)::text ~ '^[0-9a-f]{64}$'::text) AND ((config_hash)::text ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chk_tbri_ids CHECK ((((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 1024)) AND ((octet_length(project_id) >= 1) AND (octet_length(project_id) <= 1024)) AND ((octet_length(root_task_id) >= 1) AND (octet_length(root_task_id) <= 1024)) AND ((octet_length(batch_id) >= 1) AND (octet_length(batch_id) <= 1024)) AND ((octet_length(operator_id) >= 1) AND (octet_length(operator_id) <= 1024)) AND ((octet_length(attempt_id) >= 1) AND (octet_length(attempt_id) <= 1024)))),
    CONSTRAINT chk_tbri_outcome CHECK (((attempt_no >= 1) AND (config_version >= 1) AND ((octet_length(rule_version) >= 1) AND (octet_length(rule_version) <= 1024)) AND ((octet_length((before_status)::text) >= 1) AND (octet_length((before_status)::text) <= 64)) AND ((octet_length((after_status)::text) >= 1) AND (octet_length((after_status)::text) <= 64)))),
    CONSTRAINT chk_tbri_schema_operation CHECK ((((octet_length((schema_version)::text) >= 1) AND (octet_length((schema_version)::text) <= 64)) AND ((octet_length((operation)::text) >= 1) AND (octet_length((operation)::text) <= 64))))
);

CREATE SEQUENCE public.task_batch_retry_idempotencies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.task_batch_retry_idempotencies_id_seq OWNED BY public.task_batch_retry_idempotencies.id;

CREATE TABLE public.task_batches (
    id text NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    root_task_id text NOT NULL,
    sequence integer NOT NULL,
    kind text DEFAULT 'asset_scan'::text NOT NULL,
    target_type text DEFAULT 'legacy'::text NOT NULL,
    targets text DEFAULT '[]'::text NOT NULL,
    target_count integer DEFAULT 0 NOT NULL,
    status text NOT NULL,
    config_version integer DEFAULT 1 NOT NULL,
    rule_version text DEFAULT ''::text NOT NULL,
    priority integer DEFAULT 1 NOT NULL,
    timeout_sec integer DEFAULT 0 NOT NULL,
    agent_selector text DEFAULT '{}'::text NOT NULL,
    agent_selector_rules text DEFAULT '{}'::text NOT NULL,
    current_attempt_no integer DEFAULT 1 NOT NULL,
    attempt_count integer DEFAULT 1 NOT NULL,
    latest_attempt_id text DEFAULT ''::text NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    archived_at timestamp with time zone,
    control_state text DEFAULT 'active'::text NOT NULL
);

CREATE TABLE public.task_config_revisions (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    root_task_id text NOT NULL,
    version integer NOT NULL,
    config text DEFAULT '{}'::text NOT NULL,
    config_hash character varying(64) NOT NULL,
    priority integer DEFAULT 1 NOT NULL,
    timeout_sec integer DEFAULT 0 NOT NULL,
    agent_selector text DEFAULT '{}'::text NOT NULL,
    agent_selector_rules text DEFAULT '{}'::text NOT NULL,
    created_by text DEFAULT ''::text NOT NULL,
    change_note text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.task_config_revisions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.task_config_revisions_id_seq OWNED BY public.task_config_revisions.id;

CREATE TABLE public.task_coverage_links (
    id bigint NOT NULL,
    schema_version character varying(32) NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    root_task_id text NOT NULL,
    batch_id text NOT NULL,
    attempt_id text DEFAULT ''::text NOT NULL,
    work_key_hash character varying(64) NOT NULL,
    link_type character varying(32) NOT NULL,
    status character varying(32) NOT NULL,
    coverage_id bigint DEFAULT 0 NOT NULL,
    claim_id bigint DEFAULT 0 NOT NULL,
    source_task_id text DEFAULT ''::text NOT NULL,
    source_batch_id text DEFAULT ''::text NOT NULL,
    source_attempt_id text DEFAULT ''::text NOT NULL,
    reason text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.task_coverage_links_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.task_coverage_links_id_seq OWNED BY public.task_coverage_links.id;

CREATE TABLE public.task_creation_idempotencies (
    id bigint NOT NULL,
    schema_version character varying(64) NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    operator_id text NOT NULL,
    operation character varying(64) NOT NULL,
    idempotency_key_hash character varying(64) NOT NULL,
    request_hash character varying(64) NOT NULL,
    root_task_id text NOT NULL,
    attempt_ids jsonb NOT NULL,
    project_scope_added integer NOT NULL,
    project_seeds_added integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_tci_attempt_ids CHECK ((jsonb_typeof(attempt_ids) = 'array'::text)),
    CONSTRAINT chk_tci_counts CHECK (((project_scope_added >= 0) AND (project_seeds_added >= 0))),
    CONSTRAINT chk_tci_hashes CHECK ((((idempotency_key_hash)::text ~ '^[0-9a-f]{64}$'::text) AND ((request_hash)::text ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chk_tci_ids CHECK ((((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 1024)) AND ((octet_length(project_id) >= 1) AND (octet_length(project_id) <= 1024)) AND ((octet_length(operator_id) >= 1) AND (octet_length(operator_id) <= 1024)) AND ((octet_length(root_task_id) >= 1) AND (octet_length(root_task_id) <= 1024)))),
    CONSTRAINT chk_tci_operation CHECK (((octet_length((operation)::text) >= 1) AND (octet_length((operation)::text) <= 64))),
    CONSTRAINT chk_tci_schema CHECK (((octet_length((schema_version)::text) >= 1) AND (octet_length((schema_version)::text) <= 64)))
);

CREATE SEQUENCE public.task_creation_idempotencies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.task_creation_idempotencies_id_seq OWNED BY public.task_creation_idempotencies.id;

CREATE TABLE public.task_retry_idempotencies (
    id bigint NOT NULL,
    schema_version character varying(64) NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text NOT NULL,
    root_task_id text NOT NULL,
    operator_id text NOT NULL,
    operation character varying(64) NOT NULL,
    idempotency_key_hash character varying(64) NOT NULL,
    request_hash character varying(64) NOT NULL,
    before_status character varying(64) NOT NULL,
    after_status character varying(64) NOT NULL,
    attempt_ids jsonb NOT NULL,
    completed_skipped integer NOT NULL,
    paused_skipped integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_tri_attempt_ids CHECK (((jsonb_typeof(attempt_ids) = 'array'::text) AND (jsonb_array_length(attempt_ids) >= 1))),
    CONSTRAINT chk_tri_counts CHECK (((completed_skipped >= 0) AND (paused_skipped >= 0))),
    CONSTRAINT chk_tri_hashes CHECK ((((idempotency_key_hash)::text ~ '^[0-9a-f]{64}$'::text) AND ((request_hash)::text ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT chk_tri_ids CHECK ((((octet_length(tenant_id) >= 1) AND (octet_length(tenant_id) <= 1024)) AND ((octet_length(project_id) >= 1) AND (octet_length(project_id) <= 1024)) AND ((octet_length(root_task_id) >= 1) AND (octet_length(root_task_id) <= 1024)) AND ((octet_length(operator_id) >= 1) AND (octet_length(operator_id) <= 1024)))),
    CONSTRAINT chk_tri_schema_operation CHECK ((((octet_length((schema_version)::text) >= 1) AND (octet_length((schema_version)::text) <= 64)) AND ((octet_length((operation)::text) >= 1) AND (octet_length((operation)::text) <= 64)))),
    CONSTRAINT chk_tri_statuses CHECK ((((octet_length((before_status)::text) >= 1) AND (octet_length((before_status)::text) <= 64)) AND ((octet_length((after_status)::text) >= 1) AND (octet_length((after_status)::text) <= 64))))
);

CREATE SEQUENCE public.task_retry_idempotencies_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.task_retry_idempotencies_id_seq OWNED BY public.task_retry_idempotencies.id;

CREATE TABLE public.tenant_quotas (
    tenant_id text DEFAULT 'default'::text NOT NULL,
    max_concurrent_tasks integer DEFAULT 0 NOT NULL,
    max_running_sub_tasks integer DEFAULT 0 NOT NULL,
    daily_task_limit integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone,
    updated_at timestamp with time zone
);

CREATE VIEW public.tenant_quota AS
 SELECT tenant_quotas.tenant_id,
    tenant_quotas.max_concurrent_tasks,
    tenant_quotas.max_running_sub_tasks,
    tenant_quotas.daily_task_limit,
    tenant_quotas.created_at,
    tenant_quotas.updated_at
   FROM public.tenant_quotas;

CREATE TABLE public.users (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    username text,
    password_hash text,
    role text DEFAULT 'viewer'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    exp_authorized boolean DEFAULT false NOT NULL
);

CREATE SEQUENCE public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;

CREATE TABLE public.vulnerabilities (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    task_id text,
    target text,
    plugin text,
    severity text,
    payload text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    project_id text,
    status text DEFAULT 'open'::text NOT NULL,
    assignee text,
    ignore_reason text,
    verify_task_id text,
    request text,
    response text,
    description text,
    reference text,
    matched_at text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    root_task_id text
);

CREATE SEQUENCE public.vulnerabilities_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.vulnerabilities_id_seq OWNED BY public.vulnerabilities.id;

CREATE TABLE public.workflow_product_summaries (
    tenant_id text DEFAULT 'default'::text NOT NULL,
    product_name text NOT NULL,
    is_general_poc boolean DEFAULT false NOT NULL,
    match_types jsonb DEFAULT '[]'::jsonb NOT NULL,
    poc_names jsonb DEFAULT '[]'::jsonb NOT NULL,
    poc_count integer DEFAULT 0 NOT NULL,
    missing_poc_names jsonb DEFAULT '[]'::jsonb NOT NULL,
    missing_poc_count integer DEFAULT 0 NOT NULL,
    fingerprint_bound boolean DEFAULT false NOT NULL,
    fingerprint_rule_count integer DEFAULT 0 NOT NULL,
    state text,
    enabled boolean DEFAULT false NOT NULL,
    content_hash text,
    version integer DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.workflow_rules (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    artifact_id text,
    source_file text,
    product_name text NOT NULL,
    poc_name text NOT NULL,
    match_type text NOT NULL,
    content_hash text,
    version integer DEFAULT 1 NOT NULL,
    state text,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.workflow_rules_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.workflow_rules_id_seq OWNED BY public.workflow_rules.id;

CREATE TABLE public.ws_event_logs (
    id bigint NOT NULL,
    tenant_id text DEFAULT 'default'::text NOT NULL,
    project_id text,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    occurred_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE SEQUENCE public.ws_event_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.ws_event_logs_id_seq OWNED BY public.ws_event_logs.id;

ALTER TABLE ONLY public.active_fingerprint_rules ALTER COLUMN id SET DEFAULT nextval('public.active_fingerprint_rules_id_seq'::regclass);

ALTER TABLE ONLY public.agent_log_alert_events ALTER COLUMN id SET DEFAULT nextval('public.agent_log_alert_events_id_seq'::regclass);

ALTER TABLE ONLY public.agent_log_alert_rules ALTER COLUMN id SET DEFAULT nextval('public.agent_log_alert_rules_id_seq'::regclass);

ALTER TABLE ONLY public.agent_log_archives ALTER COLUMN id SET DEFAULT nextval('public.agent_log_archives_id_seq'::regclass);

ALTER TABLE ONLY public.agent_logs ALTER COLUMN id SET DEFAULT nextval('public.agent_logs_id_seq'::regclass);

ALTER TABLE ONLY public.agent_session_audits ALTER COLUMN id SET DEFAULT nextval('public.agent_session_audits_id_seq'::regclass);

ALTER TABLE ONLY public.ai_tool_invocations ALTER COLUMN id SET DEFAULT nextval('public.ai_tool_invocations_id_seq'::regclass);

ALTER TABLE ONLY public.arsenal_ai_reviews ALTER COLUMN id SET DEFAULT nextval('public.arsenal_ai_reviews_id_seq'::regclass);

ALTER TABLE ONLY public.arsenal_events ALTER COLUMN id SET DEFAULT nextval('public.arsenal_events_id_seq'::regclass);

ALTER TABLE ONLY public.asset_change_logs ALTER COLUMN id SET DEFAULT nextval('public.asset_change_logs_id_seq'::regclass);

ALTER TABLE ONLY public.asset_discovery_audits ALTER COLUMN id SET DEFAULT nextval('public.asset_discovery_audits_id_seq'::regclass);

ALTER TABLE ONLY public.asset_discovery_notebook_distribution_intent_items ALTER COLUMN id SET DEFAULT nextval('public.asset_discovery_notebook_distribution_intent_items_id_seq'::regclass);

ALTER TABLE ONLY public.asset_discovery_notebook_distribution_intents ALTER COLUMN id SET DEFAULT nextval('public.asset_discovery_notebook_distribution_intents_id_seq'::regclass);

ALTER TABLE ONLY public.asset_discovery_notebook_distribution_materializations ALTER COLUMN id SET DEFAULT nextval('public.asset_discovery_notebook_distribution_materializations_id_seq'::regclass);

ALTER TABLE ONLY public.asset_discovery_notebook_item_tags ALTER COLUMN id SET DEFAULT nextval('public.asset_discovery_notebook_item_tags_id_seq'::regclass);

ALTER TABLE ONLY public.asset_discovery_notebook_items ALTER COLUMN id SET DEFAULT nextval('public.asset_discovery_notebook_items_id_seq'::regclass);

ALTER TABLE ONLY public.asset_discovery_notebook_sources ALTER COLUMN id SET DEFAULT nextval('public.asset_discovery_notebook_sources_id_seq'::regclass);

ALTER TABLE ONLY public.asset_discovery_notebook_tags ALTER COLUMN id SET DEFAULT nextval('public.asset_discovery_notebook_tags_id_seq'::regclass);

ALTER TABLE ONLY public.asset_discovery_snapshot_items ALTER COLUMN id SET DEFAULT nextval('public.asset_discovery_snapshot_items_id_seq'::regclass);

ALTER TABLE ONLY public.asset_discovery_snapshots ALTER COLUMN id SET DEFAULT nextval('public.asset_discovery_snapshots_id_seq'::regclass);

ALTER TABLE ONLY public.assets ALTER COLUMN id SET DEFAULT nextval('public.assets_id_seq'::regclass);

ALTER TABLE ONLY public.build_jobs ALTER COLUMN id SET DEFAULT nextval('public.build_jobs_id_seq'::regclass);

ALTER TABLE ONLY public.cloud_account_bindings ALTER COLUMN id SET DEFAULT nextval('public.cloud_account_bindings_id_seq'::regclass);

ALTER TABLE ONLY public.credential_dictionary_revisions ALTER COLUMN id SET DEFAULT nextval('public.credential_dictionary_revisions_id_seq'::regclass);

ALTER TABLE ONLY public.credential_reveal_audits ALTER COLUMN id SET DEFAULT nextval('public.credential_reveal_audits_id_seq'::regclass);

ALTER TABLE ONLY public.custom_roles ALTER COLUMN id SET DEFAULT nextval('public.custom_roles_id_seq'::regclass);

ALTER TABLE ONLY public.dir_rules ALTER COLUMN id SET DEFAULT nextval('public.dir_rules_id_seq'::regclass);

ALTER TABLE ONLY public.domains ALTER COLUMN id SET DEFAULT nextval('public.domains_id_seq'::regclass);

ALTER TABLE ONLY public.exp_asset_refs ALTER COLUMN id SET DEFAULT nextval('public.exp_asset_refs_id_seq'::regclass);

ALTER TABLE ONLY public.exp_assets ALTER COLUMN id SET DEFAULT nextval('public.exp_assets_id_seq'::regclass);

ALTER TABLE ONLY public.exp_audits ALTER COLUMN id SET DEFAULT nextval('public.exp_audits_id_seq'::regclass);

ALTER TABLE ONLY public.exp_dependencies ALTER COLUMN id SET DEFAULT nextval('public.exp_dependencies_id_seq'::regclass);

ALTER TABLE ONLY public.exp_egress_audits ALTER COLUMN id SET DEFAULT nextval('public.exp_egress_audits_id_seq'::regclass);

ALTER TABLE ONLY public.exp_revisions ALTER COLUMN id SET DEFAULT nextval('public.exp_revisions_id_seq'::regclass);

ALTER TABLE ONLY public.exp_risk_waivers ALTER COLUMN id SET DEFAULT nextval('public.exp_risk_waivers_id_seq'::regclass);

ALTER TABLE ONLY public.fingerprint_hits ALTER COLUMN id SET DEFAULT nextval('public.fingerprint_hits_id_seq'::regclass);

ALTER TABLE ONLY public.fingerprint_rules ALTER COLUMN id SET DEFAULT nextval('public.fingerprint_rules_id_seq'::regclass);

ALTER TABLE ONLY public.notification_rules ALTER COLUMN id SET DEFAULT nextval('public.notification_rules_id_seq'::regclass);

ALTER TABLE ONLY public.poc_rules ALTER COLUMN id SET DEFAULT nextval('public.poc_rules_id_seq'::regclass);

ALTER TABLE ONLY public.risk_validation_execution_idempotencies ALTER COLUMN id SET DEFAULT nextval('public.risk_validation_execution_idempotencies_id_seq'::regclass);

ALTER TABLE ONLY public.scan_coverages ALTER COLUMN id SET DEFAULT nextval('public.scan_coverages_id_seq'::regclass);

ALTER TABLE ONLY public.scan_observations ALTER COLUMN id SET DEFAULT nextval('public.scan_observations_id_seq'::regclass);

ALTER TABLE ONLY public.scan_policy_intents ALTER COLUMN id SET DEFAULT nextval('public.scan_policy_intents_id_seq'::regclass);

ALTER TABLE ONLY public.scan_stage_derivations ALTER COLUMN id SET DEFAULT nextval('public.scan_stage_derivations_id_seq'::regclass);

ALTER TABLE ONLY public.scan_timing_events ALTER COLUMN id SET DEFAULT nextval('public.scan_timing_events_id_seq'::regclass);

ALTER TABLE ONLY public.scan_work_claims ALTER COLUMN id SET DEFAULT nextval('public.scan_work_claims_id_seq'::regclass);

ALTER TABLE ONLY public.subdomain_dictionary_revisions ALTER COLUMN id SET DEFAULT nextval('public.subdomain_dictionary_revisions_id_seq'::regclass);

ALTER TABLE ONLY public.task_append_idempotencies ALTER COLUMN id SET DEFAULT nextval('public.task_append_idempotencies_id_seq'::regclass);

ALTER TABLE ONLY public.task_audits ALTER COLUMN id SET DEFAULT nextval('public.task_audits_id_seq'::regclass);

ALTER TABLE ONLY public.task_batch_retry_idempotencies ALTER COLUMN id SET DEFAULT nextval('public.task_batch_retry_idempotencies_id_seq'::regclass);

ALTER TABLE ONLY public.task_config_revisions ALTER COLUMN id SET DEFAULT nextval('public.task_config_revisions_id_seq'::regclass);

ALTER TABLE ONLY public.task_coverage_links ALTER COLUMN id SET DEFAULT nextval('public.task_coverage_links_id_seq'::regclass);

ALTER TABLE ONLY public.task_creation_idempotencies ALTER COLUMN id SET DEFAULT nextval('public.task_creation_idempotencies_id_seq'::regclass);

ALTER TABLE ONLY public.task_retry_idempotencies ALTER COLUMN id SET DEFAULT nextval('public.task_retry_idempotencies_id_seq'::regclass);

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);

ALTER TABLE ONLY public.vulnerabilities ALTER COLUMN id SET DEFAULT nextval('public.vulnerabilities_id_seq'::regclass);

ALTER TABLE ONLY public.workflow_rules ALTER COLUMN id SET DEFAULT nextval('public.workflow_rules_id_seq'::regclass);

ALTER TABLE ONLY public.ws_event_logs ALTER COLUMN id SET DEFAULT nextval('public.ws_event_logs_id_seq'::regclass);

ALTER TABLE ONLY public.active_fingerprint_rules
    ADD CONSTRAINT active_fingerprint_rules_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.agent_log_alert_events
    ADD CONSTRAINT agent_log_alert_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.agent_log_alert_rules
    ADD CONSTRAINT agent_log_alert_rules_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.agent_log_archives
    ADD CONSTRAINT agent_log_archives_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.agent_logs
    ADD CONSTRAINT agent_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.agent_session_audits
    ADD CONSTRAINT agent_session_audits_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.ai_tool_invocations
    ADD CONSTRAINT ai_tool_invocations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.arsenal_ai_reviews
    ADD CONSTRAINT arsenal_ai_reviews_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.arsenal_events
    ADD CONSTRAINT arsenal_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.arsenals
    ADD CONSTRAINT arsenals_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.asset_change_logs
    ADD CONSTRAINT asset_change_logs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.asset_discovery_audits
    ADD CONSTRAINT asset_discovery_audits_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.asset_discovery_notebook_distribution_intent_items
    ADD CONSTRAINT asset_discovery_notebook_distribution_intent_items_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.asset_discovery_notebook_distribution_intents
    ADD CONSTRAINT asset_discovery_notebook_distribution_intents_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.asset_discovery_notebook_distribution_materializations
    ADD CONSTRAINT asset_discovery_notebook_distribution_materializations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.asset_discovery_notebook_item_tags
    ADD CONSTRAINT asset_discovery_notebook_item_tags_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.asset_discovery_notebook_items
    ADD CONSTRAINT asset_discovery_notebook_items_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.asset_discovery_notebook_sources
    ADD CONSTRAINT asset_discovery_notebook_sources_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.asset_discovery_notebook_tags
    ADD CONSTRAINT asset_discovery_notebook_tags_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.asset_discovery_snapshot_items
    ADD CONSTRAINT asset_discovery_snapshot_items_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.asset_discovery_snapshots
    ADD CONSTRAINT asset_discovery_snapshots_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.build_jobs
    ADD CONSTRAINT build_jobs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloud_account_bindings
    ADD CONSTRAINT cloud_account_bindings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloud_accounts
    ADD CONSTRAINT cloud_accounts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloud_instances
    ADD CONSTRAINT cloud_instances_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloud_scaling_policies
    ADD CONSTRAINT cloud_scaling_policies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.credential_bundles
    ADD CONSTRAINT credential_bundles_pkey PRIMARY KEY (ref);

ALTER TABLE ONLY public.credential_dictionaries
    ADD CONSTRAINT credential_dictionaries_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.credential_dictionary_revisions
    ADD CONSTRAINT credential_dictionary_revisions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.credential_finding_secrets
    ADD CONSTRAINT credential_finding_secrets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.credential_reveal_audits
    ADD CONSTRAINT credential_reveal_audits_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cron_tasks
    ADD CONSTRAINT cron_tasks_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.custom_roles
    ADD CONSTRAINT custom_roles_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.dir_rules
    ADD CONSTRAINT dir_rules_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.exp_asset_refs
    ADD CONSTRAINT exp_asset_refs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.exp_assets
    ADD CONSTRAINT exp_assets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.exp_audits
    ADD CONSTRAINT exp_audits_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.exp_dependencies
    ADD CONSTRAINT exp_dependencies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.exp_egress_audits
    ADD CONSTRAINT exp_egress_audits_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.exp_revisions
    ADD CONSTRAINT exp_revisions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.exp_risk_waivers
    ADD CONSTRAINT exp_risk_waivers_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.exp_runs
    ADD CONSTRAINT exp_runs_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.exp_test_cases
    ADD CONSTRAINT exp_test_cases_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.exps
    ADD CONSTRAINT exps_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.fingerprint_hits
    ADD CONSTRAINT fingerprint_hits_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.fingerprint_rules
    ADD CONSTRAINT fingerprint_rules_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.task_batches
    ADD CONSTRAINT idx_task_batches_task_sequence UNIQUE (root_task_id, sequence);

ALTER TABLE ONLY public.task_config_revisions
    ADD CONSTRAINT idx_task_config_revisions_task_version UNIQUE (root_task_id, version);

ALTER TABLE ONLY public.nodes
    ADD CONSTRAINT nodes_pkey PRIMARY KEY (agent_id);

ALTER TABLE ONLY public.notification_rules
    ADD CONSTRAINT notification_rules_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.poc_rules
    ADD CONSTRAINT poc_rules_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.project_members
    ADD CONSTRAINT project_members_pkey PRIMARY KEY (project_id, user_id);

ALTER TABLE ONLY public.projects
    ADD CONSTRAINT projects_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.risk_validation_execution_idempotencies
    ADD CONSTRAINT risk_validation_execution_idempotencies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.root_tasks
    ADD CONSTRAINT root_tasks_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.rule_catalog_bootstraps
    ADD CONSTRAINT rule_catalog_bootstraps_pkey PRIMARY KEY (key);

ALTER TABLE ONLY public.scan_coverages
    ADD CONSTRAINT scan_coverages_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.scan_observations
    ADD CONSTRAINT scan_observations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.scan_policy_intents
    ADD CONSTRAINT scan_policy_intents_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.scan_stage_derivations
    ADD CONSTRAINT scan_stage_derivations_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.scan_timing_events
    ADD CONSTRAINT scan_timing_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.scan_work_claims
    ADD CONSTRAINT scan_work_claims_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sub_tasks
    ADD CONSTRAINT sub_tasks_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.subdomain_dictionaries
    ADD CONSTRAINT subdomain_dictionaries_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.subdomain_dictionary_revisions
    ADD CONSTRAINT subdomain_dictionary_revisions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.system_configs
    ADD CONSTRAINT system_configs_pkey PRIMARY KEY (key);

ALTER TABLE ONLY public.task_append_idempotencies
    ADD CONSTRAINT task_append_idempotencies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.task_audits
    ADD CONSTRAINT task_audits_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.task_batch_retry_idempotencies
    ADD CONSTRAINT task_batch_retry_idempotencies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.task_batches
    ADD CONSTRAINT task_batches_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.task_config_revisions
    ADD CONSTRAINT task_config_revisions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.task_coverage_links
    ADD CONSTRAINT task_coverage_links_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.task_creation_idempotencies
    ADD CONSTRAINT task_creation_idempotencies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.task_retry_idempotencies
    ADD CONSTRAINT task_retry_idempotencies_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.tenant_quotas
    ADD CONSTRAINT tenant_quotas_pkey PRIMARY KEY (tenant_id);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.vulnerabilities
    ADD CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.workflow_product_summaries
    ADD CONSTRAINT workflow_product_summaries_pkey PRIMARY KEY (tenant_id, product_name);

ALTER TABLE ONLY public.workflow_rules
    ADD CONSTRAINT workflow_rules_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.ws_event_logs
    ADD CONSTRAINT ws_event_logs_pkey PRIMARY KEY (id);

CREATE UNIQUE INDEX idx_active_finger_rule_unique ON public.active_fingerprint_rules USING btree (tenant_id, source_file);

CREATE INDEX idx_active_fingerprint_rules_artifact_id ON public.active_fingerprint_rules USING btree (artifact_id);

CREATE INDEX idx_active_fingerprint_rules_auto_eligible ON public.active_fingerprint_rules USING btree (auto_eligible);

CREATE INDEX idx_active_fingerprint_rules_content_hash ON public.active_fingerprint_rules USING btree (content_hash);

CREATE INDEX idx_active_fingerprint_rules_enabled ON public.active_fingerprint_rules USING btree (enabled);

CREATE INDEX idx_active_fingerprint_rules_product_name ON public.active_fingerprint_rules USING btree (product_name);

CREATE INDEX idx_active_fingerprint_rules_state ON public.active_fingerprint_rules USING btree (state);

CREATE INDEX idx_active_fingerprint_rules_tenant_auto ON public.active_fingerprint_rules USING btree (tenant_id, enabled, auto_eligible, source_file);

CREATE UNIQUE INDEX idx_addi_idempotency ON public.asset_discovery_notebook_distribution_intents USING btree (tenant_id, project_id, operator_id, operation, idempotency_key_hash);

CREATE INDEX idx_addi_operator_created ON public.asset_discovery_notebook_distribution_intents USING btree (tenant_id, project_id, operator_id, created_at);

CREATE UNIQUE INDEX idx_addi_scope_id ON public.asset_discovery_notebook_distribution_intents USING btree (tenant_id, project_id, id);

CREATE INDEX idx_addi_status_created ON public.asset_discovery_notebook_distribution_intents USING btree (tenant_id, project_id, status, created_at);

CREATE INDEX idx_addi_task_created ON public.asset_discovery_notebook_distribution_intents USING btree (tenant_id, project_id, root_task_id, created_at);

CREATE UNIQUE INDEX idx_addii_intent_notebook_item ON public.asset_discovery_notebook_distribution_intent_items USING btree (tenant_id, project_id, intent_id, notebook_item_id);

CREATE UNIQUE INDEX idx_addii_intent_position ON public.asset_discovery_notebook_distribution_intent_items USING btree (tenant_id, project_id, intent_id, "position");

CREATE UNIQUE INDEX idx_addii_intent_target_hash ON public.asset_discovery_notebook_distribution_intent_items USING btree (tenant_id, project_id, intent_id, target_hash);

CREATE INDEX idx_addii_notebook_item ON public.asset_discovery_notebook_distribution_intent_items USING btree (tenant_id, project_id, notebook_item_id);

CREATE UNIQUE INDEX idx_addii_scope_id ON public.asset_discovery_notebook_distribution_intent_items USING btree (tenant_id, project_id, id);

CREATE INDEX idx_addii_target_hash ON public.asset_discovery_notebook_distribution_intent_items USING btree (tenant_id, project_id, target_hash);

CREATE UNIQUE INDEX idx_addm_intent ON public.asset_discovery_notebook_distribution_materializations USING btree (tenant_id, project_id, intent_id);

CREATE UNIQUE INDEX idx_addm_scope_id ON public.asset_discovery_notebook_distribution_materializations USING btree (tenant_id, project_id, id);

CREATE INDEX idx_addm_task_created ON public.asset_discovery_notebook_distribution_materializations USING btree (tenant_id, project_id, root_task_id, created_at);

CREATE UNIQUE INDEX idx_adn_item_tag ON public.asset_discovery_notebook_item_tags USING btree (tenant_id, project_id, notebook_item_id, tag_id);

CREATE INDEX idx_adn_items_active_updated ON public.asset_discovery_notebook_items USING btree (tenant_id, project_id, removed_at, updated_at DESC, id DESC);

CREATE UNIQUE INDEX idx_adn_tag ON public.asset_discovery_notebook_tags USING btree (tenant_id, project_id, name);

CREATE UNIQUE INDEX idx_adn_tag_scope ON public.asset_discovery_notebook_tags USING btree (tenant_id, project_id, id);

CREATE INDEX idx_agent_log_alert_events_agent_id ON public.agent_log_alert_events USING btree (agent_id);

CREATE INDEX idx_agent_log_alert_events_created_at ON public.agent_log_alert_events USING btree (created_at);

CREATE INDEX idx_agent_log_alert_events_level ON public.agent_log_alert_events USING btree (level);

CREATE INDEX idx_agent_log_alert_events_log_id ON public.agent_log_alert_events USING btree (log_id);

CREATE INDEX idx_agent_log_alert_events_rule_id ON public.agent_log_alert_events USING btree (rule_id);

CREATE INDEX idx_agent_log_alert_events_tenant_id ON public.agent_log_alert_events USING btree (tenant_id);

CREATE INDEX idx_agent_log_alert_rules_agent_id ON public.agent_log_alert_rules USING btree (agent_id);

CREATE INDEX idx_agent_log_alert_rules_level ON public.agent_log_alert_rules USING btree (level);

CREATE INDEX idx_agent_log_alert_rules_name ON public.agent_log_alert_rules USING btree (name);

CREATE INDEX idx_agent_log_alert_rules_tenant_id ON public.agent_log_alert_rules USING btree (tenant_id);

CREATE INDEX idx_agent_log_archives_day ON public.agent_log_archives USING btree (day);

CREATE INDEX idx_agent_log_archives_status ON public.agent_log_archives USING btree (status);

CREATE INDEX idx_agent_log_archives_tenant_id ON public.agent_log_archives USING btree (tenant_id);

CREATE INDEX idx_agent_logs_agent_id ON public.agent_logs USING btree (agent_id);

CREATE INDEX idx_agent_logs_tenant_id ON public.agent_logs USING btree (tenant_id);

CREATE INDEX idx_agent_logs_timestamp ON public.agent_logs USING btree ("timestamp");

CREATE INDEX idx_agent_session_audits_action ON public.agent_session_audits USING btree (action);

CREATE INDEX idx_agent_session_audits_agent_id ON public.agent_session_audits USING btree (agent_id);

CREATE INDEX idx_agent_session_audits_created_at ON public.agent_session_audits USING btree (created_at);

CREATE INDEX idx_agent_session_audits_operator_id ON public.agent_session_audits USING btree (operator_id);

CREATE INDEX idx_agent_session_audits_tenant_id ON public.agent_session_audits USING btree (tenant_id);

CREATE INDEX idx_ai_tool_invocations_agent_id ON public.ai_tool_invocations USING btree (agent_id);

CREATE INDEX idx_ai_tool_invocations_created_at ON public.ai_tool_invocations USING btree (created_at);

CREATE INDEX idx_ai_tool_invocations_module ON public.ai_tool_invocations USING btree (module);

CREATE INDEX idx_ai_tool_invocations_status ON public.ai_tool_invocations USING btree (status);

CREATE INDEX idx_ai_tool_invocations_tenant_id ON public.ai_tool_invocations USING btree (tenant_id);

CREATE INDEX idx_ai_tool_invocations_tool_name ON public.ai_tool_invocations USING btree (tool_name);

CREATE INDEX idx_ai_tool_invocations_user_id ON public.ai_tool_invocations USING btree (user_id);

CREATE INDEX idx_arsenal_ai_reviews_cache ON public.arsenal_ai_reviews USING btree (tenant_id, type, content_hash, created_at DESC);

CREATE INDEX idx_arsenal_ai_reviews_content_hash ON public.arsenal_ai_reviews USING btree (content_hash);

CREATE INDEX idx_arsenal_ai_reviews_created_by ON public.arsenal_ai_reviews USING btree (created_by);

CREATE INDEX idx_arsenal_ai_reviews_file_name ON public.arsenal_ai_reviews USING btree (file_name);

CREATE INDEX idx_arsenal_ai_reviews_suggestion ON public.arsenal_ai_reviews USING btree (suggestion);

CREATE INDEX idx_arsenal_ai_reviews_tenant_id ON public.arsenal_ai_reviews USING btree (tenant_id);

CREATE INDEX idx_arsenal_ai_reviews_type ON public.arsenal_ai_reviews USING btree (type);

CREATE INDEX idx_arsenal_event_artifact ON public.arsenal_events USING btree (tenant_id, artifact_id, created_at DESC);

CREATE INDEX idx_arsenal_events_action ON public.arsenal_events USING btree (action);

CREATE INDEX idx_arsenal_events_actor_id ON public.arsenal_events USING btree (actor_id);

CREATE INDEX idx_arsenal_events_created_at ON public.arsenal_events USING btree (created_at);

CREATE INDEX idx_arsenal_events_file_name ON public.arsenal_events USING btree (file_name);

CREATE INDEX idx_arsenal_events_hash ON public.arsenal_events USING btree (hash);

CREATE INDEX idx_arsenal_events_state ON public.arsenal_events USING btree (state);

CREATE INDEX idx_arsenal_events_type ON public.arsenal_events USING btree (type);

CREATE INDEX idx_arsenal_events_version ON public.arsenal_events USING btree (version);

CREATE INDEX idx_arsenals_file_name ON public.arsenals USING btree (file_name);

CREATE INDEX idx_arsenals_state ON public.arsenals USING btree (state);

CREATE INDEX idx_arsenals_tenant_id ON public.arsenals USING btree (tenant_id);

CREATE UNIQUE INDEX idx_arsenals_tenant_type_file ON public.arsenals USING btree (tenant_id, type, file_name);

CREATE INDEX idx_arsenals_tenant_type_state_updated ON public.arsenals USING btree (tenant_id, type, state, updated_at DESC, id);

CREATE INDEX idx_arsenals_type ON public.arsenals USING btree (type);

CREATE INDEX idx_asset_change_logs_change_type ON public.asset_change_logs USING btree (change_type);

CREATE INDEX idx_asset_change_logs_entity_id ON public.asset_change_logs USING btree (entity_id);

CREATE INDEX idx_asset_change_logs_entity_type ON public.asset_change_logs USING btree (entity_type);

CREATE INDEX idx_asset_change_logs_project_id ON public.asset_change_logs USING btree (project_id);

CREATE INDEX idx_asset_change_logs_task_id ON public.asset_change_logs USING btree (task_id);

CREATE UNIQUE INDEX idx_asset_dedupe ON public.assets USING btree (project_id, target, protocol);

CREATE INDEX idx_asset_discovery_audits_action ON public.asset_discovery_audits USING btree (action);

CREATE INDEX idx_asset_discovery_audits_created_at ON public.asset_discovery_audits USING btree (created_at);

CREATE INDEX idx_asset_discovery_audits_error_code ON public.asset_discovery_audits USING btree (error_code);

CREATE INDEX idx_asset_discovery_audits_notebook_item_id ON public.asset_discovery_audits USING btree (notebook_item_id);

CREATE INDEX idx_asset_discovery_audits_operator_id ON public.asset_discovery_audits USING btree (operator_id);

CREATE INDEX idx_asset_discovery_audits_project_id ON public.asset_discovery_audits USING btree (project_id);

CREATE INDEX idx_asset_discovery_audits_provider ON public.asset_discovery_audits USING btree (provider);

CREATE INDEX idx_asset_discovery_audits_query_hash ON public.asset_discovery_audits USING btree (query_hash);

CREATE UNIQUE INDEX idx_asset_discovery_audits_scope_id ON public.asset_discovery_audits USING btree (tenant_id, project_id, id);

CREATE INDEX idx_asset_discovery_audits_status ON public.asset_discovery_audits USING btree (status);

CREATE INDEX idx_asset_discovery_audits_tenant_id ON public.asset_discovery_audits USING btree (tenant_id);

CREATE INDEX idx_asset_discovery_notebook_items_created_at ON public.asset_discovery_notebook_items USING btree (created_at);

CREATE INDEX idx_asset_discovery_notebook_items_created_by ON public.asset_discovery_notebook_items USING btree (created_by);

CREATE INDEX idx_asset_discovery_notebook_items_project_id ON public.asset_discovery_notebook_items USING btree (project_id);

CREATE INDEX idx_asset_discovery_notebook_items_removed_at ON public.asset_discovery_notebook_items USING btree (removed_at);

CREATE INDEX idx_asset_discovery_notebook_items_removed_by ON public.asset_discovery_notebook_items USING btree (removed_by);

CREATE UNIQUE INDEX idx_asset_discovery_notebook_items_scope_id ON public.asset_discovery_notebook_items USING btree (tenant_id, project_id, id);

CREATE UNIQUE INDEX idx_asset_discovery_notebook_items_target ON public.asset_discovery_notebook_items USING btree (tenant_id, project_id, target_hash);

CREATE INDEX idx_asset_discovery_notebook_items_tenant_id ON public.asset_discovery_notebook_items USING btree (tenant_id);

CREATE INDEX idx_asset_discovery_notebook_items_updated_at ON public.asset_discovery_notebook_items USING btree (updated_at);

CREATE INDEX idx_asset_discovery_notebook_items_updated_by ON public.asset_discovery_notebook_items USING btree (updated_by);

CREATE INDEX idx_asset_discovery_notebook_sources_archived_at ON public.asset_discovery_notebook_sources USING btree (archived_at);

CREATE INDEX idx_asset_discovery_notebook_sources_archived_by ON public.asset_discovery_notebook_sources USING btree (archived_by);

CREATE INDEX idx_asset_discovery_notebook_sources_audit_id ON public.asset_discovery_notebook_sources USING btree (audit_id);

CREATE INDEX idx_asset_discovery_notebook_sources_notebook_item_id ON public.asset_discovery_notebook_sources USING btree (notebook_item_id);

CREATE INDEX idx_asset_discovery_notebook_sources_project_id ON public.asset_discovery_notebook_sources USING btree (project_id);

CREATE INDEX idx_asset_discovery_notebook_sources_snapshot_id ON public.asset_discovery_notebook_sources USING btree (snapshot_id);

CREATE UNIQUE INDEX idx_asset_discovery_notebook_sources_snapshot_item ON public.asset_discovery_notebook_sources USING btree (tenant_id, project_id, snapshot_id, snapshot_item_id);

CREATE INDEX idx_asset_discovery_notebook_sources_snapshot_item_id ON public.asset_discovery_notebook_sources USING btree (snapshot_item_id);

CREATE INDEX idx_asset_discovery_notebook_sources_tenant_id ON public.asset_discovery_notebook_sources USING btree (tenant_id);

CREATE INDEX idx_asset_discovery_snapshot_items_domain ON public.asset_discovery_snapshot_items USING btree (domain);

CREATE INDEX idx_asset_discovery_snapshot_items_ip ON public.asset_discovery_snapshot_items USING btree (ip);

CREATE INDEX idx_asset_discovery_snapshot_items_observed_at ON public.asset_discovery_snapshot_items USING btree (observed_at);

CREATE INDEX idx_asset_discovery_snapshot_items_project_id ON public.asset_discovery_snapshot_items USING btree (project_id);

CREATE INDEX idx_asset_discovery_snapshot_items_project_snapshot ON public.asset_discovery_snapshot_items USING btree (tenant_id, project_id, snapshot_id, "position");

CREATE INDEX idx_asset_discovery_snapshot_items_protocol ON public.asset_discovery_snapshot_items USING btree (protocol);

CREATE UNIQUE INDEX idx_asset_discovery_snapshot_items_scope_id ON public.asset_discovery_snapshot_items USING btree (tenant_id, project_id, snapshot_id, id);

CREATE INDEX idx_asset_discovery_snapshot_items_snapshot_id ON public.asset_discovery_snapshot_items USING btree (snapshot_id);

CREATE INDEX idx_asset_discovery_snapshot_items_source ON public.asset_discovery_snapshot_items USING btree (source);

CREATE UNIQUE INDEX idx_asset_discovery_snapshot_items_target ON public.asset_discovery_snapshot_items USING btree (snapshot_id, target_hash);

CREATE INDEX idx_asset_discovery_snapshot_items_tenant_id ON public.asset_discovery_snapshot_items USING btree (tenant_id);

CREATE UNIQUE INDEX idx_asset_discovery_snapshots_audit_id ON public.asset_discovery_snapshots USING btree (audit_id);

CREATE INDEX idx_asset_discovery_snapshots_created_at ON public.asset_discovery_snapshots USING btree (created_at);

CREATE INDEX idx_asset_discovery_snapshots_created_by ON public.asset_discovery_snapshots USING btree (created_by);

CREATE INDEX idx_asset_discovery_snapshots_project_created ON public.asset_discovery_snapshots USING btree (tenant_id, project_id, created_at DESC);

CREATE INDEX idx_asset_discovery_snapshots_project_id ON public.asset_discovery_snapshots USING btree (project_id);

CREATE INDEX idx_asset_discovery_snapshots_provider ON public.asset_discovery_snapshots USING btree (provider);

CREATE INDEX idx_asset_discovery_snapshots_query_hash ON public.asset_discovery_snapshots USING btree (query_hash);

CREATE UNIQUE INDEX idx_asset_discovery_snapshots_scope_id ON public.asset_discovery_snapshots USING btree (tenant_id, project_id, id);

CREATE INDEX idx_asset_discovery_snapshots_tenant_id ON public.asset_discovery_snapshots USING btree (tenant_id);

CREATE INDEX idx_assets_cred_id ON public.assets USING btree (cred_id);

CREATE INDEX idx_assets_owner_id ON public.assets USING btree (owner_id);

CREATE INDEX idx_assets_root_task_id ON public.assets USING btree (root_task_id);

CREATE INDEX idx_assets_status ON public.assets USING btree (status);

CREATE INDEX idx_assets_task_id ON public.assets USING btree (task_id);

CREATE INDEX idx_assets_tenant_id ON public.assets USING btree (tenant_id);

CREATE INDEX idx_build_jobs_arch ON public.build_jobs USING btree (arch);

CREATE INDEX idx_build_jobs_platform ON public.build_jobs USING btree (platform);

CREATE INDEX idx_build_jobs_status ON public.build_jobs USING btree (status);

CREATE UNIQUE INDEX idx_cloud_account_binding_unique ON public.cloud_account_bindings USING btree (tenant_id, cloud_account_id, user_id);

CREATE INDEX idx_cloud_account_bindings_cloud_account_id ON public.cloud_account_bindings USING btree (cloud_account_id);

CREATE INDEX idx_cloud_account_bindings_tenant_id ON public.cloud_account_bindings USING btree (tenant_id);

CREATE INDEX idx_cloud_account_bindings_user_id ON public.cloud_account_bindings USING btree (user_id);

CREATE INDEX idx_cloud_accounts_owner_user_id ON public.cloud_accounts USING btree (owner_user_id);

CREATE INDEX idx_cloud_accounts_provider ON public.cloud_accounts USING btree (provider);

CREATE INDEX idx_cloud_accounts_status ON public.cloud_accounts USING btree (status);

CREATE INDEX idx_cloud_accounts_tenant ON public.cloud_accounts USING btree (tenant_id);

CREATE INDEX idx_cloud_instances_account ON public.cloud_instances USING btree (cloud_account_id);

CREATE INDEX idx_cloud_instances_agent ON public.cloud_instances USING btree (agent_id);

CREATE INDEX idx_cloud_instances_deleted ON public.cloud_instances USING btree (deleted_at);

CREATE INDEX idx_cloud_instances_policy ON public.cloud_instances USING btree (policy_id);

CREATE INDEX idx_cloud_instances_provider_id ON public.cloud_instances USING btree (provider_instance_id);

CREATE INDEX idx_cloud_instances_status ON public.cloud_instances USING btree (status);

CREATE INDEX idx_cloud_instances_tenant ON public.cloud_instances USING btree (tenant_id);

CREATE INDEX idx_cloud_policies_account ON public.cloud_scaling_policies USING btree (cloud_account_id);

CREATE INDEX idx_cloud_policies_enabled ON public.cloud_scaling_policies USING btree (enabled);

CREATE INDEX idx_cloud_policies_tenant ON public.cloud_scaling_policies USING btree (tenant_id);

CREATE INDEX idx_credential_bundles_attempt_id ON public.credential_bundles USING btree (attempt_id);

CREATE INDEX idx_credential_bundles_expires_at ON public.credential_bundles USING btree (expires_at);

CREATE INDEX idx_credential_dictionaries_project_id ON public.credential_dictionaries USING btree (project_id);

CREATE UNIQUE INDEX idx_credential_dictionary_name ON public.credential_dictionaries USING btree (tenant_id, project_id, kind, name) WHERE (deleted_at IS NULL);

CREATE UNIQUE INDEX idx_credential_dictionary_revision ON public.credential_dictionary_revisions USING btree (dictionary_id, revision);

CREATE INDEX idx_credential_dictionary_revisions_tenant_id ON public.credential_dictionary_revisions USING btree (tenant_id);

CREATE INDEX idx_credential_finding_secrets_root_task_id ON public.credential_finding_secrets USING btree (root_task_id);

CREATE INDEX idx_credential_finding_secrets_tenant_id ON public.credential_finding_secrets USING btree (tenant_id);

CREATE INDEX idx_credential_reveal_audits_finding_id ON public.credential_reveal_audits USING btree (finding_id);

CREATE INDEX idx_credential_reveal_audits_tenant_id ON public.credential_reveal_audits USING btree (tenant_id);

CREATE INDEX idx_credentials_deleted_at ON public.credentials USING btree (deleted_at);

CREATE INDEX idx_credentials_project_id ON public.credentials USING btree (project_id);

CREATE INDEX idx_credentials_type ON public.credentials USING btree (type);

CREATE INDEX idx_cron_tasks_cron_expr ON public.cron_tasks USING btree (cron_expr);

CREATE INDEX idx_cron_tasks_deleted_at ON public.cron_tasks USING btree (deleted_at);

CREATE INDEX idx_cron_tasks_next_run_at ON public.cron_tasks USING btree (next_run_at);

CREATE INDEX idx_cron_tasks_project_id ON public.cron_tasks USING btree (project_id);

CREATE INDEX idx_cron_tasks_status ON public.cron_tasks USING btree (status);

CREATE INDEX idx_custom_roles_base_role ON public.custom_roles USING btree (base_role);

CREATE UNIQUE INDEX idx_custom_roles_tenant_name ON public.custom_roles USING btree (tenant_id, name);

CREATE UNIQUE INDEX idx_dir_rule_unique ON public.dir_rules USING btree (tenant_id, path, product_name);

CREATE INDEX idx_dir_rules_artifact_id ON public.dir_rules USING btree (artifact_id);

CREATE INDEX idx_dir_rules_content_hash ON public.dir_rules USING btree (content_hash);

CREATE INDEX idx_dir_rules_enabled ON public.dir_rules USING btree (enabled);

CREATE INDEX idx_dir_rules_path ON public.dir_rules USING btree (path);

CREATE INDEX idx_dir_rules_product_name ON public.dir_rules USING btree (product_name);

CREATE INDEX idx_dir_rules_source_file ON public.dir_rules USING btree (source_file);

CREATE INDEX idx_dir_rules_state ON public.dir_rules USING btree (state);

CREATE INDEX idx_dir_rules_tenant_id ON public.dir_rules USING btree (tenant_id);

CREATE UNIQUE INDEX idx_domain_dedupe ON public.domains USING btree (tenant_id, project_id, name);

CREATE INDEX idx_domains_status ON public.domains USING btree (status);

CREATE INDEX idx_domains_task_id ON public.domains USING btree (task_id);

CREATE UNIQUE INDEX idx_exp_asset_identity ON public.exp_assets USING btree (tenant_id, asset_id, version);

CREATE UNIQUE INDEX idx_exp_asset_ref ON public.exp_asset_refs USING btree (exp_id, revision, asset_id);

CREATE INDEX idx_exp_asset_refs_tenant_id ON public.exp_asset_refs USING btree (tenant_id);

CREATE INDEX idx_exp_assets_sha256 ON public.exp_assets USING btree (sha256);

CREATE INDEX idx_exp_assets_tenant_id ON public.exp_assets USING btree (tenant_id);

CREATE INDEX idx_exp_audits_action ON public.exp_audits USING btree (action);

CREATE INDEX idx_exp_audits_actor_id ON public.exp_audits USING btree (actor_id);

CREATE INDEX idx_exp_audits_exp_id ON public.exp_audits USING btree (exp_id);

CREATE INDEX idx_exp_audits_tenant_id ON public.exp_audits USING btree (tenant_id);

CREATE INDEX idx_exp_dependencies_tenant_id ON public.exp_dependencies USING btree (tenant_id);

CREATE UNIQUE INDEX idx_exp_dependency ON public.exp_dependencies USING btree (parent_exp_id, parent_revision, dependency_exp_id, dependency_revision);

CREATE INDEX idx_exp_egress_audits_agent_id ON public.exp_egress_audits USING btree (agent_id);

CREATE INDEX idx_exp_egress_audits_error_code ON public.exp_egress_audits USING btree (error_code);

CREATE INDEX idx_exp_egress_audits_expires_at ON public.exp_egress_audits USING btree (expires_at);

CREATE INDEX idx_exp_egress_audits_finished_at ON public.exp_egress_audits USING btree (finished_at);

CREATE INDEX idx_exp_egress_audits_issued_at ON public.exp_egress_audits USING btree (issued_at);

CREATE INDEX idx_exp_egress_audits_operator_id ON public.exp_egress_audits USING btree (operator_id);

CREATE UNIQUE INDEX idx_exp_egress_audits_route_id ON public.exp_egress_audits USING btree (route_id);

CREATE INDEX idx_exp_egress_audits_status ON public.exp_egress_audits USING btree (status);

CREATE INDEX idx_exp_egress_audits_tenant_id ON public.exp_egress_audits USING btree (tenant_id);

CREATE UNIQUE INDEX idx_exp_revision ON public.exp_revisions USING btree (exp_id, revision);

CREATE INDEX idx_exp_revisions_source_sha256 ON public.exp_revisions USING btree (source_sha256);

CREATE INDEX idx_exp_revisions_tenant_id ON public.exp_revisions USING btree (tenant_id);

CREATE UNIQUE INDEX idx_exp_risk_waiver ON public.exp_risk_waivers USING btree (tenant_id, exp_id);

CREATE INDEX idx_exp_runs_artifact_expires_at ON public.exp_runs USING btree (artifact_expires_at);

CREATE INDEX idx_exp_runs_exp_id ON public.exp_runs USING btree (exp_id);

CREATE INDEX idx_exp_runs_status ON public.exp_runs USING btree (status);

CREATE INDEX idx_exp_runs_tenant_id ON public.exp_runs USING btree (tenant_id);

CREATE INDEX idx_exp_test_case_revision ON public.exp_test_cases USING btree (exp_id, revision);

CREATE INDEX idx_exp_test_cases_tenant_id ON public.exp_test_cases USING btree (tenant_id);

CREATE INDEX idx_exps_parent_exp_id ON public.exps USING btree (parent_exp_id);

CREATE UNIQUE INDEX idx_exps_parent_variant ON public.exps USING btree (parent_exp_id, variant_key) WHERE (parent_exp_id IS NOT NULL);

CREATE INDEX idx_exps_status ON public.exps USING btree (status);

CREATE INDEX idx_exps_tenant_id ON public.exps USING btree (tenant_id);

CREATE UNIQUE INDEX idx_exps_tenant_id_id ON public.exps USING btree (tenant_id, id);

CREATE UNIQUE INDEX idx_exps_tenant_name ON public.exps USING btree (tenant_id, name);

CREATE INDEX idx_exps_tenant_product ON public.exps USING btree (tenant_id, product_name);

CREATE INDEX idx_fingerprint_hits_root_task_id ON public.fingerprint_hits USING btree (root_task_id);

CREATE INDEX idx_fingerprint_hits_task_id ON public.fingerprint_hits USING btree (task_id);

CREATE INDEX idx_fingerprint_hits_tenant_id ON public.fingerprint_hits USING btree (tenant_id);

CREATE INDEX idx_fingerprint_rules_artifact_id ON public.fingerprint_rules USING btree (artifact_id);

CREATE INDEX idx_fingerprint_rules_category ON public.fingerprint_rules USING btree (category);

CREATE INDEX idx_fingerprint_rules_content_hash ON public.fingerprint_rules USING btree (content_hash);

CREATE INDEX idx_fingerprint_rules_enabled ON public.fingerprint_rules USING btree (enabled);

CREATE INDEX idx_fingerprint_rules_product_name ON public.fingerprint_rules USING btree (product_name);

CREATE INDEX idx_fingerprint_rules_product_trgm ON public.fingerprint_rules USING gin (product_name public.gin_trgm_ops);

CREATE INDEX idx_fingerprint_rules_source_file ON public.fingerprint_rules USING btree (source_file);

CREATE INDEX idx_fingerprint_rules_state ON public.fingerprint_rules USING btree (state);

CREATE INDEX idx_fingerprint_rules_tenant_enabled_product ON public.fingerprint_rules USING btree (tenant_id, enabled, product_name);

CREATE INDEX idx_fingerprint_rules_tenant_id ON public.fingerprint_rules USING btree (tenant_id);

CREATE INDEX idx_fingerprint_rules_tenant_state_product ON public.fingerprint_rules USING btree (tenant_id, state, product_name);

CREATE UNIQUE INDEX idx_fp_dedupe ON public.fingerprint_hits USING btree (project_id, target, product_name);

CREATE UNIQUE INDEX idx_fp_rule_unique ON public.fingerprint_rules USING btree (tenant_id, product_name, rule_expr);

CREATE INDEX idx_nodes_tenant_id ON public.nodes USING btree (tenant_id);

CREATE INDEX idx_notification_rules_event ON public.notification_rules USING btree (event);

CREATE INDEX idx_notification_rules_project_id ON public.notification_rules USING btree (project_id);

CREATE UNIQUE INDEX idx_poc_rule_unique ON public.poc_rules USING btree (tenant_id, source_file);

CREATE INDEX idx_poc_rules_artifact_id ON public.poc_rules USING btree (artifact_id);

CREATE INDEX idx_poc_rules_compatibility_status ON public.poc_rules USING btree (compatibility_status);

CREATE INDEX idx_poc_rules_content_hash ON public.poc_rules USING btree (content_hash);

CREATE INDEX idx_poc_rules_cve ON public.poc_rules USING btree (cve);

CREATE INDEX idx_poc_rules_cve_trgm ON public.poc_rules USING gin (cve public.gin_trgm_ops);

CREATE INDEX idx_poc_rules_enabled ON public.poc_rules USING btree (enabled);

CREATE INDEX idx_poc_rules_execution_class ON public.poc_rules USING btree (execution_class);

CREATE INDEX idx_poc_rules_name ON public.poc_rules USING btree (name);

CREATE INDEX idx_poc_rules_name_trgm ON public.poc_rules USING gin (name public.gin_trgm_ops);

CREATE INDEX idx_poc_rules_risk_level ON public.poc_rules USING btree (risk_level);

CREATE INDEX idx_poc_rules_severity ON public.poc_rules USING btree (severity);

CREATE INDEX idx_poc_rules_source_file ON public.poc_rules USING btree (source_file);

CREATE INDEX idx_poc_rules_source_file_trgm ON public.poc_rules USING gin (source_file public.gin_trgm_ops);

CREATE INDEX idx_poc_rules_state ON public.poc_rules USING btree (state);

CREATE INDEX idx_poc_rules_tags_trgm ON public.poc_rules USING gin (tags public.gin_trgm_ops);

CREATE INDEX idx_poc_rules_target_product ON public.poc_rules USING btree (target_product);

CREATE INDEX idx_poc_rules_target_product_trgm ON public.poc_rules USING gin (target_product public.gin_trgm_ops);

CREATE INDEX idx_poc_rules_tenant_compat_updated ON public.poc_rules USING btree (tenant_id, compatibility_status, updated_at DESC, id DESC);

CREATE INDEX idx_poc_rules_tenant_enabled_updated ON public.poc_rules USING btree (tenant_id, enabled, updated_at DESC, id DESC);

CREATE INDEX idx_poc_rules_tenant_id ON public.poc_rules USING btree (tenant_id);

CREATE INDEX idx_poc_rules_tenant_severity_updated ON public.poc_rules USING btree (tenant_id, severity, updated_at DESC, id DESC);

CREATE INDEX idx_project_members_tenant_project ON public.project_members USING btree (tenant_id, project_id);

CREATE INDEX idx_project_members_tenant_user ON public.project_members USING btree (tenant_id, user_id);

CREATE INDEX idx_projects_deleted_at ON public.projects USING btree (deleted_at);

CREATE INDEX idx_projects_name ON public.projects USING btree (name);

CREATE INDEX idx_projects_owner_user_id ON public.projects USING btree (owner_user_id);

CREATE UNIQUE INDEX idx_projects_scope_id ON public.projects USING btree (tenant_id, id);

CREATE INDEX idx_projects_status ON public.projects USING btree (status);

CREATE INDEX idx_projects_tenant_id ON public.projects USING btree (tenant_id);

CREATE INDEX idx_reports_created_by ON public.reports USING btree (created_by);

CREATE INDEX idx_reports_project_id ON public.reports USING btree (project_id);

CREATE INDEX idx_reports_type ON public.reports USING btree (type);

CREATE INDEX idx_root_tasks_archived_at ON public.root_tasks USING btree (archived_at);

CREATE INDEX idx_root_tasks_cron_task_id ON public.root_tasks USING btree (cron_task_id);

CREATE INDEX idx_root_tasks_project_id ON public.root_tasks USING btree (project_id);

CREATE UNIQUE INDEX idx_root_tasks_scope_id ON public.root_tasks USING btree (tenant_id, project_id, id);

CREATE INDEX idx_root_tasks_status ON public.root_tasks USING btree (status);

CREATE INDEX idx_root_tasks_tenant_id ON public.root_tasks USING btree (tenant_id);

CREATE INDEX idx_root_tasks_user_id ON public.root_tasks USING btree (user_id);

CREATE INDEX idx_rule_catalog_bootstraps_aggregate_hash ON public.rule_catalog_bootstraps USING btree (aggregate_hash);

CREATE INDEX idx_rule_catalog_bootstraps_status ON public.rule_catalog_bootstraps USING btree (status);

CREATE UNIQUE INDEX idx_rvei_idempotency ON public.risk_validation_execution_idempotencies USING btree (tenant_id, project_id, root_task_id, operator_id, operation, idempotency_key_hash);

CREATE INDEX idx_rvei_operator_created ON public.risk_validation_execution_idempotencies USING btree (tenant_id, project_id, operator_id, created_at);

CREATE UNIQUE INDEX idx_rvei_scope_id ON public.risk_validation_execution_idempotencies USING btree (tenant_id, project_id, root_task_id, id);

CREATE INDEX idx_rvei_task_created ON public.risk_validation_execution_idempotencies USING btree (tenant_id, project_id, root_task_id, created_at);

CREATE INDEX idx_scan_coverages_finished_at ON public.scan_coverages USING btree (finished_at);

CREATE INDEX idx_scan_coverages_lookup ON public.scan_coverages USING btree (tenant_id, project_id, network_zone, target_hash, stage);

CREATE INDEX idx_scan_coverages_outcome ON public.scan_coverages USING btree (outcome);

CREATE INDEX idx_scan_coverages_project_id ON public.scan_coverages USING btree (project_id);

CREATE INDEX idx_scan_coverages_rule_version ON public.scan_coverages USING btree (rule_version);

CREATE INDEX idx_scan_coverages_source_attempt_id ON public.scan_coverages USING btree (source_attempt_id);

CREATE INDEX idx_scan_coverages_source_batch_id ON public.scan_coverages USING btree (source_batch_id);

CREATE INDEX idx_scan_coverages_source_observation_id ON public.scan_coverages USING btree (source_observation_id);

CREATE INDEX idx_scan_coverages_source_task_id ON public.scan_coverages USING btree (source_task_id);

CREATE INDEX idx_scan_coverages_stage ON public.scan_coverages USING btree (stage);

CREATE INDEX idx_scan_coverages_status ON public.scan_coverages USING btree (status);

CREATE INDEX idx_scan_coverages_tenant_id ON public.scan_coverages USING btree (tenant_id);

CREATE UNIQUE INDEX idx_scan_coverages_tenant_project_work ON public.scan_coverages USING btree (tenant_id, project_id, work_key_hash);

CREATE INDEX idx_scan_coverages_valid_until ON public.scan_coverages USING btree (valid_until);

CREATE INDEX idx_scan_observations_agent_id ON public.scan_observations USING btree (agent_id);

CREATE INDEX idx_scan_observations_attempt_id ON public.scan_observations USING btree (attempt_id);

CREATE INDEX idx_scan_observations_batch_id ON public.scan_observations USING btree (batch_id);

CREATE INDEX idx_scan_observations_observed_at ON public.scan_observations USING btree (observed_at);

CREATE INDEX idx_scan_observations_outcome ON public.scan_observations USING btree (outcome);

CREATE INDEX idx_scan_observations_project_id ON public.scan_observations USING btree (project_id);

CREATE INDEX idx_scan_observations_root_task_id ON public.scan_observations USING btree (root_task_id);

CREATE INDEX idx_scan_observations_rule_version ON public.scan_observations USING btree (rule_version);

CREATE INDEX idx_scan_observations_scope ON public.scan_observations USING btree (tenant_id, project_id, network_zone, stage, observed_at DESC);

CREATE INDEX idx_scan_observations_stage ON public.scan_observations USING btree (stage);

CREATE INDEX idx_scan_observations_target_hash ON public.scan_observations USING btree (target_hash);

CREATE UNIQUE INDEX idx_scan_observations_tenant_event ON public.scan_observations USING btree (tenant_id, source_event_id) WHERE (source_event_id IS NOT NULL);

CREATE INDEX idx_scan_observations_tenant_id ON public.scan_observations USING btree (tenant_id);

CREATE INDEX idx_scan_observations_work_key_hash ON public.scan_observations USING btree (work_key_hash);

CREATE UNIQUE INDEX idx_scan_policy_intent_root ON public.scan_policy_intents USING btree (tenant_id, root_task_id);

CREATE INDEX idx_scan_policy_intents_plan_hash ON public.scan_policy_intents USING btree (plan_hash);

CREATE INDEX idx_scan_policy_intents_policy_hash ON public.scan_policy_intents USING btree (policy_hash);

CREATE INDEX idx_scan_policy_intents_project_id ON public.scan_policy_intents USING btree (project_id);

CREATE UNIQUE INDEX idx_scan_stage_derivation ON public.scan_stage_derivations USING btree (tenant_id, root_task_id, stage);

CREATE INDEX idx_scan_stage_derivations_batch_id ON public.scan_stage_derivations USING btree (batch_id);

CREATE INDEX idx_scan_timing_events_attempt_created ON public.scan_timing_events USING btree (tenant_id, project_id, root_task_id, attempt_id, created_at);

CREATE INDEX idx_scan_timing_events_scope_created ON public.scan_timing_events USING btree (tenant_id, project_id, root_task_id, created_at);

CREATE UNIQUE INDEX idx_scan_timing_events_tenant_source_event ON public.scan_timing_events USING btree (tenant_id, source_event_id);

CREATE INDEX idx_scan_work_claims_lease_expires_at ON public.scan_work_claims USING btree (lease_expires_at);

CREATE INDEX idx_scan_work_claims_network_zone ON public.scan_work_claims USING btree (network_zone);

CREATE INDEX idx_scan_work_claims_owner_agent_id ON public.scan_work_claims USING btree (owner_agent_id);

CREATE INDEX idx_scan_work_claims_owner_attempt_id ON public.scan_work_claims USING btree (owner_attempt_id);

CREATE INDEX idx_scan_work_claims_owner_batch_id ON public.scan_work_claims USING btree (owner_batch_id);

CREATE INDEX idx_scan_work_claims_owner_task_id ON public.scan_work_claims USING btree (owner_task_id);

CREATE INDEX idx_scan_work_claims_project_id ON public.scan_work_claims USING btree (project_id);

CREATE INDEX idx_scan_work_claims_rule_version ON public.scan_work_claims USING btree (rule_version);

CREATE INDEX idx_scan_work_claims_stage ON public.scan_work_claims USING btree (stage);

CREATE INDEX idx_scan_work_claims_status ON public.scan_work_claims USING btree (status);

CREATE INDEX idx_scan_work_claims_target_hash ON public.scan_work_claims USING btree (target_hash);

CREATE INDEX idx_scan_work_claims_tenant_id ON public.scan_work_claims USING btree (tenant_id);

CREATE UNIQUE INDEX idx_scan_work_claims_tenant_project_work ON public.scan_work_claims USING btree (tenant_id, project_id, work_key_hash);

CREATE INDEX idx_sub_tasks_agent_id ON public.sub_tasks USING btree (agent_id);

CREATE INDEX idx_sub_tasks_batch_id ON public.sub_tasks USING btree (batch_id);

CREATE INDEX idx_sub_tasks_finished_at ON public.sub_tasks USING btree (finished_at);

CREATE INDEX idx_sub_tasks_parent_attempt_id ON public.sub_tasks USING btree (parent_attempt_id);

CREATE INDEX idx_sub_tasks_priority ON public.sub_tasks USING btree (priority);

CREATE INDEX idx_sub_tasks_project_id ON public.sub_tasks USING btree (project_id);

CREATE INDEX idx_sub_tasks_root_task_id ON public.sub_tasks USING btree (root_task_id);

CREATE UNIQUE INDEX idx_sub_tasks_scope_attempt_agent_id ON public.sub_tasks USING btree (tenant_id, project_id, root_task_id, batch_id, id, agent_id);

CREATE UNIQUE INDEX idx_sub_tasks_scope_attempt_id ON public.sub_tasks USING btree (tenant_id, project_id, root_task_id, batch_id, id);

CREATE INDEX idx_sub_tasks_started_at ON public.sub_tasks USING btree (started_at);

CREATE INDEX idx_sub_tasks_status ON public.sub_tasks USING btree (status);

CREATE INDEX idx_sub_tasks_tenant_id ON public.sub_tasks USING btree (tenant_id);

CREATE INDEX idx_sub_tasks_trigger ON public.sub_tasks USING btree (trigger);

CREATE INDEX idx_subdomain_dictionaries_project_id ON public.subdomain_dictionaries USING btree (project_id);

CREATE UNIQUE INDEX idx_subdomain_dictionary_name ON public.subdomain_dictionaries USING btree (tenant_id, project_id, name) WHERE (deleted_at IS NULL);

CREATE UNIQUE INDEX idx_subdomain_dictionary_revision ON public.subdomain_dictionary_revisions USING btree (dictionary_id, revision);

CREATE INDEX idx_subdomain_dictionary_revisions_tenant_id ON public.subdomain_dictionary_revisions USING btree (tenant_id);

CREATE UNIQUE INDEX idx_tai_idempotency ON public.task_append_idempotencies USING btree (tenant_id, project_id, root_task_id, operator_id, operation, idempotency_key_hash);

CREATE INDEX idx_tai_operator_created ON public.task_append_idempotencies USING btree (tenant_id, project_id, operator_id, created_at);

CREATE UNIQUE INDEX idx_tai_scope_id ON public.task_append_idempotencies USING btree (tenant_id, project_id, root_task_id, id);

CREATE INDEX idx_tai_task_created ON public.task_append_idempotencies USING btree (tenant_id, project_id, root_task_id, created_at);

CREATE INDEX idx_task_audits_action ON public.task_audits USING btree (action);

CREATE INDEX idx_task_audits_attempt_id ON public.task_audits USING btree (attempt_id);

CREATE INDEX idx_task_audits_batch_id ON public.task_audits USING btree (batch_id);

CREATE INDEX idx_task_audits_created_at ON public.task_audits USING btree (created_at);

CREATE INDEX idx_task_audits_operator_id ON public.task_audits USING btree (operator_id);

CREATE INDEX idx_task_audits_project_id ON public.task_audits USING btree (project_id);

CREATE INDEX idx_task_audits_root_task_id ON public.task_audits USING btree (root_task_id);

CREATE INDEX idx_task_audits_tenant_id ON public.task_audits USING btree (tenant_id);

CREATE INDEX idx_task_batches_archived_at ON public.task_batches USING btree (archived_at);

CREATE INDEX idx_task_batches_control_state ON public.task_batches USING btree (control_state);

CREATE INDEX idx_task_batches_created_by ON public.task_batches USING btree (created_by);

CREATE INDEX idx_task_batches_kind ON public.task_batches USING btree (kind);

CREATE INDEX idx_task_batches_latest_attempt_id ON public.task_batches USING btree (latest_attempt_id);

CREATE INDEX idx_task_batches_project_id ON public.task_batches USING btree (project_id);

CREATE INDEX idx_task_batches_root_task_id ON public.task_batches USING btree (root_task_id);

CREATE UNIQUE INDEX idx_task_batches_scope_id ON public.task_batches USING btree (tenant_id, project_id, root_task_id, id);

CREATE INDEX idx_task_batches_status ON public.task_batches USING btree (status);

CREATE INDEX idx_task_batches_target_type ON public.task_batches USING btree (target_type);

CREATE INDEX idx_task_batches_tenant_id ON public.task_batches USING btree (tenant_id);

CREATE INDEX idx_task_config_revisions_config_hash ON public.task_config_revisions USING btree (config_hash);

CREATE INDEX idx_task_config_revisions_created_by ON public.task_config_revisions USING btree (created_by);

CREATE INDEX idx_task_config_revisions_project_id ON public.task_config_revisions USING btree (project_id);

CREATE INDEX idx_task_config_revisions_root_task_id ON public.task_config_revisions USING btree (root_task_id);

CREATE UNIQUE INDEX idx_task_config_revisions_scope_version ON public.task_config_revisions USING btree (tenant_id, project_id, root_task_id, version);

CREATE INDEX idx_task_config_revisions_tenant_id ON public.task_config_revisions USING btree (tenant_id);

CREATE INDEX idx_task_coverage_links_attempt_id ON public.task_coverage_links USING btree (attempt_id);

CREATE INDEX idx_task_coverage_links_batch_id ON public.task_coverage_links USING btree (batch_id);

CREATE INDEX idx_task_coverage_links_claim_id ON public.task_coverage_links USING btree (claim_id);

CREATE INDEX idx_task_coverage_links_coverage_id ON public.task_coverage_links USING btree (coverage_id);

CREATE UNIQUE INDEX idx_task_coverage_links_destination_work ON public.task_coverage_links USING btree (tenant_id, project_id, root_task_id, batch_id, attempt_id, work_key_hash, link_type);

CREATE INDEX idx_task_coverage_links_link_type ON public.task_coverage_links USING btree (link_type);

CREATE INDEX idx_task_coverage_links_project_id ON public.task_coverage_links USING btree (project_id);

CREATE INDEX idx_task_coverage_links_root_task_id ON public.task_coverage_links USING btree (root_task_id);

CREATE INDEX idx_task_coverage_links_source_attempt_id ON public.task_coverage_links USING btree (source_attempt_id);

CREATE INDEX idx_task_coverage_links_source_batch_id ON public.task_coverage_links USING btree (source_batch_id);

CREATE INDEX idx_task_coverage_links_source_task_id ON public.task_coverage_links USING btree (source_task_id);

CREATE INDEX idx_task_coverage_links_status ON public.task_coverage_links USING btree (status);

CREATE INDEX idx_task_coverage_links_tenant_id ON public.task_coverage_links USING btree (tenant_id);

CREATE INDEX idx_task_coverage_links_work_key_hash ON public.task_coverage_links USING btree (work_key_hash);

CREATE INDEX idx_tbri_batch_created ON public.task_batch_retry_idempotencies USING btree (tenant_id, project_id, root_task_id, batch_id, created_at);

CREATE UNIQUE INDEX idx_tbri_idempotency ON public.task_batch_retry_idempotencies USING btree (tenant_id, project_id, root_task_id, batch_id, operator_id, operation, idempotency_key_hash);

CREATE INDEX idx_tbri_operator_created ON public.task_batch_retry_idempotencies USING btree (tenant_id, project_id, operator_id, created_at);

CREATE UNIQUE INDEX idx_tbri_scope_id ON public.task_batch_retry_idempotencies USING btree (tenant_id, project_id, root_task_id, batch_id, id);

CREATE UNIQUE INDEX idx_tci_idempotency ON public.task_creation_idempotencies USING btree (tenant_id, project_id, operator_id, operation, idempotency_key_hash);

CREATE INDEX idx_tci_operator_created ON public.task_creation_idempotencies USING btree (tenant_id, project_id, operator_id, created_at);

CREATE UNIQUE INDEX idx_tci_scope_id ON public.task_creation_idempotencies USING btree (tenant_id, project_id, id);

CREATE INDEX idx_tci_task_created ON public.task_creation_idempotencies USING btree (tenant_id, project_id, root_task_id, created_at);

CREATE UNIQUE INDEX idx_tri_idempotency ON public.task_retry_idempotencies USING btree (tenant_id, project_id, root_task_id, operator_id, operation, idempotency_key_hash);

CREATE INDEX idx_tri_operator_created ON public.task_retry_idempotencies USING btree (tenant_id, project_id, operator_id, created_at);

CREATE UNIQUE INDEX idx_tri_scope_id ON public.task_retry_idempotencies USING btree (tenant_id, project_id, root_task_id, id);

CREATE INDEX idx_tri_task_created ON public.task_retry_idempotencies USING btree (tenant_id, project_id, root_task_id, created_at);

CREATE UNIQUE INDEX idx_users_username ON public.users USING btree (username);

CREATE UNIQUE INDEX idx_vuln_new_dedupe ON public.vulnerabilities USING btree (project_id, target, plugin);

CREATE INDEX idx_vulnerabilities_assignee ON public.vulnerabilities USING btree (assignee);

CREATE INDEX idx_vulnerabilities_root_task_id ON public.vulnerabilities USING btree (root_task_id);

CREATE INDEX idx_vulnerabilities_status ON public.vulnerabilities USING btree (status);

CREATE INDEX idx_vulnerabilities_task_id ON public.vulnerabilities USING btree (task_id);

CREATE INDEX idx_vulnerabilities_tenant_id ON public.vulnerabilities USING btree (tenant_id);

CREATE INDEX idx_vulnerabilities_verify_task_id ON public.vulnerabilities USING btree (verify_task_id);

CREATE INDEX idx_workflow_product_summaries_product_trgm ON public.workflow_product_summaries USING gin (product_name public.gin_trgm_ops);

CREATE INDEX idx_workflow_product_summaries_tenant_enabled ON public.workflow_product_summaries USING btree (tenant_id, enabled, product_name);

CREATE INDEX idx_workflow_product_summaries_tenant_general ON public.workflow_product_summaries USING btree (tenant_id, is_general_poc, product_name);

CREATE INDEX idx_workflow_product_summaries_tenant_health ON public.workflow_product_summaries USING btree (tenant_id, fingerprint_bound, missing_poc_count, product_name);

CREATE UNIQUE INDEX idx_workflow_rule_unique ON public.workflow_rules USING btree (tenant_id, product_name, poc_name, match_type);

CREATE INDEX idx_workflow_rules_artifact_id ON public.workflow_rules USING btree (artifact_id);

CREATE INDEX idx_workflow_rules_content_hash ON public.workflow_rules USING btree (content_hash);

CREATE INDEX idx_workflow_rules_enabled ON public.workflow_rules USING btree (enabled);

CREATE INDEX idx_workflow_rules_match_type ON public.workflow_rules USING btree (match_type);

CREATE INDEX idx_workflow_rules_poc_name ON public.workflow_rules USING btree (poc_name);

CREATE INDEX idx_workflow_rules_poc_trgm ON public.workflow_rules USING gin (poc_name public.gin_trgm_ops);

CREATE INDEX idx_workflow_rules_product_name ON public.workflow_rules USING btree (product_name);

CREATE INDEX idx_workflow_rules_product_trgm ON public.workflow_rules USING gin (product_name public.gin_trgm_ops);

CREATE INDEX idx_workflow_rules_source_file ON public.workflow_rules USING btree (source_file);

CREATE INDEX idx_workflow_rules_state ON public.workflow_rules USING btree (state);

CREATE INDEX idx_workflow_rules_tenant_enabled_product ON public.workflow_rules USING btree (tenant_id, enabled, product_name);

CREATE INDEX idx_workflow_rules_tenant_id ON public.workflow_rules USING btree (tenant_id);

CREATE INDEX idx_workflow_rules_tenant_poc ON public.workflow_rules USING btree (tenant_id, poc_name);

CREATE INDEX idx_workflow_rules_tenant_state_product ON public.workflow_rules USING btree (tenant_id, state, product_name);

CREATE INDEX idx_ws_event_logs_occurred_at ON public.ws_event_logs USING btree (occurred_at);

CREATE INDEX idx_ws_event_logs_project_id ON public.ws_event_logs USING btree (project_id);

CREATE INDEX idx_ws_event_logs_tenant_id ON public.ws_event_logs USING btree (tenant_id);

ALTER TABLE ONLY public.credential_dictionary_revisions
    ADD CONSTRAINT credential_dictionary_revisions_dictionary_id_fkey FOREIGN KEY (dictionary_id) REFERENCES public.credential_dictionaries(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_notebook_distribution_intents
    ADD CONSTRAINT fk_addi_config_revision FOREIGN KEY (tenant_id, project_id, root_task_id, config_version) REFERENCES public.task_config_revisions(tenant_id, project_id, root_task_id, version) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_notebook_distribution_intents
    ADD CONSTRAINT fk_addi_root_task FOREIGN KEY (tenant_id, project_id, root_task_id) REFERENCES public.root_tasks(tenant_id, project_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_notebook_distribution_intent_items
    ADD CONSTRAINT fk_addii_intent FOREIGN KEY (tenant_id, project_id, intent_id) REFERENCES public.asset_discovery_notebook_distribution_intents(tenant_id, project_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_notebook_distribution_intent_items
    ADD CONSTRAINT fk_addii_notebook_item FOREIGN KEY (tenant_id, project_id, notebook_item_id) REFERENCES public.asset_discovery_notebook_items(tenant_id, project_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_notebook_distribution_materializations
    ADD CONSTRAINT fk_addm_intent FOREIGN KEY (tenant_id, project_id, intent_id) REFERENCES public.asset_discovery_notebook_distribution_intents(tenant_id, project_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_notebook_distribution_materializations
    ADD CONSTRAINT fk_addm_root_task FOREIGN KEY (tenant_id, project_id, root_task_id) REFERENCES public.root_tasks(tenant_id, project_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_notebook_items
    ADD CONSTRAINT fk_adn_item_project FOREIGN KEY (tenant_id, project_id) REFERENCES public.projects(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_notebook_item_tags
    ADD CONSTRAINT fk_adn_item_tag_item FOREIGN KEY (tenant_id, project_id, notebook_item_id) REFERENCES public.asset_discovery_notebook_items(tenant_id, project_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_notebook_item_tags
    ADD CONSTRAINT fk_adn_item_tag_tag FOREIGN KEY (tenant_id, project_id, tag_id) REFERENCES public.asset_discovery_notebook_tags(tenant_id, project_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_notebook_tags
    ADD CONSTRAINT fk_adn_tag_project FOREIGN KEY (tenant_id, project_id) REFERENCES public.projects(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_audits
    ADD CONSTRAINT fk_asset_discovery_audit_notebook_item FOREIGN KEY (tenant_id, project_id, notebook_item_id) REFERENCES public.asset_discovery_notebook_items(tenant_id, project_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.asset_discovery_notebook_sources
    ADD CONSTRAINT fk_asset_discovery_notebook_sources_audit FOREIGN KEY (tenant_id, project_id, audit_id) REFERENCES public.asset_discovery_audits(tenant_id, project_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_notebook_sources
    ADD CONSTRAINT fk_asset_discovery_notebook_sources_item FOREIGN KEY (tenant_id, project_id, notebook_item_id) REFERENCES public.asset_discovery_notebook_items(tenant_id, project_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_notebook_sources
    ADD CONSTRAINT fk_asset_discovery_notebook_sources_snapshot_item FOREIGN KEY (tenant_id, project_id, snapshot_id, snapshot_item_id) REFERENCES public.asset_discovery_snapshot_items(tenant_id, project_id, snapshot_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_snapshot_items
    ADD CONSTRAINT fk_asset_discovery_snapshot_items_snapshot FOREIGN KEY (tenant_id, project_id, snapshot_id) REFERENCES public.asset_discovery_snapshots(tenant_id, project_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.asset_discovery_snapshots
    ADD CONSTRAINT fk_asset_discovery_snapshots_audit FOREIGN KEY (tenant_id, project_id, audit_id) REFERENCES public.asset_discovery_audits(tenant_id, project_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.exp_asset_refs
    ADD CONSTRAINT fk_exp_asset_ref_asset FOREIGN KEY (tenant_id, asset_id, asset_version) REFERENCES public.exp_assets(tenant_id, asset_id, version) ON DELETE RESTRICT;

ALTER TABLE ONLY public.exp_asset_refs
    ADD CONSTRAINT fk_exp_asset_ref_revision FOREIGN KEY (exp_id, revision) REFERENCES public.exp_revisions(exp_id, revision) ON DELETE RESTRICT;

ALTER TABLE ONLY public.exp_dependencies
    ADD CONSTRAINT fk_exp_dependency_child FOREIGN KEY (dependency_exp_id, dependency_revision) REFERENCES public.exp_revisions(exp_id, revision) ON DELETE RESTRICT;

ALTER TABLE ONLY public.exp_dependencies
    ADD CONSTRAINT fk_exp_dependency_parent FOREIGN KEY (parent_exp_id, parent_revision) REFERENCES public.exp_revisions(exp_id, revision) ON DELETE RESTRICT;

ALTER TABLE ONLY public.exp_revisions
    ADD CONSTRAINT fk_exp_revisions_exp FOREIGN KEY (exp_id) REFERENCES public.exps(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.exp_risk_waivers
    ADD CONSTRAINT fk_exp_risk_waiver_exp FOREIGN KEY (exp_id) REFERENCES public.exps(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.exp_runs
    ADD CONSTRAINT fk_exp_run_revision FOREIGN KEY (exp_id, revision) REFERENCES public.exp_revisions(exp_id, revision) ON DELETE RESTRICT;

ALTER TABLE ONLY public.exp_test_cases
    ADD CONSTRAINT fk_exp_test_case_revision FOREIGN KEY (exp_id, revision) REFERENCES public.exp_revisions(exp_id, revision) ON DELETE RESTRICT;

ALTER TABLE ONLY public.exps
    ADD CONSTRAINT fk_exps_parent_same_tenant FOREIGN KEY (tenant_id, parent_exp_id) REFERENCES public.exps(tenant_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.risk_validation_execution_idempotencies
    ADD CONSTRAINT fk_rvei_attempt FOREIGN KEY (tenant_id, project_id, root_task_id, batch_id, attempt_id) REFERENCES public.sub_tasks(tenant_id, project_id, root_task_id, batch_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.risk_validation_execution_idempotencies
    ADD CONSTRAINT fk_rvei_batch FOREIGN KEY (tenant_id, project_id, root_task_id, batch_id) REFERENCES public.task_batches(tenant_id, project_id, root_task_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.risk_validation_execution_idempotencies
    ADD CONSTRAINT fk_rvei_config FOREIGN KEY (tenant_id, project_id, root_task_id, config_version) REFERENCES public.task_config_revisions(tenant_id, project_id, root_task_id, version) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.risk_validation_execution_idempotencies
    ADD CONSTRAINT fk_rvei_root_task FOREIGN KEY (tenant_id, project_id, root_task_id) REFERENCES public.root_tasks(tenant_id, project_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.scan_timing_events
    ADD CONSTRAINT fk_scan_timing_event_attempt FOREIGN KEY (tenant_id, project_id, root_task_id, batch_id, attempt_id) REFERENCES public.sub_tasks(tenant_id, project_id, root_task_id, batch_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.scan_timing_events
    ADD CONSTRAINT fk_scan_timing_event_attempt_agent FOREIGN KEY (tenant_id, project_id, root_task_id, batch_id, attempt_id, agent_id) REFERENCES public.sub_tasks(tenant_id, project_id, root_task_id, batch_id, id, agent_id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.scan_timing_events
    ADD CONSTRAINT fk_scan_timing_event_batch FOREIGN KEY (tenant_id, project_id, root_task_id, batch_id) REFERENCES public.task_batches(tenant_id, project_id, root_task_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.scan_timing_events
    ADD CONSTRAINT fk_scan_timing_event_root FOREIGN KEY (tenant_id, project_id, root_task_id) REFERENCES public.root_tasks(tenant_id, project_id, id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.task_append_idempotencies
    ADD CONSTRAINT fk_tai_root_task FOREIGN KEY (tenant_id, project_id, root_task_id) REFERENCES public.root_tasks(tenant_id, project_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.task_batch_retry_idempotencies
    ADD CONSTRAINT fk_tbri_attempt FOREIGN KEY (tenant_id, project_id, root_task_id, batch_id, attempt_id) REFERENCES public.sub_tasks(tenant_id, project_id, root_task_id, batch_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.task_batch_retry_idempotencies
    ADD CONSTRAINT fk_tbri_batch FOREIGN KEY (tenant_id, project_id, root_task_id, batch_id) REFERENCES public.task_batches(tenant_id, project_id, root_task_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.task_batch_retry_idempotencies
    ADD CONSTRAINT fk_tbri_root_task FOREIGN KEY (tenant_id, project_id, root_task_id) REFERENCES public.root_tasks(tenant_id, project_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.task_creation_idempotencies
    ADD CONSTRAINT fk_tci_root_task FOREIGN KEY (tenant_id, project_id, root_task_id) REFERENCES public.root_tasks(tenant_id, project_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.task_retry_idempotencies
    ADD CONSTRAINT fk_tri_root_task FOREIGN KEY (tenant_id, project_id, root_task_id) REFERENCES public.root_tasks(tenant_id, project_id, id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE ONLY public.subdomain_dictionary_revisions
    ADD CONSTRAINT subdomain_dictionary_revisions_dictionary_id_fkey FOREIGN KEY (dictionary_id) REFERENCES public.subdomain_dictionaries(id) ON DELETE RESTRICT;
