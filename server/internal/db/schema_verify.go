package db

import (
	"fmt"
	"strings"

	"gorm.io/gorm"
)

type schemaTableSpec struct {
	Table   string
	Columns []string
	Indexes []string
}

func schemaTableSpecs() []schemaTableSpec {
	return []schemaTableSpec{
		{
			Table:   "schema_migrations",
			Columns: []string{"version", "name", "checksum", "applied_at"},
		},
		{
			Table:   "oauth_clients",
			Columns: []string{"client_id", "redirect_uris", "public", "tenant_id", "created_at"},
			Indexes: []string{"idx_oauth_clients_tenant_id"},
		},
		{
			Table:   "oauth_authorization_codes",
			Columns: []string{"code_hash", "client_id", "redirect_uri", "resource", "code_challenge", "user_id", "tenant_id", "role", "role_base", "exp_authorized", "expires_at", "used_at", "created_at"},
			Indexes: []string{"idx_oauth_authorization_codes_client_id", "idx_oauth_authorization_codes_tenant_id", "idx_oauth_authorization_codes_expires_at"},
		},
		{
			Table:   "oauth_refresh_tokens",
			Columns: []string{"token_hash", "client_id", "user_id", "tenant_id", "role", "role_base", "exp_authorized", "resource", "expires_at", "revoked_at", "created_at"},
			Indexes: []string{"idx_oauth_refresh_tokens_client_id", "idx_oauth_refresh_tokens_user_id", "idx_oauth_refresh_tokens_tenant_id", "idx_oauth_refresh_tokens_expires_at", "idx_oauth_refresh_tokens_revoked_at"},
		},
		{
			Table:   "tenant_mcp_settings",
			Columns: []string{"tenant_id", "enabled", "updated_at", "updated_by"},
		},
		{
			Table:   "oauth_tenant_client_blocks",
			Columns: []string{"tenant_id", "client_id", "blocked_at", "actor_id"},
			Indexes: []string{"idx_oauth_tenant_client_blocks_client_id"},
		},
		{
			Table:   "mcp_admin_events",
			Columns: []string{"id", "tenant_id", "actor_id", "action", "client_id", "details", "created_at"},
			Indexes: []string{"idx_mcp_admin_events_tenant_id", "idx_mcp_admin_events_actor_id", "idx_mcp_admin_events_action", "idx_mcp_admin_events_created_at"},
		},
		{Table: "scan_policy_intents", Columns: []string{"tenant_id", "project_id", "root_task_id", "schema_version", "policy_json", "policy_hash", "plan_hash", "risk_status", "credential_status", "authorization_actor_id", "authorized_at", "created_at", "updated_at"}, Indexes: []string{"idx_scan_policy_intent_root", "idx_scan_policy_intents_project_id", "idx_scan_policy_intents_policy_hash", "idx_scan_policy_intents_plan_hash"}},
		{Table: "scan_stage_derivations", Columns: []string{"tenant_id", "project_id", "root_task_id", "stage", "status", "plan_hash", "observation_hash", "batch_id", "attempt_id", "item_count", "summary", "created_at", "updated_at"}, Indexes: []string{"idx_scan_stage_derivation", "idx_scan_stage_derivations_batch_id"}},
		{Table: "credential_dictionaries", Columns: []string{"id", "tenant_id", "project_id", "kind", "name", "created_by", "created_at", "updated_at", "deleted_at"}, Indexes: []string{"idx_credential_dictionary_name", "idx_credential_dictionaries_project_id"}},
		{Table: "credential_dictionary_revisions", Columns: []string{"tenant_id", "project_id", "dictionary_id", "revision", "sha256", "item_count", "ciphertext", "nonce", "created_by", "created_at"}, Indexes: []string{"idx_credential_dictionary_revision", "idx_credential_dictionary_revisions_tenant_id"}},
		{Table: "subdomain_dictionaries", Columns: []string{"id", "tenant_id", "project_id", "name", "created_by", "created_at", "updated_at", "deleted_at"}, Indexes: []string{"idx_subdomain_dictionary_name", "idx_subdomain_dictionaries_project_id"}},
		{Table: "subdomain_dictionary_revisions", Columns: []string{"tenant_id", "project_id", "dictionary_id", "revision", "sha256", "item_count", "values_json", "created_by", "created_at"}, Indexes: []string{"idx_subdomain_dictionary_revision", "idx_subdomain_dictionary_revisions_tenant_id"}},
		{Table: "subdomain_passive_cache", Columns: []string{"domain", "subdomains", "sources", "collected_at", "expires_at"}, Indexes: []string{"idx_subdomain_passive_cache_expires"}},
		{Table: "subdomain_passive_jobs", Columns: []string{"id", "tenant_id", "project_id", "root_task_id", "batch_id", "attempt_id", "domains", "domains_done", "state", "note", "created_at", "updated_at"}, Indexes: []string{"idx_subdomain_passive_jobs_state", "idx_subdomain_passive_jobs_attempt", "idx_subdomain_passive_jobs_root", "idx_subdomain_passive_jobs_tenant"}},
		{Table: "credential_bundles", Columns: []string{"ref", "tenant_id", "project_id", "root_task_id", "batch_id", "attempt_id", "agent_id", "sha256", "pair_count", "ciphertext", "nonce", "expires_at", "claimed_at", "consumed_at", "created_at"}, Indexes: []string{"idx_credential_bundles_attempt_id", "idx_credential_bundles_expires_at"}},
		{Table: "credential_finding_secrets", Columns: []string{"id", "tenant_id", "project_id", "root_task_id", "attempt_id", "endpoint", "service", "plugin", "masked_username", "ciphertext", "nonce", "created_at"}, Indexes: []string{"idx_credential_finding_secrets_tenant_id", "idx_credential_finding_secrets_root_task_id"}},
		{Table: "credential_reveal_audits", Columns: []string{"tenant_id", "project_id", "finding_id", "actor_id", "action", "created_at"}, Indexes: []string{"idx_credential_reveal_audits_tenant_id", "idx_credential_reveal_audits_finding_id"}},
		{
			Table: "exp_egress_audits",
			Columns: []string{
				"route_id", "tenant_id", "operator_id", "agent_id", "targets", "resolved_ips", "status", "error_code",
				"connection_count", "bytes_to_agent", "bytes_from_agent", "issued_at", "claimed_at", "finished_at", "expires_at", "created_at", "updated_at",
			},
			Indexes: []string{
				"idx_exp_egress_audits_route_id", "idx_exp_egress_audits_tenant_id", "idx_exp_egress_audits_operator_id",
				"idx_exp_egress_audits_agent_id", "idx_exp_egress_audits_status", "idx_exp_egress_audits_error_code",
				"idx_exp_egress_audits_issued_at", "idx_exp_egress_audits_finished_at", "idx_exp_egress_audits_expires_at",
			},
		},
		{Table: "exps", Columns: []string{"id", "tenant_id", "name", "description", "risk_level", "status", "active_revision", "created_by", "created_at", "updated_at", "deprecated_at"}, Indexes: []string{"idx_exps_tenant_name", "idx_exps_tenant_id", "idx_exps_status"}},
		{Table: "exp_revisions", Columns: []string{"exp_id", "tenant_id", "revision", "status", "source_object_key", "source_sha256", "source_size", "cli_schema", "inspect_summary", "validate_summary", "tests_passed_at", "test_cases_sha256", "created_by", "published_by", "published_at", "created_at"}, Indexes: []string{"idx_exp_revision", "idx_exp_revisions_tenant_id", "idx_exp_revisions_source_sha256"}},
		{Table: "exp_dependencies", Columns: []string{"tenant_id", "parent_exp_id", "parent_revision", "dependency_exp_id", "dependency_revision", "source_sha256"}, Indexes: []string{"idx_exp_dependency", "idx_exp_dependencies_tenant_id"}},
		{Table: "exp_assets", Columns: []string{"tenant_id", "asset_id", "version", "object_key", "sha256", "size", "media_type", "created_by", "created_at"}, Indexes: []string{"idx_exp_asset_identity", "idx_exp_assets_tenant_id", "idx_exp_assets_sha256"}},
		{Table: "exp_asset_refs", Columns: []string{"tenant_id", "exp_id", "revision", "asset_id", "asset_version", "sha256"}, Indexes: []string{"idx_exp_asset_ref", "idx_exp_asset_refs_tenant_id"}},
		{Table: "exp_test_cases", Columns: []string{"id", "tenant_id", "exp_id", "revision", "name", "params", "fixtures", "assertions", "enabled", "created_by", "created_at", "updated_at"}, Indexes: []string{"idx_exp_test_case_revision", "idx_exp_test_cases_tenant_id"}},
		{Table: "exp_runs", Columns: []string{"id", "tenant_id", "exp_id", "revision", "source_sha256", "action", "operator_id", "egress_mode", "agent_id", "status", "provenance", "attested", "result_summary", "artifact_object_key", "artifact_sha256", "artifact_expires_at", "error_code", "started_at", "finished_at", "created_at"}, Indexes: []string{"idx_exp_runs_tenant_id", "idx_exp_runs_exp_id", "idx_exp_runs_status", "idx_exp_runs_artifact_expires_at"}},
		{Table: "exp_audits", Columns: []string{"tenant_id", "exp_id", "revision", "actor_id", "action", "details", "created_at"}, Indexes: []string{"idx_exp_audits_tenant_id", "idx_exp_audits_exp_id", "idx_exp_audits_actor_id", "idx_exp_audits_action"}},
		{Table: "exp_risk_waivers", Columns: []string{"tenant_id", "exp_id", "reason", "granted_by", "expires_at", "created_at", "updated_at"}, Indexes: []string{"idx_exp_risk_waiver"}},
		{
			Table:   "projects",
			Columns: []string{"tenant_id", "owner_user_id", "name", "status", "deleted_at"},
			Indexes: []string{"idx_projects_tenant_id", "idx_projects_owner_user_id", "idx_projects_status", "idx_projects_deleted_at", "idx_projects_scope_id"},
		},
		{
			Table:   "project_members",
			Columns: []string{"tenant_id", "project_id", "user_id", "role"},
		},
		{
			Table:   "root_tasks",
			Columns: []string{"project_id", "total_targets", "completed_targets", "status", "archived_at", "current_config_version"},
			Indexes: []string{"idx_root_tasks_tenant_id", "idx_root_tasks_project_id", "idx_root_tasks_status", "idx_root_tasks_archived_at", "idx_root_tasks_scope_id"},
		},
		{
			Table:   "sub_tasks",
			Columns: []string{"project_id", "batch_id", "attempt_no", "parent_attempt_id", "trigger", "failure_reason", "agent_selector", "agent_selector_rules", "timeout_sec", "retry_count", "max_retry", "config_version", "rule_version", "started_at", "finished_at"},
			Indexes: []string{"idx_sub_tasks_project_id", "idx_sub_tasks_root_task_id", "idx_sub_tasks_batch_id", "idx_sub_tasks_parent_attempt_id", "idx_sub_tasks_trigger", "idx_sub_tasks_status", "idx_sub_tasks_started_at", "idx_sub_tasks_finished_at", "idx_sub_tasks_scope_attempt_id", "idx_sub_tasks_scope_attempt_agent_id"},
		},
		{
			Table:   "task_batches",
			Columns: []string{"tenant_id", "project_id", "root_task_id", "sequence", "kind", "target_type", "targets", "target_count", "status", "control_state", "config_version", "rule_version", "priority", "timeout_sec", "agent_selector", "agent_selector_rules", "current_attempt_no", "attempt_count", "latest_attempt_id", "created_by", "created_at", "updated_at", "archived_at"},
			Indexes: []string{"idx_task_batches_tenant_id", "idx_task_batches_project_id", "idx_task_batches_root_task_id", "idx_task_batches_task_sequence", "idx_task_batches_kind", "idx_task_batches_target_type", "idx_task_batches_status", "idx_task_batches_control_state", "idx_task_batches_latest_attempt_id", "idx_task_batches_created_by", "idx_task_batches_archived_at", "idx_task_batches_scope_id"},
		},
		{
			Table:   "task_config_revisions",
			Columns: []string{"tenant_id", "project_id", "root_task_id", "version", "config", "config_hash", "priority", "timeout_sec", "agent_selector", "agent_selector_rules", "created_by", "change_note", "created_at"},
			Indexes: []string{"idx_task_config_revisions_tenant_id", "idx_task_config_revisions_project_id", "idx_task_config_revisions_root_task_id", "idx_task_config_revisions_task_version", "idx_task_config_revisions_config_hash", "idx_task_config_revisions_created_by", "idx_task_config_revisions_scope_version"},
		},
		{
			Table:   "task_audits",
			Columns: []string{"tenant_id", "project_id", "root_task_id", "batch_id", "attempt_id", "operator_id", "action", "before_status", "after_status", "details", "created_at"},
			Indexes: []string{"idx_task_audits_tenant_id", "idx_task_audits_project_id", "idx_task_audits_root_task_id", "idx_task_audits_batch_id", "idx_task_audits_attempt_id", "idx_task_audits_operator_id", "idx_task_audits_action", "idx_task_audits_created_at"},
		},
		{
			Table: "asset_discovery_audits",
			Columns: []string{
				"tenant_id", "project_id", "notebook_item_id", "provider", "action", "operator_id", "query_hash", "config_version", "config_hash",
				"requested_limit", "provider_total", "returned_count", "skipped_rows", "truncated", "status", "error_code", "duration_ms", "created_at",
			},
			Indexes: []string{
				"idx_asset_discovery_audits_tenant_id", "idx_asset_discovery_audits_project_id", "idx_asset_discovery_audits_provider",
				"idx_asset_discovery_audits_action", "idx_asset_discovery_audits_operator_id", "idx_asset_discovery_audits_query_hash",
				"idx_asset_discovery_audits_status", "idx_asset_discovery_audits_error_code", "idx_asset_discovery_audits_created_at",
				"idx_asset_discovery_audits_scope_id", "idx_asset_discovery_audits_notebook_item_id",
			},
		},
		{
			Table: "asset_discovery_snapshots",
			Columns: []string{
				"schema_version", "tenant_id", "project_id", "audit_id", "provider", "expression", "query_hash", "config_version", "config_hash",
				"requested_limit", "provider_total", "returned_count", "skipped_rows", "truncated", "created_by", "created_at",
			},
			Indexes: []string{
				"idx_asset_discovery_snapshots_audit_id", "idx_asset_discovery_snapshots_tenant_id", "idx_asset_discovery_snapshots_project_id",
				"idx_asset_discovery_snapshots_provider", "idx_asset_discovery_snapshots_query_hash", "idx_asset_discovery_snapshots_created_by",
				"idx_asset_discovery_snapshots_created_at", "idx_asset_discovery_snapshots_project_created",
				"idx_asset_discovery_snapshots_scope_id",
			},
		},
		{
			Table: "asset_discovery_snapshot_items",
			Columns: []string{
				"tenant_id", "project_id", "snapshot_id", "position", "normalized_target", "target_hash", "ip", "port", "domain", "protocol",
				"title", "icp", "country", "city", "company", "status_code", "source", "observed_at", "created_at",
			},
			Indexes: []string{
				"idx_asset_discovery_snapshot_items_target", "idx_asset_discovery_snapshot_items_tenant_id", "idx_asset_discovery_snapshot_items_project_id",
				"idx_asset_discovery_snapshot_items_snapshot_id", "idx_asset_discovery_snapshot_items_ip", "idx_asset_discovery_snapshot_items_domain",
				"idx_asset_discovery_snapshot_items_protocol", "idx_asset_discovery_snapshot_items_source", "idx_asset_discovery_snapshot_items_observed_at",
				"idx_asset_discovery_snapshot_items_project_snapshot",
				"idx_asset_discovery_snapshot_items_scope_id",
			},
		},
		{
			Table: "asset_discovery_notebook_items",
			Columns: []string{
				"tenant_id", "project_id", "normalized_target", "target_hash", "created_by", "created_at", "updated_at", "updated_by", "note", "removed_at", "removed_by",
			},
			Indexes: []string{
				"idx_asset_discovery_notebook_items_target", "idx_asset_discovery_notebook_items_scope_id",
				"idx_asset_discovery_notebook_items_tenant_id", "idx_asset_discovery_notebook_items_project_id",
				"idx_asset_discovery_notebook_items_created_by", "idx_asset_discovery_notebook_items_created_at",
				"idx_asset_discovery_notebook_items_updated_at", "idx_asset_discovery_notebook_items_updated_by",
				"idx_asset_discovery_notebook_items_removed_at", "idx_asset_discovery_notebook_items_removed_by", "idx_adn_items_active_updated",
			},
		},
		{
			Table: "asset_discovery_notebook_sources",
			Columns: []string{
				"tenant_id", "project_id", "notebook_item_id", "snapshot_id", "snapshot_item_id", "audit_id", "archived_by", "archived_at",
			},
			Indexes: []string{
				"idx_asset_discovery_notebook_sources_snapshot_item", "idx_asset_discovery_notebook_sources_tenant_id",
				"idx_asset_discovery_notebook_sources_project_id", "idx_asset_discovery_notebook_sources_notebook_item_id",
				"idx_asset_discovery_notebook_sources_snapshot_id", "idx_asset_discovery_notebook_sources_snapshot_item_id",
				"idx_asset_discovery_notebook_sources_audit_id", "idx_asset_discovery_notebook_sources_archived_by",
				"idx_asset_discovery_notebook_sources_archived_at",
			},
		},
		{Table: "asset_discovery_notebook_tags", Columns: []string{"id", "tenant_id", "project_id", "name", "created_at"}, Indexes: []string{"idx_adn_tag", "idx_adn_tag_scope"}},
		{Table: "asset_discovery_notebook_item_tags", Columns: []string{"id", "tenant_id", "project_id", "notebook_item_id", "tag_id", "created_at"}, Indexes: []string{"idx_adn_item_tag"}},
		{
			Table: "asset_discovery_notebook_distribution_intents",
			Columns: []string{
				"schema_version", "tenant_id", "project_id", "root_task_id", "operator_id", "operation", "idempotency_key_hash", "request_hash", "plan_hash", "config_hash", "preview_schema_version", "task_status", "config_version", "rule_version", "selected", "fresh", "duplicate", "scope_added", "seed_targets_added", "batch_count", "status", "created_at",
			},
			Indexes: []string{"idx_addi_scope_id", "idx_addi_idempotency", "idx_addi_task_created", "idx_addi_operator_created", "idx_addi_status_created"},
		},
		{
			Table:   "asset_discovery_notebook_distribution_intent_items",
			Columns: []string{"tenant_id", "project_id", "intent_id", "position", "notebook_item_id", "normalized_target", "target_hash", "disposition", "created_at"},
			Indexes: []string{"idx_addii_scope_id", "idx_addii_intent_position", "idx_addii_intent_notebook_item", "idx_addii_intent_target_hash", "idx_addii_notebook_item", "idx_addii_target_hash"},
		},
		{
			Table:   "asset_discovery_notebook_distribution_materializations",
			Columns: []string{"tenant_id", "project_id", "intent_id", "root_task_id", "status", "task_status", "batch_ids", "attempt_ids", "created_at"},
			Indexes: []string{"idx_addm_scope_id", "idx_addm_intent", "idx_addm_task_created"},
		},
		{
			Table:   "task_creation_idempotencies",
			Columns: []string{"schema_version", "tenant_id", "project_id", "operator_id", "operation", "idempotency_key_hash", "request_hash", "root_task_id", "attempt_ids", "project_scope_added", "project_seeds_added", "created_at"},
			Indexes: []string{"idx_tci_scope_id", "idx_tci_idempotency", "idx_tci_task_created", "idx_tci_operator_created"},
		},
		{
			Table:   "task_append_idempotencies",
			Columns: []string{"schema_version", "tenant_id", "project_id", "root_task_id", "operator_id", "operation", "idempotency_key_hash", "request_hash", "outcome", "config_version", "config_hash", "rule_version", "before_status", "after_status", "batch_ids", "attempt_ids", "requested_targets", "new_targets", "duplicate_targets", "project_scope_added", "project_seeds_added", "total_chunks", "total_targets", "created_at"},
			Indexes: []string{"idx_tai_scope_id", "idx_tai_idempotency", "idx_tai_task_created", "idx_tai_operator_created"},
		},
		{
			Table:   "task_retry_idempotencies",
			Columns: []string{"schema_version", "tenant_id", "project_id", "root_task_id", "operator_id", "operation", "idempotency_key_hash", "request_hash", "before_status", "after_status", "attempt_ids", "completed_skipped", "paused_skipped", "created_at"},
			Indexes: []string{"idx_tri_scope_id", "idx_tri_idempotency", "idx_tri_task_created", "idx_tri_operator_created"},
		},
		{
			Table:   "task_batch_retry_idempotencies",
			Columns: []string{"schema_version", "tenant_id", "project_id", "root_task_id", "batch_id", "operator_id", "operation", "idempotency_key_hash", "request_hash", "attempt_id", "attempt_no", "config_version", "config_hash", "rule_version", "before_status", "after_status", "created_at"},
			Indexes: []string{"idx_tbri_scope_id", "idx_tbri_idempotency", "idx_tbri_batch_created", "idx_tbri_operator_created"},
		},
		{
			Table:   "risk_validation_execution_idempotencies",
			Columns: []string{"schema_version", "tenant_id", "project_id", "root_task_id", "operator_id", "operation", "idempotency_key_hash", "request_hash", "plan_hash", "poc_set_hash", "config_version", "config_hash", "rule_version", "batch_id", "batch_sequence", "attempt_id", "attempt_no", "candidate_count", "target_count", "poc_count", "estimated_requests", "second_confirmation_required", "before_status", "after_status", "created_at"},
			Indexes: []string{"idx_rvei_scope_id", "idx_rvei_idempotency", "idx_rvei_task_created", "idx_rvei_operator_created"},
		},
		{
			Table: "scan_observations",
			Columns: []string{
				"schema_version", "tenant_id", "project_id", "network_zone", "normalized_target", "target_hash", "stage", "work_key_hash",
				"scope_hash", "config_hash", "rule_version", "poc_set_hash", "endpoint_content_hash", "source_event_id", "root_task_id", "batch_id",
				"attempt_id", "agent_id", "outcome", "content_hash", "checkpoint", "checkpoint_hash", "evidence_hash", "error_code", "error_message", "observed_at", "created_at",
			},
			Indexes: []string{
				"idx_scan_observations_tenant_event", "idx_scan_observations_tenant_id", "idx_scan_observations_project_id", "idx_scan_observations_target_hash",
				"idx_scan_observations_stage", "idx_scan_observations_work_key_hash", "idx_scan_observations_rule_version", "idx_scan_observations_root_task_id",
				"idx_scan_observations_batch_id", "idx_scan_observations_attempt_id", "idx_scan_observations_agent_id", "idx_scan_observations_outcome",
				"idx_scan_observations_observed_at", "idx_scan_observations_scope",
			},
		},
		{
			Table: "scan_coverages",
			Columns: []string{
				"schema_version", "tenant_id", "project_id", "network_zone", "normalized_target", "target_hash", "stage", "work_key_hash",
				"scope_hash", "config_hash", "rule_version", "poc_set_hash", "endpoint_content_hash", "status", "outcome", "started_at", "finished_at",
				"valid_until", "observation_hash", "source_observation_id", "source_task_id", "source_batch_id", "source_attempt_id", "revision",
				"invalid_reason", "created_at", "updated_at",
			},
			Indexes: []string{
				"idx_scan_coverages_tenant_project_work", "idx_scan_coverages_tenant_id", "idx_scan_coverages_project_id", "idx_scan_coverages_stage",
				"idx_scan_coverages_rule_version", "idx_scan_coverages_status", "idx_scan_coverages_outcome", "idx_scan_coverages_finished_at",
				"idx_scan_coverages_valid_until", "idx_scan_coverages_source_observation_id", "idx_scan_coverages_source_task_id",
				"idx_scan_coverages_source_batch_id", "idx_scan_coverages_source_attempt_id", "idx_scan_coverages_lookup",
			},
		},
		{
			Table: "scan_work_claims",
			Columns: []string{
				"schema_version", "tenant_id", "project_id", "network_zone", "normalized_target", "target_hash", "stage", "work_key_hash", "scope_hash", "config_hash",
				"rule_version", "poc_set_hash", "endpoint_content_hash", "status", "owner_task_id", "owner_batch_id", "owner_attempt_id", "owner_agent_id",
				"lease_token_hash", "lease_expires_at", "claimed_at", "released_at", "revision", "last_error", "created_at", "updated_at",
			},
			Indexes: []string{
				"idx_scan_work_claims_tenant_project_work", "idx_scan_work_claims_tenant_id", "idx_scan_work_claims_project_id",
				"idx_scan_work_claims_network_zone", "idx_scan_work_claims_target_hash", "idx_scan_work_claims_stage", "idx_scan_work_claims_rule_version",
				"idx_scan_work_claims_status", "idx_scan_work_claims_owner_task_id", "idx_scan_work_claims_owner_batch_id",
				"idx_scan_work_claims_owner_attempt_id", "idx_scan_work_claims_owner_agent_id", "idx_scan_work_claims_lease_expires_at",
			},
		},
		{
			Table: "task_coverage_links",
			Columns: []string{
				"schema_version", "tenant_id", "project_id", "root_task_id", "batch_id", "attempt_id", "work_key_hash", "link_type", "status", "coverage_id", "claim_id",
				"source_task_id", "source_batch_id", "source_attempt_id", "reason", "created_at", "updated_at",
			},
			Indexes: []string{
				"idx_task_coverage_links_destination_work", "idx_task_coverage_links_tenant_id", "idx_task_coverage_links_project_id",
				"idx_task_coverage_links_root_task_id", "idx_task_coverage_links_batch_id", "idx_task_coverage_links_attempt_id",
				"idx_task_coverage_links_work_key_hash", "idx_task_coverage_links_link_type", "idx_task_coverage_links_status",
				"idx_task_coverage_links_coverage_id", "idx_task_coverage_links_claim_id", "idx_task_coverage_links_source_task_id",
				"idx_task_coverage_links_source_batch_id", "idx_task_coverage_links_source_attempt_id",
			},
		},
		{
			Table:   "scan_timing_events",
			Columns: []string{"schema_version", "tenant_id", "project_id", "root_task_id", "batch_id", "attempt_id", "agent_id", "source_event_id", "kind", "stage", "outcome", "started_at", "finished_at", "duration_ns", "config_version", "rule_version", "created_at"},
			Indexes: []string{"idx_scan_timing_events_tenant_source_event", "idx_scan_timing_events_scope_created", "idx_scan_timing_events_attempt_created"},
		},
		{
			Table:   "nodes",
			Columns: []string{"tenant_id", "running_task_ids", "os", "arch", "cpu_usage", "mem_usage", "token_expires_at", "token_revoked_at", "last_token_rotated_at"},
			Indexes: []string{"idx_nodes_tenant_id"},
		},
		{
			Table:   "agent_session_audits",
			Columns: []string{"tenant_id", "agent_id", "action", "reason", "operator_id", "created_at"},
			Indexes: []string{"idx_agent_session_audits_tenant_id", "idx_agent_session_audits_agent_id", "idx_agent_session_audits_action", "idx_agent_session_audits_operator_id", "idx_agent_session_audits_created_at"},
		},
		{
			Table:   "ws_event_logs",
			Columns: []string{"tenant_id", "project_id", "event_type", "payload", "occurred_at"},
			Indexes: []string{"idx_ws_event_logs_tenant_id", "idx_ws_event_logs_project_id", "idx_ws_event_logs_occurred_at"},
		},
		{
			Table:   "users",
			Columns: []string{"tenant_id", "username", "password_hash", "role", "status", "exp_authorized", "created_at", "updated_at"},
			Indexes: []string{"idx_users_username"},
		},
		{
			Table:   "system_configs",
			Columns: []string{"key", "value", "updated_at"},
		},
		{
			Table:   "domains",
			Columns: []string{"project_id", "records", "whois", "status"},
			Indexes: []string{"idx_domain_dedupe"},
		},
		{
			Table:   "assets",
			Columns: []string{"project_id", "tags", "cdn", "status", "owner_id", "cred_id", "updated_at"},
			Indexes: []string{"idx_asset_dedupe", "idx_assets_task_id", "idx_assets_status"},
		},
		{
			Table:   "credentials",
			Columns: []string{"project_id", "type", "deleted_at"},
			Indexes: []string{"idx_credentials_project_id", "idx_credentials_type", "idx_credentials_deleted_at"},
		},
		{
			Table:   "fingerprint_hits",
			Columns: []string{"project_id", "task_id", "rule_name", "updated_at"},
			Indexes: []string{"idx_fp_dedupe", "idx_fingerprint_hits_task_id"},
		},
		{
			Table:   "vulnerabilities",
			Columns: []string{"project_id", "status", "assignee", "ignore_reason", "verify_task_id", "request", "response", "description", "reference", "matched_at", "updated_at"},
			Indexes: []string{"idx_vuln_new_dedupe", "idx_vulnerabilities_status", "idx_vulnerabilities_verify_task_id"},
		},
		{
			Table:   "arsenals",
			Columns: []string{"previous_hash", "previous_content", "state"},
			Indexes: []string{"idx_arsenals_type", "idx_arsenals_state", "idx_arsenals_tenant_type_file", "idx_arsenals_tenant_type_state_updated"},
		},
		{
			Table:   "arsenal_events",
			Columns: []string{"tenant_id", "artifact_id", "type", "file_name", "version", "hash", "state", "action", "actor_id", "content", "details", "created_at"},
			Indexes: []string{"idx_arsenal_event_artifact", "idx_arsenal_events_type", "idx_arsenal_events_file_name", "idx_arsenal_events_version", "idx_arsenal_events_hash", "idx_arsenal_events_state", "idx_arsenal_events_action", "idx_arsenal_events_actor_id", "idx_arsenal_events_created_at"},
		},
		{
			Table:   "arsenal_ai_reviews",
			Columns: []string{"tenant_id", "type", "file_name", "content_hash", "suggestion", "confidence", "issues", "duplicate_candidates", "raw_response"},
			Indexes: []string{"idx_arsenal_ai_reviews_cache", "idx_arsenal_ai_reviews_content_hash", "idx_arsenal_ai_reviews_suggestion"},
		},
		{
			Table:   "ai_tool_invocations",
			Columns: []string{"tenant_id", "user_id", "module", "tool_name", "args_summary", "agent_id", "target_url", "duration_ms", "status", "error_summary", "created_at"},
			Indexes: []string{"idx_ai_tool_invocations_tenant_id", "idx_ai_tool_invocations_user_id", "idx_ai_tool_invocations_module", "idx_ai_tool_invocations_tool_name", "idx_ai_tool_invocations_status"},
		},
		{
			Table:   "custom_roles",
			Columns: []string{"tenant_id", "name", "label", "description", "base_role", "permissions", "created_at", "updated_at"},
			Indexes: []string{"idx_custom_roles_tenant_name", "idx_custom_roles_base_role"},
		},
		{
			Table:   "tenant_quotas",
			Columns: []string{"tenant_id", "max_concurrent_tasks", "max_running_sub_tasks", "daily_task_limit", "created_at", "updated_at"},
		},
		{
			Table:   "agent_logs",
			Columns: []string{"tenant_id", "agent_id", "level", "message", "timestamp", "created_at"},
			Indexes: []string{"idx_agent_logs_tenant_id", "idx_agent_logs_agent_id", "idx_agent_logs_timestamp"},
		},
		{
			Table:   "agent_log_alert_rules",
			Columns: []string{"tenant_id", "name", "agent_id", "level", "keyword", "enabled", "created_at", "updated_at"},
			Indexes: []string{"idx_agent_log_alert_rules_tenant_id", "idx_agent_log_alert_rules_name", "idx_agent_log_alert_rules_agent_id", "idx_agent_log_alert_rules_level"},
		},
		{
			Table:   "agent_log_alert_events",
			Columns: []string{"tenant_id", "rule_id", "agent_id", "level", "message", "log_id", "created_at"},
			Indexes: []string{"idx_agent_log_alert_events_tenant_id", "idx_agent_log_alert_events_rule_id", "idx_agent_log_alert_events_agent_id", "idx_agent_log_alert_events_level", "idx_agent_log_alert_events_log_id", "idx_agent_log_alert_events_created_at"},
		},
		{
			Table:   "agent_log_archives",
			Columns: []string{"tenant_id", "day", "storage_key", "log_count", "status", "error", "created_at"},
			Indexes: []string{"idx_agent_log_archives_tenant_id", "idx_agent_log_archives_day", "idx_agent_log_archives_status"},
		},
		{
			Table:   "build_jobs",
			Columns: []string{"platform", "arch", "components", "pack", "status", "artifact", "artifacts", "log_tail", "log_text", "error", "started_at", "finished_at"},
			Indexes: []string{"idx_build_jobs_platform", "idx_build_jobs_arch", "idx_build_jobs_status"},
		},
		{
			Table:   "reports",
			Columns: []string{"project_id", "type", "format", "file_url", "status", "created_by"},
			Indexes: []string{"idx_reports_project_id", "idx_reports_type", "idx_reports_created_by"},
		},
		{
			Table:   "rule_catalog_bootstraps",
			Columns: []string{"status", "aggregate_hash", "last_error"},
			Indexes: []string{"idx_rule_catalog_bootstraps_status", "idx_rule_catalog_bootstraps_aggregate_hash"},
		},
		{
			Table:   "cloud_accounts",
			Columns: []string{"tenant_id", "owner_user_id", "name", "provider", "access_key_id", "access_key_secret", "oss_bucket", "oss_endpoint", "status"},
			Indexes: []string{"idx_cloud_accounts_tenant", "idx_cloud_accounts_owner_user_id", "idx_cloud_accounts_status"},
		},
		{
			Table:   "cloud_account_bindings",
			Columns: []string{"tenant_id", "cloud_account_id", "user_id", "access_type"},
			Indexes: []string{"idx_cloud_account_binding_unique", "idx_cloud_account_bindings_user_id"},
		},
		{
			Table:   "cloud_scaling_policies",
			Columns: []string{"tenant_id", "cloud_account_id", "name", "enabled", "min_instances", "max_instances", "scale_up_threshold", "scale_down_threshold", "cooldown_seconds", "instance_ttl_minutes", "spot_strategy", "max_spot_price", "user_data_template", "last_scale_action"},
			Indexes: []string{"idx_cloud_policies_tenant", "idx_cloud_policies_account", "idx_cloud_policies_enabled"},
		},
		{
			Table:   "cloud_instances",
			Columns: []string{"tenant_id", "cloud_account_id", "policy_id", "provider_instance_id", "agent_id", "ip", "region", "status", "spot", "reboot_count", "error_message", "launched_at", "ready_at", "terminated_at", "deleted_at"},
			Indexes: []string{"idx_cloud_instances_tenant", "idx_cloud_instances_account", "idx_cloud_instances_policy", "idx_cloud_instances_agent", "idx_cloud_instances_provider_id", "idx_cloud_instances_status", "idx_cloud_instances_deleted"},
		},
		{
			Table:   "fingerprint_rules",
			Columns: []string{"artifact_id", "source_file", "product_name", "rule_expr", "enabled"},
			Indexes: []string{"idx_fp_rule_unique", "idx_fingerprint_rules_enabled", "idx_fingerprint_rules_tenant_enabled_product", "idx_fingerprint_rules_tenant_state_product", "idx_fingerprint_rules_product_trgm"},
		},
		{
			Table:   "poc_rules",
			Columns: []string{"artifact_id", "source_file", "name", "target_product", "cve", "compatibility_status", "source_version", "severity", "execution_class", "risk_level", "enabled"},
			Indexes: []string{"idx_poc_rule_unique", "idx_poc_rules_enabled", "idx_poc_rules_target_product", "idx_poc_rules_cve", "idx_poc_rules_compatibility_status", "idx_poc_rules_execution_class", "idx_poc_rules_risk_level", "idx_poc_rules_tenant_enabled_updated", "idx_poc_rules_name_trgm", "idx_poc_rules_source_file_trgm"},
		},
		{
			Table:   "active_fingerprint_rules",
			Columns: []string{"tenant_id", "artifact_id", "source_file", "name", "product_name", "content_hash", "version", "state", "enabled", "declared_auto_profile", "computed_auto_profile", "auto_eligible", "max_requests", "classification_reason"},
			Indexes: []string{"idx_active_finger_rule_unique", "idx_active_fingerprint_rules_artifact_id", "idx_active_fingerprint_rules_product_name", "idx_active_fingerprint_rules_content_hash", "idx_active_fingerprint_rules_state", "idx_active_fingerprint_rules_enabled", "idx_active_fingerprint_rules_auto_eligible", "idx_active_fingerprint_rules_tenant_auto"},
		},
		{
			Table:   "workflow_rules",
			Columns: []string{"artifact_id", "source_file", "product_name", "poc_name", "match_type", "enabled"},
			Indexes: []string{"idx_workflow_rule_unique", "idx_workflow_rules_enabled", "idx_workflow_rules_tenant_enabled_product", "idx_workflow_rules_tenant_poc", "idx_workflow_rules_product_trgm", "idx_workflow_rules_poc_trgm"},
		},
		{
			Table:   "workflow_product_summaries",
			Columns: []string{"tenant_id", "product_name", "is_general_poc", "match_types", "poc_names", "poc_count", "missing_poc_names", "missing_poc_count", "fingerprint_bound", "fingerprint_rule_count", "state", "enabled", "content_hash", "version", "updated_at"},
			Indexes: []string{"workflow_product_summaries_pkey", "idx_workflow_product_summaries_tenant_general", "idx_workflow_product_summaries_tenant_health", "idx_workflow_product_summaries_product_trgm"},
		},
		{
			Table:   "dir_rules",
			Columns: []string{"artifact_id", "source_file", "path", "product_name", "enabled"},
			Indexes: []string{"idx_dir_rule_unique", "idx_dir_rules_enabled"},
		},
	}
}

func VerifySchema(db *gorm.DB) error {
	specs := schemaTableSpecs()
	var missing []string
	for _, spec := range specs {
		ok, err := hasTable(db, spec.Table)
		if err != nil {
			return err
		}
		if !ok {
			missing = append(missing, fmt.Sprintf("missing table %s", spec.Table))
			continue
		}

		for _, column := range spec.Columns {
			ok, err := hasColumn(db, spec.Table, column)
			if err != nil {
				return err
			}
			if !ok {
				missing = append(missing, fmt.Sprintf("missing column %s.%s", spec.Table, column))
			}
		}

		for _, index := range spec.Indexes {
			ok, err := hasIndex(db, index)
			if err != nil {
				return err
			}
			if !ok {
				missing = append(missing, fmt.Sprintf("missing index %s", index))
			}
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("schema verification failed:\n- %s", strings.Join(missing, "\n- "))
	}

	return nil
}

func hasTable(db *gorm.DB, table string) (bool, error) {
	var exists bool
	err := db.Raw(`
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.tables
			WHERE table_schema = current_schema()
			  AND table_name = ?
		)
	`, table).Scan(&exists).Error
	if err != nil {
		return false, fmt.Errorf("check table %s failed: %w", table, err)
	}
	return exists, nil
}

func hasColumn(db *gorm.DB, table, column string) (bool, error) {
	var exists bool
	err := db.Raw(`
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.columns
			WHERE table_schema = current_schema()
			  AND table_name = ?
			  AND column_name = ?
		)
	`, table, column).Scan(&exists).Error
	if err != nil {
		return false, fmt.Errorf("check column %s.%s failed: %w", table, column, err)
	}
	return exists, nil
}

func hasIndex(db *gorm.DB, index string) (bool, error) {
	var exists bool
	err := db.Raw(`
		SELECT EXISTS (
			SELECT 1
			FROM pg_indexes
			WHERE schemaname = current_schema()
			  AND indexname = ?
		)
	`, index).Scan(&exists).Error
	if err != nil {
		return false, fmt.Errorf("check index %s failed: %w", index, err)
	}
	return exists, nil
}
