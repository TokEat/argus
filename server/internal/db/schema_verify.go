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
			Table:   "projects",
			Columns: []string{"tenant_id", "owner_user_id", "name", "status", "deleted_at"},
			Indexes: []string{"idx_projects_tenant_id", "idx_projects_owner_user_id", "idx_projects_status", "idx_projects_deleted_at"},
		},
		{
			Table:   "project_members",
			Columns: []string{"tenant_id", "project_id", "user_id", "role"},
		},
		{
			Table:   "cron_tasks",
			Columns: []string{"project_id", "cron_expr", "next_run_at", "status", "deleted_at"},
			Indexes: []string{"idx_cron_tasks_project_id", "idx_cron_tasks_status", "idx_cron_tasks_deleted_at"},
		},
		{
			Table:   "root_tasks",
			Columns: []string{"project_id", "cron_task_id", "total_targets", "completed_targets", "status"},
			Indexes: []string{"idx_root_tasks_tenant_id", "idx_root_tasks_project_id", "idx_root_tasks_status"},
		},
		{
			Table:   "sub_tasks",
			Columns: []string{"project_id", "agent_selector", "agent_selector_rules", "timeout_sec", "retry_count", "max_retry"},
			Indexes: []string{"idx_sub_tasks_project_id", "idx_sub_tasks_root_task_id", "idx_sub_tasks_status"},
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
			Columns: []string{"project_id", "tags", "status", "owner_id", "cred_id", "updated_at"},
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
			Table:   "exploit_audits",
			Columns: []string{"tenant_id", "exploit_rule_id", "rule_id", "action", "reason", "operator_id", "metadata", "created_at"},
			Indexes: []string{"idx_exploit_audits_tenant_id", "idx_exploit_audits_exploit_rule_id", "idx_exploit_audits_rule_id", "idx_exploit_audits_action", "idx_exploit_audits_operator_id"},
		},
		{
			Table:   "exploit_risk_waivers",
			Columns: []string{"tenant_id", "rule_id", "reason", "created_by", "expires_at", "created_at", "updated_at"},
			Indexes: []string{"idx_exploit_risk_waiver_rule", "idx_exploit_risk_waivers_created_by", "idx_exploit_risk_waivers_expires_at"},
		},
		{
			Table:   "exploit_runs",
			Columns: []string{"tenant_id", "project_id", "target", "exploit_id", "agent_id", "risk_level", "status", "credential_ref", "params_digest", "params_ciphertext", "cleanup_status"},
			Indexes: []string{"idx_exploit_runs_tenant_id", "idx_exploit_runs_project_id", "idx_exploit_runs_exploit_id", "idx_exploit_runs_status", "idx_exploit_runs_credential_ref"},
		},
		{
			Table:   "exploit_artifacts",
			Columns: []string{"tenant_id", "run_id", "artifact_type", "file_name", "content", "content_hash", "size_bytes", "created_at"},
			Indexes: []string{"idx_exploit_artifacts_tenant_id", "idx_exploit_artifacts_run_id", "idx_exploit_artifacts_type"},
		},
		{
			Table:   "agent_pyenv_jobs",
			Columns: []string{"tenant_id", "agent_id", "operator_id", "exploit_rule_id", "requirements", "requirements_hash", "status", "logs", "error", "started_at", "finished_at"},
			Indexes: []string{"idx_agent_pyenv_jobs_tenant_id", "idx_agent_pyenv_jobs_agent_id", "idx_agent_pyenv_jobs_operator_id", "idx_agent_pyenv_jobs_exploit_rule_id", "idx_agent_pyenv_jobs_requirements_hash", "idx_agent_pyenv_jobs_status"},
		},
		{
			Table:   "notification_rules",
			Columns: []string{"project_id", "event", "channel", "config", "status"},
			Indexes: []string{"idx_notification_rules_project_id", "idx_notification_rules_event"},
		},
		{
			Table:   "asset_change_logs",
			Columns: []string{"project_id", "task_id", "entity_type", "entity_id", "change_type", "details"},
			Indexes: []string{"idx_asset_change_logs_project_id", "idx_asset_change_logs_task_id", "idx_asset_change_logs_entity_type"},
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
			Columns: []string{"artifact_id", "source_file", "name", "target_product", "cve", "compatibility_status", "source_version", "severity", "enabled"},
			Indexes: []string{"idx_poc_rule_unique", "idx_poc_rules_enabled", "idx_poc_rules_target_product", "idx_poc_rules_cve", "idx_poc_rules_compatibility_status", "idx_poc_rules_tenant_enabled_updated", "idx_poc_rules_name_trgm", "idx_poc_rules_source_file_trgm"},
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
		{
			Table:   "exploit_rules",
			Columns: []string{"artifact_id", "source_file", "rule_id", "name", "description", "target_product", "cve", "risk_level", "requires_auth", "side_effects", "cleanup_supported", "cleanup_required", "dry_run_supported", "capabilities", "linked_pocs", "params_schema", "requirements", "requirements_hash", "sandbox_profile", "timeout_sec", "runtime_engine", "enabled"},
			Indexes: []string{"idx_exploit_rule_unique", "idx_exploit_rules_enabled", "idx_exploit_rules_runtime_engine", "idx_exploit_rules_requirements_hash", "idx_exploit_rules_sandbox_profile", "idx_exploit_rules_tenant_enabled_updated", "idx_exploit_rules_rule_id_trgm", "idx_exploit_rules_name_trgm"},
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
