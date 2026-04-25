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

func VerifySchema(db *gorm.DB) error {
	specs := []schemaTableSpec{
		{
			Table:   "schema_migrations",
			Columns: []string{"version", "name", "checksum", "applied_at"},
		},
		{
			Table:   "projects",
			Columns: []string{"tenant_id", "name", "status", "deleted_at"},
			Indexes: []string{"idx_projects_tenant_id", "idx_projects_status", "idx_projects_deleted_at"},
		},
		{
			Table:   "project_members",
			Columns: []string{"project_id", "user_id", "role"},
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
			Columns: []string{"project_id", "agent_selector", "timeout_sec", "retry_count", "max_retry"},
			Indexes: []string{"idx_sub_tasks_project_id", "idx_sub_tasks_root_task_id", "idx_sub_tasks_status"},
		},
		{
			Table:   "nodes",
			Columns: []string{"tenant_id", "running_task_ids", "os", "arch", "cpu_usage", "mem_usage"},
			Indexes: []string{"idx_nodes_tenant_id"},
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
			Indexes: []string{"idx_arsenals_type", "idx_arsenals_state"},
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
			Table:   "fingerprint_rules",
			Columns: []string{"artifact_id", "source_file", "product_name", "rule_expr", "enabled"},
			Indexes: []string{"idx_fp_rule_unique", "idx_fingerprint_rules_enabled"},
		},
		{
			Table:   "poc_rules",
			Columns: []string{"artifact_id", "source_file", "name", "severity", "enabled"},
			Indexes: []string{"idx_poc_rule_unique", "idx_poc_rules_enabled"},
		},
		{
			Table:   "workflow_rules",
			Columns: []string{"artifact_id", "source_file", "product_name", "poc_name", "match_type", "enabled"},
			Indexes: []string{"idx_workflow_rule_unique", "idx_workflow_rules_enabled"},
		},
		{
			Table:   "dir_rules",
			Columns: []string{"artifact_id", "source_file", "path", "product_name", "enabled"},
			Indexes: []string{"idx_dir_rule_unique", "idx_dir_rules_enabled"},
		},
	}

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
