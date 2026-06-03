package db

import (
	"reflect"
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

func TestSchemaModelTableNames(t *testing.T) {
	expected := map[string]string{
		"SchemaMigration":      "schema_migrations",
		"Project":              "projects",
		"ProjectMember":        "project_members",
		"CronTask":             "cron_tasks",
		"RootTask":             "root_tasks",
		"SubTask":              "sub_tasks",
		"NotificationRule":     "notification_rules",
		"Domain":               "domains",
		"Asset":                "assets",
		"Credential":           "credentials",
		"FingerprintHit":       "fingerprint_hits",
		"Vulnerability":        "vulnerabilities",
		"AssetChangeLog":       "asset_change_logs",
		"Report":               "reports",
		"Node":                 "nodes",
		"AgentSessionAudit":    "agent_session_audits",
		"WSEventLog":           "ws_event_logs",
		"Arsenal":              "arsenals",
		"ArsenalAIReview":      "arsenal_ai_reviews",
		"AIToolInvocation":     "ai_tool_invocations",
		"User":                 "users",
		"CustomRole":           "custom_roles",
		"TenantQuota":          "tenant_quotas",
		"SystemConfig":         "system_configs",
		"AgentLog":             "agent_logs",
		"AgentLogAlertRule":    "agent_log_alert_rules",
		"AgentLogAlertEvent":   "agent_log_alert_events",
		"AgentLogArchive":      "agent_log_archives",
		"BuildJob":             "build_jobs",
		"RuleCatalogBootstrap": "rule_catalog_bootstraps",
		"FingerprintRule":      "fingerprint_rules",
		"PocRule":              "poc_rules",
		"WorkflowRule":         "workflow_rules",
		"DirRule":              "dir_rules",
		"ExploitRule":          "exploit_rules",
		"ExploitAudit":         "exploit_audits",
		"ExploitRiskWaiver":    "exploit_risk_waivers",
		"ExploitRun":           "exploit_runs",
		"ExploitArtifact":      "exploit_artifacts",
		"AgentPyenvJob":        "agent_pyenv_jobs",
		"CloudAccount":         "cloud_accounts",
		"CloudAccountBinding":  "cloud_account_bindings",
		"CloudScalingPolicy":   "cloud_scaling_policies",
		"CloudInstance":        "cloud_instances",
	}

	models := append([]interface{}{&SchemaMigration{}}, schemaModels()...)
	seen := make(map[string]bool, len(models))
	for _, model := range models {
		modelName := reflect.TypeOf(model).Elem().Name()
		want, ok := expected[modelName]
		if !ok {
			t.Fatalf("missing expected table name for model %s", modelName)
		}
		got := gormTableName(t, model)
		if got != want {
			t.Fatalf("%s table name = %q, want %q", modelName, got, want)
		}
		seen[modelName] = true
	}

	for modelName := range expected {
		if !seen[modelName] {
			t.Fatalf("expected model %s was not covered by schemaModels", modelName)
		}
	}
}

func TestSchemaVerifyCoversRuntimeModels(t *testing.T) {
	verifiedTables := make(map[string]bool)
	for _, spec := range schemaTableSpecs() {
		verifiedTables[spec.Table] = true
	}

	for _, model := range schemaModels() {
		tableName := gormTableName(t, model)
		if !verifiedTables[tableName] {
			t.Fatalf("schema verification does not cover model table %q", tableName)
		}
	}
}

func gormTableName(t *testing.T, model interface{}) string {
	t.Helper()
	parsed, err := schema.Parse(model, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatalf("parse schema for %T: %v", model, err)
	}
	return parsed.Table
}
