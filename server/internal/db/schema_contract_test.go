package db

import (
	"reflect"
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

func TestSchemaModelTableNames(t *testing.T) {
	expected := map[string]string{
		"SchemaMigration":              "schema_migrations",
		"Project":                      "projects",
		"ProjectMember":                "project_members",
		"RootTask":                     "root_tasks",
		"SubTask":                      "sub_tasks",
		"TaskBatch":                    "task_batches",
		"TaskConfigRevision":           "task_config_revisions",
		"TaskAudit":                    "task_audits",
		"ScanPolicyIntent":             "scan_policy_intents",
		"ScanStageDerivation":          "scan_stage_derivations",
		"CredentialDictionary":         "credential_dictionaries",
		"CredentialDictionaryRevision": "credential_dictionary_revisions",
		"SubdomainDictionary":          "subdomain_dictionaries",
		"SubdomainDictionaryRevision":  "subdomain_dictionary_revisions",
		"SubdomainPassiveCache":        "subdomain_passive_cache",
		"SubdomainPassiveJob":          "subdomain_passive_jobs",
		"CredentialBundle":             "credential_bundles",
		"CredentialFindingSecret":      "credential_finding_secrets",
		"CredentialRevealAudit":        "credential_reveal_audits",
		"AssetDiscoveryAudit":          "asset_discovery_audits",
		"ScanObservation":              "scan_observations",
		"ScanCoverage":                 "scan_coverages",
		"ScanWorkClaim":                "scan_work_claims",
		"TaskCoverageLink":             "task_coverage_links",
		"ScanTimingEvent":              "scan_timing_events",
		"Domain":                       "domains",
		"Asset":                        "assets",
		"Credential":                   "credentials",
		"FingerprintHit":               "fingerprint_hits",
		"Vulnerability":                "vulnerabilities",
		"Report":                       "reports",
		"Node":                         "nodes",
		"AgentSessionAudit":            "agent_session_audits",
		"WSEventLog":                   "ws_event_logs",
		"Arsenal":                      "arsenals",
		"ArsenalEvent":                 "arsenal_events",
		"ArsenalAIReview":              "arsenal_ai_reviews",
		"AIToolInvocation":             "ai_tool_invocations",
		"User":                         "users",
		"CustomRole":                   "custom_roles",
		"TenantQuota":                  "tenant_quotas",
		"SystemConfig":                 "system_configs",
		"AgentLog":                     "agent_logs",
		"AgentLogAlertRule":            "agent_log_alert_rules",
		"AgentLogAlertEvent":           "agent_log_alert_events",
		"AgentLogArchive":              "agent_log_archives",
		"BuildJob":                     "build_jobs",
		"RuleCatalogBootstrap":         "rule_catalog_bootstraps",
		"FingerprintRule":              "fingerprint_rules",
		"PocRule":                      "poc_rules",
		"ActiveFingerprintRule":        "active_fingerprint_rules",
		"WorkflowRule":                 "workflow_rules",
		"WorkflowProductSummary":       "workflow_product_summaries",
		"DirRule":                      "dir_rules",
		"ExpEgressAudit":               "exp_egress_audits",
		"Exp":                          "exps",
		"ExpRevision":                  "exp_revisions",
		"ExpDependency":                "exp_dependencies",
		"ExpAsset":                     "exp_assets",
		"ExpAssetRef":                  "exp_asset_refs",
		"ExpTestCase":                  "exp_test_cases",
		"ExpRun":                       "exp_runs",
		"ExpAudit":                     "exp_audits",
		"ExpRiskWaiver":                "exp_risk_waivers",
		"CloudAccount":                 "cloud_accounts",
		"CloudAccountBinding":          "cloud_account_bindings",
		"CloudScalingPolicy":           "cloud_scaling_policies",
		"CloudInstance":                "cloud_instances",
		"OAuthClient":                  "oauth_clients",
		"OAuthAuthorizationCode":       "oauth_authorization_codes",
		"OAuthRefreshToken":            "oauth_refresh_tokens",
	}
	expected["AssetDiscoverySnapshot"] = "asset_discovery_snapshots"
	expected["AssetDiscoverySnapshotItem"] = "asset_discovery_snapshot_items"
	expected["AssetDiscoveryNotebookItem"] = "asset_discovery_notebook_items"
	expected["AssetDiscoveryNotebookSource"] = "asset_discovery_notebook_sources"
	expected["AssetDiscoveryNotebookTag"] = "asset_discovery_notebook_tags"
	expected["AssetDiscoveryNotebookItemTag"] = "asset_discovery_notebook_item_tags"
	expected["AssetDiscoveryNotebookDistributionIntent"] = "asset_discovery_notebook_distribution_intents"
	expected["AssetDiscoveryNotebookDistributionIntentItem"] = "asset_discovery_notebook_distribution_intent_items"
	expected["AssetDiscoveryNotebookDistributionMaterialization"] = "asset_discovery_notebook_distribution_materializations"
	expected["TaskCreationIdempotency"] = "task_creation_idempotencies"
	expected["TaskAppendIdempotency"] = "task_append_idempotencies"
	expected["TaskRetryIdempotency"] = "task_retry_idempotencies"
	expected["TaskBatchRetryIdempotency"] = "task_batch_retry_idempotencies"
	expected["RiskValidationExecutionIdempotency"] = "risk_validation_execution_idempotencies"

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
