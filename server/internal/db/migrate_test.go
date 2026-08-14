package db

import (
	"strings"
	"testing"
)

func TestParseMigrationMode(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    MigrationMode
		wantErr bool
	}{
		{name: "empty defaults to apply", raw: "", want: MigrationModeApply},
		{name: "apply", raw: "apply", want: MigrationModeApply},
		{name: "verify", raw: "verify", want: MigrationModeVerify},
		{name: "dev-auto", raw: "dev-auto", want: MigrationModeDevAuto},
		{name: "invalid", raw: "sqlite", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMigrationMode(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestLoadMigrations(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations returned error: %v", err)
	}
	if len(migrations) == 0 {
		t.Fatalf("expected embedded migrations, got none")
	}

	prev := ""
	for _, migration := range migrations {
		if migration.Version == "" || migration.Name == "" {
			t.Fatalf("invalid migration metadata: %+v", migration)
		}
		if migration.Checksum == "" {
			t.Fatalf("migration checksum missing for %s", migration.Path)
		}
		if prev != "" && migration.Version < prev {
			t.Fatalf("migrations out of order: %s before %s", prev, migration.Version)
		}
		prev = migration.Version
	}
}

func TestRetiredMigrationVersionIsNotReused(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := retiredMigrationVersions["510"]; !ok {
		t.Fatal("version 510 must remain retired for databases containing either historical checksum")
	}

	foundScanPolicy := false
	for _, migration := range migrations {
		if _, retired := retiredMigrationVersions[migration.Version]; retired {
			t.Fatalf("retired migration version %s is reused by %s", migration.Version, migration.Path)
		}
		if migration.Version == "560" && migration.Name == "add_scan_policy_orchestration" {
			foundScanPolicy = true
		}
	}
	if !foundScanPolicy {
		t.Fatal("scan policy orchestration migration must use version 560")
	}
}

func TestActiveFingerprintMigrationIsAdditive(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if migration.Version != "540" {
			continue
		}
		for _, required := range []string{
			"CREATE TABLE IF NOT EXISTS active_fingerprint_rules",
			"idx_active_finger_rule_unique",
			"idx_active_fingerprint_rules_tenant_auto",
			"ADD COLUMN IF NOT EXISTS active_finger_count",
		} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("active fingerprint migration missing %q", required)
			}
		}
		if strings.Contains(strings.ToUpper(migration.SQL), "DROP TABLE") {
			t.Fatal("active fingerprint migration must be additive")
		}
		return
	}
	t.Fatal("expected active fingerprint migration 540")
}

func TestSplitSQLStatements(t *testing.T) {
	sql := `
CREATE TABLE foo (id INT);

ALTER TABLE foo ADD COLUMN name TEXT;
`
	stmts := splitSQLStatements(sql)
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}
}

func TestTenantQuotaCompatMigrationPresent(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations returned error: %v", err)
	}

	found220 := false
	found230 := false
	for _, migration := range migrations {
		switch migration.Version {
		case "220":
			found220 = true
			if !strings.Contains(migration.SQL, "CREATE TABLE IF NOT EXISTS tenant_quotas") {
				t.Fatalf("tenant quota compat migration must ensure tenant_quotas exists")
			}
			if !strings.Contains(migration.SQL, "CREATE VIEW public.tenant_quota") {
				t.Fatalf("tenant quota compat migration must provide the singular compatibility view")
			}
		case "230":
			found230 = true
			if !strings.Contains(migration.SQL, "ALTER TABLE public.tenant_quota RENAME TO") {
				t.Fatalf("tenant quota canonical migration must move legacy singular tables away")
			}
		}
	}

	if !found220 || !found230 {
		t.Fatalf("expected tenant quota compatibility migrations 220 and 230, got 220=%v 230=%v", found220, found230)
	}
}

func TestTaskBatchMigrationBackfillsAttemptsWithoutDroppingLegacyData(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations returned error: %v", err)
	}

	for _, migration := range migrations {
		if migration.Version != "310" {
			continue
		}
		for _, required := range []string{
			"CREATE TABLE IF NOT EXISTS task_batches",
			"INSERT INTO task_batches",
			"FROM sub_tasks st",
			"UPDATE sub_tasks SET batch_id = id",
		} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("task batch migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		if strings.Contains(upperSQL, "DROP TABLE") || strings.Contains(upperSQL, "DELETE FROM SUB_TASKS") {
			t.Fatal("task batch migration must not drop or delete legacy attempts")
		}
		return
	}

	t.Fatal("expected task batch migration 310")
}

func TestAttemptHistoryMigrationPreservesLegacyRows(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations returned error: %v", err)
	}

	for _, migration := range migrations {
		if migration.Version != "320" {
			continue
		}
		for _, required := range []string{
			"ADD COLUMN IF NOT EXISTS parent_attempt_id",
			"ADD COLUMN IF NOT EXISTS trigger",
			"ADD COLUMN IF NOT EXISTS failure_reason",
			"ADD COLUMN IF NOT EXISTS started_at",
			"ADD COLUMN IF NOT EXISTS finished_at",
		} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("attempt history migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		if strings.Contains(upperSQL, "DROP TABLE") || strings.Contains(upperSQL, "DELETE FROM SUB_TASKS") {
			t.Fatal("attempt history migration must not drop or delete legacy attempts")
		}
		return
	}

	t.Fatal("expected attempt history migration 320")
}

func TestTaskBatchControlMigrationIsAdditive(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations returned error: %v", err)
	}

	for _, migration := range migrations {
		if migration.Version != "330" {
			continue
		}
		for _, required := range []string{
			"ADD COLUMN IF NOT EXISTS control_state",
			"DEFAULT 'active'",
			"idx_task_batches_control_state",
		} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("task batch control migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		if strings.Contains(upperSQL, "DROP TABLE") || strings.Contains(upperSQL, "DELETE FROM TASK_BATCHES") {
			t.Fatal("task batch control migration must not drop or delete batches")
		}
		return
	}

	t.Fatal("expected task batch control migration 330")
}

func TestPocExecutionGovernanceMigrationIsAdditive(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations returned error: %v", err)
	}

	for _, migration := range migrations {
		if migration.Version != "340" {
			continue
		}
		for _, required := range []string{
			"ADD COLUMN IF NOT EXISTS execution_class",
			"ADD COLUMN IF NOT EXISTS risk_level",
			"DEFAULT 'detection'",
			"DEFAULT 'unknown'",
			"idx_poc_rules_execution_class",
			"idx_poc_rules_risk_level",
		} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("POC execution governance migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		if strings.Contains(upperSQL, "DROP TABLE") || strings.Contains(upperSQL, "DELETE FROM POC_RULES") {
			t.Fatal("POC execution governance migration must not drop or delete rules")
		}
		return
	}

	t.Fatal("expected POC execution governance migration 340")
}

func TestScanMemoryStorageMigrationIsAdditiveAndTenantScoped(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "350" {
			continue
		}
		for _, required := range []string{
			"CREATE TABLE IF NOT EXISTS scan_observations",
			"CREATE TABLE IF NOT EXISTS scan_coverages",
			"CREATE TABLE IF NOT EXISTS scan_work_claims",
			"CREATE TABLE IF NOT EXISTS task_coverage_links",
			"idx_scan_observations_tenant_event",
			"idx_scan_coverages_tenant_project_work",
			"idx_scan_work_claims_tenant_project_work",
			"idx_task_coverage_links_destination_work",
		} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("scan memory migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		if strings.Contains(upperSQL, "DROP TABLE") || strings.Contains(upperSQL, "DELETE FROM") || strings.Contains(upperSQL, "TRUNCATE") {
			t.Fatal("scan memory migration must only add storage and indexes")
		}
		return
	}
	t.Fatal("expected scan memory migration 350")
}

func TestScanObservationCheckpointMigrationIsAdditive(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "360" {
			continue
		}
		for _, required := range []string{
			"ALTER TABLE scan_observations",
			"ADD COLUMN IF NOT EXISTS checkpoint JSONB",
			"ADD COLUMN IF NOT EXISTS checkpoint_hash VARCHAR(64)",
		} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("scan checkpoint migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		if strings.Contains(upperSQL, "DROP TABLE") || strings.Contains(upperSQL, "DELETE FROM") || strings.Contains(upperSQL, "TRUNCATE") {
			t.Fatal("scan checkpoint migration must only add columns")
		}
		return
	}
	t.Fatal("expected scan checkpoint migration 360")
}

func TestAssetDiscoveryAuditMigrationIsAdditiveAndDoesNotStoreSecrets(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "370" {
			continue
		}
		for _, required := range []string{
			"CREATE TABLE IF NOT EXISTS asset_discovery_audits",
			"query_hash VARCHAR(64)",
			"config_hash VARCHAR(64)",
			"idx_asset_discovery_audits_tenant_id",
			"idx_asset_discovery_audits_project_id",
			"idx_asset_discovery_audits_query_hash",
		} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("asset discovery audit migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "TRUNCATE ", "CREDENTIAL", "API_KEY", "RESPONSE_BODY", "QUERY_EXPRESSION"} {
			if strings.Contains(upperSQL, forbidden) {
				t.Fatalf("asset discovery audit migration contains forbidden term %q", forbidden)
			}
		}
		return
	}
	t.Fatal("expected asset discovery audit migration 370")
}

func TestAssetDiscoverySnapshotMigrationIsAdditiveAndScoped(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "380" {
			continue
		}
		for _, required := range []string{
			"CREATE TABLE IF NOT EXISTS asset_discovery_snapshots",
			"CREATE TABLE IF NOT EXISTS asset_discovery_snapshot_items",
			"schema_version VARCHAR(64)",
			"tenant_id TEXT",
			"project_id TEXT",
			"audit_id BIGINT",
			"expression TEXT",
			"normalized_target TEXT",
			"target_hash VARCHAR(64)",
			"idx_asset_discovery_audits_scope_id",
			"idx_asset_discovery_snapshots_project_created",
			"fk_asset_discovery_snapshots_audit",
			"idx_asset_discovery_snapshots_scope_id",
			"idx_asset_discovery_snapshot_items_target",
			"fk_asset_discovery_snapshot_items_snapshot",
			"idx_asset_discovery_snapshot_items_project_snapshot",
		} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("asset discovery snapshot migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "TRUNCATE ", "CREDENTIAL", "API_KEY", "TOKEN", "RAW_RESPONSE", "RESPONSE_BODY"} {
			if strings.Contains(upperSQL, forbidden) {
				t.Fatalf("asset discovery snapshot migration contains forbidden term %q", forbidden)
			}
		}
		return
	}
	t.Fatal("expected asset discovery snapshot migration 380")
}

func TestAssetDiscoveryNotebookMigrationIsAdditiveAndScoped(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "390" {
			continue
		}
		for _, required := range []string{
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_discovery_snapshot_items_scope_id",
			"CREATE TABLE IF NOT EXISTS asset_discovery_notebook_items",
			"CREATE TABLE IF NOT EXISTS asset_discovery_notebook_sources",
			"normalized_target TEXT",
			"target_hash VARCHAR(64)",
			"notebook_item_id BIGINT",
			"snapshot_item_id BIGINT",
			"fk_asset_discovery_notebook_sources_item",
			"fk_asset_discovery_notebook_sources_snapshot_item",
			"fk_asset_discovery_notebook_sources_audit",
			"ON DELETE RESTRICT",
			"idx_asset_discovery_notebook_items_target",
			"idx_asset_discovery_notebook_sources_snapshot_item",
		} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("asset discovery notebook migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "TRUNCATE ", "CREDENTIAL", "API_KEY", "TOKEN", "RAW_RESPONSE", "RESPONSE_BODY", "EXPRESSION"} {
			if strings.Contains(upperSQL, forbidden) {
				t.Fatalf("asset discovery notebook migration contains forbidden term %q", forbidden)
			}
		}
		return
	}
	t.Fatal("expected asset discovery notebook migration 390")
}

func TestAssetDiscoveryNotebookDistributionIntentMigrationIsAdditiveAndScoped(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "400" {
			continue
		}
		for _, required := range []string{
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_root_tasks_scope_id",
			"CREATE UNIQUE INDEX IF NOT EXISTS idx_task_config_revisions_scope_version",
			"CREATE TABLE IF NOT EXISTS asset_discovery_notebook_distribution_intents",
			"CREATE TABLE IF NOT EXISTS asset_discovery_notebook_distribution_intent_items",
			"schema_version VARCHAR(64)",
			"idempotency_key_hash VARCHAR(64)",
			"idempotency_key_hash ~ '^[0-9a-f]{64}$'",
			"CHECK (operation = 'materialize')",
			"selected BETWEEN 1 AND 100",
			"fresh + duplicate = selected",
			"CHECK (status = 'recorded')",
			"CHECK (position BETWEEN 0 AND 99)",
			"target_hash ~ '^[0-9a-f]{64}$'",
			"CHECK (disposition IN ('new', 'duplicate'))",
			"fk_addi_root_task",
			"fk_addi_config_revision",
			"fk_addii_intent",
			"fk_addii_notebook_item",
			"ON DELETE RESTRICT",
			"idx_addi_idempotency",
			"idx_addii_intent_position",
			"idx_addii_intent_notebook_item",
			"idx_addii_intent_target_hash",
		} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("asset discovery notebook distribution intent migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "TRUNCATE ", "CREDENTIAL", "API_KEY", "TOKEN", "RAW_RESPONSE", "RESPONSE_BODY", "EXPRESSION"} {
			if strings.Contains(upperSQL, forbidden) {
				t.Fatalf("asset discovery notebook distribution intent migration contains forbidden term %q", forbidden)
			}
		}
		return
	}
	t.Fatal("expected asset discovery notebook distribution intent migration 400")
}

func TestScanTimingEventMigrationIsAdditiveAndScoped(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "410" {
			continue
		}
		for _, required := range []string{"CREATE TABLE IF NOT EXISTS scan_timing_events", "schema_version = 'argus.timing/v1'", "source_event_id ~ '^[0-9a-f]{64}$'", "duration_ns >= 0", "finished_at >= started_at", "CREATE INDEX IF NOT EXISTS idx_scan_timing_events_scope_created", "idx_scan_timing_events_tenant_source_event", "idx_sub_tasks_scope_attempt_agent_id", "fk_scan_timing_event_attempt", "fk_scan_timing_event_attempt_agent", "ON DELETE RESTRICT"} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("scan timing migration missing %q", required)
			}
		}
		if strings.Contains(migration.SQL, "CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_timing_events_scope_created") {
			t.Fatal("scope-created timing index must not be unique")
		}
		if strings.Contains(migration.SQL, "REFERENCES nodes") {
			t.Fatal("timing evidence must not block cleanup of ephemeral Agent nodes")
		}
		upperSQL := strings.ToUpper(migration.SQL)
		for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "TRUNCATE ", "MESSAGE", "CREDENTIAL"} {
			if strings.Contains(upperSQL, forbidden) {
				t.Fatalf("scan timing migration contains forbidden term %q", forbidden)
			}
		}
		return
	}
	t.Fatal("expected scan timing event migration 410")
}

func TestNotebookDistributionMaterializationMigrationIsAdditiveAndScoped(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "420" {
			continue
		}
		for _, required := range []string{"CREATE TABLE IF NOT EXISTS asset_discovery_notebook_distribution_materializations", "intent_id BIGINT NOT NULL", "batch_ids JSONB NOT NULL", "attempt_ids JSONB NOT NULL", "CHECK (status IN ('materialized', 'unchanged'))", "jsonb_typeof(batch_ids) = 'array'", "jsonb_array_length(batch_ids) <= 100", "status <> 'unchanged' OR jsonb_array_length(batch_ids) = 0", "fk_addm_intent", "fk_addm_root_task", "ON DELETE RESTRICT", "idx_addm_intent"} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("materialization migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "TRUNCATE ", "CREDENTIAL", "API_KEY", "TOKEN", "RAW_RESPONSE", "RESPONSE_BODY", "EXPRESSION"} {
			if strings.Contains(upperSQL, forbidden) {
				t.Fatalf("materialization migration contains forbidden term %q", forbidden)
			}
		}
		return
	}
	t.Fatal("expected notebook distribution materialization migration 420")
}

func TestTaskCreationIdempotencyMigrationIsAdditiveAndScoped(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "430" {
			continue
		}
		for _, required := range []string{"CREATE TABLE IF NOT EXISTS task_creation_idempotencies", "schema_version VARCHAR(64)", "idempotency_key_hash VARCHAR(64)", "request_hash VARCHAR(64)", "attempt_ids JSONB NOT NULL", "idempotency_key_hash ~ '^[0-9a-f]{64}$'", "jsonb_typeof(attempt_ids) = 'array'", "DEFERRABLE INITIALLY DEFERRED", "fk_tci_root_task", "ON DELETE RESTRICT", "idx_tci_idempotency"} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("task creation idempotency migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "TRUNCATE ", "CREDENTIAL", "API_KEY", "TOKEN", "RAW_RESPONSE", "RESPONSE_BODY", "TARGETS", "CONFIG", "PROVIDER"} {
			if strings.Contains(upperSQL, forbidden) {
				t.Fatalf("task creation idempotency migration contains forbidden term %q", forbidden)
			}
		}
		return
	}
	t.Fatal("expected task creation idempotency migration 430")
}

func TestTaskAppendIdempotencyMigrationIsAdditiveAndScoped(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "440" {
			continue
		}
		for _, required := range []string{"CREATE TABLE IF NOT EXISTS task_append_idempotencies", "root_task_id TEXT NOT NULL", "idempotency_key_hash VARCHAR(64)", "request_hash VARCHAR(64)", "config_hash VARCHAR(64)", "batch_ids JSONB NOT NULL", "attempt_ids JSONB NOT NULL", "outcome IN ('appended', 'unchanged')", "requested_targets = new_targets + duplicate_targets", "octet_length(rule_version) BETWEEN 1 AND 1024", "DEFERRABLE INITIALLY DEFERRED", "fk_tai_root_task", "ON DELETE RESTRICT", "idx_tai_idempotency"} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("task append idempotency migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "TRUNCATE ", "CREDENTIAL", "API_KEY", "TOKEN", "RAW_RESPONSE", "RESPONSE_BODY", "TARGETS TEXT", "CONFIG TEXT", "PROVIDER"} {
			if strings.Contains(upperSQL, forbidden) {
				t.Fatalf("task append idempotency migration contains forbidden term %q", forbidden)
			}
		}
		return
	}
	t.Fatal("expected task append idempotency migration 440")
}

func TestTaskRetryIdempotencyMigrationIsAdditiveAndScoped(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "450" {
			continue
		}
		for _, required := range []string{"CREATE TABLE IF NOT EXISTS task_retry_idempotencies", "root_task_id TEXT NOT NULL", "idempotency_key_hash VARCHAR(64)", "request_hash VARCHAR(64)", "attempt_ids JSONB NOT NULL", "completed_skipped INTEGER NOT NULL", "paused_skipped INTEGER NOT NULL", "jsonb_typeof(attempt_ids) = 'array'", "jsonb_array_length(attempt_ids) >= 1", "DEFERRABLE INITIALLY DEFERRED", "fk_tri_root_task", "ON DELETE RESTRICT", "idx_tri_idempotency"} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("task retry idempotency migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "TRUNCATE ", "CREDENTIAL", "API_KEY", "TOKEN", "RAW_RESPONSE", "RESPONSE_BODY", "TARGETS TEXT", "CONFIG TEXT", "PROVIDER"} {
			if strings.Contains(upperSQL, forbidden) {
				t.Fatalf("task retry idempotency migration contains forbidden term %q", forbidden)
			}
		}
		return
	}
	t.Fatal("expected task retry idempotency migration 450")
}

func TestTaskBatchRetryIdempotencyMigrationIsAdditiveAndScoped(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "460" {
			continue
		}
		for _, required := range []string{"CREATE TABLE IF NOT EXISTS task_batch_retry_idempotencies", "root_task_id TEXT NOT NULL", "batch_id TEXT NOT NULL", "idempotency_key_hash VARCHAR(64)", "request_hash VARCHAR(64)", "attempt_id TEXT NOT NULL", "attempt_no INTEGER NOT NULL", "config_version INTEGER NOT NULL", "config_hash VARCHAR(64)", "rule_version TEXT NOT NULL", "DEFERRABLE INITIALLY DEFERRED", "fk_tbri_root_task", "fk_tbri_batch", "fk_tbri_attempt", "REFERENCES sub_tasks (tenant_id, project_id, root_task_id, batch_id, id)", "ON DELETE RESTRICT", "idx_tbri_idempotency"} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("task batch retry idempotency migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "TRUNCATE ", "CREDENTIAL", "API_KEY", "TOKEN", "RAW_RESPONSE", "RESPONSE_BODY", "TARGETS TEXT", "CONFIG TEXT", "PROVIDER"} {
			if strings.Contains(upperSQL, forbidden) {
				t.Fatalf("task batch retry idempotency migration contains forbidden term %q", forbidden)
			}
		}
		return
	}
	t.Fatal("expected task batch retry idempotency migration 460")
}

func TestRiskValidationExecutionIdempotencyMigrationIsAdditiveAndScoped(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "470" {
			continue
		}
		for _, required := range []string{"CREATE TABLE IF NOT EXISTS risk_validation_execution_idempotencies", "idempotency_key_hash VARCHAR(64)", "request_hash VARCHAR(64)", "plan_hash VARCHAR(64)", "poc_set_hash VARCHAR(64)", "config_version INTEGER NOT NULL", "batch_id TEXT NOT NULL", "attempt_id TEXT NOT NULL", "second_confirmation_required BOOLEAN NOT NULL", "fk_rvei_root_task", "fk_rvei_config", "fk_rvei_batch", "fk_rvei_attempt", "DEFERRABLE INITIALLY DEFERRED", "ON DELETE RESTRICT", "idx_rvei_idempotency"} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("risk validation execution idempotency migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "TRUNCATE ", "CREDENTIAL", "API_KEY", "TOKEN", "RAW_RESPONSE", "RESPONSE_BODY", "TARGETS TEXT", "CONFIG TEXT", "PROVIDER"} {
			if strings.Contains(upperSQL, forbidden) {
				t.Fatalf("risk validation execution idempotency migration contains forbidden term %q", forbidden)
			}
		}
		return
	}
	t.Fatal("expected risk validation execution idempotency migration 470")
}

func TestAssetDiscoveryNotebookOperationsMigrationIsAdditiveAndScoped(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "480" {
			continue
		}
		for _, required := range []string{
			"ADD COLUMN IF NOT EXISTS note TEXT",
			"ADD COLUMN IF NOT EXISTS removed_at TIMESTAMPTZ",
			"ADD COLUMN IF NOT EXISTS notebook_item_id BIGINT",
			"idx_adn_items_active_updated",
			"idx_asset_discovery_audits_notebook_item_id",
			"idx_projects_scope_id",
			"orphan notebook items exist",
			"CREATE TABLE IF NOT EXISTS asset_discovery_notebook_tags",
			"CREATE TABLE IF NOT EXISTS asset_discovery_notebook_item_tags",
			"fk_asset_discovery_audit_notebook_item",
			"fk_adn_item_project",
			"fk_adn_tag_project",
			"fk_adn_item_tag_item",
			"fk_adn_item_tag_tag",
			"ON DELETE RESTRICT",
		} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("notebook operations migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "TRUNCATE ", "CREDENTIAL", "API_KEY", "TOKEN", "RAW_RESPONSE", "RESPONSE_BODY", "EXPRESSION"} {
			if strings.Contains(upperSQL, forbidden) {
				t.Fatalf("notebook operations migration contains forbidden term %q", forbidden)
			}
		}
		return
	}
	t.Fatal("expected asset discovery notebook operations migration 480")
}

func TestSubdomainDictionaryMigrationIsAdditiveAndScoped(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	for _, migration := range migrations {
		if migration.Version != "520" {
			continue
		}
		for _, required := range []string{
			"CREATE TABLE IF NOT EXISTS subdomain_dictionaries",
			"tenant_id VARCHAR(128) NOT NULL",
			"project_id VARCHAR(255) NOT NULL",
			"CREATE TABLE IF NOT EXISTS subdomain_dictionary_revisions",
			"values_json JSONB NOT NULL",
			"REFERENCES subdomain_dictionaries(id) ON DELETE RESTRICT",
			"idx_subdomain_dictionary_name",
			"idx_subdomain_dictionary_revision",
		} {
			if !strings.Contains(migration.SQL, required) {
				t.Fatalf("subdomain dictionary migration missing %q", required)
			}
		}
		upperSQL := strings.ToUpper(migration.SQL)
		for _, forbidden := range []string{"DROP TABLE", "DELETE FROM", "TRUNCATE ", "PASSWORD", "TOKEN", "API_KEY", "FILE_PATH"} {
			if strings.Contains(upperSQL, forbidden) {
				t.Fatalf("subdomain dictionary migration contains forbidden term %q", forbidden)
			}
		}
		return
	}
	t.Fatal("expected subdomain dictionary migration 520")
}
