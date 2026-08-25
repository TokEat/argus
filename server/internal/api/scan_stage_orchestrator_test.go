package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/credentialvault"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/scheduler"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
	"gorm.io/gorm"
)

func TestCommonPortProfileDerivationIsAccepted(t *testing.T) {
	store := setupAITestDB(t)
	root := db.RootTask{ID: "common-profile-root", TenantID: "default", ProjectID: "common-profile-project", Status: "Running", RuleVersion: "rules-v1"}
	intent := db.ScanPolicyIntent{
		TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID,
		PolicyJSON: `{"schema_version":"argus.scan-policy/v1","preset":"quick","port_profile":"common-100","scan_method":"tcp","intensity":"low"}`,
		RiskStatus: db.ScanStageIntentPending, CredentialStatus: db.ScanStageIntentPending,
	}
	if err := store.Create(&db.Project{ID: root.ProjectID, TenantID: root.TenantID, OwnerUserID: "1", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&db.SystemConfig{Key: "rule_version", Value: root.RuleVersion}).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&intent).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&db.TaskBatch{ID: "common-asset-batch", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Kind: "asset_scan", Status: "Done", LatestAttemptID: "common-asset-attempt"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&db.SubTask{ID: "common-asset-attempt", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: "common-asset-batch", Status: "Done", Config: `{}`}).Error; err != nil {
		t.Fatal(err)
	}
	queue := scheduler.NewTaskQueue("")
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })
	if err := NewScanStageOrchestrator().DeriveRoot(context.Background(), root.TenantID, root.ID); err != nil {
		t.Fatal(err)
	}
	var got db.ScanPolicyIntent
	if err := store.First(&got, "root_task_id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	// 原生契约：零指纹命中批次的空风险兄弟在控制面本地完结 → risk=complete；
	// 凭据阶段无合格服务 → 保持 skipped。
	if got.RiskStatus != db.ScanStageIntentComplete || got.CredentialStatus != db.ScanStageIntentSkipped {
		t.Fatalf("common profile statuses = %s/%s", got.RiskStatus, got.CredentialStatus)
	}
	var derivations []db.ScanStageDerivation
	if err := store.Where("root_task_id = ?", root.ID).Find(&derivations).Error; err != nil {
		t.Fatal(err)
	}
	if len(derivations) != 2 {
		t.Fatalf("common profile derivations = %+v", derivations)
	}
	summary := derivations[0].Summary + derivations[1].Summary
	if !strings.Contains(summary, `"matching":"agent_native"`) || !strings.Contains(summary, "no_eligible_services") {
		t.Fatalf("common profile derivations = %+v", derivations)
	}
}

func TestCredentialTargetsFromAssetsUsesProtocolThenSafePortFallback(t *testing.T) {
	assets := []db.Asset{
		{Target: "192.0.2.10", Port: 2222, Protocol: "tcp", Service: "ssh"},
		{Target: "192.0.2.20", Port: 22, Protocol: "TCP"},
		{Target: "192.0.2.30", Port: 80, Protocol: "http", Service: "http"},
		{Target: "192.0.2.40", Port: 22, Protocol: "smtp", Service: "smtp"},
	}
	plans, _ := credentialTargetsFromAssets(assets)
	if len(plans) != 2 {
		t.Fatalf("eligible plans=%d want=2: %+v", len(plans), plans)
	}
	if plans[0].Eligibility != "protocol" || plans[0].Service != "ssh" || plans[1].Eligibility != "standard_port" {
		t.Fatalf("unexpected eligibility: %+v", plans)
	}
	for _, plan := range plans {
		if strings.Contains(plan.Endpoint, "192.0.2.30") || strings.Contains(plan.Endpoint, "192.0.2.40") {
			t.Fatalf("HTTP or conflicting observed protocol entered credential validation: %+v", plan)
		}
	}
}

func TestManualRiskConfigStillRejectsEmptySelection(t *testing.T) {
	if _, _, _, _, err := buildRiskValidationAttemptConfig(db.TaskConfigRevision{Config: `{}`}, "rules-a", nil); err != errRiskValidationEmptyPlan {
		t.Fatalf("empty manual risk selection err=%v, want %v", err, errRiskValidationEmptyPlan)
	}
}

func TestScanStageOrchestratorDerivesGoPocOnlyRiskBatch(t *testing.T) {
	store := setupAITestDB(t)
	queue := scheduler.NewTaskQueue("")
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })

	// 原生匹配派发下，资产服务观察（无指纹命中）不再触发 GoPoc-only 批次；
	// 没有任何指纹命中时应整体跳过并记录原因。
	root := db.RootTask{ID: "gopoc-risk-root", TenantID: "default", ProjectID: "gopoc-risk-project", UserID: "1", Status: "Running", Config: `{}`, RuleVersion: "unknown", CurrentConfigVersion: 1, TimeoutSec: 3600}
	batch := db.TaskBatch{ID: "gopoc-risk-asset", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Kind: "asset_scan", Status: "Done", LatestAttemptID: "gopoc-risk-discovery"}
	attempt := db.SubTask{ID: batch.LatestAttemptID, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID, Status: "Done", Config: `{}`, RuleVersion: root.RuleVersion}
	revision := db.NewTaskConfigRevision(root, 1, `{}`, `{}`, "1", "initial")
	policy, _ := scanpolicy.PresetPolicy(scanpolicy.PresetStandard)
	policy.Authorization.ValidationConfirmed = true
	policyJSON, _ := json.Marshal(policy)
	intent := db.ScanPolicyIntent{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, SchemaVersion: scanpolicy.SchemaVersion, PolicyJSON: string(policyJSON), PolicyHash: "policy-hash", PlanHash: "plan-hash", RiskStatus: db.ScanStageIntentPending, CredentialStatus: db.ScanStageIntentSkipped, AuthorizationActorID: "1"}
	asset := db.Asset{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Target: "192.0.2.10", Protocol: "smb", Service: "smb", Port: 445}
	for _, row := range []interface{}{&db.Project{ID: root.ProjectID, TenantID: root.TenantID, OwnerUserID: "1", Status: "active"}, &root, &batch, &attempt, &revision, &intent, &asset} {
		if err := store.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	if err := NewScanStageOrchestrator().DeriveRoot(context.Background(), root.TenantID, root.ID); err != nil {
		t.Fatalf("derive fingerprint-less risk stage: %v", err)
	}
	var got db.ScanPolicyIntent
	if err := store.First(&got, "root_task_id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	// 原生契约：零指纹命中批次创建空兄弟批次并在控制面立即正常完结，
	// 不入队；唯一兄弟终态后 intent 进入 complete。
	if got.RiskStatus != db.ScanStageIntentComplete {
		t.Fatalf("risk status = %s, want complete via empty sibling", got.RiskStatus)
	}
	var child db.SubTask
	if err := store.Where("root_task_id = ? AND trigger = ?", root.ID, "automatic_risk_validation").First(&child).Error; err != nil {
		t.Fatal(err)
	}
	if db.CanonicalAttemptState(child.Status) != db.AttemptStateCompleted || child.FinishedAt == nil {
		t.Fatalf("empty sibling was not completed locally: status=%s finished=%v", child.Status, child.FinishedAt)
	}
	if queued, _, err := queue.TryPopTask(context.Background(), "agent-empty"); err != nil || queued != nil {
		t.Fatalf("empty sibling was dispatched: task=%v err=%v", queued, err)
	}
	var cfg struct {
		NoPoc                      bool                `json:"NoPoc"`
		TargetFingerprints         map[string][]string `json:"TargetFingerprints"`
		RiskValidationTargets      map[string][]string `json:"RiskValidationTargets"`
		AllowHighRiskAutoExecution bool                `json:"AllowHighRiskAutoExecution"`
	}
	if err := json.Unmarshal([]byte(child.Config), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.NoPoc || len(cfg.TargetFingerprints) != 0 || len(cfg.RiskValidationTargets) != 0 {
		t.Fatalf("empty sibling contract violated: %+v", cfg)
	}
	var derivation db.ScanStageDerivation
	if err := store.Where("root_task_id = ? AND stage = ?", root.ID, automaticRiskStage).First(&derivation).Error; err != nil {
		t.Fatal(err)
	}
	if derivation.Status != db.ScanStageIntentComplete || !strings.Contains(derivation.Summary, `"local_complete":true`) {
		t.Fatalf("empty sibling derivation = status=%s summary=%s", derivation.Status, derivation.Summary)
	}
}

func TestScanStageOrchestratorDerivesShiroGoPocFromActiveFingerprint(t *testing.T) {
	store := setupAITestDB(t)
	queue := scheduler.NewTaskQueue("")
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })

	// 原生匹配派发：指纹命中（APACHE-Shiro）进入 TargetFingerprints 下发，
	// Agent 本地完成 workflow→POC 匹配；服务端不再构建显式映射表。
	root := db.RootTask{ID: "active-shiro-root", TenantID: "default", ProjectID: "active-shiro-project", UserID: "1", Status: "Running", Config: `{}`, RuleVersion: "unknown", CurrentConfigVersion: 1, TimeoutSec: 3600}
	batch := db.TaskBatch{ID: "active-shiro-asset", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Kind: "asset_scan", Status: "Done", LatestAttemptID: "active-shiro-discovery"}
	attempt := db.SubTask{ID: batch.LatestAttemptID, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID, Status: "Done", Config: `{}`, RuleVersion: root.RuleVersion}
	revision := db.NewTaskConfigRevision(root, 1, `{}`, `{}`, "1", "initial")
	policy, _ := scanpolicy.PresetPolicy(scanpolicy.PresetStandard)
	policy.Authorization.ValidationConfirmed = true
	policyJSON, _ := json.Marshal(policy)
	intent := db.ScanPolicyIntent{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, SchemaVersion: scanpolicy.SchemaVersion, PolicyJSON: string(policyJSON), PolicyHash: "policy-hash", PlanHash: "plan-hash", RiskStatus: db.ScanStageIntentPending, CredentialStatus: db.ScanStageIntentSkipped, AuthorizationActorID: "1"}
	hit := db.FingerprintHit{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, TaskID: attempt.ID, Target: "http://192.0.2.50:8080", ProductName: "APACHE-Shiro", Evidence: `{"additional_msg":"[behavior-probe:shiro-detect]"}`}
	rule := db.ActiveFingerprintRule{TenantID: root.TenantID, ArtifactID: "active-shiro", SourceFile: "shiro-detect.yaml", Name: "shiro-detect", ProductName: "APACHE-Shiro", ContentHash: strings.Repeat("a", 32), Version: 1, State: "Approved", Enabled: true, AutoEligible: true}
	for _, row := range []interface{}{&db.Project{ID: root.ProjectID, TenantID: root.TenantID, OwnerUserID: "1", Status: "active"}, &root, &batch, &attempt, &revision, &intent, &hit, &rule} {
		if err := store.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	if err := NewScanStageOrchestrator().DeriveRoot(context.Background(), root.TenantID, root.ID); err != nil {
		t.Fatalf("derive Shiro active-fingerprint risk stage: %v", err)
	}
	var child db.SubTask
	if err := store.Where("root_task_id = ? AND trigger = ?", root.ID, "automatic_risk_validation").First(&child).Error; err != nil {
		t.Fatal(err)
	}
	var config struct {
		RiskValidationTargets       map[string][]string `json:"RiskValidationTargets"`
		RiskValidationPocHashes     map[string]string   `json:"RiskValidationPocHashes"`
		TargetFingerprints          map[string][]string `json:"TargetFingerprints"`
		NoPoc                       bool                `json:"NoPoc"`
		AllowHighRiskAutoExecution  bool                `json:"AllowHighRiskAutoExecution"`
		ValidationRequestBudget     int64               `json:"ValidationRequestBudget"`
		ValidationEstimatedRequests int64               `json:"ValidationEstimatedRequests"`
	}
	if err := json.Unmarshal([]byte(child.Config), &config); err != nil {
		t.Fatal(err)
	}
	prints := config.TargetFingerprints["http://192.0.2.50:8080"]
	if len(prints) != 1 || prints[0] != "APACHE-Shiro" {
		t.Fatalf("fingerprint dispatch missing Shiro hit: %+v", config.TargetFingerprints)
	}
	if config.NoPoc {
		t.Fatal("native risk dispatch must enable POC execution")
	}
	if len(config.RiskValidationTargets) != 0 || len(config.RiskValidationPocHashes) != 0 {
		t.Fatalf("explicit mapping table must not be built for automatic native dispatch: %+v", config)
	}
	if config.ValidationRequestBudget != 0 || config.ValidationEstimatedRequests != 0 {
		t.Fatalf("native dispatch must not seal a Nuclei request budget: %+v", config)
	}
}

func seedHighRiskWorkflowRiskIntent(t *testing.T, allowHighRisk bool) (*gorm.DB, db.RootTask) {
	t.Helper()
	store := setupAITestDB(t)
	queue := scheduler.NewTaskQueue("")
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })

	root := db.RootTask{ID: "auto-high-risk-root", TenantID: "default", ProjectID: "auto-high-risk-project", UserID: "1", Status: "Running", Config: `{}`, RuleVersion: "unknown", CurrentConfigVersion: 1, TimeoutSec: 3600}
	batch := db.TaskBatch{ID: "auto-high-risk-asset", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Kind: "asset_scan", Status: "Done", LatestAttemptID: "auto-high-risk-discovery"}
	attempt := db.SubTask{ID: batch.LatestAttemptID, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID, Status: "Done", Config: `{}`, RuleVersion: root.RuleVersion}
	revision := db.NewTaskConfigRevision(root, 1, `{}`, `{}`, "1", "initial")
	policy, _ := scanpolicy.PresetPolicy(scanpolicy.PresetStandard)
	policy.Capabilities.RiskValidation = true
	policy.Authorization.ValidationConfirmed = true
	policy.Authorization.AllowHighRiskAutoExecution = allowHighRisk
	policyJSON, _ := json.Marshal(policy)
	intent := db.ScanPolicyIntent{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, SchemaVersion: scanpolicy.SchemaVersion, PolicyJSON: string(policyJSON), PolicyHash: "policy-hash", PlanHash: "plan-hash", RiskStatus: db.ScanStageIntentPending, CredentialStatus: db.ScanStageIntentSkipped, AuthorizationActorID: "1"}
	hit := db.FingerprintHit{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, TaskID: "auto-high-risk-discovery", Target: "https://risk.example", ProductName: "nginx"}
	arsenal := db.Arsenal{ID: "auto-risk-poc", TenantID: root.TenantID, Type: "poc", FileName: "nginx-risk.yaml", State: "Approved", Content: "id: nginx-risk\ninfo:\n  name: risk\n  severity: high\nhttp:\n  - path: ['{{BaseURL}}/check']\n"}
	poc := db.PocRule{TenantID: root.TenantID, ArtifactID: arsenal.ID, SourceFile: "nginx-risk.yaml", Name: "nginx-risk", Severity: "high", ExecutionClass: db.PocExecutionClassVerification, RiskLevel: db.PocRiskLevelHigh, ContentHash: "content-v2", State: "Approved", Enabled: true}
	workflow := db.WorkflowRule{TenantID: root.TenantID, ProductName: "nginx", PocName: "nginx-risk.yaml", MatchType: "root", SourceFile: "workflow.yaml", State: "Approved", Enabled: true}
	for _, row := range []interface{}{&db.Project{ID: root.ProjectID, TenantID: root.TenantID, OwnerUserID: "1", Status: "active"}, &root, &batch, &attempt, &revision, &intent, &hit, &arsenal, &poc, &workflow} {
		if err := store.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	return store, root
}

func TestAutomaticRiskStageGatesHighRiskWithoutPreAuthorization(t *testing.T) {
	store, root := seedHighRiskWorkflowRiskIntent(t, false)
	if err := NewScanStageOrchestrator().DeriveRoot(context.Background(), root.TenantID, root.ID); err != nil {
		t.Fatalf("derive gated risk stage: %v", err)
	}
	// 预授权门已下沉到 Agent 本地（按 workflow risk_level 过滤）：
	// 服务端始终密封批次，但必须把授权开关原样=false 传下去。
	var child db.SubTask
	if err := store.Where("root_task_id = ? AND trigger = ?", root.ID, "automatic_risk_validation").First(&child).Error; err != nil {
		t.Fatal(err)
	}
	var config struct {
		NoPoc                      bool                `json:"NoPoc"`
		TargetFingerprints         map[string][]string `json:"TargetFingerprints"`
		RiskValidationTargets      map[string][]string `json:"RiskValidationTargets"`
		AllowHighRiskAutoExecution bool                `json:"AllowHighRiskAutoExecution"`
	}
	if err := json.Unmarshal([]byte(child.Config), &config); err != nil {
		t.Fatal(err)
	}
	if config.AllowHighRiskAutoExecution {
		t.Fatal("pre-authorization flag must stay false without operator approval")
	}
	if config.NoPoc || len(config.RiskValidationTargets) != 0 {
		t.Fatalf("native dispatch contract violated: NoPoc=%v explicit map=%+v", config.NoPoc, config.RiskValidationTargets)
	}
	prints := config.TargetFingerprints["https://risk.example"]
	if len(prints) != 1 || prints[0] != "nginx" {
		t.Fatalf("fingerprint dispatch missing nginx hit: %+v", config.TargetFingerprints)
	}
	var derivation db.ScanStageDerivation
	if err := store.Where("root_task_id = ? AND stage = ?", root.ID, automaticRiskStage).First(&derivation).Error; err != nil {
		t.Fatal(err)
	}
	if derivation.Status != db.ScanStageIntentDerived || !strings.Contains(derivation.Summary, `"matching":"agent_native"`) {
		t.Fatalf("unexpected gated derivation: status=%s summary=%s", derivation.Status, derivation.Summary)
	}
}

func TestAutomaticRiskStageSealsHighRiskWithPreAuthorization(t *testing.T) {
	store, root := seedHighRiskWorkflowRiskIntent(t, true)
	if err := NewScanStageOrchestrator().DeriveRoot(context.Background(), root.TenantID, root.ID); err != nil {
		t.Fatalf("derive authorized risk stage: %v", err)
	}
	var child db.SubTask
	if err := store.Where("root_task_id = ? AND trigger = ?", root.ID, "automatic_risk_validation").First(&child).Error; err != nil {
		t.Fatal(err)
	}
	var config struct {
		NoPoc                      bool                `json:"NoPoc"`
		TargetFingerprints         map[string][]string `json:"TargetFingerprints"`
		RiskValidationTargets      map[string][]string `json:"RiskValidationTargets"`
		AllowHighRiskAutoExecution bool                `json:"AllowHighRiskAutoExecution"`
		TimeoutSec                 int                 `json:"TimeoutSec"`
	}
	if err := json.Unmarshal([]byte(child.Config), &config); err != nil {
		t.Fatal(err)
	}
	prints := config.TargetFingerprints["https://risk.example"]
	if len(prints) != 1 || prints[0] != "nginx" {
		t.Fatalf("fingerprint dispatch missing nginx hit: %+v", config.TargetFingerprints)
	}
	if !config.AllowHighRiskAutoExecution {
		t.Fatal("pre-authorization must travel to the agent for local gating")
	}
	if config.NoPoc || len(config.RiskValidationTargets) != 0 {
		t.Fatalf("native dispatch contract violated: NoPoc=%v explicit map=%+v", config.NoPoc, config.RiskValidationTargets)
	}
	if child.TimeoutSec != 3600 {
		t.Fatalf("small batch must keep base timeout, got %d", child.TimeoutSec)
	}
	var derivation db.ScanStageDerivation
	if err := store.Where("root_task_id = ? AND stage = ?", root.ID, automaticRiskStage).First(&derivation).Error; err != nil {
		t.Fatal(err)
	}
	if derivation.Status != db.ScanStageIntentDerived || !strings.Contains(derivation.Summary, `"high_risk_auto_authorized":true`) {
		t.Fatalf("unexpected authorized derivation: status=%s summary=%s", derivation.Status, derivation.Summary)
	}
}

func TestDeriveValidationAffinityUsesSuccessfulDiscoveryAgentAndZone(t *testing.T) {
	store := setupAITestDB(t)
	root := db.RootTask{ID: "affinity-root", TenantID: "default", ProjectID: "affinity-project"}
	batch := db.TaskBatch{ID: "affinity-batch", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Kind: "asset_scan", LatestAttemptID: "affinity-attempt"}
	attempt := db.SubTask{ID: batch.LatestAttemptID, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID, AgentID: "agent-zone-a", Status: "Done"}
	node := db.Node{TenantID: root.TenantID, AgentID: attempt.AgentID, Tags: `{"network_zone":"zone-a"}`}
	for _, row := range []interface{}{&db.Project{ID: root.ProjectID, TenantID: root.TenantID, OwnerUserID: "1"}, &root, &batch, &attempt, &node} {
		if err := store.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	before := time.Now().UTC().Unix()
	affinity := deriveValidationAffinity(store, root)
	if affinity.AgentID != attempt.AgentID || affinity.NetworkZone != "zone-a" {
		t.Fatalf("unexpected affinity: %+v", affinity)
	}
	if affinity.AgentUntilUnix < before+14 || affinity.AgentUntilUnix > before+16 {
		t.Fatalf("unexpected Agent affinity deadline: %+v", affinity)
	}
	if affinity.NetworkUntilUnix < before+29 || affinity.NetworkUntilUnix > before+31 {
		t.Fatalf("unexpected network affinity deadline: %+v", affinity)
	}
}

func TestScanStageOrchestratorDerivesCredentialBatchOnce(t *testing.T) {
	store := setupAITestDB(t)
	queue := scheduler.NewTaskQueue("")
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() {
		queue.Close()
		routerRuntime().TaskQueue = oldQueue
	})

	root := db.RootTask{ID: "semantic-root", TenantID: "default", ProjectID: "semantic-project", UserID: "1", Status: "Running", Config: `{}`, RuleVersion: "rules-a", CurrentConfigVersion: 1, TimeoutSec: 3600}
	batch := db.TaskBatch{ID: "semantic-root-batch-0-domain", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Sequence: 0, Kind: "asset_scan", TargetType: "domain", Status: "Done", LatestAttemptID: "semantic-attempt"}
	attempt := db.SubTask{ID: "semantic-attempt", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID, Status: "Done", Config: `{}`, ConfigVersion: 1, RuleVersion: root.RuleVersion}
	revision := db.NewTaskConfigRevision(root, 1, `{}`, `{}`, "1", "initial")
	policy, _ := scanpolicy.PresetPolicy(scanpolicy.PresetQuick)
	policy.Capabilities.CredentialValidation = true
	policy.Authorization.ValidationConfirmed = true
	policyJSON, _ := json.Marshal(policy)
	intent := db.ScanPolicyIntent{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, SchemaVersion: scanpolicy.SchemaVersion, PolicyJSON: string(policyJSON), PolicyHash: "policy-hash", PlanHash: "plan-hash", RiskStatus: db.ScanStageIntentSkipped, CredentialStatus: db.ScanStageIntentPending, AuthorizationActorID: "1"}
	for _, row := range []interface{}{&db.Project{ID: root.ProjectID, TenantID: root.TenantID, OwnerUserID: "1", Status: "active"}, &root, &batch, &attempt, &revision, &intent} {
		if err := store.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	assets := []db.Asset{
		{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Target: "192.0.2.10", Protocol: "tcp", Service: "ssh", Port: 22},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Target: "192.0.2.20", Protocol: "http", Service: "http", Port: 80},
	}
	if err := store.Create(&assets).Error; err != nil {
		t.Fatal(err)
	}
	orchestrator := NewScanStageOrchestrator()
	if err := orchestrator.DeriveRoot(context.Background(), root.TenantID, root.ID); err != nil {
		t.Fatalf("derive credential stage: %v", err)
	}
	if err := orchestrator.DeriveRoot(context.Background(), root.TenantID, root.ID); err != nil {
		t.Fatalf("repeat derive: %v", err)
	}
	var derivations int64
	if err := store.Model(&db.ScanStageDerivation{}).Where("root_task_id = ? AND stage = ?", root.ID, automaticCredentialStage).Count(&derivations).Error; err != nil || derivations != 1 {
		t.Fatalf("derivations=%d err=%v", derivations, err)
	}
	var child db.SubTask
	if err := store.Where("root_task_id = ? AND trigger = ?", root.ID, "automatic_credential_validation").First(&child).Error; err != nil {
		t.Fatal(err)
	}
	if strings.Contains(child.Config, "PasswordFile") && !strings.Contains(child.Config, `"PasswordFile":""`) {
		t.Fatalf("credential child contains Agent file path: %s", child.Config)
	}
	var config struct {
		ExecutionMode               string                     `json:"ExecutionMode"`
		CredentialValidationTargets []credentialTargetEnvelope `json:"CredentialValidationTargets"`
		CredentialBundleRef         string                     `json:"CredentialBundleRef"`
		ValidationBudgetID          string                     `json:"ValidationBudgetID"`
		ValidationTargetConcurrency int                        `json:"ValidationTargetConcurrency"`
		ValidationRateLimit         int                        `json:"ValidationRateLimit"`
		ValidationRequestBudget     int64                      `json:"ValidationRequestBudget"`
	}
	if err := json.Unmarshal([]byte(child.Config), &config); err != nil {
		t.Fatal(err)
	}
	if config.ExecutionMode != automaticCredentialStage || len(config.CredentialValidationTargets) != 1 || config.CredentialBundleRef != "" {
		t.Fatalf("unexpected credential child config: %+v", config)
	}
	if config.CredentialValidationTargets[0].Plugin != "SSH-Crack" {
		t.Fatalf("unexpected credential target: %+v", config.CredentialValidationTargets[0])
	}
	if config.ValidationBudgetID != root.ID || config.ValidationTargetConcurrency != 2 || config.ValidationRateLimit != 10 || config.ValidationRequestBudget != int64(policy.Credentials.PairLimit) {
		t.Fatalf("unexpected credential allocation: %+v", config)
	}
}

func TestCredentialRetryReissuesOneTimeBundle(t *testing.T) {
	store := setupAITestDB(t)
	root := db.RootTask{ID: "retry-root", TenantID: "default", ProjectID: "retry-project", TimeoutSec: 3600}
	batch := db.TaskBatch{ID: "retry-batch", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Kind: automaticCredentialStage}
	previous := db.SubTask{ID: "retry-attempt-1", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID}
	next := db.SubTask{ID: "retry-attempt-2", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID}
	vault, err := credentialvault.NewFromEnvironment(true)
	if err != nil {
		t.Fatal(err)
	}
	usernameDictionary := db.CredentialDictionary{ID: "retry-users", TenantID: root.TenantID, ProjectID: root.ProjectID, Kind: "username", Name: "retry users", CreatedBy: "1"}
	passwordDictionary := db.CredentialDictionary{ID: "retry-passwords", TenantID: root.TenantID, ProjectID: root.ProjectID, Kind: "password", Name: "retry passwords", CreatedBy: "1"}
	usernameRevision, err := sealDictionaryRevision(vault, root.TenantID, root.ProjectID, usernameDictionary.ID, 1, []string{"admin"}, "1")
	if err != nil {
		t.Fatal(err)
	}
	passwordRevision, err := sealDictionaryRevision(vault, root.TenantID, root.ProjectID, passwordDictionary.ID, 1, []string{"incremental"}, "1")
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := scanpolicy.PresetPolicy(scanpolicy.PresetQuick)
	policy.Capabilities.CredentialValidation = true
	policy.Authorization.ValidationConfirmed = true
	policy.Credentials.UsernameBooks = []scanpolicy.DictionaryRef{{ID: usernameDictionary.ID, Revision: 1, SHA256: usernameRevision.SHA256, Count: 1}}
	policy.Credentials.PasswordBooks = []scanpolicy.DictionaryRef{{ID: passwordDictionary.ID, Revision: 1, SHA256: passwordRevision.SHA256, Count: 1}}
	policyJSON, _ := json.Marshal(policy)
	intent := db.ScanPolicyIntent{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, PolicyJSON: string(policyJSON)}
	previous.Config = `{"ExecutionMode":"credential_validation","CredentialBundleRef":"retired-ref","CredentialBundleSHA256":"retired-hash","CredentialBundleCount":1}`
	next.Config = previous.Config
	for _, row := range []interface{}{&db.Project{ID: root.ProjectID, TenantID: root.TenantID, OwnerUserID: "1"}, &root, &batch, &previous, &next, &usernameDictionary, &passwordDictionary, &usernameRevision, &passwordRevision, &intent} {
		if err := store.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	if err := store.Transaction(func(tx *gorm.DB) error {
		return reissueCredentialBundle(tx, root, batch, previous, &next)
	}); err != nil {
		t.Fatalf("reissue bundle: %v", err)
	}
	var config struct {
		CredentialBundleRef    string
		CredentialBundleSHA256 string
		CredentialBundleCount  int
	}
	if err := json.Unmarshal([]byte(next.Config), &config); err != nil {
		t.Fatal(err)
	}
	if config.CredentialBundleRef == "" || config.CredentialBundleRef == "retired-ref" {
		t.Fatalf("bundle ref was not rotated: %+v", config)
	}
	if config.CredentialBundleSHA256 == "" || config.CredentialBundleCount != 1 {
		t.Fatalf("bundle integrity contract was not rebound: %+v", config)
	}
	var copied db.CredentialBundle
	if err := store.First(&copied, "ref = ?", config.CredentialBundleRef).Error; err != nil {
		t.Fatal(err)
	}
	if copied.AttemptID != next.ID || copied.PairCount != 1 {
		t.Fatalf("bundle was not rebound to retry attempt: %+v", copied)
	}
}

func TestAutomaticStageTerminalStatusFollowsLatestAttempt(t *testing.T) {
	store := setupAITestDB(t)
	root := db.RootTask{ID: "status-root", TenantID: "default", ProjectID: "status-project", Status: "Running"}
	batch := db.TaskBatch{ID: "status-risk", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Kind: automaticRiskStage, LatestAttemptID: "status-risk-attempt"}
	attempt := db.SubTask{ID: batch.LatestAttemptID, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID, Status: "Done"}
	intent := db.ScanPolicyIntent{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, RiskStatus: db.ScanStageIntentDerived, CredentialStatus: db.ScanStageIntentSkipped}
	derivation := db.ScanStageDerivation{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Stage: automaticRiskStage, Status: db.ScanStageIntentDerived, BatchID: batch.ID, AttemptID: attempt.ID}
	for _, row := range []interface{}{&db.Project{ID: root.ProjectID, TenantID: root.TenantID, OwnerUserID: "1"}, &root, &batch, &attempt, &intent, &derivation} {
		if err := store.Create(row).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := updateAutomaticStageStatus(context.Background(), batch, attempt); err != nil {
		t.Fatal(err)
	}
	if err := store.First(&intent, "root_task_id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.First(&derivation, "root_task_id = ? AND stage = ?", root.ID, automaticRiskStage).Error; err != nil {
		t.Fatal(err)
	}
	if intent.RiskStatus != db.ScanStageIntentComplete || derivation.Status != db.ScanStageIntentComplete {
		t.Fatalf("terminal status not projected: intent=%s derivation=%s", intent.RiskStatus, derivation.Status)
	}
}

func TestAutomaticStageTimeoutSecScalesWithTargets(t *testing.T) {
	cases := []struct {
		name        string
		base        int
		targetCount int
		want        int
	}{
		{"small batch keeps base", 3600, 355, 3600},
		{"threshold boundary keeps base", 3600, 500, 3600},
		{"large batch scales linearly", 3600, 3559, 3600 * 8},
		{"zero base falls back to one hour", 0, 100, 3600},
		{"scaling is capped at 24h", 3600, 100000, 24 * 3600},
	}
	for _, tc := range cases {
		if got := automaticStageTimeoutSec(tc.base, tc.targetCount); got != tc.want {
			t.Fatalf("%s: automaticStageTimeoutSec(%d,%d)=%d want %d", tc.name, tc.base, tc.targetCount, got, tc.want)
		}
	}
}

// 流水线化派发回归：每个资产批次各自派生风险兄弟批次（含零指纹空批次），
// intent 仅在全部兄弟批次终态后聚合翻转。
func TestDeriveRootPipelinesRiskSiblingPerAssetBatchAndAggregates(t *testing.T) {
	store := setupAITestDB(t)
	queue := scheduler.NewTaskQueue("")
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })

	const ruleVersion = "v-pipeline"
	root := db.RootTask{ID: "pipeline-root", TenantID: "default", ProjectID: "pipeline-project", UserID: "1", Status: "Running", Config: `{}`, RuleVersion: ruleVersion, CurrentConfigVersion: 1, TimeoutSec: 3600}
	batch1 := db.TaskBatch{ID: "pipeline-asset-1", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Kind: "asset_scan", Status: "Done", LatestAttemptID: "pipeline-asset-1-attempt"}
	attempt1 := db.SubTask{ID: batch1.LatestAttemptID, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch1.ID, Status: "Done", Config: `{}`, RuleVersion: ruleVersion}
	batch2 := db.TaskBatch{ID: "pipeline-asset-2", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Sequence: 1, Kind: "asset_scan", Status: "Done", LatestAttemptID: "pipeline-asset-2-attempt"}
	attempt2 := db.SubTask{ID: batch2.LatestAttemptID, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch2.ID, Status: "Done", Config: `{}`, RuleVersion: ruleVersion}
	revision := db.NewTaskConfigRevision(root, 1, `{}`, `{}`, "1", "initial")
	policy, _ := scanpolicy.PresetPolicy(scanpolicy.PresetStandard)
	policy.Authorization.ValidationConfirmed = true
	policyJSON, _ := json.Marshal(policy)
	intent := db.ScanPolicyIntent{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, SchemaVersion: scanpolicy.SchemaVersion, PolicyJSON: string(policyJSON), PolicyHash: "policy-hash", PlanHash: "plan-hash", RiskStatus: db.ScanStageIntentPending, CredentialStatus: db.ScanStageIntentSkipped, AuthorizationActorID: "1"}
	hit := db.FingerprintHit{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, TaskID: attempt1.ID, Target: "https://a.example", ProductName: "nginx"}
	for _, row := range []interface{}{&db.SystemConfig{Key: "rule_version", Value: ruleVersion}, &db.Project{ID: root.ProjectID, TenantID: root.TenantID, OwnerUserID: "1", Status: "active"}, &root, &batch1, &attempt1, &batch2, &attempt2, &revision, &intent, &hit} {
		if err := store.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	if err := NewScanStageOrchestrator().DeriveRoot(context.Background(), root.TenantID, root.ID); err != nil {
		t.Fatal(err)
	}
	var riskBatches []db.TaskBatch
	if err := store.Where("root_task_id = ? AND kind = ?", root.ID, automaticRiskStage).Order("id ASC").Find(&riskBatches).Error; err != nil {
		t.Fatal(err)
	}
	if len(riskBatches) != 2 {
		t.Fatalf("expected one risk sibling per asset batch, got %d", len(riskBatches))
	}
	var configs []struct {
		BatchID               string              `json:"-"`
		TargetFingerprints    map[string][]string `json:"TargetFingerprints"`
		RiskValidationTargets map[string][]string `json:"RiskValidationTargets"`
	}
	var attempts []db.SubTask
	if err := store.Where("root_task_id = ? AND trigger = ?", root.ID, "automatic_risk_validation").Order("batch_id ASC").Find(&attempts).Error; err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 {
		t.Fatalf("expected 2 risk attempts, got %d", len(attempts))
	}
	for _, at := range attempts {
		var c struct {
			TargetFingerprints    map[string][]string `json:"TargetFingerprints"`
			RiskValidationTargets map[string][]string `json:"RiskValidationTargets"`
		}
		if err := json.Unmarshal([]byte(at.Config), &c); err != nil {
			t.Fatal(err)
		}
		configs = append(configs, struct {
			BatchID               string              `json:"-"`
			TargetFingerprints    map[string][]string `json:"TargetFingerprints"`
			RiskValidationTargets map[string][]string `json:"RiskValidationTargets"`
		}{at.BatchID, c.TargetFingerprints, c.RiskValidationTargets})
	}
	byBatch := map[string]map[string][]string{}
	for _, c := range configs {
		if len(c.RiskValidationTargets) != 0 {
			t.Fatalf("explicit mapping leaked into native dispatch: %+v", c)
		}
		byBatch[c.BatchID] = c.TargetFingerprints
	}
	if prints := byBatch["pipeline-asset-1-risk"]["https://a.example"]; len(prints) != 1 || prints[0] != "nginx" {
		t.Fatalf("batch1 fingerprints missing nginx hit: %+v", byBatch["pipeline-asset-1-risk"])
	}
	if fp2 := byBatch["pipeline-asset-2-risk"]; len(fp2) != 0 {
		t.Fatalf("zero-hit batch must carry empty fingerprint scope: %+v", fp2)
	}

	var fingerprintAttempt, emptyAttempt db.SubTask
	for _, at := range attempts {
		var c struct {
			TargetFingerprints map[string][]string `json:"TargetFingerprints"`
		}
		if err := json.Unmarshal([]byte(at.Config), &c); err != nil {
			t.Fatal(err)
		}
		if len(c.TargetFingerprints) == 0 {
			emptyAttempt = at
		} else {
			fingerprintAttempt = at
		}
	}
	if fingerprintAttempt.ID == "" || emptyAttempt.ID == "" {
		t.Fatalf("expected one fingerprint sibling and one empty sibling, got %+v", attempts)
	}
	if db.CanonicalAttemptState(emptyAttempt.Status) != db.AttemptStateCompleted {
		t.Fatalf("empty sibling should complete locally, status=%s", emptyAttempt.Status)
	}
	if db.IsTerminalAttemptStatus(fingerprintAttempt.Status) {
		t.Fatalf("fingerprint sibling should still be queued, status=%s", fingerprintAttempt.Status)
	}
	var mid db.ScanPolicyIntent
	if err := store.First(&mid, "root_task_id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if mid.RiskStatus != db.ScanStageIntentDerived {
		t.Fatalf("intent flipped before fingerprint sibling terminal: %s", mid.RiskStatus)
	}
	completeAutomaticRiskAttempt(t, store, fingerprintAttempt.ID, "DONE")
	var final db.ScanPolicyIntent
	if err := store.First(&final, "root_task_id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if final.RiskStatus != db.ScanStageIntentComplete {
		t.Fatalf("aggregate completion failed: %s", final.RiskStatus)
	}
}

func seedAutomaticRiskPipeline(t *testing.T, store *gorm.DB, rootID string, firstStatus, secondStatus string) (db.RootTask, db.SubTask, db.SubTask) {
	t.Helper()
	const ruleVersion = "v-pipeline"
	root := db.RootTask{ID: rootID, TenantID: "default", ProjectID: rootID + "-project", UserID: "1", Status: "Running", Config: `{}`, RuleVersion: ruleVersion, CurrentConfigVersion: 1, TimeoutSec: 3600}
	batch1 := db.TaskBatch{ID: rootID + "-asset-1", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Kind: "asset_scan", Status: firstStatus, LatestAttemptID: rootID + "-asset-1-attempt"}
	attempt1 := db.SubTask{ID: batch1.LatestAttemptID, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch1.ID, Status: firstStatus, Config: `{}`, RuleVersion: ruleVersion, AgentID: "agent-a"}
	batch2 := db.TaskBatch{ID: rootID + "-asset-2", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Sequence: 1, Kind: "asset_scan", Status: secondStatus, LatestAttemptID: rootID + "-asset-2-attempt"}
	attempt2 := db.SubTask{ID: batch2.LatestAttemptID, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch2.ID, Status: secondStatus, Config: `{}`, RuleVersion: ruleVersion, AgentID: "agent-b"}
	revision := db.NewTaskConfigRevision(root, 1, `{}`, `{}`, "1", "initial")
	policy, _ := scanpolicy.PresetPolicy(scanpolicy.PresetStandard)
	policy.Authorization.ValidationConfirmed = true
	policyJSON, _ := json.Marshal(policy)
	intent := db.ScanPolicyIntent{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, SchemaVersion: scanpolicy.SchemaVersion, PolicyJSON: string(policyJSON), PolicyHash: "policy-hash", PlanHash: "plan-hash", RiskStatus: db.ScanStageIntentPending, CredentialStatus: db.ScanStageIntentSkipped, AuthorizationActorID: "1"}
	for _, row := range []interface{}{&db.SystemConfig{Key: "rule_version", Value: ruleVersion}, &db.Project{ID: root.ProjectID, TenantID: root.TenantID, OwnerUserID: "1", Status: "active"}, &root, &batch1, &attempt1, &batch2, &attempt2, &revision, &intent} {
		if err := store.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}
	return root, attempt1, attempt2
}

func completeAutomaticRiskAttempt(t *testing.T, store *gorm.DB, attemptID, status string) db.SubTask {
	t.Helper()
	var attempt db.SubTask
	if err := store.Where("id = ?", attemptID).First(&attempt).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Model(&db.SubTask{}).Where("id = ?", attempt.ID).Update("status", status).Error; err != nil {
		t.Fatal(err)
	}
	attempt.Status = status
	if err := NewScanStageOrchestrator().HandleAttemptTerminal(context.Background(), attempt); err != nil {
		t.Fatal(err)
	}
	return attempt
}

func TestHandleAttemptTerminalDoesNotCompleteRiskStageAfterFirstEmptySibling(t *testing.T) {
	store := setupAITestDB(t)
	queue := scheduler.NewTaskQueue("")
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })

	root, firstAsset, secondAsset := seedAutomaticRiskPipeline(t, store, "stagger-root", "Done", "Running")
	if err := NewScanStageOrchestrator().HandleAttemptTerminal(context.Background(), firstAsset); err != nil {
		t.Fatal(err)
	}
	var firstSibling db.SubTask
	if err := store.Where("id = ?", riskSiblingBatchID(firstAsset.BatchID)+"-attempt-1").First(&firstSibling).Error; err != nil {
		t.Fatal(err)
	}
	if db.CanonicalAttemptState(firstSibling.Status) != db.AttemptStateCompleted {
		t.Fatalf("first empty sibling should complete locally, status=%s", firstSibling.Status)
	}

	var mid db.ScanPolicyIntent
	if err := store.First(&mid, "root_task_id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if mid.RiskStatus != db.ScanStageIntentDerived {
		t.Fatalf("empty sibling completion flipped stage too early: %s", mid.RiskStatus)
	}
	var riskCount int64
	if err := store.Model(&db.TaskBatch{}).Where("root_task_id = ? AND kind = ?", root.ID, automaticRiskStage).Count(&riskCount).Error; err != nil {
		t.Fatal(err)
	}
	if riskCount != 1 {
		t.Fatalf("risk siblings after first empty completion = %d, want 1", riskCount)
	}

	if err := store.Model(&db.TaskBatch{}).Where("id = ?", secondAsset.BatchID).Update("status", "Done").Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Model(&db.SubTask{}).Where("id = ?", secondAsset.ID).Update("status", "Done").Error; err != nil {
		t.Fatal(err)
	}
	secondAsset.Status = "Done"
	if err := store.Create(&db.FingerprintHit{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, TaskID: secondAsset.ID, Target: "https://b.example", ProductName: "nginx"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := NewScanStageOrchestrator().HandleAttemptTerminal(context.Background(), secondAsset); err != nil {
		t.Fatal(err)
	}

	var riskBatches []db.TaskBatch
	if err := store.Where("root_task_id = ? AND kind = ?", root.ID, automaticRiskStage).Order("id ASC").Find(&riskBatches).Error; err != nil {
		t.Fatal(err)
	}
	if len(riskBatches) != 2 {
		t.Fatalf("expected second asset batch to still derive a sibling, got %d", len(riskBatches))
	}
	var secondRisk db.SubTask
	if err := store.Where("id = ?", riskBatches[1].LatestAttemptID).First(&secondRisk).Error; err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		TargetFingerprints map[string][]string `json:"TargetFingerprints"`
	}
	if err := json.Unmarshal([]byte(secondRisk.Config), &cfg); err != nil {
		t.Fatal(err)
	}
	if prints := cfg.TargetFingerprints["https://b.example"]; len(prints) != 1 || prints[0] != "nginx" {
		t.Fatalf("second sibling missing fingerprint snapshot: %+v", cfg.TargetFingerprints)
	}

	completeAutomaticRiskAttempt(t, store, secondRisk.ID, "DONE")
	var final db.ScanPolicyIntent
	if err := store.First(&final, "root_task_id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if final.RiskStatus != db.ScanStageIntentComplete {
		t.Fatalf("stage status after 1:1 siblings = %s, want complete", final.RiskStatus)
	}
}

func TestHandleAttemptTerminalKeepsRiskDerivedWhenFirstSiblingFailsEarly(t *testing.T) {
	store := setupAITestDB(t)
	queue := scheduler.NewTaskQueue("")
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })

	root, firstAsset, secondAsset := seedAutomaticRiskPipeline(t, store, "stagger-fail-root", "Done", "Running")
	if err := NewScanStageOrchestrator().HandleAttemptTerminal(context.Background(), firstAsset); err != nil {
		t.Fatal(err)
	}
	completeAutomaticRiskAttempt(t, store, riskSiblingBatchID(firstAsset.BatchID)+"-attempt-1", "FAILED")

	var mid db.ScanPolicyIntent
	if err := store.First(&mid, "root_task_id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if mid.RiskStatus != db.ScanStageIntentDerived {
		t.Fatalf("first sibling failure flipped stage before 1:1 set existed: %s", mid.RiskStatus)
	}

	if err := store.Model(&db.TaskBatch{}).Where("id = ?", secondAsset.BatchID).Update("status", "Done").Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Model(&db.SubTask{}).Where("id = ?", secondAsset.ID).Update("status", "Done").Error; err != nil {
		t.Fatal(err)
	}
	secondAsset.Status = "Done"
	if err := NewScanStageOrchestrator().HandleAttemptTerminal(context.Background(), secondAsset); err != nil {
		t.Fatal(err)
	}
	completeAutomaticRiskAttempt(t, store, riskSiblingBatchID(secondAsset.BatchID)+"-attempt-1", "DONE")

	var final db.ScanPolicyIntent
	if err := store.First(&final, "root_task_id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if final.RiskStatus != db.ScanStageIntentFailed {
		t.Fatalf("stage status after mixed sibling terminals = %s, want failed", final.RiskStatus)
	}
}

func TestDeriveRootRepairsMissingRiskSiblingWhileStatusIsDerived(t *testing.T) {
	store := setupAITestDB(t)
	queue := scheduler.NewTaskQueue("")
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })

	root, firstAsset, secondAsset := seedAutomaticRiskPipeline(t, store, "repair-root", "Done", "Done")
	if err := NewScanStageOrchestrator().HandleAttemptTerminal(context.Background(), firstAsset); err != nil {
		t.Fatal(err)
	}
	completeAutomaticRiskAttempt(t, store, riskSiblingBatchID(firstAsset.BatchID)+"-attempt-1", "DONE")
	if err := store.Create(&db.FingerprintHit{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, TaskID: secondAsset.ID, Target: "https://repair.example", ProductName: "nginx"}).Error; err != nil {
		t.Fatal(err)
	}

	if err := NewScanStageOrchestrator().Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	var riskCount int64
	if err := store.Model(&db.TaskBatch{}).Where("root_task_id = ? AND kind = ?", root.ID, automaticRiskStage).Count(&riskCount).Error; err != nil {
		t.Fatal(err)
	}
	if riskCount != 2 {
		t.Fatalf("reconcile did not repair missing sibling: risk batches=%d", riskCount)
	}
	var intent db.ScanPolicyIntent
	if err := store.First(&intent, "root_task_id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if intent.RiskStatus != db.ScanStageIntentDerived {
		t.Fatalf("repaired sibling should leave stage derived until it terminals: %s", intent.RiskStatus)
	}
}
