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
	if err := NewScanStageOrchestrator().DeriveRoot(context.Background(), root.TenantID, root.ID); err != nil {
		t.Fatal(err)
	}
	var got db.ScanPolicyIntent
	if err := store.First(&got, "root_task_id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.RiskStatus != db.ScanStageIntentSkipped || got.CredentialStatus != db.ScanStageIntentSkipped {
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
	if !strings.Contains(summary, "no_approved_workflow_matches") || !strings.Contains(summary, "no_eligible_services") {
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

func TestRiskGoPocTargetsFromObservationsOnlyIncludesVulnerabilityChecks(t *testing.T) {
	items, estimated := riskGoPocTargetsFromObservations([]db.Asset{
		{Target: "192.0.2.10", Port: 445, Protocol: "smb", Service: "smb"},
		{Target: "192.0.2.20", Port: 22, Protocol: "ssh", Service: "ssh"},
	}, nil, nil, nil)
	if len(items) != 1 || items[0].Plugin != "SMB-MS17-010" || items[0].Capability != scanpolicy.GoPocVulnerabilityCheck || estimated != 1 {
		t.Fatalf("unexpected risk GoPoc plan: items=%+v estimated=%d", items, estimated)
	}
}

func TestRiskGoPocTargetsFromActiveFingerprintUsesReviewedSignal(t *testing.T) {
	hit := db.FingerprintHit{
		ID: 7, Target: "http://192.0.2.40:8080", ProductName: "APACHE-Shiro",
		Evidence: `{"uri":"http://192.0.2.40:8080","finger":["APACHE-Shiro"],"additional_msg":"[behavior-probe:shiro-detect]"}`,
	}
	rule := db.ActiveFingerprintRule{
		SourceFile: "shiro-detect.yaml", Name: "shiro-detect", ProductName: "APACHE-Shiro",
		ContentHash: strings.Repeat("a", 32), Version: 3, State: "Approved", Enabled: true, AutoEligible: true,
	}
	items, estimated := riskGoPocTargetsFromObservations(nil, nil, []db.FingerprintHit{hit}, []db.ActiveFingerprintRule{rule})
	if len(items) != 1 || items[0].Plugin != "Shiro-Key-Crack" || items[0].Trigger != "nuclei:shiro-detect" || items[0].Target != hit.Target || estimated != 128 {
		t.Fatalf("unexpected active-fingerprint GoPoc plan: items=%+v estimated=%d", items, estimated)
	}
}

func TestActiveFingerprintDownstreamValidationsExposeReviewedGoPoc(t *testing.T) {
	if got := activeFingerprintDownstreamValidations("shiro-detect"); len(got) != 1 || got[0] != "Shiro-Key-Crack" {
		t.Fatalf("unexpected Shiro downstream validations: %v", got)
	}
	if got := activeFingerprintDownstreamValidations("unknown-probe"); len(got) != 0 {
		t.Fatalf("unknown behavior probe exposed downstream validations: %v", got)
	}
}

func TestRiskGoPocTargetsFromActiveFingerprintRejectsUnsealedOrMismatchedSignal(t *testing.T) {
	rule := db.ActiveFingerprintRule{
		SourceFile: "shiro-detect.yaml", Name: "shiro-detect", ProductName: "APACHE-Shiro",
		ContentHash: strings.Repeat("a", 32), Version: 1, State: "Approved", Enabled: true, AutoEligible: true,
	}
	hits := []db.FingerprintHit{
		{Target: "http://192.0.2.41:8080", ProductName: "APACHE-Shiro", Evidence: `{"additional_msg":""}`},
		{Target: "http://192.0.2.42:8080", ProductName: "RuoYi", Evidence: `{"additional_msg":"[behavior-probe:shiro-detect]"}`},
		{Target: "http://192.0.2.43:8080", ProductName: "APACHE-Shiro", Evidence: `{"additional_msg":"[behavior-probe:other-probe]"}`},
	}
	items, estimated := riskGoPocTargetsFromObservations(nil, nil, hits, []db.ActiveFingerprintRule{rule})
	if len(items) != 0 || estimated != 0 {
		t.Fatalf("unsealed or mismatched behavior signal activated GoPoc: items=%+v estimated=%d", items, estimated)
	}
}

func TestRiskGoPocTargetsFromActiveFingerprintRejectsAmbiguousSourceStem(t *testing.T) {
	hit := db.FingerprintHit{Target: "http://192.0.2.44:8080", ProductName: "APACHE-Shiro", Evidence: `{"additional_msg":"[behavior-probe:shiro-detect]"}`}
	rules := []db.ActiveFingerprintRule{
		{SourceFile: "shiro-detect.yaml", Name: "shiro-detect", ProductName: "APACHE-Shiro", ContentHash: strings.Repeat("a", 32), Version: 1},
		{SourceFile: "shiro-detect.yml", Name: "other-id", ProductName: "APACHE-Shiro", ContentHash: strings.Repeat("b", 32), Version: 1},
	}
	if items := riskGoPocTargetsFromActiveFingerprints([]db.FingerprintHit{hit}, rules); len(items) != 0 {
		t.Fatalf("ambiguous behavior-probe source stem activated GoPoc: %+v", items)
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
		t.Fatalf("derive GoPoc risk stage: %v", err)
	}
	var child db.SubTask
	if err := store.Where("root_task_id = ? AND trigger = ?", root.ID, "automatic_risk_validation").First(&child).Error; err != nil {
		t.Fatal(err)
	}
	var config struct {
		ExecutionMode               string                   `json:"ExecutionMode"`
		RiskValidationGoPocTargets  []scanpolicy.GoPocTarget `json:"RiskValidationGoPocTargets"`
		GoPocCatalogSHA256          string                   `json:"GoPocCatalogSHA256"`
		ValidationEstimatedRequests int64                    `json:"ValidationEstimatedRequests"`
	}
	if err := json.Unmarshal([]byte(child.Config), &config); err != nil {
		t.Fatal(err)
	}
	if config.ExecutionMode != automaticRiskStage || len(config.RiskValidationGoPocTargets) != 1 || config.RiskValidationGoPocTargets[0].Plugin != "SMB-MS17-010" || config.GoPocCatalogSHA256 != scanpolicy.GoPocCatalogSHA256() || config.ValidationEstimatedRequests != 1 {
		t.Fatalf("unexpected GoPoc-only risk config: %+v", config)
	}
}

func TestScanStageOrchestratorDerivesShiroGoPocFromActiveFingerprint(t *testing.T) {
	store := setupAITestDB(t)
	queue := scheduler.NewTaskQueue("")
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() { queue.Close(); routerRuntime().TaskQueue = oldQueue })

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
		RiskValidationTargets       map[string][]string      `json:"RiskValidationTargets"`
		RiskValidationGoPocTargets  []scanpolicy.GoPocTarget `json:"RiskValidationGoPocTargets"`
		ValidationEstimatedRequests int64                    `json:"ValidationEstimatedRequests"`
	}
	if err := json.Unmarshal([]byte(child.Config), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.RiskValidationGoPocTargets) != 1 || config.RiskValidationGoPocTargets[0].Plugin != "Shiro-Key-Crack" || config.RiskValidationGoPocTargets[0].Trigger != "nuclei:shiro-detect" || config.ValidationEstimatedRequests != 128 {
		t.Fatalf("unexpected Shiro active-fingerprint risk config: %+v", config)
	}
	if len(config.RiskValidationTargets) != 0 {
		t.Fatalf("active fingerprint unexpectedly reintroduced shiro-detect as a Nuclei POC: %+v", config.RiskValidationTargets)
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
