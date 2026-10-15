package api

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/credentialvault"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
)

func TestCompileTaskScanPolicyPresetsAndSafeDiscoveryConfig(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "policy-project", TenantID: "default", OwnerUserID: "1", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	ctx, _ := newTenantContextWithRole(http.MethodPost, "/tasks/plan-preview", "admin", "1")
	for _, tc := range []struct {
		preset scanpolicy.Preset
		ports  int
	}{
		{scanpolicy.PresetQuick, scanpolicy.PortCount(scanpolicy.Common100Ports)},
		{scanpolicy.PresetStandard, scanpolicy.PortCount(scanpolicy.Top1000TCPPorts)},
		{scanpolicy.PresetDeep, 65535},
	} {
		policy, err := scanpolicy.PresetPolicy(tc.preset)
		if err != nil {
			t.Fatal(err)
		}
		if policy.Capabilities.RiskValidation {
			policy.Authorization.ValidationConfirmed = true
		}
		plan, err := compileTaskScanPolicy(ctx, scanPolicyPlanRequest{ProjectID: "policy-project", Targets: json.RawMessage(`"example.com"`), Policy: policy})
		if err != nil {
			t.Fatalf("compile %s: %v", tc.preset, err)
		}
		if plan.PortCount != tc.ports {
			t.Fatalf("%s port count=%d want=%d", tc.preset, plan.PortCount, tc.ports)
		}
		if plan.ValidationBudget.TargetConcurrency < 1 || plan.ValidationBudget.RateLimit < 1 || plan.ValidationBudget.CredentialMaxPerTarget != scanpolicy.DefaultCredentialPairLimit {
			t.Fatalf("%s validation budget is incomplete: %+v", tc.preset, plan.ValidationBudget)
		}
		var config taskScanConfig
		if err := json.Unmarshal([]byte(plan.ScannerConfig), &config); err != nil {
			t.Fatal(err)
		}
		if !config.NoPoc || config.GolangPoc || config.Password != "" || config.PasswordFile != "" {
			t.Fatalf("discovery config can execute validation or expose credential paths: %+v", config)
		}
		if !config.ProtocolCheckEnabled || config.GoPocCatalogSHA256 != scanpolicy.GoPocCatalogSHA256() || config.ProtocolCheckTargetLimit < 1 || config.ProtocolCheckRequestBudget < 1 {
			t.Fatalf("%s protocol-check contract is incomplete: %+v", tc.preset, config)
		}
		ports, err := scanpolicy.PortsForProfile(policy.PortProfile, policy.CustomPorts)
		if err != nil {
			t.Fatal(err)
		}
		wantProtocolLimit, err := scanpolicy.GoPocTargetLimitForPorts(ports, 1, scanpolicy.GoPocProtocolCheck)
		if err != nil {
			t.Fatal(err)
		}
		if config.ProtocolCheckTargetLimit != wantProtocolLimit || config.ProtocolCheckRequestBudget != int64(wantProtocolLimit) {
			t.Fatalf("%s protocol-check budget=%d/%d want %d", tc.preset, config.ProtocolCheckTargetLimit, config.ProtocolCheckRequestBudget, wantProtocolLimit)
		}
		var selector db.AgentSelectorRules
		if err := json.Unmarshal([]byte(plan.SelectorRules), &selector); err != nil {
			t.Fatal(err)
		}
		if got := selector.Match["gopoc_scoped"]; len(got) != 1 || got[0] != "v1" {
			t.Fatalf("%s policy did not require scoped GoPoc Agent: %+v", tc.preset, selector)
		}
		if tc.preset == scanpolicy.PresetDeep {
			if got := selector.Match["subdomain_depth"]; len(got) != 1 || got[0] != "v1" {
				t.Fatalf("deep policy did not require recursive-capable Agent: %+v", selector)
			}
		}
	}
}

func TestCompileTaskScanPolicyMapsPacing(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "pacing-project", TenantID: "default", OwnerUserID: "1", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	ctx, _ := newTenantContextWithRole(http.MethodPost, "/tasks/plan-preview", "admin", "1")

	policy, err := scanpolicy.PresetPolicy(scanpolicy.PresetQuick)
	if err != nil {
		t.Fatal(err)
	}
	compile := func(p scanpolicy.Policy) taskScanConfig {
		t.Helper()
		plan, err := compileTaskScanPolicy(ctx, scanPolicyPlanRequest{ProjectID: "pacing-project", Targets: json.RawMessage(`"example.com"`), Policy: p})
		if err != nil {
			t.Fatalf("compile pacing policy: %v", err)
		}
		var config taskScanConfig
		if err := json.Unmarshal([]byte(plan.ScannerConfig), &config); err != nil {
			t.Fatal(err)
		}
		return config
	}

	config := compile(policy)
	if config.PortScanScatter {
		t.Fatalf("pacing must default to disabled: %+v", config)
	}
	if config.PortScanProbeInterval != scanpolicy.DefaultPacingIntervalMillis {
		t.Fatalf("default probe interval = %d, want %d", config.PortScanProbeInterval, scanpolicy.DefaultPacingIntervalMillis)
	}

	policy.Pacing = &scanpolicy.ScanPacing{Enabled: true, IntervalMillis: 200}
	config = compile(policy)
	if !config.PortScanScatter || config.PortScanProbeInterval != 200 {
		t.Fatalf("pacing not mapped into scanner config: %+v", config)
	}
}

func TestCompileTaskScanPolicyBudgetsProtocolChecksForCIDRTargets(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "policy-cidr-project", TenantID: "default", OwnerUserID: "1", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	ctx, _ := newTenantContextWithRole(http.MethodPost, "/tasks/plan-preview", "admin", "1")

	policy, err := scanpolicy.PresetPolicy(scanpolicy.PresetQuick)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := compileTaskScanPolicy(ctx, scanPolicyPlanRequest{ProjectID: "policy-cidr-project", Targets: json.RawMessage(`"192.0.2.0/24"`), Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	var config taskScanConfig
	if err := json.Unmarshal([]byte(plan.ScannerConfig), &config); err != nil {
		t.Fatal(err)
	}
	ports, err := scanpolicy.PortsForProfile(policy.PortProfile, policy.CustomPorts)
	if err != nil {
		t.Fatal(err)
	}
	want, err := scanpolicy.GoPocTargetLimitForPorts(ports, 256, scanpolicy.GoPocProtocolCheck)
	if err != nil {
		t.Fatal(err)
	}
	singleTargetLimit, err := scanpolicy.GoPocTargetLimitForPorts(ports, 1, scanpolicy.GoPocProtocolCheck)
	if err != nil {
		t.Fatal(err)
	}
	if config.ProtocolCheckTargetLimit != want || config.ProtocolCheckRequestBudget != int64(want) {
		t.Fatalf("CIDR protocol-check budget=%d/%d want %d", config.ProtocolCheckTargetLimit, config.ProtocolCheckRequestBudget, want)
	}
	if config.ProtocolCheckTargetLimit <= singleTargetLimit {
		t.Fatalf("CIDR protocol-check budget stayed at single-target limit %d", singleTargetLimit)
	}
}

func TestCompileTaskScanPolicyUsesDeduplicatedDictionaryUnion(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "dictionary-project", TenantID: "default", OwnerUserID: "1", Status: "active"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	vault, err := credentialvault.NewFromEnvironment(true)
	if err != nil {
		t.Fatal(err)
	}
	seed := func(id, kind string, values []string) scanpolicy.DictionaryRef {
		t.Helper()
		dictionary := db.CredentialDictionary{ID: id, TenantID: "default", ProjectID: project.ID, Kind: kind, Name: id, CreatedBy: "1"}
		revision, err := sealDictionaryRevision(vault, "default", project.ID, id, 1, values, "1")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Create(&dictionary).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.Create(&revision).Error; err != nil {
			t.Fatal(err)
		}
		return scanpolicy.DictionaryRef{ID: id, Revision: 1, SHA256: revision.SHA256, Count: revision.ItemCount}
	}
	u1 := seed("u1", "username", []string{"admin", "root"})
	u2 := seed("u2", "username", []string{"root", "service"})
	p1 := seed("p1", "password", []string{"secret"})
	policy, _ := scanpolicy.PresetPolicy(scanpolicy.PresetQuick)
	policy.Capabilities.CredentialValidation = true
	policy.Authorization.ValidationConfirmed = true
	policy.Credentials.UsernameBooks = []scanpolicy.DictionaryRef{u1, u2}
	policy.Credentials.PasswordBooks = []scanpolicy.DictionaryRef{p1}
	policy.Credentials.PairLimit = 3
	ctx, _ := newTenantContextWithRole(http.MethodPost, "/tasks/plan-preview", "admin", "1")
	plan, err := compileTaskScanPolicy(ctx, scanPolicyPlanRequest{ProjectID: project.ID, Targets: json.RawMessage(`"example.com"`), Policy: policy})
	if err != nil {
		t.Fatalf("compile deduplicated policy: %v", err)
	}
	if plan.CustomPairs != 3 {
		t.Fatalf("custom pairs=%d want=3", plan.CustomPairs)
	}
}

func TestCompileTaskScanPolicySealsAutomaticBehaviorProbes(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "behavior-project", TenantID: "default", OwnerUserID: "1", Status: "active"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	content := "id: shiro-detect\ninfo:\n  name: Detect Apache Shiro\n  severity: info\n  metadata:\n    argus-rule-kind: active-fingerprint\n    argus-product: APACHE-Shiro\n    argus-behavior-kind: cookie\n    argus-auto-profile: safe\n    max-request: 1\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    headers: {Cookie: 'rememberMe={{randstr}}'}\n    matchers: [{type: status, status: [200]}]\n"
	artifactHash := fmt.Sprintf("%x", md5.Sum([]byte(content)))
	artifact := db.Arsenal{ID: db.BuildTenantArsenalID("default", "active_fingerprint", "shiro-detect.yaml"), TenantID: "default", Type: "active_fingerprint", FileName: "shiro-detect.yaml", Content: content, Hash: artifactHash, Version: 3, State: "Approved"}
	if err := store.Create(&artifact).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&db.ActiveFingerprintRule{TenantID: "default", ArtifactID: artifact.ID, SourceFile: artifact.FileName, Name: "shiro-detect", ProductName: "APACHE-Shiro", ContentHash: artifact.Hash, Version: 3, State: "Approved", Enabled: true, ComputedAutoProfile: "safe", AutoEligible: true, MaxRequests: 1}).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&db.SystemConfig{Key: "rule_version", Value: "rules-v3"}).Error; err != nil {
		t.Fatal(err)
	}
	policy, _ := scanpolicy.PresetPolicy(scanpolicy.PresetStandard)
	policy.Authorization.ValidationConfirmed = true
	ctx, _ := newTenantContextWithRole(http.MethodPost, "/tasks/plan-preview", "admin", "1")
	plan, err := compileTaskScanPolicy(ctx, scanPolicyPlanRequest{ProjectID: project.ID, Targets: json.RawMessage(`"example.com"`), Policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	var config taskScanConfig
	if err := json.Unmarshal([]byte(plan.ScannerConfig), &config); err != nil {
		t.Fatal(err)
	}
	wantHash := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	if !config.BehaviorProbe || config.ActiveFingerprintHashes[artifact.FileName] != wantHash || config.ActiveFingerprintProducts[artifact.FileName] != "APACHE-Shiro" || config.RequiredRuleVersion != "rules-v3" {
		t.Fatalf("behavior probe plan is not sealed: %+v", config)
	}
	var selector db.AgentSelectorRules
	if err := json.Unmarshal([]byte(plan.SelectorRules), &selector); err != nil {
		t.Fatal(err)
	}
	if got := selector.Match["behavior_probe"]; len(got) != 1 || got[0] != "v1" {
		t.Fatalf("behavior-capable Agent was not required: %+v", selector)
	}
	if err := store.Model(&db.Arsenal{}).Where("id = ?", artifact.ID).Update("content", content+"# draft drift\n").Error; err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAutomaticActiveFingerprints("default"); err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Fatalf("changed source was accepted without a new approved catalog revision: %v", err)
	}
}

func TestCreateTaskRejectsStaleSemanticPlanHash(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "stale-project", TenantID: "default", OwnerUserID: "1", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	policy, _ := scanpolicy.PresetPolicy(scanpolicy.PresetQuick)
	body, _ := json.Marshal(map[string]interface{}{
		"project_id": "stale-project",
		"name":       "stale",
		"targets":    "example.com",
		"policy":     policy,
		"plan_hash":  strings.Repeat("0", 64),
	})
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks", "admin", "1")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/tasks", strings.NewReader(string(body)))
	ctx.Request.Header.Set("Content-Type", "application/json")
	createTask(ctx)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "scan_plan_changed") {
		t.Fatalf("stale plan status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestCompileTaskScanPolicySkipsUnsupportedOnlyWhenRequested(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "skip-project", TenantID: "default", OwnerUserID: "1", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	policy, _ := scanpolicy.PresetPolicy(scanpolicy.PresetQuick)
	ctx, _ := newTenantContextWithRole(http.MethodPost, "/tasks/plan-preview", "admin", "1")
	targets := json.RawMessage(`["example.com","bad target with spaces"]`)
	if _, err := compileTaskScanPolicy(ctx, scanPolicyPlanRequest{ProjectID: "skip-project", Targets: targets, Policy: policy}); err == nil {
		t.Fatal("unsupported target was accepted without skip_unsupported")
	}
	plan, err := compileTaskScanPolicy(ctx, scanPolicyPlanRequest{ProjectID: "skip-project", Targets: targets, Policy: policy, SkipUnsupported: true})
	if err != nil {
		t.Fatalf("compile skip_unsupported: %v", err)
	}
	if len(plan.TargetsNormalized) != 1 || len(plan.SkippedTargets) != 1 {
		t.Fatalf("unexpected target classification: accepted=%v skipped=%v", plan.TargetsNormalized, plan.SkippedTargets)
	}
}

func TestCompileTaskScanPolicyPairLimitRequiresAdmin(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "limit-project", TenantID: "default", OwnerUserID: "7", Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	policy, _ := scanpolicy.PresetPolicy(scanpolicy.PresetQuick)
	policy.Credentials.PairLimit = 10_000
	ctx, _ := newTenantContextWithRole(http.MethodPost, "/tasks/plan-preview", "operator", "7")
	if _, err := compileTaskScanPolicy(ctx, scanPolicyPlanRequest{ProjectID: "limit-project", Targets: json.RawMessage(`"example.com"`), Policy: policy}); err == nil || !strings.Contains(err.Error(), "tenant admin") {
		t.Fatalf("operator pair limit error=%v", err)
	}
}

func TestCheckedCredentialPairCountRejectsBeforeCartesianAllocation(t *testing.T) {
	if _, err := checkedCredentialPairCount(100_000, 100_000, scanpolicy.MaximumCredentialPairLimit); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized cartesian product error=%v", err)
	}
	if got, err := checkedCredentialPairCount(250, 200, scanpolicy.DefaultCredentialPairLimit); err != nil || got != 50_000 {
		t.Fatalf("boundary pair count=%d err=%v", got, err)
	}
}

func TestScanPolicyPlanHashBindsActiveFingerprintFiles(t *testing.T) {
	first, err := hashScanPolicyPlan("project", []string{"example.com"}, strings.Repeat("a", 64), "rules-v1", map[string]string{"one.yaml": strings.Repeat("1", 64)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := hashScanPolicyPlan("project", []string{"example.com"}, strings.Repeat("a", 64), "rules-v1", map[string]string{"one.yaml": strings.Repeat("2", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("active fingerprint hash drift did not change the task plan hash")
	}
}
