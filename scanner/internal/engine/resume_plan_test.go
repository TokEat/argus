package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
)

func TestValidateResumePlanRestoresPortDependency(t *testing.T) {
	target := "192.0.2.10"
	checkpoint := testResumeCheckpoint(t, target, scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion,
		Stage:         scanplan.StagePortScan,
		OpenPorts:     []string{"192.0.2.10:443"},
	})
	plan := &scanplan.ResumePlan{
		SchemaVersion: scanplan.ResumePlanSchemaVersion,
		TenantID:      "tenant-a", ProjectID: "project-a", NetworkZone: "public", Target: target,
		ScopeHash: testResumeHash("scope"), ConfigHash: testResumeHash("config"), RuleVersion: "rules-a",
		RequiredStages:  []scanplan.Stage{scanplan.StagePortScan, scanplan.StageProtocolIdentify, scanplan.StageHTTPProbe, scanplan.StageFingerprint},
		ReusedStages:    []scanplan.Stage{scanplan.StagePortScan},
		ExecutionStages: []scanplan.Stage{scanplan.StageProtocolIdentify, scanplan.StageHTTPProbe, scanplan.StageFingerprint},
		StartStage:      scanplan.StageProtocolIdentify,
		Checkpoints:     []scanplan.ResumeCheckpoint{checkpoint},
	}
	planHash, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Targets: []string{target}, SkipHostDiscovery: true, NoHostBind: true, NoDirSearch: true, NoPoc: true, DisableGeneralPoc: true}
	if err := ValidateResumePlan(cfg, cfg.Targets, "rules-a", planHash, plan); err != nil {
		t.Fatalf("ValidateResumePlan: %v", err)
	}
	ctx := &ScanContext{ResumePlan: plan, IPPortMap: make(map[string]string)}
	if resumeStageEnabled(ctx, scanplan.StagePortScan) || !resumeStageEnabled(ctx, scanplan.StageProtocolIdentify) {
		t.Fatal("execution suffix was not enforced")
	}
	if got := resumeCheckpoint(ctx, scanplan.StagePortScan); got == nil || len(got.OpenPorts) != 1 || got.OpenPorts[0] != "192.0.2.10:443" {
		t.Fatalf("port checkpoint was not restored: %+v", got)
	}
}

func TestRequiredResumeStagesUsesValidatorSmallTargetPolicy(t *testing.T) {
	stages, ok := RequiredResumeStages("192.0.2.1", Config{})
	if !ok || len(stages) == 0 || stages[0] != scanplan.StagePortScan {
		t.Fatalf("stages = %v, ok=%v", stages, ok)
	}
}

func TestValidateResumePlanRejectsMissingDependencyAndUnsafeHTTPContentStart(t *testing.T) {
	target := "192.0.2.10"
	cfg := Config{Targets: []string{target}, SkipHostDiscovery: true, NoHostBind: true, NoDirSearch: true, NoPoc: true, DisableGeneralPoc: true}
	base := scanplan.ResumePlan{
		SchemaVersion: scanplan.ResumePlanSchemaVersion,
		TenantID:      "tenant-a", ProjectID: "project-a", NetworkZone: "public", Target: target,
		ScopeHash: testResumeHash("scope"), ConfigHash: testResumeHash("config"), RuleVersion: "rules-a",
		RequiredStages:  []scanplan.Stage{scanplan.StagePortScan, scanplan.StageProtocolIdentify, scanplan.StageHTTPProbe, scanplan.StageFingerprint},
		ReusedStages:    []scanplan.Stage{scanplan.StagePortScan},
		ExecutionStages: []scanplan.Stage{scanplan.StageProtocolIdentify, scanplan.StageHTTPProbe, scanplan.StageFingerprint},
		StartStage:      scanplan.StageProtocolIdentify,
	}
	hash, err := base.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateResumePlan(cfg, cfg.Targets, "rules-a", hash, &base); err == nil {
		t.Fatal("plan without the port dependency checkpoint was accepted")
	}

	urlTarget := "https://example.test"
	unsafe := scanplan.ResumePlan{
		SchemaVersion: scanplan.ResumePlanSchemaVersion,
		TenantID:      "tenant-a", ProjectID: "project-a", NetworkZone: "public", Target: urlTarget,
		ScopeHash: testResumeHash("scope"), ConfigHash: testResumeHash("config"), RuleVersion: "rules-a",
		RequiredStages:  []scanplan.Stage{scanplan.StageHTTPProbe, scanplan.StageFingerprint},
		ReusedStages:    []scanplan.Stage{scanplan.StageHTTPProbe},
		ExecutionStages: []scanplan.Stage{scanplan.StageFingerprint},
		StartStage:      scanplan.StageFingerprint,
	}
	unsafeHash, err := unsafe.Digest()
	if err != nil {
		t.Fatal(err)
	}
	urlCfg := Config{Targets: []string{urlTarget}, NoHostBind: true, NoDirSearch: true, NoPoc: true, DisableGeneralPoc: true}
	if err := ValidateResumePlan(urlCfg, urlCfg.Targets, "rules-a", unsafeHash, &unsafe); err == nil {
		t.Fatal("plan that skips the non-replayable HTTP body was accepted")
	}
}

func TestRestoreResumeProtocolServices(t *testing.T) {
	target := "192.0.2.10:443"
	checkpoint := testResumeCheckpoint(t, target, scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion,
		Stage:         scanplan.StageProtocolIdentify,
		Services:      []scanplan.ServiceCheckpoint{{Endpoint: target, Protocol: "https"}},
	})
	ctx := &ScanContext{
		IPPortMap: make(map[string]string),
		ResumePlan: &scanplan.ResumePlan{
			Checkpoints: []scanplan.ResumeCheckpoint{checkpoint},
		},
	}
	restoreResumeProtocolServices(ctx)
	if got := ctx.IPPortMap[target]; got != "https" {
		t.Fatalf("protocol checkpoint restored %q, want https", got)
	}
}

func testResumeCheckpoint(t *testing.T, target string, checkpoint scanplan.StageCheckpoint) scanplan.ResumeCheckpoint {
	t.Helper()
	if err := checkpoint.ValidateForTarget(target); err != nil {
		t.Fatal(err)
	}
	canonical, err := checkpoint.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	return scanplan.ResumeCheckpoint{
		Stage: checkpoint.Stage, WorkKeyHash: testResumeHash("work"), CoverageID: 1,
		SourceObservationID: 1, ObservationHash: testResumeHash("observation"),
		CheckpointHash: hex.EncodeToString(sum[:]), Checkpoint: checkpoint,
	}
}

func testResumeHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
