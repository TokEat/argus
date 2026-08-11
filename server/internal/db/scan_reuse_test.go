package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/user/dddd-proto/go/scanplan"
	"gorm.io/gorm"
)

const reusableTestConfig = `{"Hunter":false,"Fofa":false,"Quake":false,"OnlyIPPort":false,"Subdomain":true,"SkipHostDiscovery":false,"NoICMPPing":false,"TCPPing":false,"NoHostBind":true,"NoDirSearch":true,"NoPoc":true,"GolangPoc":false,"DisableGeneralPoc":true,"PocNameForSearch":""}`

type scanReuseFixture struct {
	store   *gorm.DB
	project Project
	batch   TaskBatch
	attempt SubTask
}

func newScanReuseFixture(t *testing.T, targets []string) scanReuseFixture {
	t.Helper()
	store, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&Project{}, &Node{}, &RootTask{}, &TaskBatch{}, &SubTask{}, &TaskConfigRevision{}, &ScanObservation{}, &ScanCoverage{}, &ScanWorkClaim{}, &TaskCoverageLink{}); err != nil {
		t.Fatalf("migrate reuse store: %v", err)
	}
	encoded, _ := json.Marshal(targets)
	project := Project{ID: "project-destination", TenantID: "tenant-a", Scope: `{}`}
	attempt := SubTask{
		ID: "attempt-destination", TenantID: project.TenantID, ProjectID: project.ID, RootTaskID: "task-destination",
		BatchID: "batch-destination", AttemptNo: 1, Trigger: AttemptTriggerInitial, ChunkTargets: string(encoded),
		Status: "Pending", Config: reusableTestConfig, Priority: 1, TimeoutSec: 60, MaxRetry: 3,
		ConfigVersion: 1, RuleVersion: "rules-v1", AgentSelector: `{}`, AgentSelectorRules: `{}`,
	}
	batch := TaskBatch{
		ID: attempt.BatchID, TenantID: attempt.TenantID, ProjectID: attempt.ProjectID, RootTaskID: attempt.RootTaskID,
		Sequence: 0, Kind: "asset_scan", Targets: string(encoded), TargetCount: len(targets), Status: "Pending",
		ControlState: string(BatchControlActive), ConfigVersion: 1, RuleVersion: attempt.RuleVersion,
		LatestAttemptID: attempt.ID, CurrentAttemptNo: 1, AttemptCount: 1,
	}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&Node{AgentID: "agent-a", TenantID: project.TenantID, Status: "Alive", Capacity: 1}).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&RootTask{ID: attempt.RootTaskID, TenantID: project.TenantID, ProjectID: project.ID, Status: "Queued", TotalChunks: 1, TotalTargets: len(targets)}).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&batch).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&attempt).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&SubTask{ID: "attempt-source", TenantID: project.TenantID, ProjectID: project.ID, Status: "Done"}).Error; err != nil {
		t.Fatal(err)
	}
	return scanReuseFixture{store: store, project: project, batch: batch, attempt: attempt}
}

func (f scanReuseFixture) seedCoverage(t *testing.T, target string, stage scanplan.Stage, outcome scanplan.ObservationOutcome, mutate func(*ScanCoverage)) ScanCoverage {
	t.Helper()
	scopeHash, ok := canonicalJSONHash(f.project.Scope)
	if !ok {
		t.Fatal("fixture scope is invalid")
	}
	configHash := TaskConfigHash(f.attempt.Config, f.attempt.Priority, f.attempt.TimeoutSec, f.attempt.AgentSelector, f.attempt.AgentSelectorRules)
	var node Node
	if err := f.store.Select("tags").Where("agent_id = ? AND tenant_id = ?", "agent-a", f.attempt.TenantID).First(&node).Error; err != nil {
		t.Fatal(err)
	}
	key := scanplan.WorkKey{
		TenantID: f.attempt.TenantID, ProjectID: f.attempt.ProjectID, NetworkZone: scanNetworkZoneForTarget("agent-a", node.Tags, target),
		NormalizedTarget: target, Stage: stage, ScopeHash: scopeHash, ConfigHash: configHash, RuleVersion: f.attempt.RuleVersion,
	}
	digest, err := key.Digest()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	validUntil := now.Add(serverCoverageTTL(stage))
	coverage := ScanCoverage{
		SchemaVersion: scanplan.SchemaVersion, TenantID: f.attempt.TenantID, ProjectID: f.attempt.ProjectID,
		NetworkZone: key.NetworkZone, NormalizedTarget: target, TargetHash: sha256Hex([]byte(target)), Stage: string(stage),
		WorkKeyHash: digest, ScopeHash: scopeHash, ConfigHash: configHash, RuleVersion: f.attempt.RuleVersion,
		Status: string(scanplan.CoverageComplete), Outcome: string(outcome), StartedAt: now.Add(-time.Second), FinishedAt: now, ValidUntil: &validUntil,
		SourceTaskID: "task-source", SourceBatchID: "batch-source", SourceAttemptID: "attempt-source", Revision: 1,
	}
	if mutate != nil {
		mutate(&coverage)
	}
	if err := f.store.Create(&coverage).Error; err != nil {
		t.Fatalf("seed %s coverage: %v", stage, err)
	}
	return coverage
}

func (f scanReuseFixture) seedCheckpointCoverage(t *testing.T, target string, checkpoint scanplan.StageCheckpoint) ScanCoverage {
	t.Helper()
	coverage := f.seedCoverage(t, target, checkpoint.Stage, scanplan.ObservationSuccess, nil)
	encoded, err := checkpoint.CanonicalJSON()
	if err != nil {
		t.Fatalf("encode %s checkpoint: %v", checkpoint.Stage, err)
	}
	checkpointHash := sha256Hex(encoded)
	workKey := scanplan.WorkKey{
		TenantID: coverage.TenantID, ProjectID: coverage.ProjectID, NetworkZone: coverage.NetworkZone,
		NormalizedTarget: coverage.NormalizedTarget, Stage: checkpoint.Stage, ScopeHash: coverage.ScopeHash,
		ConfigHash: coverage.ConfigHash, RuleVersion: coverage.RuleVersion,
	}
	evidenceHash, err := canonicalContractHash(scanplan.Observation{
		SchemaVersion:  scanplan.SchemaVersion,
		WorkKey:        workKey,
		Outcome:        scanplan.ObservationSuccess,
		ObservedAt:     coverage.FinishedAt,
		ContentHash:    "content-v1",
		CheckpointHash: checkpointHash,
	})
	if err != nil {
		t.Fatalf("hash %s checkpoint observation: %v", checkpoint.Stage, err)
	}
	observation := ScanObservation{
		SchemaVersion: scanplan.SchemaVersion,
		TenantID:      coverage.TenantID, ProjectID: coverage.ProjectID, NetworkZone: coverage.NetworkZone,
		NormalizedTarget: coverage.NormalizedTarget, TargetHash: coverage.TargetHash, Stage: coverage.Stage,
		WorkKeyHash: coverage.WorkKeyHash, ScopeHash: coverage.ScopeHash, ConfigHash: coverage.ConfigHash,
		RuleVersion: coverage.RuleVersion, RootTaskID: coverage.SourceTaskID, BatchID: coverage.SourceBatchID,
		AttemptID: coverage.SourceAttemptID, AgentID: "agent-a", Outcome: coverage.Outcome,
		ContentHash: "content-v1", Checkpoint: string(encoded), CheckpointHash: checkpointHash,
		EvidenceHash: evidenceHash, ObservedAt: coverage.FinishedAt,
	}
	if err := f.store.Create(&observation).Error; err != nil {
		t.Fatalf("seed %s checkpoint observation: %v", checkpoint.Stage, err)
	}
	coverage.SourceObservationID = observation.ID
	coverage.ObservationHash = evidenceHash
	if err := f.store.Model(&ScanCoverage{}).Where("id = ?", coverage.ID).Updates(map[string]interface{}{
		"source_observation_id": observation.ID,
		"observation_hash":      evidenceHash,
	}).Error; err != nil {
		t.Fatalf("link %s checkpoint coverage: %v", checkpoint.Stage, err)
	}
	return coverage
}

func TestApplyReusableCoverageAtClaimUsesPublicAndPrivateNetworkZones(t *testing.T) {
	for _, test := range []struct {
		name       string
		target     string
		agentATags string
		agentBTags string
		wantReuse  bool
	}{
		{name: "public across Agents", target: "https://example.com", wantReuse: true},
		{name: "same labelled private zone", target: "http://10.0.0.8", agentATags: `{"network_zone":"corp"}`, agentBTags: `{"network_zone":"corp"}`, wantReuse: true},
		{name: "different private zones", target: "http://10.0.0.8", agentATags: `{"network_zone":"corp-a"}`, agentBTags: `{"network_zone":"corp-b"}`, wantReuse: false},
		{name: "unlabelled private Agents", target: "http://10.0.0.8", wantReuse: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScanReuseFixture(t, []string{test.target})
			if err := fixture.store.Model(&Node{}).Where("agent_id = ?", "agent-a").Update("tags", test.agentATags).Error; err != nil {
				t.Fatal(err)
			}
			if err := fixture.store.Create(&Node{AgentID: "agent-b", TenantID: fixture.attempt.TenantID, Status: "Alive", Tags: test.agentBTags}).Error; err != nil {
				t.Fatal(err)
			}
			fixture.seedReusableURL(t, test.target)
			result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-b")
			if err != nil || result.FullyReused != test.wantReuse {
				t.Fatalf("reuse=%+v err=%v want=%v", result, err, test.wantReuse)
			}
		})
	}
}

func (f scanReuseFixture) seedReusableURL(t *testing.T, target string) {
	f.seedCoverage(t, target, scanplan.StageHTTPProbe, scanplan.ObservationNegative, nil)
	f.seedCoverage(t, target, scanplan.StageFingerprint, scanplan.ObservationNegative, nil)
}

func TestApplyReusableCoverageAtClaimCompletesFullyReusedBatch(t *testing.T) {
	target := "https://one.example.test"
	fixture := newScanReuseFixture(t, []string{target})
	fixture.seedReusableURL(t, target)

	result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
	if err != nil {
		t.Fatalf("apply reuse: %v", err)
	}
	if !result.FullyReused || result.ReusedTargets != 1 || result.ReusedStages != 2 || len(result.RemainingTargets) != 0 {
		t.Fatalf("unexpected reuse result: %+v", result)
	}
	var attempt SubTask
	if err := fixture.store.First(&attempt, "id = ?", fixture.attempt.ID).Error; err != nil {
		t.Fatal(err)
	}
	if CanonicalAttemptState(attempt.Status) != AttemptStateCompleted || attempt.FinishedAt == nil || attempt.ChunkTargets != "[]" || attempt.AgentID != "" {
		t.Fatalf("fully reused attempt was not completed without assignment: %+v", attempt)
	}
	var batch TaskBatch
	if err := fixture.store.First(&batch, "id = ?", fixture.batch.ID).Error; err != nil {
		t.Fatal(err)
	}
	if CanonicalAttemptState(batch.Status) != AttemptStateCompleted || batch.Targets != fixture.batch.Targets || batch.TargetCount != 1 {
		t.Fatalf("stable batch scope was changed: %+v", batch)
	}
	var links []TaskCoverageLink
	if err := fixture.store.Order("work_key_hash").Find(&links).Error; err != nil || len(links) != 2 {
		t.Fatalf("reused links=%d err=%v", len(links), err)
	}
	for _, link := range links {
		if link.LinkType != "reused" || link.SourceTaskID != "task-source" || link.SourceBatchID != "batch-source" || link.SourceAttemptID != "attempt-source" || link.Reason != "valid_project_coverage" {
			t.Fatalf("incomplete reuse provenance: %+v", link)
		}
	}
}

func TestApplyReusableCoverageAtClaimTreatsNegativePortScanAsCompleteWithoutProtocolWork(t *testing.T) {
	for _, test := range []struct {
		name        string
		portOutcome scanplan.ObservationOutcome
		wantReuse   bool
	}{
		{name: "no open port", portOutcome: scanplan.ObservationNegative, wantReuse: true},
		{name: "open port requires protocol", portOutcome: scanplan.ObservationSuccess, wantReuse: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := "192.0.2.10"
			fixture := newScanReuseFixture(t, []string{target})
			fixture.seedCoverage(t, target, scanplan.StagePortScan, test.portOutcome, nil)
			fixture.seedCoverage(t, target, scanplan.StageHTTPProbe, scanplan.ObservationNegative, nil)
			fixture.seedCoverage(t, target, scanplan.StageFingerprint, scanplan.ObservationNegative, nil)

			result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
			if err != nil || result.FullyReused != test.wantReuse {
				t.Fatalf("port outcome %s result=%+v err=%v", test.portOutcome, result, err)
			}
		})
	}
}

func TestApplyReusableCoverageAtClaimReturnsPartialPlanWithoutPersistingAgentScopedDecision(t *testing.T) {
	covered := "https://covered.example.test"
	uncovered := "https://uncovered.example.test"
	fixture := newScanReuseFixture(t, []string{covered, uncovered})
	fixture.seedReusableURL(t, covered)

	result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
	if err != nil || result.FullyReused || result.ReusedTargets != 1 || len(result.RemainingTargets) != 1 || result.RemainingTargets[0] != uncovered {
		t.Fatalf("partial reuse result=%+v err=%v", result, err)
	}
	var attempt SubTask
	if err := fixture.store.First(&attempt, "id = ?", fixture.attempt.ID).Error; err != nil {
		t.Fatal(err)
	}
	if attempt.Status != fixture.attempt.Status || attempt.ChunkTargets != fixture.attempt.ChunkTargets {
		t.Fatalf("partial reuse escaped the eventual Agent lease transaction: %+v", attempt)
	}
	var batch TaskBatch
	if err := fixture.store.First(&batch, "id = ?", fixture.batch.ID).Error; err != nil {
		t.Fatal(err)
	}
	if batch.Targets != fixture.batch.Targets || batch.TargetCount != 2 {
		t.Fatalf("partial reuse changed stable batch scope: %+v", batch)
	}

	replayed, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
	if err != nil || replayed.ReusedTargets != 1 || len(replayed.RemainingTargets) != 1 || replayed.RemainingTargets[0] != uncovered {
		t.Fatalf("repeatable partial plan result=%+v err=%v", replayed, err)
	}
	var linkCount int64
	fixture.store.Model(&TaskCoverageLink{}).Count(&linkCount)
	if linkCount != 0 {
		t.Fatalf("partial plan persisted %d links before an Agent lease", linkCount)
	}
	if err := fixture.store.Transaction(func(tx *gorm.DB) error {
		return ValidateReusableCoverageLinksAtLease(tx, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a", result.Links)
	}); err != nil {
		t.Fatalf("fresh partial plan failed lease validation: %v", err)
	}
	if err := fixture.store.Model(&ScanCoverage{}).
		Where("stage = ?", string(scanplan.StageHTTPProbe)).
		Update("status", string(scanplan.CoverageInvalidated)).Error; err != nil {
		t.Fatal(err)
	}
	err = fixture.store.Transaction(func(tx *gorm.DB) error {
		return ValidateReusableCoverageLinksAtLease(tx, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a", result.Links)
	})
	if !errors.Is(err, ErrReusableCoverageChanged) {
		t.Fatalf("stale partial plan validation err=%v, want ErrReusableCoverageChanged", err)
	}
}

func TestApplyReusableCoverageAtClaimRejectsUnsafeOrStaleCoverage(t *testing.T) {
	for _, test := range []struct {
		name          string
		mutateAttempt func(*SubTask)
		mutateBatch   func(*TaskBatch)
		mutateHTTP    func(*ScanCoverage)
	}{
		{name: "manual retry", mutateAttempt: func(attempt *SubTask) { attempt.Trigger = AttemptTriggerManualRetry }},
		{name: "risk validation", mutateBatch: func(batch *TaskBatch) { batch.Kind = "risk_validation" }},
		{name: "paused batch", mutateBatch: func(batch *TaskBatch) { batch.ControlState = string(BatchControlPaused) }},
		{name: "incomplete", mutateHTTP: func(coverage *ScanCoverage) { coverage.Status = string(scanplan.CoverageIncomplete) }},
		{name: "invalidated", mutateHTTP: func(coverage *ScanCoverage) { coverage.Status = string(scanplan.CoverageInvalidated) }},
		{name: "failed", mutateHTTP: func(coverage *ScanCoverage) { coverage.Outcome = string(scanplan.ObservationFailed) }},
		{name: "expired", mutateHTTP: func(coverage *ScanCoverage) { expired := time.Now().Add(-time.Minute); coverage.ValidUntil = &expired }},
		{name: "wrong zone", mutateHTTP: func(coverage *ScanCoverage) { coverage.NetworkZone = "agent:agent-b" }},
		{name: "foreign tenant", mutateHTTP: func(coverage *ScanCoverage) { coverage.TenantID = "tenant-b" }},
		{name: "foreign project", mutateHTTP: func(coverage *ScanCoverage) { coverage.ProjectID = "project-b" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := "https://one.example.test"
			fixture := newScanReuseFixture(t, []string{target})
			if test.mutateAttempt != nil {
				test.mutateAttempt(&fixture.attempt)
				if err := fixture.store.Save(&fixture.attempt).Error; err != nil {
					t.Fatal(err)
				}
			}
			if test.mutateBatch != nil {
				test.mutateBatch(&fixture.batch)
				if err := fixture.store.Save(&fixture.batch).Error; err != nil {
					t.Fatal(err)
				}
			}
			fixture.seedCoverage(t, target, scanplan.StageHTTPProbe, scanplan.ObservationNegative, test.mutateHTTP)
			fixture.seedCoverage(t, target, scanplan.StageFingerprint, scanplan.ObservationNegative, nil)

			result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
			if err != nil || result.ReusedTargets != 0 || result.FullyReused || len(result.RemainingTargets) != 1 {
				t.Fatalf("unsafe coverage result=%+v err=%v", result, err)
			}
			var linkCount int64
			fixture.store.Model(&TaskCoverageLink{}).Count(&linkCount)
			if linkCount != 0 {
				t.Fatalf("unsafe coverage created %d links", linkCount)
			}
		})
	}
}

func TestApplyReusableCoverageAtClaimRejectsCoverageWhenWorkKeyDimensionsChange(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, scanReuseFixture)
	}{
		{
			name: "rule version changed",
			mutate: func(t *testing.T, fixture scanReuseFixture) {
				if err := fixture.store.Model(&SubTask{}).Where("id = ?", fixture.attempt.ID).Update("rule_version", "rules-v2").Error; err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "scan config changed",
			mutate: func(t *testing.T, fixture scanReuseFixture) {
				changed := strings.Replace(fixture.attempt.Config, `"NoDirSearch":true`, `"NoDirSearch":false`, 1)
				if err := fixture.store.Model(&SubTask{}).Where("id = ?", fixture.attempt.ID).Update("config", changed).Error; err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "project scope changed",
			mutate: func(t *testing.T, fixture scanReuseFixture) {
				if err := fixture.store.Model(&Project{}).Where("id = ? AND tenant_id = ?", fixture.project.ID, fixture.project.TenantID).Update("scope", `{"allowed":["other.example"]}`).Error; err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := "https://one.example.test"
			fixture := newScanReuseFixture(t, []string{target})
			fixture.seedReusableURL(t, target)
			test.mutate(t, fixture)
			result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
			if err != nil || result.ReusedTargets != 0 || result.FullyReused || len(result.RemainingTargets) != 1 {
				t.Fatalf("changed WorkKey reused stale coverage: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestApplyReusableCoverageAtClaimRequiresTenantBoundAliveAgent(t *testing.T) {
	target := "https://one.example.test"
	fixture := newScanReuseFixture(t, []string{target})
	fixture.seedReusableURL(t, target)

	result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-b")
	if err != nil || result.ReusedTargets != 0 || result.FullyReused || len(result.RemainingTargets) != 1 {
		t.Fatalf("foreign Agent reuse result=%+v err=%v", result, err)
	}
	if err := fixture.store.Model(&Node{}).Where("agent_id = ?", "agent-a").Update("status", "Draining").Error; err != nil {
		t.Fatal(err)
	}
	result, err = ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
	if err != nil || result.ReusedTargets != 0 || result.FullyReused || len(result.RemainingTargets) != 1 {
		t.Fatalf("draining Agent reuse result=%+v err=%v", result, err)
	}
}

func TestApplyReusableCoverageAtClaimDoesNotTreatRunningSourceAsHistory(t *testing.T) {
	target := "https://one.example.test"
	fixture := newScanReuseFixture(t, []string{target})
	fixture.seedReusableURL(t, target)
	if err := fixture.store.Model(&SubTask{}).Where("id = ?", "attempt-source").Update("status", "Running").Error; err != nil {
		t.Fatal(err)
	}
	result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
	if err != nil || result.ReusedTargets != 0 || result.FullyReused || len(result.RemainingTargets) != 1 {
		t.Fatalf("running source reuse result=%+v err=%v", result, err)
	}
}

func TestApplyReusableCoverageAtClaimFailsClosedForLegacyConfigAndIdentityDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*scanReuseFixture)
	}{
		{name: "legacy partial config", mutate: func(f *scanReuseFixture) { f.attempt.Config = `{"NoPoc":true}` }},
		{name: "rule drift", mutate: func(f *scanReuseFixture) { f.attempt.RuleVersion = "rules-v2" }},
		{name: "scope drift", mutate: func(f *scanReuseFixture) { f.project.Scope = `{"allowed":["other"]}` }},
		{name: "config drift", mutate: func(f *scanReuseFixture) { f.attempt.TimeoutSec++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := "https://one.example.test"
			fixture := newScanReuseFixture(t, []string{target})
			fixture.seedReusableURL(t, target)
			test.mutate(&fixture)
			if err := fixture.store.Save(&fixture.attempt).Error; err != nil {
				t.Fatal(err)
			}
			if err := fixture.store.Save(&fixture.project).Error; err != nil {
				t.Fatal(err)
			}
			result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
			if err != nil || result.ReusedTargets != 0 || result.FullyReused {
				t.Fatalf("identity drift result=%+v err=%v", result, err)
			}
		})
	}
}

func TestApplyReusableCoverageAtClaimPlansHTTPReplayWhenBodyIsNotCheckpointed(t *testing.T) {
	target := "https://one.example.test"
	fixture := newScanReuseFixture(t, []string{target})
	fixture.seedCheckpointCoverage(t, target, scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion,
		Stage:         scanplan.StageHTTPProbe,
		URLs:          []string{target},
	})

	result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if result.ResumePlan == nil || result.ResumePlan.StartStage != scanplan.StageHTTPProbe ||
		len(result.ResumePlan.ReusedStages) != 0 || len(result.ResumePlan.Checkpoints) != 0 ||
		result.ResumePlan.FallbackReason != "http_content_not_replayable" || len(result.ResumePlanHash) != 64 {
		t.Fatalf("HTTP body dependency was not safely replayed: %+v", result.ResumePlan)
	}
}

func TestApplyReusableCoverageAtClaimPlansProtocolFromPortCheckpoint(t *testing.T) {
	target := "192.0.2.10"
	fixture := newScanReuseFixture(t, []string{target})
	fixture.seedCheckpointCoverage(t, target, scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion,
		Stage:         scanplan.StagePortScan,
		OpenPorts:     []string{"192.0.2.10:443"},
	})

	result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	plan := result.ResumePlan
	if plan == nil || plan.StartStage != scanplan.StageProtocolIdentify ||
		len(plan.ReusedStages) != 1 || plan.ReusedStages[0] != scanplan.StagePortScan ||
		len(plan.Checkpoints) != 1 || plan.Checkpoints[0].Stage != scanplan.StagePortScan {
		t.Fatalf("port checkpoint did not seed protocol resume: %+v", plan)
	}
}

func TestValidateResumePlanAtLeaseAcceptsExactEvidenceAndRejectsDrift(t *testing.T) {
	target := "192.0.2.10"
	fixture := newScanReuseFixture(t, []string{target})
	if err := fixture.store.Model(&Node{}).Where("agent_id = ?", "agent-a").Update("rule_version", fixture.attempt.RuleVersion).Error; err != nil {
		t.Fatal(err)
	}
	coverage := fixture.seedCheckpointCoverage(t, target, scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion,
		Stage:         scanplan.StagePortScan,
		OpenPorts:     []string{"192.0.2.10:443"},
	})
	result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
	if err != nil || result.ResumePlan == nil {
		t.Fatalf("plan resume: plan=%+v err=%v", result.ResumePlan, err)
	}
	var links []TaskCoverageLink
	if err := fixture.store.Transaction(func(tx *gorm.DB) error {
		var validateErr error
		links, validateErr = ValidateResumePlanAtLease(tx, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a", result.ResumePlan, result.ResumePlanHash)
		return validateErr
	}); err != nil {
		t.Fatalf("validate exact resume plan: %v", err)
	}
	if len(links) != 1 || links[0].CoverageID != coverage.ID || links[0].Reason != "resume_plan:"+result.ResumePlanHash {
		t.Fatalf("unexpected resume links: %+v", links)
	}

	expired := time.Now().UTC().Add(-time.Minute)
	if err := fixture.store.Model(&ScanCoverage{}).Where("id = ?", coverage.ID).Update("valid_until", expired).Error; err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Transaction(func(tx *gorm.DB) error {
		_, validateErr := ValidateResumePlanAtLease(tx, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a", result.ResumePlan, result.ResumePlanHash)
		return validateErr
	}); !errors.Is(err, ErrReusableCoverageChanged) {
		t.Fatalf("expired resume evidence error=%v, want ErrReusableCoverageChanged", err)
	}
}

func TestValidateResumePlanAtLeaseRejectsTamperedPlanHash(t *testing.T) {
	target := "192.0.2.10"
	fixture := newScanReuseFixture(t, []string{target})
	if err := fixture.store.Model(&Node{}).Where("agent_id = ?", "agent-a").Update("rule_version", fixture.attempt.RuleVersion).Error; err != nil {
		t.Fatal(err)
	}
	fixture.seedCheckpointCoverage(t, target, scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion,
		Stage:         scanplan.StagePortScan,
		OpenPorts:     []string{"192.0.2.10:443"},
	})
	result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
	if err != nil || result.ResumePlan == nil {
		t.Fatalf("plan resume: plan=%+v err=%v", result.ResumePlan, err)
	}
	if _, err := ValidateResumePlanAtLease(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a", result.ResumePlan, strings.Repeat("0", 64)); !errors.Is(err, ErrReusableCoverageChanged) {
		t.Fatalf("tampered plan hash error=%v, want ErrReusableCoverageChanged", err)
	}
}

func TestApplyReusableCoverageAtClaimCarriesEarlierLivenessIntoPortDependency(t *testing.T) {
	target := "10.20.0.0/16"
	fixture := newScanReuseFixture(t, []string{target})
	fixture.attempt.Config = strings.Replace(fixture.attempt.Config, `"TCPPing":false`, `"TCPPing":true`, 1)
	if err := fixture.store.Save(&fixture.attempt).Error; err != nil {
		t.Fatal(err)
	}
	fixture.seedCheckpointCoverage(t, target, scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion,
		Stage:         scanplan.StageICMPDiscovery,
		AliveHosts:    []string{"10.20.0.8"},
	})

	result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	plan := result.ResumePlan
	if plan == nil || plan.StartStage != scanplan.StageTCPLiveness ||
		len(plan.ReusedStages) != 1 || plan.ReusedStages[0] != scanplan.StageICMPDiscovery ||
		len(plan.Checkpoints) != 1 || plan.Checkpoints[0].Stage != scanplan.StageICMPDiscovery {
		t.Fatalf("reused ICMP output was not carried into the liveness union: %+v", plan)
	}
}

func TestApplyReusableCoverageAtClaimPlansHTTPFromProtocolCheckpoint(t *testing.T) {
	target := "192.0.2.10"
	fixture := newScanReuseFixture(t, []string{target})
	fixture.seedCoverage(t, target, scanplan.StagePortScan, scanplan.ObservationSuccess, nil)
	fixture.seedCheckpointCoverage(t, target, scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion,
		Stage:         scanplan.StageProtocolIdentify,
		Services: []scanplan.ServiceCheckpoint{{
			Endpoint: "192.0.2.10:443",
			Protocol: "https",
		}},
	})

	result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	plan := result.ResumePlan
	if plan == nil || plan.StartStage != scanplan.StageHTTPProbe || len(plan.ReusedStages) != 2 ||
		plan.ReusedStages[0] != scanplan.StagePortScan || plan.ReusedStages[1] != scanplan.StageProtocolIdentify ||
		len(plan.Checkpoints) != 1 || plan.Checkpoints[0].Stage != scanplan.StageProtocolIdentify {
		t.Fatalf("protocol checkpoint did not seed HTTP resume: %+v", plan)
	}
}

func TestApplyReusableCoverageAtClaimFallsBackForUntrustedCheckpoint(t *testing.T) {
	target := "192.0.2.10"
	fixture := newScanReuseFixture(t, []string{target})
	coverage := fixture.seedCheckpointCoverage(t, target, scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion,
		Stage:         scanplan.StagePortScan,
		OpenPorts:     []string{"192.0.2.10:443"},
	})
	mutatedCheckpoint := `{"schema_version":"argus.checkpoint/v1","stage":"port_scan","open_ports":["192.0.2.10:80"]}`
	if err := fixture.store.Model(&ScanObservation{}).Where("id = ?", coverage.SourceObservationID).
		Updates(map[string]interface{}{
			"checkpoint":      mutatedCheckpoint,
			"checkpoint_hash": sha256Hex([]byte(mutatedCheckpoint)),
		}).Error; err != nil {
		t.Fatal(err)
	}

	result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	plan := result.ResumePlan
	if plan == nil || plan.StartStage != scanplan.StagePortScan || len(plan.ReusedStages) != 0 ||
		len(plan.Checkpoints) != 0 || plan.FallbackReason != "checkpoint_unavailable:port_scan" {
		t.Fatalf("mutated checkpoint did not fall back to port scan: %+v", plan)
	}
}

func TestApplyReusableCoverageAtClaimDoesNotPlanResumeForMultiTargetOrForcedAttempts(t *testing.T) {
	t.Run("multi target", func(t *testing.T) {
		multi := newScanReuseFixture(t, []string{"192.0.2.10", "192.0.2.11"})
		multi.seedCheckpointCoverage(t, "192.0.2.10", scanplan.StageCheckpoint{
			SchemaVersion: scanplan.CheckpointSchemaVersion,
			Stage:         scanplan.StagePortScan,
			OpenPorts:     []string{"192.0.2.10:443"},
		})
		result, err := ApplyReusableCoverageAtClaim(multi.store, multi.attempt.ID, multi.attempt.TenantID, "agent-a")
		if err != nil || result.ResumePlan != nil {
			t.Fatalf("multi-target Attempt received resume plan: plan=%+v err=%v", result.ResumePlan, err)
		}
	})

	t.Run("manual retry", func(t *testing.T) {
		forced := newScanReuseFixture(t, []string{"192.0.2.12"})
		forced.attempt.Trigger = AttemptTriggerManualRetry
		if err := forced.store.Save(&forced.attempt).Error; err != nil {
			t.Fatal(err)
		}
		forced.seedCheckpointCoverage(t, "192.0.2.12", scanplan.StageCheckpoint{
			SchemaVersion: scanplan.CheckpointSchemaVersion,
			Stage:         scanplan.StagePortScan,
			OpenPorts:     []string{"192.0.2.12:443"},
		})
		result, err := ApplyReusableCoverageAtClaim(forced.store, forced.attempt.ID, forced.attempt.TenantID, "agent-a")
		if err != nil || result.ResumePlan != nil {
			t.Fatalf("manual retry received resume plan: plan=%+v err=%v", result.ResumePlan, err)
		}
	})
}

func TestApplyReusableCoverageAtClaimFallsBackWhenSourceAttemptIsNotComplete(t *testing.T) {
	target := "192.0.2.10"
	fixture := newScanReuseFixture(t, []string{target})
	fixture.seedCheckpointCoverage(t, target, scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion,
		Stage:         scanplan.StagePortScan,
		OpenPorts:     []string{"192.0.2.10:443"},
	})
	if err := fixture.store.Model(&SubTask{}).Where("id = ?", "attempt-source").Update("status", "Running").Error; err != nil {
		t.Fatal(err)
	}

	result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if result.ResumePlan == nil || result.ResumePlan.StartStage != scanplan.StagePortScan ||
		len(result.ResumePlan.ReusedStages) != 0 || len(result.ResumePlan.Checkpoints) != 0 {
		t.Fatalf("running source was used for resume: %+v", result.ResumePlan)
	}
}

func TestApplyReusableCoverageAtClaimResumePlannerRejectsInvalidCoverageDimensions(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, scanReuseFixture, ScanCoverage)
	}{
		{
			name: "incomplete coverage",
			mutate: func(t *testing.T, fixture scanReuseFixture, coverage ScanCoverage) {
				if err := fixture.store.Model(&ScanCoverage{}).Where("id = ?", coverage.ID).
					Update("status", string(scanplan.CoverageIncomplete)).Error; err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "expired coverage",
			mutate: func(t *testing.T, fixture scanReuseFixture, coverage ScanCoverage) {
				expired := time.Now().UTC().Add(-time.Minute)
				if err := fixture.store.Model(&ScanCoverage{}).Where("id = ?", coverage.ID).
					Update("valid_until", expired).Error; err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing TTL",
			mutate: func(t *testing.T, fixture scanReuseFixture, coverage ScanCoverage) {
				if err := fixture.store.Model(&ScanCoverage{}).Where("id = ?", coverage.ID).
					Update("valid_until", nil).Error; err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "rule version WorkKey changed",
			mutate: func(t *testing.T, fixture scanReuseFixture, _ ScanCoverage) {
				if err := fixture.store.Model(&SubTask{}).Where("id = ?", fixture.attempt.ID).
					Update("rule_version", "rules-v2").Error; err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := "192.0.2.10"
			fixture := newScanReuseFixture(t, []string{target})
			coverage := fixture.seedCheckpointCoverage(t, target, scanplan.StageCheckpoint{
				SchemaVersion: scanplan.CheckpointSchemaVersion,
				Stage:         scanplan.StagePortScan,
				OpenPorts:     []string{"192.0.2.10:443"},
			})
			test.mutate(t, fixture, coverage)
			result, err := ApplyReusableCoverageAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a")
			if err != nil {
				t.Fatal(err)
			}
			if result.ResumePlan == nil || result.ResumePlan.StartStage != scanplan.StagePortScan ||
				len(result.ResumePlan.ReusedStages) != 0 || len(result.ResumePlan.Checkpoints) != 0 {
				t.Fatalf("invalid coverage influenced resume plan: %+v", result.ResumePlan)
			}
		})
	}
}
