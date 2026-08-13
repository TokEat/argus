package db

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func openObservationMergeTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	store, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&Project{}, &Node{}, &ScanObservation{}, &ScanCoverage{}); err != nil {
		t.Fatalf("migrate observation store: %v", err)
	}
	return store
}

func TestMergeStageObservationDerivesZonePerTargetFromServerNode(t *testing.T) {
	store := openObservationMergeTestDB(t)
	project := Project{ID: "project-zone", TenantID: "tenant-zone", Scope: `{}`}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&Node{
		AgentID: "agent-zone", TenantID: project.TenantID, Status: "Alive",
		Tags: `{"network_zone":"corp-a","network_scope":"public"}`,
	}).Error; err != nil {
		t.Fatal(err)
	}
	attempt := SubTask{
		ID: "attempt-zone", TenantID: project.TenantID, ProjectID: project.ID, RootTaskID: "task-zone", BatchID: "batch-zone",
		AgentID: "agent-zone", Config: `{}`, Priority: 1, TimeoutSec: 60, AgentSelector: `{}`, AgentSelectorRules: `{}`, RuleVersion: "rules-v1",
	}
	now := time.Now().UTC()
	event := mergeTestEvent(attempt, "event-zone", scanplan.StageHTTPProbe, scanplan.ObservationNegative, now.Add(-time.Second), now)
	event.Targets = []string{"http://10.0.0.8", "https://example.com"}
	if _, err := MergeStageObservationEvent(store, attempt, event); err != nil {
		t.Fatalf("merge mixed network event: %v", err)
	}
	var observations []ScanObservation
	if err := store.Order("normalized_target asc").Find(&observations).Error; err != nil || len(observations) != 2 {
		t.Fatalf("observations=%+v err=%v", observations, err)
	}
	zones := make(map[string]string, len(observations))
	for _, observation := range observations {
		zones[observation.NormalizedTarget] = observation.NetworkZone
	}
	if zones["http://10.0.0.8"] != "private:corp-a" || zones["https://example.com"] != "public" {
		t.Fatalf("Server-derived per-target zones=%v", zones)
	}
}

func mergeTestEvent(attempt SubTask, eventID string, stage scanplan.Stage, outcome scanplan.ObservationOutcome, startedAt, finishedAt time.Time) scanplan.StageObservationEvent {
	configDigest := sha256.Sum256([]byte(attempt.Config))
	event := scanplan.StageObservationEvent{
		SchemaVersion: scanplan.SchemaVersion,
		EventID:       eventID,
		AttemptID:     attempt.ID,
		AgentID:       attempt.AgentID,
		Stage:         stage,
		Outcome:       outcome,
		Targets:       []string{"https://example.test"},
		ConfigHash:    fmt.Sprintf("%x", configDigest),
		RuleVersion:   attempt.RuleVersion,
		StartedAt:     startedAt,
		FinishedAt:    finishedAt,
		ContentHash:   fmt.Sprintf("%x", sha256.Sum256([]byte(eventID))),
	}
	if outcome == scanplan.ObservationFailed || outcome == scanplan.ObservationSkipped {
		event.ErrorCode = "stage_failed"
		event.ErrorMessage = "test failure"
	}
	return event
}

func TestMergeStageObservationEventIsIdempotentAndFailureIsNotReusable(t *testing.T) {
	store := openObservationMergeTestDB(t)
	project := Project{ID: "project-a", TenantID: "tenant-a", Scope: `{"allowed":["https://example.test"]}`}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	attempt := SubTask{
		ID: "attempt-a", TenantID: "tenant-a", ProjectID: project.ID, RootTaskID: "task-a", BatchID: "batch-a", AgentID: "agent-a",
		Config: `{}`, Priority: 1, TimeoutSec: 60, AgentSelector: `{}`, AgentSelectorRules: `{}`, RuleVersion: "rules-v1",
	}
	now := time.Now().UTC()
	success := mergeTestEvent(attempt, "event-success", scanplan.StageHTTPProbe, scanplan.ObservationNegative, now.Add(-time.Second), now)
	merged, err := MergeStageObservationEvent(store, attempt, success)
	if err != nil {
		t.Fatalf("merge success: %v", err)
	}
	if merged.ObservationsCreated != 1 || merged.CoveragesCreated != 1 || merged.CoveragesUpdated != 0 {
		t.Fatalf("unexpected first merge result: %+v", merged)
	}
	var observation ScanObservation
	if err := store.First(&observation).Error; err != nil {
		t.Fatalf("load observation: %v", err)
	}
	if observation.TenantID != attempt.TenantID || observation.ProjectID != attempt.ProjectID || observation.NetworkZone != "agent:agent-a" || observation.RuleVersion != attempt.RuleVersion || observation.ConfigHash == "" || observation.ScopeHash == "" {
		t.Fatalf("observation snapshot incomplete: %+v", observation)
	}
	var coverage ScanCoverage
	if err := store.First(&coverage).Error; err != nil {
		t.Fatalf("load coverage: %v", err)
	}
	if coverage.Status != string(scanplan.CoverageComplete) || coverage.Outcome != string(scanplan.ObservationNegative) || coverage.Revision != 1 {
		t.Fatalf("unexpected complete coverage: %+v", coverage)
	}

	replayed, err := MergeStageObservationEvent(store, attempt, success)
	if err != nil || replayed != (ScanObservationMergeResult{}) {
		t.Fatalf("idempotent replay result=%+v err=%v", replayed, err)
	}
	var observationCount, coverageCount int64
	store.Model(&ScanObservation{}).Count(&observationCount)
	store.Model(&ScanCoverage{}).Count(&coverageCount)
	if observationCount != 1 || coverageCount != 1 {
		t.Fatalf("replay duplicated rows: observations=%d coverages=%d", observationCount, coverageCount)
	}

	failed := mergeTestEvent(attempt, "event-failed", scanplan.StageHTTPProbe, scanplan.ObservationFailed, now, now.Add(time.Second))
	merged, err = MergeStageObservationEvent(store, attempt, failed)
	if err != nil || merged.ObservationsCreated != 1 || merged.CoveragesUpdated != 1 {
		t.Fatalf("merge failure result=%+v err=%v", merged, err)
	}
	if err := store.First(&coverage, coverage.ID).Error; err != nil {
		t.Fatalf("reload coverage: %v", err)
	}
	if coverage.Status != string(scanplan.CoverageIncomplete) || coverage.Outcome != string(scanplan.ObservationFailed) || coverage.Revision != 2 {
		t.Fatalf("failed observation became reusable: %+v", coverage)
	}

	mutatedReplay := success
	mutatedReplay.ContentHash = fmt.Sprintf("%x", sha256.Sum256([]byte("different")))
	if _, err := MergeStageObservationEvent(store, attempt, mutatedReplay); err == nil {
		t.Fatal("same event ID with different evidence was accepted")
	}
}

func TestMergeStageObservationInvalidatesVersionDriftAndUnknownRiskEndpoint(t *testing.T) {
	store := openObservationMergeTestDB(t)
	project := Project{ID: "project-a", TenantID: "tenant-a", Scope: `{}`}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	now := time.Now().UTC()
	attempt := SubTask{
		ID: "attempt-drift", TenantID: "tenant-a", ProjectID: project.ID, RootTaskID: "task-a", BatchID: "batch-a", AgentID: "agent-a",
		Config: `{}`, Priority: 1, TimeoutSec: 60, AgentSelector: `{}`, AgentSelectorRules: `{}`, RuleVersion: "rules-v1",
	}
	drift := mergeTestEvent(attempt, "event-drift", scanplan.StageFingerprint, scanplan.ObservationSuccess, now.Add(-time.Second), now)
	drift.RuleVersion = "rules-v2"
	drift.ConfigHash = fmt.Sprintf("%x", sha256.Sum256([]byte("different-config")))
	if _, err := MergeStageObservationEvent(store, attempt, drift); err != nil {
		t.Fatalf("persist drift evidence: %v", err)
	}
	var driftCoverage ScanCoverage
	if err := store.Where("stage = ?", string(scanplan.StageFingerprint)).First(&driftCoverage).Error; err != nil {
		t.Fatalf("load drift coverage: %v", err)
	}
	if driftCoverage.Status != string(scanplan.CoverageInvalidated) || !strings.Contains(driftCoverage.InvalidReason, "agent_config_hash_mismatch") || !strings.Contains(driftCoverage.InvalidReason, "rule_version_mismatch") {
		t.Fatalf("version drift was reusable: %+v", driftCoverage)
	}

	riskConfig := `{"ExecutionMode":"risk_validation","RiskValidationTargets":{"https://example.test":["safe.yaml"]},"RiskValidationPocHashes":{"safe.yaml":"0123456789abcdef0123456789abcdef"}}`
	riskAttempt := attempt
	riskAttempt.ID = "attempt-risk"
	riskAttempt.BatchID = "batch-risk"
	riskAttempt.Config = riskConfig
	risk := mergeTestEvent(riskAttempt, "event-risk", scanplan.StageRiskValidation, scanplan.ObservationNegative, now, now.Add(time.Second))
	if _, err := MergeStageObservationEvent(store, riskAttempt, risk); err != nil {
		t.Fatalf("persist risk evidence: %v", err)
	}
	var riskCoverage ScanCoverage
	if err := store.Where("stage = ?", string(scanplan.StageRiskValidation)).First(&riskCoverage).Error; err != nil {
		t.Fatalf("load risk coverage: %v", err)
	}
	if riskCoverage.Status != string(scanplan.CoverageInvalidated) || riskCoverage.POCSetHash == "" || riskCoverage.POCSetHash == "_unknown" || riskCoverage.EndpointContentHash != "_unknown" || !strings.Contains(riskCoverage.InvalidReason, "endpoint_content_unknown") {
		t.Fatalf("risk coverage without endpoint content was reusable: %+v", riskCoverage)
	}
}

func TestManualRetestAppendsEvidenceAndBecomesCurrentCoverage(t *testing.T) {
	store := openObservationMergeTestDB(t)
	project := Project{ID: "project-retest", TenantID: "tenant-retest", Scope: `{}`}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	baseAttempt := SubTask{
		ID: "attempt-initial", TenantID: project.TenantID, ProjectID: project.ID, RootTaskID: "task-retest", BatchID: "batch-retest", AgentID: "agent-retest",
		Trigger: AttemptTriggerInitial, Config: `{}`, Priority: 1, TimeoutSec: 60, AgentSelector: `{}`, AgentSelectorRules: `{}`, RuleVersion: "rules-v1",
	}
	base := time.Date(2026, 8, 9, 4, 0, 0, 0, time.UTC)
	initial := mergeTestEvent(baseAttempt, "event-initial", scanplan.StageHTTPProbe, scanplan.ObservationNegative, base.Add(-time.Second), base)
	if _, err := MergeStageObservationEvent(store, baseAttempt, initial); err != nil {
		t.Fatal(err)
	}

	retest := baseAttempt
	retest.ID = "attempt-manual-retest"
	retest.Trigger = AttemptTriggerManualRetry
	retested := mergeTestEvent(retest, "event-manual-retest", scanplan.StageHTTPProbe, scanplan.ObservationSuccess, base, base.Add(time.Minute))
	if _, err := MergeStageObservationEvent(store, retest, retested); err != nil {
		t.Fatal(err)
	}
	var observations []ScanObservation
	if err := store.Order("observed_at asc").Find(&observations).Error; err != nil || len(observations) != 2 {
		t.Fatalf("manual retest observations=%+v err=%v", observations, err)
	}
	var coverage ScanCoverage
	if err := store.First(&coverage).Error; err != nil {
		t.Fatal(err)
	}
	if coverage.SourceAttemptID != retest.ID || coverage.Revision != 2 || coverage.Outcome != string(scanplan.ObservationSuccess) {
		t.Fatalf("manual retest did not become current evidence: %+v", coverage)
	}
}

func TestRiskValidationPOCSetHashIncludesSealedGoPocPlan(t *testing.T) {
	config := `{"ExecutionMode":"risk_validation","RiskValidationTargets":{},"RiskValidationPocHashes":{},"GoPocCatalogSHA256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","RiskValidationGoPocTargets":[{"Target":"192.0.2.10:445","Plugin":"SMB-MS17-010","Capability":"vulnerability_check","Trigger":"protocol","ObservationSHA256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","PluginRevision":1,"RequestCost":1}]}`
	hash, ok := riskValidationPOCSetHash(config, "192.0.2.10:445")
	if !ok || len(hash) != 64 || hash == "_unknown" {
		t.Fatalf("sealed GoPoc plan hash=%q ok=%v", hash, ok)
	}
	if _, ok := riskValidationPOCSetHash(config, "192.0.2.20:445"); ok {
		t.Fatal("unplanned endpoint received a POC set hash")
	}
}

func TestMergeStageObservationPersistsCheckpointAndRejectsMutatedReplay(t *testing.T) {
	store := openObservationMergeTestDB(t)
	project := Project{ID: "project-checkpoint", TenantID: "tenant-checkpoint", Scope: `{}`}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	attempt := SubTask{
		ID: "attempt-checkpoint", TenantID: project.TenantID, ProjectID: project.ID, RootTaskID: "task-checkpoint", BatchID: "batch-checkpoint", AgentID: "agent-checkpoint",
		Config: `{}`, Priority: 1, TimeoutSec: 60, AgentSelector: `{}`, AgentSelectorRules: `{}`, RuleVersion: "rules-v1",
	}
	now := time.Now().UTC()
	event := mergeTestEvent(attempt, "event-checkpoint", scanplan.StagePortScan, scanplan.ObservationSuccess, now.Add(-time.Second), now)
	event.Targets = []string{"10.0.0.1"}
	event.Checkpoint = &scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion,
		Stage:         scanplan.StagePortScan,
		OpenPorts:     []string{"10.0.0.1:22", "10.0.0.1:443"},
	}
	if _, err := MergeStageObservationEvent(store, attempt, event); err != nil {
		t.Fatalf("merge checkpoint: %v", err)
	}
	var observation ScanObservation
	if err := store.First(&observation).Error; err != nil {
		t.Fatal(err)
	}
	if observation.CheckpointHash == "" || !strings.Contains(observation.Checkpoint, `"open_ports":["10.0.0.1:22","10.0.0.1:443"]`) {
		t.Fatalf("checkpoint evidence was not persisted canonically: %+v", observation)
	}

	mutated := event
	mutated.Checkpoint = &scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion,
		Stage:         scanplan.StagePortScan,
		OpenPorts:     []string{"10.0.0.1:80"},
	}
	if _, err := MergeStageObservationEvent(store, attempt, mutated); err == nil {
		t.Fatal("same event ID with a different checkpoint was accepted")
	}
	outOfScope := event
	outOfScope.EventID = "event-out-of-scope-checkpoint"
	outOfScope.Checkpoint = &scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion,
		Stage:         scanplan.StagePortScan,
		OpenPorts:     []string{"10.0.1.1:22"},
	}
	if _, err := MergeStageObservationEvent(store, attempt, outOfScope); err == nil {
		t.Fatal("checkpoint outside the assigned target was accepted")
	}
}
