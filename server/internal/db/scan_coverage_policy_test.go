package db

import (
	"testing"
	"time"

	"github.com/user/dddd-proto/go/scanplan"
)

func TestServerCoverageTTLPolicy(t *testing.T) {
	for _, test := range []struct {
		stage scanplan.Stage
		want  time.Duration
	}{
		{stage: scanplan.StageICMPDiscovery, want: 5 * time.Minute},
		{stage: scanplan.StageTCPLiveness, want: 5 * time.Minute},
		{stage: scanplan.StagePortScan, want: time.Hour},
		{stage: scanplan.StageHTTPProbe, want: 6 * time.Hour},
		{stage: scanplan.StageFingerprint, want: 6 * time.Hour},
		{stage: scanplan.StageRiskValidation, want: 24 * time.Hour},
	} {
		if got := serverCoverageTTL(test.stage); got != test.want {
			t.Fatalf("serverCoverageTTL(%s)=%s, want %s", test.stage, got, test.want)
		}
	}
	finishedAt := time.Date(2026, 8, 9, 1, 2, 3, 0, time.UTC)
	if got := coverageValidUntil(scanplan.CoverageComplete, scanplan.StagePortScan, finishedAt); got == nil || !got.Equal(finishedAt.Add(time.Hour)) {
		t.Fatalf("port valid_until=%v", got)
	}
	if got := coverageValidUntil(scanplan.CoverageIncomplete, scanplan.StagePortScan, finishedAt); got != nil {
		t.Fatalf("incomplete coverage received TTL: %v", got)
	}
}

func TestChangedContentInvalidatesOnlyOlderDependentCoverage(t *testing.T) {
	store := openObservationMergeTestDB(t)
	project := Project{ID: "project-content", TenantID: "tenant-content", Scope: `{}`}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	attempt := SubTask{
		ID: "attempt-content", TenantID: project.TenantID, ProjectID: project.ID, RootTaskID: "task-content", BatchID: "batch-content", AgentID: "agent-content",
		Config: `{}`, Priority: 1, TimeoutSec: 60, AgentSelector: `{}`, AgentSelectorRules: `{}`, RuleVersion: "rules-v1",
	}
	target := "https://example.test"
	base := time.Date(2026, 8, 9, 2, 0, 0, 0, time.UTC)
	merge := func(eventID string, stage scanplan.Stage, finishedAt time.Time, content string) ScanObservationMergeResult {
		t.Helper()
		event := mergeTestEvent(attempt, eventID, stage, scanplan.ObservationSuccess, finishedAt.Add(-time.Second), finishedAt)
		event.Targets = []string{target}
		event.ContentHash = sha256Hex([]byte(content))
		result, err := MergeStageObservationEvent(store, attempt, event)
		if err != nil {
			t.Fatalf("merge %s: %v", stage, err)
		}
		return result
	}

	merge("protocol-v1", scanplan.StageProtocolIdentify, base, "protocol")
	merge("http-v1", scanplan.StageHTTPProbe, base.Add(time.Minute), "body-v1")
	merge("finger-v1", scanplan.StageFingerprint, base.Add(2*time.Minute), "finger-v1")

	var httpCoverage ScanCoverage
	if err := store.Where("stage = ?", string(scanplan.StageHTTPProbe)).First(&httpCoverage).Error; err != nil {
		t.Fatal(err)
	}
	risk := ScanCoverage{
		SchemaVersion: scanplan.SchemaVersion, TenantID: attempt.TenantID, ProjectID: attempt.ProjectID,
		NetworkZone: httpCoverage.NetworkZone, NormalizedTarget: target, TargetHash: httpCoverage.TargetHash,
		Stage: string(scanplan.StageRiskValidation), WorkKeyHash: sha256Hex([]byte("risk-work")),
		ScopeHash: "risk-scope", ConfigHash: "risk-config", RuleVersion: attempt.RuleVersion,
		POCSetHash: "pocs", EndpointContentHash: sha256Hex([]byte("body-v1")),
		Status: string(scanplan.CoverageComplete), Outcome: string(scanplan.ObservationNegative),
		StartedAt: base, FinishedAt: base.Add(2 * time.Minute), SourceAttemptID: "attempt-risk", Revision: 1,
	}
	if err := store.Create(&risk).Error; err != nil {
		t.Fatal(err)
	}

	result := merge("http-v2", scanplan.StageHTTPProbe, base.Add(3*time.Minute), "body-v2")
	if result.CoveragesUpdated != 1 || result.CoveragesInvalidated != 2 {
		t.Fatalf("changed HTTP merge result=%+v", result)
	}
	var protocolCoverage, fingerprintCoverage, riskCoverage ScanCoverage
	if err := store.Where("stage = ?", string(scanplan.StageProtocolIdentify)).First(&protocolCoverage).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Where("stage = ?", string(scanplan.StageFingerprint)).First(&fingerprintCoverage).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.First(&riskCoverage, risk.ID).Error; err != nil {
		t.Fatal(err)
	}
	if protocolCoverage.Status != string(scanplan.CoverageComplete) {
		t.Fatalf("unrelated upstream coverage was invalidated: %+v", protocolCoverage)
	}
	for _, coverage := range []ScanCoverage{fingerprintCoverage, riskCoverage} {
		if coverage.Status != string(scanplan.CoverageInvalidated) || coverage.InvalidReason != "upstream_content_changed:http_probe" || coverage.ValidUntil != nil {
			t.Fatalf("dependent coverage stayed reusable: %+v", coverage)
		}
	}
	if err := store.Where("stage = ?", string(scanplan.StageHTTPProbe)).First(&httpCoverage).Error; err != nil {
		t.Fatal(err)
	}
	if httpCoverage.Status != string(scanplan.CoverageComplete) || httpCoverage.ValidUntil == nil || !httpCoverage.ValidUntil.Equal(base.Add(3*time.Minute+6*time.Hour)) {
		t.Fatalf("new HTTP coverage is not current: %+v", httpCoverage)
	}
}

func TestChangedContentDoesNotInvalidateNewerDependentEvidence(t *testing.T) {
	store := openObservationMergeTestDB(t)
	project := Project{ID: "project-order", TenantID: "tenant-order", Scope: `{}`}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	attempt := SubTask{
		ID: "attempt-order", TenantID: project.TenantID, ProjectID: project.ID, RootTaskID: "task-order", BatchID: "batch-order", AgentID: "agent-order",
		Config: `{}`, Priority: 1, TimeoutSec: 60, AgentSelector: `{}`, AgentSelectorRules: `{}`, RuleVersion: "rules-v1",
	}
	base := time.Date(2026, 8, 9, 3, 0, 0, 0, time.UTC)
	merge := func(id string, stage scanplan.Stage, finishedAt time.Time, content string) {
		event := mergeTestEvent(attempt, id, stage, scanplan.ObservationSuccess, finishedAt.Add(-time.Second), finishedAt)
		event.ContentHash = sha256Hex([]byte(content))
		if _, err := MergeStageObservationEvent(store, attempt, event); err != nil {
			t.Fatal(err)
		}
	}
	merge("http-old", scanplan.StageHTTPProbe, base, "old")
	merge("finger-newer", scanplan.StageFingerprint, base.Add(2*time.Minute), "newer")
	merge("http-late-delivery", scanplan.StageHTTPProbe, base.Add(time.Minute), "changed")

	var fingerprintCoverage ScanCoverage
	if err := store.Where("stage = ?", string(scanplan.StageFingerprint)).First(&fingerprintCoverage).Error; err != nil {
		t.Fatal(err)
	}
	if fingerprintCoverage.Status != string(scanplan.CoverageComplete) {
		t.Fatalf("newer dependent evidence was invalidated by older upstream event: %+v", fingerprintCoverage)
	}
}
