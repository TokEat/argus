package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"github.com/gin-gonic/gin"
)

func TestTaskDetailExplainsExecutionReuseAndInvalidationWithinProject(t *testing.T) {
	store := setupAITestDB(t)
	now := time.Now().UTC()
	expired := now.Add(-time.Minute)
	valid := now.Add(time.Hour)

	projects := []db.Project{
		{ID: "project-explain", TenantID: "default", Status: "active"},
		{ID: "project-other", TenantID: "default", Status: "active"},
	}
	if err := store.Create(&projects).Error; err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	root := db.RootTask{
		ID: "task-explain", TenantID: "default", ProjectID: projects[0].ID, Name: "Explain Task",
		Status: "Running", Config: `{}`, OriginalTargets: `["https://a.test","https://b.test","https://c.test"]`,
	}
	source := db.RootTask{ID: "task-source", TenantID: "default", ProjectID: projects[0].ID, Name: "Source Task", Status: "FINISHED", Config: `{}`}
	crossProject := db.RootTask{ID: "task-cross", TenantID: "default", ProjectID: projects[1].ID, Name: "Cross Project", Status: "FINISHED", Config: `{}`}
	if err := store.Create(&[]db.RootTask{root, source, crossProject}).Error; err != nil {
		t.Fatalf("seed tasks: %v", err)
	}
	batch := db.TaskBatch{
		ID: "batch-explain", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID,
		Targets: `["https://a.test","https://b.test","https://c.test"]`, TargetCount: 3, Status: "Running", LatestAttemptID: "attempt-explain",
	}
	attempt := db.SubTask{
		ID: "attempt-explain", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID,
		Status: "Running", ChunkTargets: batch.Targets, Config: `{}`, AgentID: "agent-explain",
	}
	if err := store.Create(&batch).Error; err != nil {
		t.Fatalf("seed batch: %v", err)
	}
	if err := store.Create(&attempt).Error; err != nil {
		t.Fatalf("seed attempt: %v", err)
	}

	observations := []db.ScanObservation{
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://d.test", Stage: string(scanplan.StageICMPDiscovery), Outcome: string(scanplan.ObservationSkipped), ErrorCode: "stage_not_executed", ErrorMessage: "stage was disabled or not applicable to this task", ObservedAt: now},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "jslgroup.cn", Stage: string(scanplan.StageSearchEngine), Outcome: string(scanplan.ObservationSkipped), ErrorCode: "stage_not_executed", ErrorMessage: "stage was disabled or not applicable to this task", ObservedAt: now},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://d.test", Stage: string(scanplan.StageHTTPProbe), Outcome: string(scanplan.ObservationFailed), ErrorCode: "phase_failed", ErrorMessage: "target HTTP budget exhausted", ObservedAt: now},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://d.test", Stage: string(scanplan.StageFingerprint), Outcome: string(scanplan.ObservationFailed), ErrorCode: "phase_failed", ErrorMessage: "upstream HTTP probe incomplete", ObservedAt: now},
	}
	if err := store.Create(&observations).Error; err != nil {
		t.Fatalf("seed observations: %v", err)
	}
	coverages := []db.ScanCoverage{
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://a.test", NetworkZone: "public", Stage: string(scanplan.StagePortScan), WorkKeyHash: "reuse-a", Status: string(scanplan.CoverageComplete), SourceTaskID: source.ID, SourceBatchID: "source-batch", SourceAttemptID: "source-attempt", ValidUntil: &valid},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://b.test", NetworkZone: "public", Stage: string(scanplan.StagePortScan), WorkKeyHash: "reuse-b", Status: string(scanplan.CoverageComplete), SourceTaskID: source.ID, SourceBatchID: "source-batch", SourceAttemptID: "source-attempt", ValidUntil: &valid},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://a.test", NetworkZone: "public", Stage: string(scanplan.StageFingerprint), WorkKeyHash: "invalid-a", Status: string(scanplan.CoverageInvalidated), InvalidReason: "upstream_content_changed:http_probe", SourceTaskID: root.ID, SourceBatchID: batch.ID, SourceAttemptID: attempt.ID},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://c.test", NetworkZone: "public", Stage: string(scanplan.StageHTTPProbe), WorkKeyHash: "expired-c", Status: string(scanplan.CoverageComplete), SourceTaskID: root.ID, SourceBatchID: batch.ID, SourceAttemptID: attempt.ID, ValidUntil: &expired},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://d.test", NetworkZone: "public", Stage: string(scanplan.StageICMPDiscovery), WorkKeyHash: "skip-d", Status: string(scanplan.CoverageIncomplete), Outcome: string(scanplan.ObservationSkipped), SourceObservationID: observations[0].ID, SourceTaskID: root.ID, SourceBatchID: batch.ID, SourceAttemptID: attempt.ID},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "jslgroup.cn", NetworkZone: "public", Stage: string(scanplan.StageSearchEngine), WorkKeyHash: "skip-search", Status: string(scanplan.CoverageIncomplete), Outcome: string(scanplan.ObservationSkipped), SourceObservationID: observations[1].ID, SourceTaskID: root.ID, SourceBatchID: batch.ID, SourceAttemptID: attempt.ID},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://d.test", NetworkZone: "public", Stage: string(scanplan.StageHTTPProbe), WorkKeyHash: "fail-http-d", Status: string(scanplan.CoverageIncomplete), Outcome: string(scanplan.ObservationFailed), SourceObservationID: observations[2].ID, SourceTaskID: root.ID, SourceBatchID: batch.ID, SourceAttemptID: attempt.ID},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://d.test", NetworkZone: "public", Stage: string(scanplan.StageFingerprint), WorkKeyHash: "fail-fp-d", Status: string(scanplan.CoverageIncomplete), Outcome: string(scanplan.ObservationFailed), SourceObservationID: observations[3].ID, SourceTaskID: root.ID, SourceBatchID: batch.ID, SourceAttemptID: attempt.ID},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://e.test", NetworkZone: "public", Stage: string(scanplan.StageRiskValidation), WorkKeyHash: "risk-unknown-e", Status: string(scanplan.CoverageInvalidated), Outcome: string(scanplan.ObservationSuccess), InvalidReason: "poc_set_unknown,endpoint_content_unknown", SourceTaskID: root.ID, SourceBatchID: batch.ID, SourceAttemptID: attempt.ID},
		{TenantID: root.TenantID, ProjectID: projects[1].ID, NormalizedTarget: "https://a.test", NetworkZone: "public", Stage: string(scanplan.StageFingerprint), WorkKeyHash: "cross-invalid", Status: string(scanplan.CoverageInvalidated), InvalidReason: "must_not_leak", SourceTaskID: crossProject.ID},
	}
	if err := store.Create(&coverages).Error; err != nil {
		t.Fatalf("seed coverages: %v", err)
	}
	claims := []db.ScanWorkClaim{
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://b.test", NetworkZone: "public", Stage: string(scanplan.StageFingerprint), WorkKeyHash: "execute-b", Status: "completed", OwnerTaskID: root.ID, OwnerBatchID: batch.ID, OwnerAttemptID: attempt.ID},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://c.test", NetworkZone: "public", Stage: string(scanplan.StageFingerprint), WorkKeyHash: "flight-c", Status: "active", OwnerTaskID: source.ID, OwnerBatchID: "source-batch", OwnerAttemptID: "source-attempt"},
	}
	if err := store.Create(&claims).Error; err != nil {
		t.Fatalf("seed claims: %v", err)
	}
	links := []db.TaskCoverageLink{
		{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID, AttemptID: attempt.ID, WorkKeyHash: coverages[0].WorkKeyHash, LinkType: "reused", Status: "active", CoverageID: coverages[0].ID, SourceTaskID: source.ID, SourceBatchID: "source-batch", SourceAttemptID: "source-attempt", Reason: "valid_project_coverage"},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID, AttemptID: attempt.ID, WorkKeyHash: coverages[1].WorkKeyHash, LinkType: "reused", Status: "active", CoverageID: coverages[1].ID, SourceTaskID: source.ID, SourceBatchID: "source-batch", SourceAttemptID: "source-attempt", Reason: "resume_plan:do-not-expose"},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID, AttemptID: attempt.ID, WorkKeyHash: claims[0].WorkKeyHash, LinkType: "executed", Status: "completed", ClaimID: claims[0].ID, SourceTaskID: root.ID, SourceBatchID: batch.ID, SourceAttemptID: attempt.ID, Reason: "claimed_for_execution"},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID, AttemptID: attempt.ID, WorkKeyHash: claims[1].WorkKeyHash, LinkType: "in_flight", Status: "waiting", ClaimID: claims[1].ID, SourceTaskID: source.ID, SourceBatchID: "source-batch", SourceAttemptID: "source-attempt", Reason: "active_work_claim"},
		{TenantID: root.TenantID, ProjectID: projects[1].ID, RootTaskID: root.ID, BatchID: batch.ID, AttemptID: attempt.ID, WorkKeyHash: "cross-invalid", LinkType: "reused", Status: "active", CoverageID: coverages[4].ID, SourceTaskID: crossProject.ID, Reason: "must_not_leak"},
	}
	if err := store.Create(&links).Error; err != nil {
		t.Fatalf("seed links: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/tasks/"+root.ID)
	ctx.Params = gin.Params{{Key: "id", Value: root.ID}}
	getTaskDetail(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("task detail status = %d (%s)", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Coverage taskCoverageExplanation `json:"coverage_explanation"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode task coverage explanation: %v", err)
	}
	got := response.Coverage
	if got.SchemaVersion != "argus.task-coverage-explanation/v1" || got.Summary.ExecutedWorkItems != 1 || got.Summary.ReusedStages != 2 || got.Summary.InFlightWorkItems != 1 {
		t.Fatalf("unexpected coverage summary: %+v", got.Summary)
	}
	if got.Summary.SavedStages != 2 || got.Summary.SavedTargets != 1 || got.Summary.InvalidatedStages != 2 || got.Summary.ExpiredStages != 1 {
		t.Fatalf("unexpected saved/invalid summary: %+v", got.Summary)
	}
	if got.Summary.SkippedStages != 1 || got.Summary.FailedStages != 2 {
		t.Fatalf("unexpected skip/fail summary: %+v", got.Summary)
	}
	if len(got.Items) != 4 || len(got.Invalidations) != 6 {
		t.Fatalf("cross-project evidence leaked or scoped evidence missing: items=%+v invalidations=%+v", got.Items, got.Invalidations)
	}
	foundCheckpoint, foundSourceName := false, false
	for _, item := range got.Items {
		if item.Reason == "checkpoint_resume" {
			foundCheckpoint = true
		}
		if item.Source.TaskID == source.ID && item.Source.TaskName == source.Name {
			foundSourceName = true
		}
		if item.Reason == "must_not_leak" || item.Source.TaskID == crossProject.ID {
			t.Fatalf("cross-project source exposed: %+v", item)
		}
	}
	if !foundCheckpoint || !foundSourceName {
		t.Fatalf("safe reason or source task name missing: %+v", got.Items)
	}
	foundSkip, foundHTTPBudget, foundUpstream, foundRiskUnknown := false, false, false, false
	for _, item := range got.Invalidations {
		if item.Reason == "must_not_leak" || item.Source.TaskID == crossProject.ID {
			t.Fatalf("cross-project invalidation exposed: %+v", item)
		}
		if item.Stage == string(scanplan.StageSearchEngine) {
			t.Fatalf("retired search_engine coverage was explained: %+v", item)
		}
		switch {
		case item.Status == "skipped" && item.Reason == "stage_not_executed":
			foundSkip = true
		case item.Status == "failed" && item.Reason == "http_budget_exhausted":
			foundHTTPBudget = true
		case item.Status == "failed" && item.Reason == "upstream_http_probe_incomplete":
			foundUpstream = true
		case item.Status == "invalidated" && item.Reason == "poc_set_unknown,endpoint_content_unknown":
			foundRiskUnknown = true
		}
	}
	if !foundSkip || !foundHTTPBudget || !foundUpstream || !foundRiskUnknown {
		t.Fatalf("classified coverage reasons missing: %+v", got.Invalidations)
	}
}

func TestTaskCoverageExplanationShowsRiskFingerprintsAndMatchedPocs(t *testing.T) {
	store := setupAITestDB(t)
	now := time.Now().UTC()
	project := db.Project{ID: "project-risk-match", TenantID: "default", Status: "active"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	root := db.RootTask{
		ID: "task-risk-match", TenantID: project.TenantID, ProjectID: project.ID, Name: "Risk Match",
		Status: "FINISHED", Config: `{}`,
	}
	if err := store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	attempt := db.SubTask{
		ID: "attempt-risk-match", TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID,
		BatchID: "batch-url-risk", Status: "DONE",
		Config: `{"ExecutionMode":"risk_validation","DisableGeneralPoc":true,"TargetFingerprints":{"https://app.example":["Nginx"],"https://bare.example":["DigiCert-Cert"]}}`,
	}
	if err := store.Create(&attempt).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&db.WorkflowRule{
		TenantID: root.TenantID, ProductName: "Nginx", PocName: "nginx-detect.yaml", MatchType: "root",
		SourceFile: "workflow.yaml", State: "Approved", Enabled: true,
	}).Error; err != nil {
		t.Fatal(err)
	}
	coverages := []db.ScanCoverage{
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://app.example", Stage: string(scanplan.StageRiskValidation), WorkKeyHash: "risk-app", Status: string(scanplan.CoverageInvalidated), Outcome: string(scanplan.ObservationNegative), InvalidReason: "poc_set_unknown,endpoint_content_unknown", SourceTaskID: root.ID, SourceBatchID: attempt.BatchID, SourceAttemptID: attempt.ID, UpdatedAt: now},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://bare.example", Stage: string(scanplan.StageRiskValidation), WorkKeyHash: "risk-bare", Status: string(scanplan.CoverageInvalidated), Outcome: string(scanplan.ObservationNegative), InvalidReason: "poc_set_unknown,endpoint_content_unknown", SourceTaskID: root.ID, SourceBatchID: attempt.BatchID, SourceAttemptID: attempt.ID, UpdatedAt: now.Add(time.Second)},
	}
	if err := store.Create(&coverages).Error; err != nil {
		t.Fatal(err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/tasks/"+root.ID)
	ctx.Params = gin.Params{{Key: "id", Value: root.ID}}
	getTaskDetail(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("task detail status = %d (%s)", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Coverage taskCoverageExplanation `json:"coverage_explanation"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	got := map[string]taskCoverageInvalidationItem{}
	for _, item := range response.Coverage.Invalidations {
		got[item.NormalizedTarget] = item
	}
	matched := got["https://app.example"]
	if matched.Reason != "poc_set_unknown,endpoint_content_unknown" || len(matched.Fingerprints) != 1 || matched.Fingerprints[0] != "Nginx" || len(matched.MatchedPocs) != 1 || matched.MatchedPocs[0] != "nginx-detect.yaml" {
		t.Fatalf("matched risk gap = %+v", matched)
	}
	unmatched := got["https://bare.example"]
	if unmatched.Reason != "fingerprint_unmatched_pocs" || len(unmatched.Fingerprints) != 1 || unmatched.Fingerprints[0] != "DigiCert-Cert" || len(unmatched.MatchedPocs) != 0 {
		t.Fatalf("unmatched risk gap = %+v", unmatched)
	}
}

func TestRefineRiskCoverageReasonKeepsReuseCodesWhenPOCsMatched(t *testing.T) {
	if got := refineRiskCoverageReason("poc_set_unknown,endpoint_content_unknown", []string{"Nginx"}, nil); got != "fingerprint_unmatched_pocs" {
		t.Fatalf("unmatched reason = %q", got)
	}
	if got := refineRiskCoverageReason("poc_set_unknown,endpoint_content_unknown", []string{"Nginx"}, []string{"nginx-detect.yaml"}); got != "poc_set_unknown,endpoint_content_unknown" {
		t.Fatalf("matched reuse codes should stay visible, got %q", got)
	}
	if got := refineRiskCoverageReason("nuclei_execution_failed,poc_set_unknown", []string{"Nginx"}, []string{"nginx-detect.yaml"}); got != "nuclei_execution_failed" {
		t.Fatalf("execution failure should remain, got %q", got)
	}
}

func TestClassifyTaskCoverageGapUsesObservationWhenInvalidReasonEmpty(t *testing.T) {
	now := time.Now().UTC()
	expired := now.Add(-time.Minute)
	obs := &db.ScanObservation{ErrorCode: "phase_failed", ErrorMessage: "target HTTP budget exhausted"}
	status, reason := classifyTaskCoverageGap(db.ScanCoverage{
		Status: string(scanplan.CoverageIncomplete), Outcome: string(scanplan.ObservationFailed),
	}, obs, now)
	if status != "failed" || reason != "http_budget_exhausted" {
		t.Fatalf("http budget gap = %s %s", status, reason)
	}
	status, reason = classifyTaskCoverageGap(db.ScanCoverage{
		Status: string(scanplan.CoverageIncomplete), Outcome: string(scanplan.ObservationSkipped),
	}, &db.ScanObservation{ErrorCode: "stage_not_executed"}, now)
	if status != "skipped" || reason != "stage_not_executed" {
		t.Fatalf("skipped gap = %s %s", status, reason)
	}
	status, reason = classifyTaskCoverageGap(db.ScanCoverage{
		Status: string(scanplan.CoverageIncomplete), Outcome: string(scanplan.ObservationFailed),
		InvalidReason: "poc_set_unknown,endpoint_content_unknown",
	}, &db.ScanObservation{ErrorCode: "phase_failed", ErrorMessage: "nuclei execution failed"}, now)
	if status != "failed" || reason != "nuclei_execution_failed" {
		t.Fatalf("failed risk observation should expose execution error, got %s %s", status, reason)
	}
	status, reason = classifyTaskCoverageGap(db.ScanCoverage{
		Status: string(scanplan.CoverageInvalidated), InvalidReason: "poc_set_unknown,endpoint_content_unknown",
	}, nil, now)
	if status != "invalidated" || reason != "poc_set_unknown,endpoint_content_unknown" {
		t.Fatalf("risk gap = %s %s", status, reason)
	}
	status, reason = classifyTaskCoverageGap(db.ScanCoverage{
		Status: string(scanplan.CoverageComplete), ValidUntil: &expired,
	}, nil, now)
	if status != "expired" || reason != "ttl_expired" {
		t.Fatalf("expired gap = %s %s", status, reason)
	}
}
