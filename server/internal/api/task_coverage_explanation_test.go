package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-proto/go/scanplan"
	"github.com/user/dddd-server/internal/db"
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

	coverages := []db.ScanCoverage{
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://a.test", NetworkZone: "public", Stage: string(scanplan.StagePortScan), WorkKeyHash: "reuse-a", Status: string(scanplan.CoverageComplete), SourceTaskID: source.ID, SourceBatchID: "source-batch", SourceAttemptID: "source-attempt", ValidUntil: &valid},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://b.test", NetworkZone: "public", Stage: string(scanplan.StagePortScan), WorkKeyHash: "reuse-b", Status: string(scanplan.CoverageComplete), SourceTaskID: source.ID, SourceBatchID: "source-batch", SourceAttemptID: "source-attempt", ValidUntil: &valid},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://a.test", NetworkZone: "public", Stage: string(scanplan.StageFingerprint), WorkKeyHash: "invalid-a", Status: string(scanplan.CoverageInvalidated), InvalidReason: "upstream_content_changed:http_probe", SourceTaskID: root.ID, SourceBatchID: batch.ID, SourceAttemptID: attempt.ID},
		{TenantID: root.TenantID, ProjectID: root.ProjectID, NormalizedTarget: "https://c.test", NetworkZone: "public", Stage: string(scanplan.StageHTTPProbe), WorkKeyHash: "expired-c", Status: string(scanplan.CoverageComplete), SourceTaskID: root.ID, SourceBatchID: batch.ID, SourceAttemptID: attempt.ID, ValidUntil: &expired},
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
	if got.Summary.SavedStages != 2 || got.Summary.SavedTargets != 1 || got.Summary.InvalidatedStages != 1 || got.Summary.ExpiredStages != 1 {
		t.Fatalf("unexpected saved/invalid summary: %+v", got.Summary)
	}
	if len(got.Items) != 4 || len(got.Invalidations) != 2 {
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
	for _, item := range got.Invalidations {
		if item.Reason == "must_not_leak" || item.Source.TaskID == crossProject.ID {
			t.Fatalf("cross-project invalidation exposed: %+v", item)
		}
	}
}
