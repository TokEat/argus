package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/shared/proto/go/scanplan"
	"github.com/gin-gonic/gin"
)

type resultPageForTest[T any] struct {
	Items []T   `json:"items"`
	Total int64 `json:"total"`
}

func invokeTaskResultHandler(t *testing.T, path string, handler gin.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("GET", path, nil)
	c.Set("tenant", "tenant-a")
	c.Set("user_id", "user-a")
	c.Set("role", "operator")
	handler(c)
	return recorder
}

func TestTaskResultsProjectActiveReusedObservationsByExactTarget(t *testing.T) {
	gin.SetMode(gin.TestMode)
	store := setupAITestDB(t)
	now := time.Now().UTC()
	validUntil := now.Add(time.Hour)

	project := db.Project{ID: "project-a", TenantID: "tenant-a", OwnerUserID: "user-a", Name: "Project A"}
	root := db.RootTask{ID: "task-destination", TenantID: "tenant-a", ProjectID: project.ID, UserID: "user-a", Status: "Finished"}
	current := db.SubTask{ID: "attempt-current", TenantID: "tenant-a", ProjectID: project.ID, RootTaskID: root.ID, BatchID: "batch-current", Status: "Finished"}
	sourceRoot := db.RootTask{ID: "task-source", TenantID: "tenant-a", ProjectID: project.ID, UserID: "user-a", Status: "Finished"}
	source := db.SubTask{ID: "attempt-source", TenantID: "tenant-a", ProjectID: project.ID, RootTaskID: sourceRoot.ID, BatchID: "batch-source", Status: "Completed"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := store.Create([]db.RootTask{root, sourceRoot}).Error; err != nil {
		t.Fatalf("seed roots: %v", err)
	}
	if err := store.Create([]db.SubTask{current, source}).Error; err != nil {
		t.Fatalf("seed attempts: %v", err)
	}

	httpCoverage := db.ScanCoverage{
		SchemaVersion: scanplan.SchemaVersion, TenantID: "tenant-a", ProjectID: project.ID,
		NormalizedTarget: "http://127.0.0.1:8082", TargetHash: "target-http", Stage: string(scanplan.StageHTTPProbe),
		WorkKeyHash: "work-http", Status: string(scanplan.CoverageComplete), Outcome: string(scanplan.ObservationSuccess),
		StartedAt: now.Add(-time.Second), FinishedAt: now, ValidUntil: &validUntil,
		SourceTaskID: sourceRoot.ID, SourceBatchID: source.BatchID, SourceAttemptID: source.ID,
	}
	fingerprintCoverage := httpCoverage
	fingerprintCoverage.ID = 0
	fingerprintCoverage.Stage = string(scanplan.StageFingerprint)
	fingerprintCoverage.WorkKeyHash = "work-fingerprint"
	fingerprintCoverage.TargetHash = "target-fingerprint"
	if err := store.Create(&httpCoverage).Error; err != nil {
		t.Fatalf("seed HTTP coverage: %v", err)
	}
	if err := store.Create(&fingerprintCoverage).Error; err != nil {
		t.Fatalf("seed fingerprint coverage: %v", err)
	}
	links := []db.TaskCoverageLink{
		{SchemaVersion: scanplan.SchemaVersion, TenantID: "tenant-a", ProjectID: project.ID, RootTaskID: root.ID, BatchID: current.BatchID, AttemptID: current.ID, WorkKeyHash: httpCoverage.WorkKeyHash, LinkType: "reused", Status: "active", CoverageID: httpCoverage.ID, SourceTaskID: sourceRoot.ID, SourceBatchID: source.BatchID, SourceAttemptID: source.ID},
		{SchemaVersion: scanplan.SchemaVersion, TenantID: "tenant-a", ProjectID: project.ID, RootTaskID: root.ID, BatchID: current.BatchID, AttemptID: current.ID, WorkKeyHash: fingerprintCoverage.WorkKeyHash, LinkType: "reused", Status: "active", CoverageID: fingerprintCoverage.ID, SourceTaskID: sourceRoot.ID, SourceBatchID: source.BatchID, SourceAttemptID: source.ID},
	}
	if err := store.Create(&links).Error; err != nil {
		t.Fatalf("seed coverage links: %v", err)
	}

	assets := []db.Asset{
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: current.ID, RootTaskID: root.ID, Target: "current.example.invalid", Protocol: "Domain"},
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: source.ID, RootTaskID: sourceRoot.ID, Target: "http://127.0.0.1:8082", Protocol: "Web"},
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: source.ID, RootTaskID: sourceRoot.ID, Target: "http://127.0.0.1:9999", Protocol: "Web"},
	}
	if err := store.Create(&assets).Error; err != nil {
		t.Fatalf("seed assets: %v", err)
	}
	fingerprints := []db.FingerprintHit{
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: source.ID, RootTaskID: sourceRoot.ID, Target: "http://127.0.0.1:8082", ProductName: "Apache-Tomcat"},
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: source.ID, RootTaskID: sourceRoot.ID, Target: "http://127.0.0.1:9999", ProductName: "Must-Not-Leak"},
	}
	if err := store.Create(&fingerprints).Error; err != nil {
		t.Fatalf("seed fingerprints: %v", err)
	}
	vulnerabilities := []db.Vulnerability{
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: current.ID, RootTaskID: root.ID, Target: "current.example.invalid", Plugin: "current-poc", Severity: "High"},
		{TenantID: "tenant-a", ProjectID: project.ID, TaskID: source.ID, RootTaskID: sourceRoot.ID, Target: "http://127.0.0.1:8082", Plugin: "historical-poc", Severity: "High"},
	}
	if err := store.Create(&vulnerabilities).Error; err != nil {
		t.Fatalf("seed vulnerabilities: %v", err)
	}

	assetsRecorder := invokeTaskResultHandler(t, "/assets?task_id="+root.ID+"&project_id="+project.ID, getAssets)
	var assetPage resultPageForTest[db.Asset]
	if err := json.Unmarshal(assetsRecorder.Body.Bytes(), &assetPage); err != nil {
		t.Fatalf("decode asset page: %v", err)
	}
	if assetsRecorder.Code != 200 || assetPage.Total != 2 {
		t.Fatalf("expected current and exact-target reused asset, status=%d body=%s", assetsRecorder.Code, assetsRecorder.Body.String())
	}

	fingerprintRecorder := invokeTaskResultHandler(t, "/fingerprints?task_id="+root.ID+"&project_id="+project.ID, getFingerprints)
	var fingerprintPage resultPageForTest[db.FingerprintHit]
	if err := json.Unmarshal(fingerprintRecorder.Body.Bytes(), &fingerprintPage); err != nil {
		t.Fatalf("decode fingerprint page: %v", err)
	}
	if fingerprintRecorder.Code != 200 || fingerprintPage.Total != 1 || fingerprintPage.Items[0].ProductName != "Apache-Tomcat" {
		t.Fatalf("expected only exact-target reused fingerprint, status=%d body=%s", fingerprintRecorder.Code, fingerprintRecorder.Body.String())
	}

	vulnerabilityRecorder := invokeTaskResultHandler(t, "/vulns?task_id="+root.ID+"&project_id="+project.ID, getVulns)
	var vulnerabilityPage resultPageForTest[db.Vulnerability]
	if err := json.Unmarshal(vulnerabilityRecorder.Body.Bytes(), &vulnerabilityPage); err != nil {
		t.Fatalf("decode vulnerability page: %v", err)
	}
	if vulnerabilityRecorder.Code != 200 || vulnerabilityPage.Total != 1 || vulnerabilityPage.Items[0].Plugin != "current-poc" {
		t.Fatalf("historical vulnerability must not be projected, status=%d body=%s", vulnerabilityRecorder.Code, vulnerabilityRecorder.Body.String())
	}

	if err := store.Model(&db.SubTask{}).Where("id = ?", source.ID).Update("status", "Failed").Error; err != nil {
		t.Fatalf("mark source failed: %v", err)
	}
	failedSourceRecorder := invokeTaskResultHandler(t, "/assets?task_id="+root.ID+"&project_id="+project.ID, getAssets)
	var failedSourcePage resultPageForTest[db.Asset]
	if err := json.Unmarshal(failedSourceRecorder.Body.Bytes(), &failedSourcePage); err != nil {
		t.Fatalf("decode failed source asset page: %v", err)
	}
	if failedSourcePage.Total != 1 || failedSourcePage.Items[0].TaskID != current.ID {
		t.Fatalf("failed source attempt must not project reused observations: %s", failedSourceRecorder.Body.String())
	}
}
