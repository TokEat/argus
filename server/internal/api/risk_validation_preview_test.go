package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

func TestPreviewTaskRiskValidationBuildsReadOnlyWorkflowPlan(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "project-risk", TenantID: "default", OwnerUserID: "1", Name: "Risk", Status: "active"}
	task := db.RootTask{
		ID: "task-risk", TenantID: "default", ProjectID: project.ID, UserID: "1", Name: "Risk Task",
		Status: "FINISHED", RuleVersion: "rules-task-v1", CurrentConfigVersion: 2,
	}
	attempt := db.SubTask{ID: "attempt-risk-1", TenantID: "default", ProjectID: project.ID, RootTaskID: task.ID, Status: "Done"}
	for _, value := range []interface{}{&project, &task, &attempt, &db.SystemConfig{Key: "rule_version", Value: "rules-current-v2"}} {
		if err := store.Create(value).Error; err != nil {
			t.Fatalf("seed preview scope: %v", err)
		}
	}

	target := "https://risk.example:443"
	if err := store.Create(&db.Asset{
		TenantID: "default", ProjectID: project.ID, TaskID: attempt.ID, RootTaskID: task.ID,
		Target: target, Protocol: "Web", Port: 443, URL: target, Title: "Risk App", Service: "https",
	}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	hits := []db.FingerprintHit{
		{TenantID: "default", ProjectID: project.ID, TaskID: attempt.ID, RootTaskID: task.ID, Target: target, ProductName: "nginx"},
		// Keep one legacy row without root_task_id beside a current row. The
		// preview must merge both layouts during the compatibility window.
		{TenantID: "default", ProjectID: project.ID, TaskID: attempt.ID, Target: target, ProductName: "tomcat"},
		{TenantID: "other", ProjectID: project.ID, TaskID: attempt.ID, RootTaskID: task.ID, Target: "https://foreign.example", ProductName: "nginx"},
	}
	if err := store.Create(&hits).Error; err != nil {
		t.Fatalf("seed fingerprint hits: %v", err)
	}

	arsenal := db.Arsenal{
		ID: "poc-artifact-risk", TenantID: "default", Type: "poc", FileName: "nginx-risk.yaml", State: "Approved",
		Content: `id: nginx-risk
info:
  name: Nginx risk validation
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/one"
      - "{{BaseURL}}/two"
`,
	}
	poc := db.PocRule{
		TenantID: "default", ArtifactID: arsenal.ID, SourceFile: arsenal.FileName, Name: "nginx-risk",
		Severity: "high", ExecutionClass: db.PocExecutionClassVerification, RiskLevel: db.PocRiskLevelHigh,
		ContentHash: "poc-content-v2", State: "Approved", Enabled: true,
	}
	workflows := []db.WorkflowRule{
		{TenantID: "default", ProductName: "nginx", PocName: "nginx-risk.yaml", MatchType: "root", SourceFile: "workflow.yaml", State: "Approved", Enabled: true},
		{TenantID: "default", ProductName: "nginx", PocName: "missing.yaml", MatchType: "root", SourceFile: "workflow.yaml", State: "Approved", Enabled: true},
		{TenantID: "other", ProductName: "nginx", PocName: "foreign.yaml", MatchType: "root", SourceFile: "workflow.yaml", State: "Approved", Enabled: true},
	}
	if err := store.Create(&arsenal).Error; err != nil {
		t.Fatalf("seed POC arsenal: %v", err)
	}
	if err := store.Create(&poc).Error; err != nil {
		t.Fatalf("seed POC rule: %v", err)
	}
	if err := store.Create(&workflows).Error; err != nil {
		t.Fatalf("seed workflows: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+task.ID+"/risk-validation/preview", "viewer", "1")
	ctx.Params = gin.Params{{Key: "id", Value: task.ID}}
	previewTaskRiskValidation(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("preview status = %d (%s)", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Task struct {
			ID        string `json:"id"`
			ProjectID string `json:"project_id"`
		} `json:"task"`
		TaskRuleVersion string                    `json:"task_rule_version"`
		RuleVersion     string                    `json:"rule_version"`
		ConfigVersion   int                       `json:"config_version"`
		PlanHash        string                    `json:"plan_hash"`
		Summary         riskValidationSummary     `json:"summary"`
		Items           []riskValidationCandidate `json:"items"`
		Unmatched       []string                  `json:"unmatched_products"`
		Excluded        []riskValidationExcluded  `json:"excluded"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if response.Task.ID != task.ID || response.Task.ProjectID != project.ID {
		t.Fatalf("unexpected task scope: %+v", response.Task)
	}
	if response.TaskRuleVersion != "rules-task-v1" || response.RuleVersion != "rules-current-v2" || response.ConfigVersion != 2 {
		t.Fatalf("unexpected preview versions: %+v", response)
	}
	if len(response.PlanHash) != 64 {
		t.Fatalf("expected stable SHA-256 plan hash, got %q", response.PlanHash)
	}
	if response.Summary.FingerprintHits != 2 || response.Summary.UniqueAssets != 1 || response.Summary.Products != 2 {
		t.Fatalf("unexpected fingerprint summary: %+v", response.Summary)
	}
	if response.Summary.Candidates != 1 || response.Summary.PocRules != 1 || response.Summary.EstimatedRequests != 2 {
		t.Fatalf("unexpected candidate summary: %+v", response.Summary)
	}
	if !response.Summary.SecondConfirmationRequired || response.Summary.SecondConfirmationItems != 1 {
		t.Fatalf("high-risk candidate must require second confirmation: %+v", response.Summary)
	}
	if len(response.Items) != 1 {
		t.Fatalf("expected one candidate, got %+v", response.Items)
	}
	item := response.Items[0]
	if item.Endpoint != target || item.Asset.Title != "Risk App" || item.PocFile != "nginx-risk.yaml" {
		t.Fatalf("unexpected preview candidate: %+v", item)
	}
	if item.TemplateRequestEstimate != 2 || item.EstimateBasis != "template_upper_bound" || item.RiskLevel != db.PocRiskLevelHigh {
		t.Fatalf("unexpected request/risk estimate: %+v", item)
	}
	if len(response.Unmatched) != 1 || response.Unmatched[0] != "tomcat" {
		t.Fatalf("unexpected unmatched products: %+v", response.Unmatched)
	}
	if len(response.Excluded) != 1 || response.Excluded[0].Reason != "missing_poc" {
		t.Fatalf("unexpected excluded mappings: %+v", response.Excluded)
	}

	for model, name := range map[interface{}]string{&db.TaskBatch{}: "batches", &db.TaskAudit{}: "audits"} {
		var count int64
		store.Model(model).Count(&count)
		if count != 0 {
			t.Fatalf("preview must not create %s, count=%d", name, count)
		}
	}
}

func TestPreviewTaskRiskValidationRejectsInaccessibleProject(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "project-private", TenantID: "default", OwnerUserID: "2", Name: "Private", Status: "active"}
	task := db.RootTask{ID: "task-private", TenantID: "default", ProjectID: project.ID, UserID: "2", Name: "Private Task"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed private project: %v", err)
	}
	if err := store.Create(&task).Error; err != nil {
		t.Fatalf("seed private task: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+task.ID+"/risk-validation/preview", "viewer", "1")
	ctx.Params = gin.Params{{Key: "id", Value: task.ID}}
	previewTaskRiskValidation(ctx)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected inaccessible project rejection, got %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestPreviewTaskRiskValidationSupportsSpecifiedApprovedPocWithoutWorkflow(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "project-specified-risk", TenantID: "default", OwnerUserID: "1", Name: "Specified", Status: "active"}
	task := db.RootTask{ID: "task-specified-risk", TenantID: "default", ProjectID: project.ID, UserID: "1", Name: "Specified", Status: "FINISHED", CurrentConfigVersion: 1}
	values := []interface{}{
		&project, &task,
		&db.SystemConfig{Key: "rule_version", Value: "rules-specified"},
		&db.Asset{TenantID: "default", ProjectID: project.ID, RootTaskID: task.ID, Target: "10.0.0.8:443", URL: "https://10.0.0.8:443", Service: "https"},
		&db.Arsenal{ID: "poc-specified", TenantID: "default", Type: "poc", FileName: "specified.yaml", State: "Approved", Content: "id: specified\ninfo:\n  name: specified\n  severity: low\nhttp:\n  - path: ['{{BaseURL}}/check']\n"},
	}
	for _, value := range values {
		if err := store.Create(value).Error; err != nil {
			t.Fatalf("seed specified preview: %v", err)
		}
	}
	if err := store.Create(&db.PocRule{
		TenantID: "default", ArtifactID: "poc-specified", SourceFile: "specified.yaml", Name: "specified",
		Severity: "low", ExecutionClass: db.PocExecutionClassDetection, RiskLevel: db.PocRiskLevelLow,
		ContentHash: "specified-content", State: "Approved", Enabled: true,
	}).Error; err != nil {
		t.Fatalf("seed specified POC: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+task.ID+"/risk-validation/preview", "viewer", "1")
	ctx.Params = gin.Params{{Key: "id", Value: task.ID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/tasks/"+task.ID+"/risk-validation/preview", strings.NewReader(`{"specified_pocs":["specified.yaml"]}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	previewTaskRiskValidation(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("specified preview status = %d (%s)", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Summary riskValidationSummary     `json:"summary"`
		Items   []riskValidationCandidate `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode specified preview: %v", err)
	}
	if response.Summary.FingerprintHits != 0 || response.Summary.Candidates != 1 || len(response.Items) != 1 {
		t.Fatalf("unexpected specified preview: %+v", response)
	}
	if response.Items[0].Endpoint != "https://10.0.0.8:443" || len(response.Items[0].MatchTypes) != 1 || response.Items[0].MatchTypes[0] != "specified" {
		t.Fatalf("unexpected specified candidate: %+v", response.Items[0])
	}
}

func TestEstimateNucleiTemplateRequestsUsesPayloadUpperBound(t *testing.T) {
	count, basis := estimateNucleiTemplateRequests(`id: estimate
info:
  name: Estimate
  severity: info
http:
  - path: ["{{BaseURL}}/one", "{{BaseURL}}/two"]
    attack: clusterbomb
    payloads:
      user: [admin, guest]
      password: [one, two, three]
tcp:
  - inputs:
      - data: one
      - data: two
`)
	if count != 14 || basis != "template_upper_bound" {
		t.Fatalf("request estimate = %d (%s), want 14 template_upper_bound", count, basis)
	}
}

func TestRiskValidationPreviewRBACIsReadOnlyViewerAccess(t *testing.T) {
	if role := matchPermission(http.MethodPost, "/api/v1/tasks/task-1/risk-validation/preview"); role != "viewer" {
		t.Fatalf("preview required role = %s, want viewer", role)
	}
}
