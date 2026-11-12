package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func seedExecutableRiskValidation(t *testing.T, taskStatus string) (db.RootTask, riskValidationPreview) {
	t.Helper()
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.RiskValidationIdempotency{}); err != nil {
		t.Fatalf("migrate risk validation idempotency: %v", err)
	}
	project := db.Project{ID: "project-risk-execute", TenantID: "default", OwnerUserID: "1", Name: "Risk", Status: "active"}
	task := db.RootTask{
		ID: "task-risk-execute", TenantID: "default", ProjectID: project.ID, UserID: "1", Name: "Risk Execute",
		Status: taskStatus, RuleVersion: "rules-v1", CurrentConfigVersion: 2, Config: `{}`, Priority: 1, TimeoutSec: 120,
	}
	revision := db.NewTaskConfigRevision(task, 2, `{}`, `{}`, "1", "current")
	values := []interface{}{
		&project, &task, &revision, &db.SystemConfig{Key: "rule_version", Value: "rules-v2"},
		&db.Asset{TenantID: "default", ProjectID: project.ID, RootTaskID: task.ID, Target: "https://risk.example", URL: "https://risk.example", Title: "Risk App", Service: "https"},
		&db.FingerprintHit{TenantID: "default", ProjectID: project.ID, RootTaskID: task.ID, Target: "https://risk.example", ProductName: "nginx"},
		&db.Arsenal{ID: "poc-risk-execute", TenantID: "default", Type: "poc", FileName: "nginx-risk.yaml", State: "Approved", Content: "id: nginx-risk\ninfo:\n  name: risk\n  severity: high\nhttp:\n  - path: ['{{BaseURL}}/check']\n"},
	}
	for _, value := range values {
		if err := store.Create(value).Error; err != nil {
			t.Fatalf("seed risk validation: %v", err)
		}
	}
	poc := db.PocRule{
		TenantID: "default", ArtifactID: "poc-risk-execute", SourceFile: "nginx-risk.yaml", Name: "nginx-risk",
		Severity: "high", ExecutionClass: db.PocExecutionClassVerification, RiskLevel: db.PocRiskLevelHigh,
		ContentHash: "content-v2", State: "Approved", Enabled: true,
	}
	workflow := db.WorkflowRule{
		TenantID: "default", ProductName: "nginx", PocName: "nginx-risk.yaml", MatchType: "root",
		SourceFile: "workflow.yaml", State: "Approved", Enabled: true,
	}
	if err := store.Create(&poc).Error; err != nil {
		t.Fatalf("seed POC: %v", err)
	}
	if err := store.Create(&workflow).Error; err != nil {
		t.Fatalf("seed workflow: %v", err)
	}
	preview, err := buildTaskRiskValidationPreview(t.Context(), "default", task, riskValidationPreviewOptions{})
	if err != nil {
		t.Fatalf("build execution preview: %v", err)
	}
	if preview.UnmatchedProducts == nil || preview.Excluded == nil {
		t.Fatal("risk validation preview collections must serialize as arrays")
	}
	return task, preview
}

func assertRiskValidationExecutionWrites(t *testing.T, taskID string, want int64) {
	t.Helper()
	for model, label := range map[interface{}]string{&db.TaskBatch{}: "batch", &db.SubTask{}: "attempt", &db.TaskAudit{}: "audit", &db.RiskValidationIdempotency{}: "ledger"} {
		var count int64
		if err := db.DB.Model(model).Where("root_task_id = ?", taskID).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != want {
			t.Fatalf("%s writes=%d, want %d", label, count, want)
		}
	}
}

func callExecuteRiskValidation(t *testing.T, taskID string, body interface{}) *httptest.ResponseRecorder {
	return callExecuteRiskValidationWithKey(t, taskID, body, "")
}

func callExecuteRiskValidationWithKey(t *testing.T, taskID string, body interface{}, key string) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+taskID+"/risk-validation", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: taskID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/tasks/"+taskID+"/risk-validation", strings.NewReader(string(encoded)))
	ctx.Request.Header.Set("Content-Type", "application/json")
	if key != "" {
		ctx.Request.Header.Set("Idempotency-Key", key)
	}
	executeTaskRiskValidation(ctx)
	return recorder
}

func TestExecuteTaskRiskValidationIdempotencyReplayDoesNotDispatchAgain(t *testing.T) {
	task, preview := seedExecutableRiskValidation(t, "FINISHED")
	withTaskCreateQueue(t)
	body := executeRiskValidationRequest{PlanHash: preview.PlanHash, Confirmed: true, SecondConfirmation: true}
	first := callExecuteRiskValidationWithKey(t, task.ID, body, "risk-execute-key")
	if first.Code != http.StatusAccepted {
		t.Fatalf("first=%d %s", first.Code, first.Body.String())
	}
	var firstResult struct {
		BatchID   string `json:"batch_id"`
		AttemptID string `json:"attempt_id"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstResult); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Model(&db.SystemConfig{}).Where("key = ?", "rule_version").Update("value", "rules-v3").Error; err != nil {
		t.Fatal(err)
	}
	queue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = nil
	t.Cleanup(func() { routerRuntime().TaskQueue = queue })
	second := callExecuteRiskValidationWithKey(t, task.ID, body, "risk-execute-key")
	if second.Code != http.StatusAccepted || !strings.Contains(second.Body.String(), `"replayed":true`) {
		t.Fatalf("replay=%d %s", second.Code, second.Body.String())
	}
	changedConfirmation := body
	changedConfirmation.Confirmed = false
	conflict := callExecuteRiskValidationWithKey(t, task.ID, changedConfirmation, "risk-execute-key")
	if conflict.Code != http.StatusConflict || !strings.Contains(conflict.Body.String(), `"idempotency_conflict"`) {
		t.Fatalf("changed confirmation=%d %s", conflict.Code, conflict.Body.String())
	}
	changedSecond := body
	changedSecond.SecondConfirmation = false
	if r := callExecuteRiskValidationWithKey(t, task.ID, changedSecond, "risk-execute-key"); r.Code != http.StatusConflict {
		t.Fatalf("changed second=%d %s", r.Code, r.Body.String())
	}
	changedSpecified := body
	changedSpecified.SpecifiedPocs = []string{"other.yaml"}
	if r := callExecuteRiskValidationWithKey(t, task.ID, changedSpecified, "risk-execute-key"); r.Code != http.StatusConflict {
		t.Fatalf("changed specified=%d %s", r.Code, r.Body.String())
	}
	changedSelection := body
	changedSelection.Selected = []riskValidationSelection{{Endpoint: "https://risk.example", PocFile: "nginx-risk.yaml", PocContentHash: "other"}}
	if r := callExecuteRiskValidationWithKey(t, task.ID, changedSelection, "risk-execute-key"); r.Code != http.StatusConflict {
		t.Fatalf("changed selection=%d %s", r.Code, r.Body.String())
	}
	var batches, audits, ledgers int64
	db.DB.Model(&db.TaskBatch{}).Where("root_task_id = ?", task.ID).Count(&batches)
	db.DB.Model(&db.TaskAudit{}).Where("root_task_id = ? AND action = ?", task.ID, "risk_validation_execute").Count(&audits)
	db.DB.Model(&db.RiskValidationIdempotency{}).Where("root_task_id = ?", task.ID).Count(&ledgers)
	if batches != 1 || audits != 1 || ledgers != 1 {
		t.Fatalf("batches=%d audits=%d ledgers=%d", batches, audits, ledgers)
	}
}

func TestExecuteTaskRiskValidationIdempotencyRejectsInvalidAndStaleWithoutWrites(t *testing.T) {
	task, preview := seedExecutableRiskValidation(t, "FINISHED")
	withTaskCreateQueue(t)
	body := executeRiskValidationRequest{PlanHash: preview.PlanHash, Confirmed: true, SecondConfirmation: true}
	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/"+task.ID+"/risk-validation", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: task.ID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/tasks/"+task.ID+"/risk-validation", strings.NewReader(`{}`))
	ctx.Request.Header["Idempotency-Key"] = []string{"one", "two"}
	executeTaskRiskValidation(ctx)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("duplicate key=%d %s", recorder.Code, recorder.Body.String())
	}
	assertRiskValidationExecutionWrites(t, task.ID, 0)
	body.PlanHash = strings.Repeat("0", 64)
	stale := callExecuteRiskValidationWithKey(t, task.ID, body, "fresh-stale-key")
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale=%d %s", stale.Code, stale.Body.String())
	}
	assertRiskValidationExecutionWrites(t, task.ID, 0)
}

func TestExecuteTaskRiskValidationIdempotencyQueueAndAuditRollback(t *testing.T) {
	task, preview := seedExecutableRiskValidation(t, "FINISHED")
	body := executeRiskValidationRequest{PlanHash: preview.PlanHash, Confirmed: true, SecondConfirmation: true}
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = nil
	t.Cleanup(func() { routerRuntime().TaskQueue = oldQueue })
	if r := callExecuteRiskValidationWithKey(t, task.ID, body, "queue-key"); r.Code != http.StatusServiceUnavailable {
		t.Fatalf("queue=%d %s", r.Code, r.Body.String())
	}
	assertRiskValidationExecutionWrites(t, task.ID, 0)
	withTaskCreateQueue(t)
	const callback = "test:fail_risk_validation_audit"
	if err := db.DB.Callback().Create().Before("gorm:create").Register(callback, func(tx *gorm.DB) {
		if tx.Statement.Schema != nil && tx.Statement.Schema.Name == "TaskAudit" {
			tx.AddError(errors.New("forced audit failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	if r := callExecuteRiskValidationWithKey(t, task.ID, body, "audit-key"); r.Code != http.StatusInternalServerError {
		t.Fatalf("audit=%d %s", r.Code, r.Body.String())
	}
	if err := db.DB.Callback().Create().Remove(callback); err != nil {
		t.Fatal(err)
	}
	assertRiskValidationExecutionWrites(t, task.ID, 0)
	if r := callExecuteRiskValidationWithKey(t, task.ID, body, "audit-key"); r.Code != http.StatusAccepted {
		t.Fatalf("retry=%d %s", r.Code, r.Body.String())
	}
}

func TestExecuteTaskRiskValidationCreatesExactAuditedBatch(t *testing.T) {
	task, preview := seedExecutableRiskValidation(t, "FINISHED")
	withTaskCreateQueue(t)
	recorder := callExecuteRiskValidation(t, task.ID, executeRiskValidationRequest{
		PlanHash: preview.PlanHash, Confirmed: true, SecondConfirmation: true,
	})
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("execute status = %d (%s)", recorder.Code, recorder.Body.String())
	}
	var response struct {
		BatchID   string `json:"batch_id"`
		AttemptID string `json:"attempt_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var batch db.TaskBatch
	if err := db.DB.First(&batch, "id = ?", response.BatchID).Error; err != nil {
		t.Fatalf("load risk batch: %v", err)
	}
	var attempt db.SubTask
	if err := db.DB.First(&attempt, "id = ?", response.AttemptID).Error; err != nil {
		t.Fatalf("load risk attempt: %v", err)
	}
	if batch.Kind != "risk_validation" || batch.TargetType != "risk_validation" || attempt.MaxRetry != 0 {
		t.Fatalf("unexpected risk batch/attempt: batch=%+v attempt=%+v", batch, attempt)
	}
	if batch.ConfigVersion != 2 || attempt.ConfigVersion != 2 || batch.RuleVersion != "rules-v2" || attempt.RuleVersion != "rules-v2" {
		t.Fatalf("version binding lost: batch=%+v attempt=%+v", batch, attempt)
	}
	var config struct {
		ExecutionMode           string              `json:"ExecutionMode"`
		RequiredRuleVersion     string              `json:"RequiredRuleVersion"`
		RiskValidationTargets   map[string][]string `json:"RiskValidationTargets"`
		RiskValidationPocHashes map[string]string   `json:"RiskValidationPocHashes"`
		GolangPoc               bool                `json:"GolangPoc"`
	}
	if err := json.Unmarshal([]byte(attempt.Config), &config); err != nil {
		t.Fatalf("decode derived config: %v", err)
	}
	if config.ExecutionMode != "risk_validation" || config.RequiredRuleVersion != "rules-v2" || config.GolangPoc || len(config.RiskValidationPocHashes["nginx-risk.yaml"]) != 32 || len(config.RiskValidationTargets) != 1 || len(config.RiskValidationTargets["https://risk.example"]) != 1 || config.RiskValidationTargets["https://risk.example"][0] != "nginx-risk.yaml" {
		t.Fatalf("unexpected exact execution config: %+v", config)
	}
	var audit db.TaskAudit
	if err := db.DB.Where("root_task_id = ? AND batch_id = ? AND action = ?", task.ID, batch.ID, "risk_validation_execute").First(&audit).Error; err != nil {
		t.Fatalf("load risk audit: %v", err)
	}
	if audit.OperatorID != "1" || !strings.Contains(audit.Details, `"authorization_confirmed":true`) || !strings.Contains(audit.Details, `"second_confirmation_confirmed":true`) || !strings.Contains(audit.Details, `"automatic_retry":false`) {
		t.Fatalf("unexpected risk audit: %+v", audit)
	}
}

func TestExecuteTaskRiskValidationSealsBudgetFields(t *testing.T) {
	task, preview := seedExecutableRiskValidation(t, "FINISHED")
	withTaskCreateQueue(t)
	recorder := callExecuteRiskValidation(t, task.ID, executeRiskValidationRequest{
		PlanHash: preview.PlanHash, Confirmed: true, SecondConfirmation: true,
	})
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("execute status = %d (%s)", recorder.Code, recorder.Body.String())
	}
	var response struct {
		BatchID   string `json:"batch_id"`
		AttemptID string `json:"attempt_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var attempt db.SubTask
	if err := db.DB.First(&attempt, "id = ?", response.AttemptID).Error; err != nil {
		t.Fatalf("load risk attempt: %v", err)
	}
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(attempt.Config), &config); err != nil {
		t.Fatalf("decode derived config: %v", err)
	}
	// The agent's risk-validation branch rejects any attempt whose sealed budget
	// is missing or non-positive, so the manual path must seal all five fields.
	if id, _ := config["ValidationBudgetID"].(string); id == "" {
		t.Fatalf("ValidationBudgetID not sealed: %s", attempt.Config)
	}
	for _, key := range []string{"ValidationTargetConcurrency", "ValidationRateLimit", "ValidationRequestBudget", "ValidationEstimatedRequests"} {
		if n, _ := config[key].(float64); n < 1 {
			t.Fatalf("%s=%v, want >= 1: %s", key, config[key], attempt.Config)
		}
	}
}

func TestExecuteTaskRiskValidationRejectsUnconfirmedAndActivePlansWithoutWrites(t *testing.T) {
	tests := []struct {
		name       string
		status     string
		confirmed  bool
		second     bool
		wantStatus int
	}{
		{name: "missing primary confirmation", status: "FINISHED", confirmed: false, second: true, wantStatus: http.StatusBadRequest},
		{name: "missing high risk confirmation", status: "FINISHED", confirmed: true, second: false, wantStatus: http.StatusBadRequest},
		{name: "active task", status: "Running", confirmed: true, second: true, wantStatus: http.StatusConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			task, preview := seedExecutableRiskValidation(t, test.status)
			withTaskCreateQueue(t)
			recorder := callExecuteRiskValidation(t, task.ID, executeRiskValidationRequest{
				PlanHash: preview.PlanHash, Confirmed: test.confirmed, SecondConfirmation: test.second,
			})
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d (%s), want %d", recorder.Code, recorder.Body.String(), test.wantStatus)
			}
			var count int64
			db.DB.Model(&db.TaskBatch{}).Where("root_task_id = ?", task.ID).Count(&count)
			if count != 0 {
				t.Fatalf("rejected request created %d batches", count)
			}
		})
	}
}

func TestRiskValidationExecutionRBACRequiresOperator(t *testing.T) {
	if role := matchPermission(http.MethodPost, "/api/v1/tasks/task-1/risk-validation"); role != "operator" {
		t.Fatalf("execution required role = %s, want operator", role)
	}
}

func TestPublicTaskConfigRejectsInternalRiskValidationFields(t *testing.T) {
	for _, payload := range []string{
		`{"ExecutionMode":"risk_validation"}`,
		`{"RequiredRuleVersion":"rules-v1"}`,
		`{"RiskValidationTargets":{"https://example.test":["demo.yaml"]}}`,
		`{"RiskValidationPocHashes":{"demo.yaml":"hash"}}`,
	} {
		if _, _, err := normalizeTaskConfigPayload(json.RawMessage(payload)); err == nil {
			t.Fatalf("public config accepted internal execution field: %s", payload)
		}
	}
}
