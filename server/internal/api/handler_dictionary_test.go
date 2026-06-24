package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/user/dddd-server/internal/db"
)

func TestDictionaryListEmptyReturnsArray(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "finger", "finger.yaml"),
		TenantID: "default",
		Type:     "finger",
		FileName: "finger.yaml",
		Content:  "{}\n",
		Hash:     "empty-finger",
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed fingerprint arsenal: %v", err)
	}
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "workflow", "workflow.yaml"),
		TenantID: "default",
		Type:     "workflow",
		FileName: "workflow.yaml",
		Content:  "{}\n",
		Hash:     "empty-workflow",
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed workflow arsenal: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/dictionaries/fingerprint", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodGet, "/dictionaries/fingerprint", nil)
	getFingerprintDict(ctx)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "[]" {
		t.Fatalf("fingerprint dict response = %d %q, want 200 []", recorder.Code, recorder.Body.String())
	}

	ctx, recorder = newTenantContextWithRole(http.MethodGet, "/dictionaries/workflow", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodGet, "/dictionaries/workflow", nil)
	getWorkflowDict(ctx)
	if recorder.Code != http.StatusOK || recorder.Body.String() != "[]" {
		t.Fatalf("workflow dict response = %d %q, want 200 []", recorder.Code, recorder.Body.String())
	}
}
