package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-proto/pyexp"
	"github.com/user/dddd-server/internal/db"
	grpcpkg "github.com/user/dddd-server/internal/grpc"
)

func TestInstallAgentPyenvRequirementsNoopForEmptyRequirements(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-1", Status: "Alive", Tags: `{"pyexp_install":"true"}`}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	if err := store.Create(&db.ExploitRule{
		TenantID:     "default",
		ID:           7,
		RuleID:       "exp-no-req",
		Name:         "No Requirements",
		Requirements: `[]`,
	}).Error; err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/agents/agent-1/pyenv/install", "admin", "9")
	ctx.Params = gin.Params{{Key: "id", Value: "agent-1"}}
	ctx.Request.Body = io.NopCloser(strings.NewReader(`{"exploit_rule_id":7}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	installAgentPyenvRequirements(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected no-op 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"status":"no_op"`) {
		t.Fatalf("response = %s, want no_op", recorder.Body.String())
	}
	var count int64
	store.Model(&db.AgentPyenvJob{}).Count(&count)
	if count != 0 {
		t.Fatalf("expected no job for empty requirements, got %d", count)
	}
}

func TestInstallAgentPyenvRequirementsRejectsUnsupportedAgent(t *testing.T) {
	store := setupAITestDB(t)
	oldHub := notifyHub
	hub := grpcpkg.NewNotifyHub()
	stream := &fakeSubscribeStream{}
	notifyHub = hub
	t.Cleanup(func() {
		notifyHub = oldHub
	})
	hub.Register("agent-1", stream, 1, nil)

	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-1", Status: "Alive", Tags: `{"python_exp":"true","pyexp_install":"false"}`}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	if err := store.Create(&db.ExploitRule{
		TenantID:         "default",
		ID:               8,
		RuleID:           "exp-with-req",
		Name:             "With Requirements",
		Requirements:     `["requests==2.32.3 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]`,
		RequirementsHash: "hash",
	}).Error; err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/agents/agent-1/pyenv/install", "admin", "9")
	ctx.Params = gin.Params{{Key: "id", Value: "agent-1"}}
	ctx.Request.Body = io.NopCloser(strings.NewReader(`{"exploit_rule_id":8}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	installAgentPyenvRequirements(ctx)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected unsupported 503, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "does not support Python EXP dependency install") {
		t.Fatalf("response = %s, want unsupported install message", recorder.Body.String())
	}
	if len(stream.sent) != 0 {
		t.Fatalf("expected no debug command to unsupported agent, got %#v", stream.sent)
	}
	var count int64
	store.Model(&db.AgentPyenvJob{}).Count(&count)
	if count != 0 {
		t.Fatalf("expected no job for unsupported agent, got %d", count)
	}
}

func TestInstallAgentPyenvRequirementsUsesComputedHash(t *testing.T) {
	store := setupAITestDB(t)
	oldHub := notifyHub
	hub := grpcpkg.NewNotifyHub()
	stream := &fakeSubscribeStream{}
	notifyHub = hub
	t.Cleanup(func() {
		notifyHub = oldHub
	})
	hub.Register("agent-1", stream, 1, nil)

	requirement := "requests==2.32.3 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-1", Status: "Alive", Tags: `{"pyexp_install":"true"}`}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	if err := store.Create(&db.ExploitRule{
		TenantID:         "default",
		ID:               9,
		RuleID:           "exp-stale-hash",
		Name:             "Stale Hash",
		Requirements:     marshalJSONArray([]string{requirement}),
		RequirementsHash: "stale-hash",
	}).Error; err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/agents/agent-1/pyenv/install", "admin", "9")
	ctx.Params = gin.Params{{Key: "id", Value: "agent-1"}}
	ctx.Request.Body = io.NopCloser(strings.NewReader(`{"exploit_rule_id":9}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	installAgentPyenvRequirements(ctx)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected accepted 202, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if len(stream.sent) != 1 || stream.sent[0].DebugCommand == nil {
		t.Fatalf("expected one debug command, got %#v", stream.sent)
	}
	var params struct {
		Requirements     []string `json:"requirements"`
		RequirementsHash string   `json:"requirements_hash"`
	}
	if err := json.Unmarshal([]byte(stream.sent[0].DebugCommand.Params), &params); err != nil {
		t.Fatalf("decode params: %v", err)
	}
	expectedHash := pyexp.RequirementsHash([]string{requirement})
	if params.RequirementsHash != expectedHash {
		t.Fatalf("requirements_hash = %q, want computed %q", params.RequirementsHash, expectedHash)
	}
	var job db.AgentPyenvJob
	if err := store.Where("exploit_rule_id = ?", 9).First(&job).Error; err != nil {
		t.Fatalf("load job: %v", err)
	}
	if job.RequirementsHash != expectedHash {
		t.Fatalf("job.RequirementsHash = %q, want %q", job.RequirementsHash, expectedHash)
	}
}

func TestGetAgentPyenvJobIsTenantScoped(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.AgentPyenvJob{
		ID:            "job-1",
		TenantID:      "other",
		AgentID:       "agent-1",
		ExploitRuleID: 3,
		Status:        "Succeeded",
	}).Error; err != nil {
		t.Fatalf("seed job: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/agents/agent-1/pyenv/jobs/job-1", "operator", "9")
	ctx.Params = gin.Params{{Key: "id", Value: "agent-1"}, {Key: "job_id", Value: "job-1"}}
	getAgentPyenvJob(ctx)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected tenant-scoped 404, got %d (%s)", recorder.Code, recorder.Body.String())
	}
}
