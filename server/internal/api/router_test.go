package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	aipkg "github.com/P0lar1ght/argus/server/internal/ai"
	"github.com/P0lar1ght/argus/server/internal/db"
	egresspkg "github.com/P0lar1ght/argus/server/internal/egress"
	"github.com/P0lar1ght/argus/server/internal/scheduler"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type nodeEgressTestService struct {
	pb.UnimplementedAgentEgressServiceServer
	broker *egresspkg.Broker
}

func (s nodeEgressTestService) EgressTunnel(stream pb.AgentEgressService_EgressTunnelServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	return s.broker.AttachAgent(first.GetAgentId(), stream)
}

func nodeEgressBufDialer(listener *bufconn.Listener) func(context.Context, string) (net.Conn, error) {
	return func(context.Context, string) (net.Conn, error) { return listener.Dial() }
}

func ptrTime(v time.Time) *time.Time {
	return &v
}

func TestShouldAgentReloadRules(t *testing.T) {
	tests := []struct {
		name             string
		agentRuleVersion string
		ruleVersion      string
		want             bool
	}{
		{name: "unknown current version", agentRuleVersion: "v1", ruleVersion: "unknown", want: false},
		{name: "empty current version", agentRuleVersion: "v1", ruleVersion: "", want: false},
		{name: "up to date", agentRuleVersion: "v2", ruleVersion: "v2", want: false},
		{name: "agent missing version", agentRuleVersion: "", ruleVersion: "v2", want: true},
		{name: "agent outdated", agentRuleVersion: "v1", ruleVersion: "v2", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldAgentReloadRules(tt.agentRuleVersion, tt.ruleVersion); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestGetAgentCommandsDoesNotExposeAPIConfigSyncState(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-api", Status: "Alive", RuleVersion: "v1"}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	if err := store.Create(&db.SystemConfig{Key: "rule_version", Value: "v1"}).Error; err != nil {
		t.Fatalf("seed rule version: %v", err)
	}
	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/agents/agent-api/commands?api_config_hash=hash-api", "admin", "agent-api")
	ctx.Params = gin.Params{{Key: "id", Value: "agent-api"}}
	getAgentCommands(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected commands 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode commands response: %v", err)
	}
	if _, ok := resp["sync_api_config"]; ok {
		t.Fatalf("commands response must not expose api config sync: %s", recorder.Body.String())
	}
	if _, ok := resp["api_config_hash"]; ok {
		t.Fatalf("commands response must not expose api config hash: %s", recorder.Body.String())
	}
}

func TestGetNodesReportsNativeEgressAvailabilityWithinTenant(t *testing.T) {
	store := setupAITestDB(t)
	for _, node := range []db.Node{
		{TenantID: "default", AgentID: "agent-egress", Status: "Alive"},
		{TenantID: "default", AgentID: "agent-scan-only", Status: "Alive"},
		{TenantID: "tenant-b", AgentID: "agent-foreign", Status: "Alive"},
	} {
		if err := store.Create(&node).Error; err != nil {
			t.Fatalf("seed node: %v", err)
		}
	}

	broker := egresspkg.NewBroker()
	oldBroker := routerRuntime().EgressBroker
	routerRuntime().EgressBroker = broker
	t.Cleanup(func() { routerRuntime().EgressBroker = oldBroker })

	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	pb.RegisterAgentEgressServiceServer(grpcServer, nodeEgressTestService{broker: broker})
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)
	connection, err := grpc.NewClient("passthrough:///agent", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(nodeEgressBufDialer(listener)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	stream, err := pb.NewAgentEgressServiceClient(connection).EgressTunnel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_HELLO, AgentId: "agent-egress"}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/nodes")
	getNodes(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response []NodeResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response) != 2 {
		t.Fatalf("tenant-scoped nodes=%d body=%s", len(response), recorder.Body.String())
	}
	availability := make(map[string]bool, len(response))
	for _, item := range response {
		availability[item.AgentID] = item.EgressOnline
	}
	if !availability["agent-egress"] || availability["agent-scan-only"] {
		t.Fatalf("unexpected egress availability: %#v", availability)
	}
}

func TestValidateUTF8TextBodyMiddlewareScopesToTextualBodies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(validateUTF8TextBodyMiddleware())
	router.POST("/echo", func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		c.String(http.StatusOK, string(body))
	})

	req := httptest.NewRequest(http.MethodPost, "/echo", bytes.NewReader([]byte{0xe4}))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid JSON UTF-8 to be rejected, got %d (%s)", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/echo", bytes.NewReader([]byte{0xe4}))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected binary body to bypass UTF-8 validation, got %d (%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Body.Bytes(); !bytes.Equal(got, []byte{0xe4}) {
		t.Fatalf("expected binary body to reach handler unchanged, got %v", got)
	}
}

func TestGetArsenalsLiteClearsLargeFieldsWithoutForcingPagination(t *testing.T) {
	store := setupAITestDB(t)
	arsenal := db.Arsenal{
		ID:              "default:poc:demo.yaml",
		TenantID:        "default",
		Type:            "poc",
		FileName:        "demo.yaml",
		Content:         "id: demo\ninfo:\n  name: demo\n",
		PreviousContent: "id: old\n",
		Hash:            "hash-demo",
		State:           "Approved",
	}
	if err := store.Create(&arsenal).Error; err != nil {
		t.Fatalf("seed arsenal: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/arsenals/poc?lite=1")
	ctx.Params = gin.Params{{Key: "type", Value: "poc"}}
	getArsenals(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected lite arsenals response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var items []db.Arsenal
	if err := json.Unmarshal(recorder.Body.Bytes(), &items); err != nil {
		t.Fatalf("expected lite response to remain an array: %v; body=%s", err, recorder.Body.String())
	}
	if len(items) != 1 || items[0].Content != "" || items[0].PreviousContent != "" {
		t.Fatalf("expected lite array to clear large fields, got %+v", items)
	}

	ctx, recorder = newTenantContext(http.MethodGet, "/arsenals/poc?lite=1&page=1&page_size=1")
	ctx.Params = gin.Params{{Key: "type", Value: "poc"}}
	getArsenals(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected paged lite arsenals response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var paged struct {
		Items []db.Arsenal `json:"items"`
		Total int64        `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &paged); err != nil {
		t.Fatalf("decode paged lite response: %v", err)
	}
	if paged.Total != 1 || len(paged.Items) != 1 || paged.Items[0].Content != "" || paged.Items[0].PreviousContent != "" {
		t.Fatalf("expected paged lite response to clear large fields, got %+v", paged)
	}
}

func TestGetTasksReturnsPagedResponse(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "project-1", TenantID: "default", OwnerUserID: "1", Name: "默认项目", Status: "active"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	base := time.Date(2026, 7, 5, 12, 0, 0, 0, time.UTC)
	for i := 1; i <= 5; i++ {
		task := db.RootTask{
			ID:        fmt.Sprintf("task-%d", i),
			TenantID:  "default",
			ProjectID: project.ID,
			Name:      fmt.Sprintf("Task %d", i),
			Status:    "Queued",
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}
		if err := store.Create(&task).Error; err != nil {
			t.Fatalf("seed task %d: %v", i, err)
		}
	}
	if err := store.Create(&db.RootTask{
		ID:        "other-tenant-task",
		TenantID:  "tenant-b",
		ProjectID: project.ID,
		Name:      "Other tenant",
		Status:    "Queued",
		CreatedAt: base.Add(10 * time.Minute),
	}).Error; err != nil {
		t.Fatalf("seed other tenant task: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/tasks?project_id=project-1&page=2&page_size=2")
	getTasks(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected paged tasks response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Items    []db.RootTask `json:"items"`
		Total    int64         `json:"total"`
		Page     int           `json:"page"`
		PageSize int           `json:"page_size"`
		HasMore  bool          `json:"has_more"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode tasks response: %v; body=%s", err, recorder.Body.String())
	}
	if resp.Total != 5 || resp.Page != 2 || resp.PageSize != 2 || !resp.HasMore {
		t.Fatalf("unexpected pagination metadata: %+v", resp)
	}
	if len(resp.Items) != 2 || resp.Items[0].ID != "task-3" || resp.Items[1].ID != "task-2" {
		t.Fatalf("unexpected page items: %+v", resp.Items)
	}
}

func TestArchiveTaskPreservesResultsAndWritesAudit(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "project-archive", TenantID: "default", OwnerUserID: "7", Name: "Archive project", Status: "active"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	root := db.RootTask{ID: "root-archive", TenantID: "default", ProjectID: project.ID, Name: "Archive me", Status: "FINISHED"}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	sub := db.SubTask{ID: "sub-archive", TenantID: "default", ProjectID: project.ID, RootTaskID: root.ID, Status: "FINISHED"}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed sub task: %v", err)
	}
	if err := store.Create(&db.Asset{TenantID: "default", ProjectID: project.ID, TaskID: sub.ID, RootTaskID: root.ID, Target: "archive.test", Protocol: "https"}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if err := store.Create(&db.FingerprintHit{TenantID: "default", ProjectID: project.ID, TaskID: sub.ID, RootTaskID: root.ID, Target: "archive.test", ProductName: "nginx"}).Error; err != nil {
		t.Fatalf("seed fingerprint: %v", err)
	}
	if err := store.Create(&db.Vulnerability{TenantID: "default", ProjectID: project.ID, TaskID: sub.ID, RootTaskID: root.ID, Target: "archive.test", Plugin: "safe-check"}).Error; err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodDelete, "/tasks/root-archive", "operator", "7")
	ctx.Params = gin.Params{{Key: "id", Value: root.ID}}
	deleteTask(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected archive 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	var archived db.RootTask
	if err := store.First(&archived, "id = ?", root.ID).Error; err != nil {
		t.Fatalf("archived root task must remain queryable: %v", err)
	}
	if archived.ArchivedAt == nil || archived.Status != "FINISHED" {
		t.Fatalf("expected separate archive timestamp without status rewrite, got %+v", archived)
	}
	for name, model := range map[string]interface{}{
		"sub task":      &db.SubTask{},
		"asset":         &db.Asset{},
		"fingerprint":   &db.FingerprintHit{},
		"vulnerability": &db.Vulnerability{},
	} {
		var count int64
		if err := store.Model(model).Where("root_task_id = ? AND tenant_id = ?", root.ID, "default").Count(&count).Error; err != nil {
			t.Fatalf("count preserved %s: %v", name, err)
		}
		if count != 1 {
			t.Fatalf("expected preserved %s, got count %d", name, count)
		}
	}
	var audit db.TaskAudit
	if err := store.Where("root_task_id = ? AND action = ?", root.ID, "archive").First(&audit).Error; err != nil {
		t.Fatalf("load archive audit: %v", err)
	}
	if audit.TenantID != "default" || audit.ProjectID != project.ID || audit.OperatorID != "7" || audit.BeforeStatus != "FINISHED" || audit.AfterStatus != "FINISHED" {
		t.Fatalf("unexpected archive audit: %+v", audit)
	}

	activeCtx, activeRecorder := newTenantContextWithRole(http.MethodGet, "/tasks?project_id=project-archive", "viewer", "7")
	getTasks(activeCtx)
	if activeRecorder.Code != http.StatusOK || strings.Contains(activeRecorder.Body.String(), root.ID) {
		t.Fatalf("default task list must exclude archived task, got %d (%s)", activeRecorder.Code, activeRecorder.Body.String())
	}
	archivedCtx, archivedRecorder := newTenantContextWithRole(http.MethodGet, "/tasks?project_id=project-archive&archived=only", "viewer", "7")
	getTasks(archivedCtx)
	if archivedRecorder.Code != http.StatusOK || !strings.Contains(archivedRecorder.Body.String(), root.ID) {
		t.Fatalf("archived task list must include archived task, got %d (%s)", archivedRecorder.Code, archivedRecorder.Body.String())
	}
	detailCtx, detailRecorder := newTenantContextWithRole(http.MethodGet, "/tasks/root-archive", "viewer", "7")
	detailCtx.Params = gin.Params{{Key: "id", Value: root.ID}}
	getTaskDetail(detailCtx)
	if detailRecorder.Code != http.StatusOK || !strings.Contains(detailRecorder.Body.String(), `"action":"archive"`) || !strings.Contains(detailRecorder.Body.String(), `"assets":1`) {
		t.Fatalf("archived task detail must retain results and audits, got %d (%s)", detailRecorder.Code, detailRecorder.Body.String())
	}
}

func TestArchiveTaskRejectsActiveAndInaccessibleTasks(t *testing.T) {
	store := setupAITestDB(t)
	projects := []db.Project{
		{ID: "owned-project", TenantID: "default", OwnerUserID: "7", Name: "Owned", Status: "active"},
		{ID: "foreign-project", TenantID: "default", OwnerUserID: "8", Name: "Foreign", Status: "active"},
	}
	if err := store.Create(&projects).Error; err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	tasks := []db.RootTask{
		{ID: "active-task-archive", TenantID: "default", ProjectID: "owned-project", Status: "Running"},
		{ID: "foreign-task-archive", TenantID: "default", ProjectID: "foreign-project", Status: "FINISHED"},
	}
	if err := store.Create(&tasks).Error; err != nil {
		t.Fatalf("seed tasks: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodDelete, "/tasks/active-task-archive", "operator", "7")
	ctx.Params = gin.Params{{Key: "id", Value: "active-task-archive"}}
	deleteTask(ctx)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected active archive conflict, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	ctx, recorder = newTenantContextWithRole(http.MethodDelete, "/tasks/foreign-task-archive", "operator", "7")
	ctx.Params = gin.Params{{Key: "id", Value: "foreign-task-archive"}}
	deleteTask(ctx)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected inaccessible project archive forbidden, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	var archiveCount int64
	store.Model(&db.RootTask{}).Where("archived_at IS NOT NULL").Count(&archiveCount)
	if archiveCount != 0 {
		t.Fatalf("rejected archives must not mutate tasks, got %d archived", archiveCount)
	}
	var auditCount int64
	store.Model(&db.TaskAudit{}).Count(&auditCount)
	if auditCount != 0 {
		t.Fatalf("rejected archives must not write audits, got %d", auditCount)
	}
}

func TestGetStatsExcludesArchivedTasks(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "project-stats-archive", TenantID: "default", OwnerUserID: "7", Name: "Stats", Status: "active"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	archivedAt := time.Now()
	tasks := []db.RootTask{
		{ID: "stats-active", TenantID: "default", ProjectID: "project-stats-archive", Status: "FINISHED"},
		{ID: "stats-archived", TenantID: "default", ProjectID: "project-stats-archive", Status: "FINISHED", ArchivedAt: &archivedAt},
	}
	if err := store.Create(&tasks).Error; err != nil {
		t.Fatalf("seed tasks: %v", err)
	}
	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/stats?project_id=project-stats-archive", "viewer", "7")
	getStats(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected stats 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Tasks int64 `json:"tasks"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if payload.Tasks != 1 {
		t.Fatalf("expected only active task in stats, got %+v", payload)
	}
}

func TestAIPermissions(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   string
	}{
		{method: "POST", path: "/api/v1/ai/arsenal/analyze", want: "admin"},
		{method: "POST", path: "/api/v1/ai/arsenal/analyze/stream", want: "admin"},
		{method: "POST", path: "/api/v1/ai/chat", want: "operator"},
		{method: "POST", path: "/api/v1/ai/actions/confirm", want: "operator"},
		{method: "GET", path: "/api/v1/ai/copilot/prompts", want: "operator"},
		{method: "GET", path: "/api/v1/ai/tool-invocations", want: "operator"},
		{method: "GET", path: "/api/v1/ai/config", want: "admin"},
		{method: "PUT", path: "/api/v1/ai/config", want: "admin"},
		{method: "GET", path: "/api/v1/ai/models", want: "admin"},
		{method: "POST", path: "/api/v1/ai/test", want: "admin"},
	}
	for _, tt := range tests {
		if got := matchPermission(tt.method, tt.path); got != tt.want {
			t.Fatalf("%s %s expected %s, got %s", tt.method, tt.path, tt.want, got)
		}
	}
}

func TestTenantRolePermissionMatrix(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   string
	}{
		{method: "GET", path: "/api/v1/projects", want: "viewer"},
		{method: "GET", path: "/api/v1/tasks/task-1", want: "viewer"},
		{method: "GET", path: "/api/v1/tasks/task-1/config-revisions", want: "viewer"},
		{method: "GET", path: "/api/v1/tasks/task-1/batches", want: "viewer"},
		{method: "GET", path: "/api/v1/reports/export/vulns", want: "viewer"},
		{method: "POST", path: "/api/v1/projects", want: "operator"},
		{method: "POST", path: "/api/v1/projects/proj-1/asset-discovery/fofa/query", want: "operator"},
		{method: "POST", path: "/api/v1/projects/proj-1/asset-discovery/hunter/query", want: "operator"},
		{method: "POST", path: "/api/v1/projects/proj-1/asset-discovery/quake/query", want: "operator"},
		{method: "GET", path: "/api/v1/projects/proj-1/members", want: "operator"},
		{method: "PUT", path: "/api/v1/projects/proj-1/members", want: "operator"},
		{method: "POST", path: "/api/v1/tasks", want: "operator"},
		{method: "POST", path: "/api/v1/tasks/preview-selector", want: "operator"},
		{method: "POST", path: "/api/v1/tasks/validate-targets", want: "operator"},
		{method: "POST", path: "/api/v1/tasks/task-1/cancel", want: "operator"},
		{method: "POST", path: "/api/v1/tasks/task-1/stop", want: "operator"},
		{method: "POST", path: "/api/v1/tasks/task-1/pause", want: "operator"},
		{method: "POST", path: "/api/v1/tasks/task-1/resume", want: "operator"},
		{method: "POST", path: "/api/v1/tasks/task-1/retry", want: "operator"},
		{method: "POST", path: "/api/v1/tasks/task-1/batches/batch-1/pause", want: "operator"},
		{method: "POST", path: "/api/v1/tasks/task-1/batches/batch-1/resume", want: "operator"},
		{method: "POST", path: "/api/v1/tasks/task-1/batches/batch-1/stop", want: "operator"},
		{method: "POST", path: "/api/v1/tasks/task-1/batches/batch-1/retry", want: "operator"},
		{method: "PUT", path: "/api/v1/tasks/task-1/config", want: "operator"},
		{method: "DELETE", path: "/api/v1/tasks/task-1", want: "operator"},
		{method: "DELETE", path: "/api/v1/tasks/task-1/batches/batch-1", want: "operator"},
		{method: "DELETE", path: "/api/v1/nodes/agent-1", want: "operator"},
		{method: "GET", path: "/api/v1/dictionaries/workflow", want: "admin"},
		{method: "POST", path: "/api/v1/dictionaries/workflow", want: "admin"},
		{method: "PUT", path: "/api/v1/dictionaries/workflow/product", want: "admin"},
		{method: "DELETE", path: "/api/v1/dictionaries/workflow/product", want: "admin"},
		{method: "GET", path: "/api/v1/arsenals/poc", want: "admin"},
		{method: "POST", path: "/api/v1/arsenals/poc/demo.yaml", want: "admin"},
		{method: "DELETE", path: "/api/v1/arsenals/poc/demo.yaml", want: "admin"},
		{method: "POST", path: "/api/v1/arsenals/poc/demo.yaml/approve", want: "admin"},
		{method: "POST", path: "/api/v1/arsenals/poc/demo.yaml/rollback", want: "admin"},
		{method: "GET", path: "/api/v1/arsenals/seed-db", want: "admin"},
		{method: "POST", path: "/api/v1/arsenals/ai/analyze", want: "admin"},
		{method: "POST", path: "/api/v1/ai/arsenal/analyze", want: "admin"},
		{method: "POST", path: "/api/v1/ai/arsenal/analyze/stream", want: "admin"},
		{method: "GET", path: "/api/v1/reports/export/assets", want: "viewer"},
		{method: "GET", path: "/api/v1/reports/export/fingerprints", want: "viewer"},
		{method: "POST", path: "/api/v1/mcp/tools/rule/context", want: "operator"},
		{method: "POST", path: "/api/v1/mcp/tools/rule/debug", want: "operator"},
		{method: "POST", path: "/api/v1/mcp/tools/rule/save", want: "operator"},
		{method: "POST", path: "/api/v1/mcp/tools/rule/apply", want: "admin"},
		{method: "GET", path: "/api/v1/mcp/admin/status", want: "admin"},
		{method: "PUT", path: "/api/v1/mcp/admin/status", want: "admin"},
		{method: "GET", path: "/api/v1/mcp/admin/clients", want: "admin"},
		{method: "POST", path: "/api/v1/mcp/admin/clients/cursor/revoke", want: "admin"},
		{method: "POST", path: "/api/v1/mcp/admin/clients/cursor/disable", want: "admin"},
		{method: "DELETE", path: "/api/v1/mcp/admin/clients/other", want: "admin"},
		{method: "GET", path: "/api/v1/mcp/admin/sessions", want: "admin"},
		{method: "POST", path: "/api/v1/mcp/admin/sessions/revoke", want: "admin"},
		{method: "GET", path: "/api/v1/users", want: "operator"},
		{method: "GET", path: "/api/v1/roles", want: "admin"},
		{method: "POST", path: "/api/v1/roles", want: "admin"},
		{method: "PUT", path: "/api/v1/roles/security-reviewer", want: "admin"},
		{method: "DELETE", path: "/api/v1/roles/security-reviewer", want: "admin"},
		{method: "GET", path: "/api/v1/cloud/accounts", want: "operator"},
		{method: "POST", path: "/api/v1/cloud/instances/cleanup", want: "operator"},
		{method: "POST", path: "/api/v1/cloud/accounts/ca-1/oss/upload", want: "operator"},
		{method: "POST", path: "/api/v1/build/client", want: "admin"},
		{method: "POST", path: "/api/v1/build/jobs/1/cancel", want: "admin"},
		{method: "POST", path: "/api/v1/build/jobs/1/retry", want: "admin"},
		{method: "GET", path: "/api/v1/undocumented", want: "admin"},
	}
	for _, tt := range tests {
		if got := matchPermission(tt.method, tt.path); got != tt.want {
			t.Fatalf("%s %s expected %s, got %s", tt.method, tt.path, tt.want, got)
		}
	}
}

func TestRBACRestrictsArsenalManagementToAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	requests := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/v1/arsenals/poc"},
		{method: http.MethodPost, path: "/api/v1/arsenals/poc/demo.yaml"},
		{method: http.MethodGet, path: "/api/v1/dictionaries/workflow"},
		{method: http.MethodPut, path: "/api/v1/dictionaries/workflow/demo"},
		{method: http.MethodPost, path: "/api/v1/ai/arsenal/analyze"},
	}
	for _, request := range requests {
		for _, role := range []string{"viewer", "operator", "admin"} {
			name := role + "_" + request.method + "_" + request.path
			t.Run(name, func(t *testing.T) {
				router := gin.New()
				router.Use(func(c *gin.Context) {
					c.Set("tenant", "tenant-a")
					c.Set("role", role)
					c.Next()
				})
				router.Use(RBACMiddleware())
				router.Handle(request.method, request.path, func(c *gin.Context) {
					c.JSON(http.StatusOK, gin.H{"status": "ok"})
				})

				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, httptest.NewRequest(request.method, request.path, nil))
				want := http.StatusForbidden
				if role == "admin" {
					want = http.StatusOK
				}
				if recorder.Code != want {
					t.Fatalf("expected %d, got %d body=%s", want, recorder.Code, recorder.Body.String())
				}
			})
		}
	}
}

func TestRBACKeepsMCPRuleAuthoringPermissions(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   string
	}{
		{method: http.MethodPost, path: "/api/v1/mcp/tools/rule/context", want: "operator"},
		{method: http.MethodPost, path: "/api/v1/mcp/tools/rule/debug", want: "operator"},
		{method: http.MethodPost, path: "/api/v1/mcp/tools/rule/save", want: "operator"},
		{method: http.MethodPost, path: "/api/v1/mcp/tools/rule/apply", want: "admin"},
	}
	for _, tt := range tests {
		if got := matchPermission(tt.method, tt.path); got != tt.want {
			t.Fatalf("%s %s expected %s, got %s", tt.method, tt.path, tt.want, got)
		}
	}
}

func TestExportVulnsRecordsReportObject(t *testing.T) {
	store := setupAITestDB(t)
	oldRoot := routerRuntime().ObjectStorageRoot
	routerRuntime().ObjectStorageRoot = t.TempDir()
	t.Cleanup(func() {
		routerRuntime().ObjectStorageRoot = oldRoot
	})
	if err := store.Create(&db.Vulnerability{
		TenantID:  "default",
		ProjectID: "p1",
		TaskID:    "task-1",
		Target:    "https://example.com",
		Plugin:    "poc-demo",
		Severity:  "high",
	}).Error; err != nil {
		t.Fatalf("seed vulnerability: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/reports/export/vulns", "admin", "7")
	ctx.Request = httptest.NewRequest(http.MethodGet, "/reports/export/vulns", nil)
	exportVulns(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected export 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "poc-demo") {
		t.Fatalf("expected CSV body to contain vulnerability row, got %s", recorder.Body.String())
	}
	var report db.Report
	if err := store.Where("type = ? AND format = ?", "vulnerabilities", "csv").First(&report).Error; err != nil {
		t.Fatalf("expected report metadata: %v", err)
	}
	key := strings.TrimPrefix(report.FileURL, "local://")
	if key == report.FileURL || key == "" {
		t.Fatalf("unexpected report file url: %s", report.FileURL)
	}
	if _, err := os.Stat(filepath.Join(routerRuntime().ObjectStorageRoot, filepath.FromSlash(key))); err != nil {
		t.Fatalf("expected report object file: %v", err)
	}
}

func TestExportAssetsScopesByRootTaskAndRecordsReportObject(t *testing.T) {
	store := setupAITestDB(t)
	oldRoot := routerRuntime().ObjectStorageRoot
	routerRuntime().ObjectStorageRoot = t.TempDir()
	t.Cleanup(func() {
		routerRuntime().ObjectStorageRoot = oldRoot
	})
	if err := store.Create(&db.Project{ID: "p1", TenantID: "default", OwnerUserID: "7", Name: "p1"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := store.Create(&db.RootTask{ID: "root-1", TenantID: "default", ProjectID: "p1", Status: "Finished"}).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	if err := store.Create(&db.SubTask{ID: "sub-1", TenantID: "default", ProjectID: "p1", RootTaskID: "root-1", Status: "Finished"}).Error; err != nil {
		t.Fatalf("seed sub task: %v", err)
	}
	assets := []db.Asset{
		{TenantID: "default", ProjectID: "p1", TaskID: "sub-1", RootTaskID: "root-1", Target: "https://in-scope.example", Protocol: "https", Port: 443, URL: "https://in-scope.example", Title: "in-scope"},
		{TenantID: "default", ProjectID: "p1", TaskID: "other-task", RootTaskID: "other-root", Target: "https://out-of-scope.example", Protocol: "https", Port: 443, URL: "https://out-of-scope.example", Title: "out-of-scope"},
	}
	if err := store.Create(&assets).Error; err != nil {
		t.Fatalf("seed assets: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/reports/export/assets?task_id=root-1", "admin", "7")
	ctx.Request = httptest.NewRequest(http.MethodGet, "/reports/export/assets?task_id=root-1", nil)
	exportAssets(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected export 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "in-scope.example") || strings.Contains(body, "out-of-scope.example") {
		t.Fatalf("expected CSV body to only contain root task assets, got %s", body)
	}
	var report db.Report
	if err := store.Where("type = ? AND format = ?", "assets", "csv").First(&report).Error; err != nil {
		t.Fatalf("expected asset report metadata: %v", err)
	}
	key := strings.TrimPrefix(report.FileURL, "local://")
	if key == report.FileURL || key == "" {
		t.Fatalf("unexpected asset report file url: %s", report.FileURL)
	}
	if _, err := os.Stat(filepath.Join(routerRuntime().ObjectStorageRoot, filepath.FromSlash(key))); err != nil {
		t.Fatalf("expected asset report object file: %v", err)
	}
}

func TestExportFingerprintsScopesByRootTaskAndRecordsReportObject(t *testing.T) {
	store := setupAITestDB(t)
	oldRoot := routerRuntime().ObjectStorageRoot
	routerRuntime().ObjectStorageRoot = t.TempDir()
	t.Cleanup(func() {
		routerRuntime().ObjectStorageRoot = oldRoot
	})
	if err := store.Create(&db.Project{ID: "p1", TenantID: "default", OwnerUserID: "7", Name: "p1"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := store.Create(&db.RootTask{ID: "root-1", TenantID: "default", ProjectID: "p1", Status: "Finished"}).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	if err := store.Create(&db.SubTask{ID: "sub-1", TenantID: "default", ProjectID: "p1", RootTaskID: "root-1", Status: "Finished"}).Error; err != nil {
		t.Fatalf("seed sub task: %v", err)
	}
	fps := []db.FingerprintHit{
		{TenantID: "default", ProjectID: "p1", TaskID: "sub-1", RootTaskID: "root-1", Target: "https://in-scope.example", ProductName: "nginx", RuleName: "nginx-title"},
		{TenantID: "default", ProjectID: "p1", TaskID: "other-task", RootTaskID: "other-root", Target: "https://out-of-scope.example", ProductName: "apache", RuleName: "apache-title"},
	}
	if err := store.Create(&fps).Error; err != nil {
		t.Fatalf("seed fingerprints: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/reports/export/fingerprints?task_id=root-1", "admin", "7")
	ctx.Request = httptest.NewRequest(http.MethodGet, "/reports/export/fingerprints?task_id=root-1", nil)
	exportFingerprints(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected export 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "nginx") || strings.Contains(body, "apache") {
		t.Fatalf("expected CSV body to only contain root task fingerprints, got %s", body)
	}
	var report db.Report
	if err := store.Where("type = ? AND format = ?", "fingerprints", "csv").First(&report).Error; err != nil {
		t.Fatalf("expected fingerprint report metadata: %v", err)
	}
	key := strings.TrimPrefix(report.FileURL, "local://")
	if key == report.FileURL || key == "" {
		t.Fatalf("unexpected fingerprint report file url: %s", report.FileURL)
	}
	if _, err := os.Stat(filepath.Join(routerRuntime().ObjectStorageRoot, filepath.FromSlash(key))); err != nil {
		t.Fatalf("expected fingerprint report object file: %v", err)
	}
}

func TestPauseTaskMovesUnclaimedSubTasksToPaused(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "p1", TenantID: "default", OwnerUserID: "7", Name: "p1"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := store.Create(&db.RootTask{ID: "root-pause", TenantID: "default", ProjectID: "p1", Status: "Running"}).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	subTasks := []db.SubTask{
		{ID: "pending", TenantID: "default", ProjectID: "p1", RootTaskID: "root-pause", Status: "Pending", AgentID: "agent-old", StreamMsgID: "msg-old"},
		{ID: "dispatching", TenantID: "default", ProjectID: "p1", RootTaskID: "root-pause", Status: subTaskStatusDispatching},
		{ID: "recovered", TenantID: "default", ProjectID: "p1", RootTaskID: "root-pause", Status: "Recovered"},
		{ID: "running", TenantID: "default", ProjectID: "p1", RootTaskID: "root-pause", Status: "Running", AgentID: "agent-1"},
		{ID: "done", TenantID: "default", ProjectID: "p1", RootTaskID: "root-pause", Status: "DONE"},
	}
	if err := store.Create(&subTasks).Error; err != nil {
		t.Fatalf("seed subtasks: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/root-pause/pause", "operator", "7")
	ctx.Params = gin.Params{{Key: "id", Value: "root-pause"}}
	pauseTask(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected pause 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	var root db.RootTask
	if err := store.First(&root, "id = ?", "root-pause").Error; err != nil {
		t.Fatalf("load root: %v", err)
	}
	if root.Status != "Paused" {
		t.Fatalf("expected root to be Paused, got %s", root.Status)
	}
	for _, id := range []string{"pending", "dispatching", "recovered"} {
		var sub db.SubTask
		if err := store.First(&sub, "id = ?", id).Error; err != nil {
			t.Fatalf("load subtask %s: %v", id, err)
		}
		if sub.Status != "Paused" || sub.AgentID != "" || sub.StreamMsgID != "" {
			t.Fatalf("expected %s to be paused and unassigned, got %+v", id, sub)
		}
	}
	var running db.SubTask
	if err := store.First(&running, "id = ?", "running").Error; err != nil {
		t.Fatalf("load running subtask: %v", err)
	}
	if running.Status != "Running" || running.AgentID != "agent-1" {
		t.Fatalf("expected running subtask to remain running, got %+v", running)
	}
	var audit db.TaskAudit
	if err := store.Where("root_task_id = ? AND action = ?", "root-pause", "pause").First(&audit).Error; err != nil {
		t.Fatalf("load pause audit: %v", err)
	}
	if audit.OperatorID != "7" || audit.BeforeStatus != "Running" || audit.AfterStatus != "Paused" {
		t.Fatalf("unexpected pause audit: %+v", audit)
	}
}

func TestCancelTaskWritesStopAuditAndPersistsStoppingState(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "p-stop", TenantID: "default", OwnerUserID: "7", Name: "p-stop"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := store.Create(&db.RootTask{ID: "root-stop", TenantID: "default", ProjectID: "p-stop", Status: "Running"}).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	subs := []db.SubTask{
		{ID: "stop-pending", TenantID: "default", ProjectID: "p-stop", RootTaskID: "root-stop", Status: "Pending"},
		{ID: "stop-running", TenantID: "default", ProjectID: "p-stop", RootTaskID: "root-stop", Status: "Running", AgentID: "agent-1"},
	}
	if err := store.Create(&subs).Error; err != nil {
		t.Fatalf("seed subtasks: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/root-stop/cancel", "operator", "7")
	ctx.Params = gin.Params{{Key: "id", Value: "root-stop"}}
	cancelTask(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected stop 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var root db.RootTask
	if err := store.First(&root, "id = ?", "root-stop").Error; err != nil {
		t.Fatalf("load stopped root: %v", err)
	}
	if root.Status != "CancelPending" {
		t.Fatalf("expected root stopping state, got %+v", root)
	}
	var audit db.TaskAudit
	if err := store.Where("root_task_id = ? AND action = ?", "root-stop", "stop").First(&audit).Error; err != nil {
		t.Fatalf("load stop audit: %v", err)
	}
	if audit.OperatorID != "7" || audit.BeforeStatus != "Running" || audit.AfterStatus != "CancelPending" {
		t.Fatalf("unexpected stop audit: %+v", audit)
	}
}

func TestCancelTaskRejectsTerminalLegacyState(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "p1", TenantID: "default", OwnerUserID: "7", Name: "p1"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := store.Create(&db.RootTask{ID: "root-finished", TenantID: "default", ProjectID: "p1", Status: "FINISHED"}).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/root-finished/cancel", "operator", "7")
	ctx.Params = gin.Params{{Key: "id", Value: "root-finished"}}
	cancelTask(ctx)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected terminal task cancel to return 400, got %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestResumeTaskOnlyReactivatesPausedSubTasks(t *testing.T) {
	store := setupAITestDB(t)
	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = nil
	t.Cleanup(func() { routerRuntime().TaskQueue = oldQueue })
	if err := store.Create(&db.Project{ID: "p1", TenantID: "default", OwnerUserID: "7", Name: "p1"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := store.Create(&db.RootTask{ID: "root-resume", TenantID: "default", ProjectID: "p1", Status: "Paused"}).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	subTasks := []db.SubTask{
		{ID: "paused", TenantID: "default", ProjectID: "p1", RootTaskID: "root-resume", Status: "Paused"},
		{ID: "stale-pending", TenantID: "default", ProjectID: "p1", RootTaskID: "root-resume", Status: "Pending"},
		{ID: "running", TenantID: "default", ProjectID: "p1", RootTaskID: "root-resume", Status: "Running"},
	}
	if err := store.Create(&subTasks).Error; err != nil {
		t.Fatalf("seed subtasks: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks/root-resume/resume", "operator", "7")
	ctx.Params = gin.Params{{Key: "id", Value: "root-resume"}}
	resumeTask(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected resume 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var paused db.SubTask
	if err := store.First(&paused, "id = ?", "paused").Error; err != nil {
		t.Fatalf("load paused subtask: %v", err)
	}
	if paused.Status != subTaskStatusDispatching {
		t.Fatalf("expected paused subtask to become Dispatching, got %+v", paused)
	}
	var stale db.SubTask
	if err := store.First(&stale, "id = ?", "stale-pending").Error; err != nil {
		t.Fatalf("load stale pending subtask: %v", err)
	}
	if stale.Status != "Pending" {
		t.Fatalf("expected stale pending subtask to remain Pending, got %+v", stale)
	}
	var root db.RootTask
	if err := store.First(&root, "id = ?", "root-resume").Error; err != nil {
		t.Fatalf("load root: %v", err)
	}
	if root.Status == "Paused" {
		t.Fatalf("expected root to leave Paused after resume, got %+v", root)
	}
	var audit db.TaskAudit
	if err := store.Where("root_task_id = ? AND action = ?", "root-resume", "resume").First(&audit).Error; err != nil {
		t.Fatalf("load resume audit: %v", err)
	}
	if audit.OperatorID != "7" || audit.BeforeStatus != "Paused" || audit.AfterStatus != "Queued" {
		t.Fatalf("unexpected resume audit: %+v", audit)
	}
}

func TestCustomRoleResolvesToBaseRole(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.CustomRole{
		TenantID: "tenant-a",
		Name:     "task-runner",
		Label:    "任务执行员",
		BaseRole: "operator",
	}).Error; err != nil {
		t.Fatalf("create custom role: %v", err)
	}
	if got := roleLevelForTenant("tenant-a", "task-runner"); got != roleHierarchy["operator"] {
		t.Fatalf("expected operator level, got %d", got)
	}
	if got := roleLevelForTenant("tenant-b", "task-runner"); got != roleHierarchy["viewer"] {
		t.Fatalf("expected unknown tenant custom role to fall back to viewer, got %d", got)
	}
	if role, ok := normalizeUserRoleForTenant("tenant-a", "task-runner"); !ok || role != "task-runner" {
		t.Fatalf("expected tenant custom role to be accepted, role=%q ok=%v", role, ok)
	}
	if _, ok := normalizeUserRoleForTenant("tenant-b", "task-runner"); ok {
		t.Fatalf("expected custom role from another tenant to be rejected")
	}
}

func TestRoleHandlersProtectBuiltinsAndAssignedRoles(t *testing.T) {
	store := setupAITestDB(t)
	ctx, recorder := newTenantContext(http.MethodPost, "/roles")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/roles", strings.NewReader(`{
		"name":"security-reviewer",
		"label":"安全观察员",
		"base_role":"viewer",
		"description":"review only"
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	createRole(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected create role ok, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	if role, ok := normalizeUserRoleForTenant("default", "security-reviewer"); !ok || role != "security-reviewer" {
		t.Fatalf("expected created custom role to be accepted, role=%q ok=%v", role, ok)
	}

	if err := store.Create(&db.User{TenantID: "default", Username: "reviewer", Role: "security-reviewer", Status: "active"}).Error; err != nil {
		t.Fatalf("assign role to user: %v", err)
	}

	ctx, recorder = newTenantContext(http.MethodDelete, "/roles/security-reviewer")
	ctx.Params = gin.Params{{Key: "name", Value: "security-reviewer"}}
	deleteRole(ctx)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected assigned role delete to conflict, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	ctx, recorder = newTenantContext(http.MethodDelete, "/roles/admin")
	ctx.Params = gin.Params{{Key: "name", Value: "admin"}}
	deleteRole(ctx)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected built-in delete to fail, got %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestCreateTaskRejectsTenantQuotaExceeded(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "project-quota", TenantID: "default", OwnerUserID: "1", Status: "active"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := store.Create(&db.TenantQuota{TenantID: "default", MaxConcurrentTasks: 1, DailyTaskLimit: 10}).Error; err != nil {
		t.Fatalf("seed quota: %v", err)
	}
	if err := store.Create(&db.RootTask{ID: "active-task", TenantID: "default", ProjectID: "project-quota", Status: "Running", CreatedAt: time.Now()}).Error; err != nil {
		t.Fatalf("seed active task: %v", err)
	}

	oldQueue := routerRuntime().TaskQueue
	routerRuntime().TaskQueue = scheduler.NewTaskQueue("")
	t.Cleanup(func() { routerRuntime().TaskQueue = oldQueue })

	ctx, recorder := newTenantContextWithRole(http.MethodPost, "/tasks", "operator", "1")
	ctx.Request = httptest.NewRequest(http.MethodPost, "/tasks", strings.NewReader(`{
		"project_id":"project-quota",
		"name":"quota blocked",
		"targets":"https://example.com",
		"config":{},
		"priority":1
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	createTask(ctx)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected quota rejection 429, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var rootCount int64
	store.Model(&db.RootTask{}).Where("tenant_id = ?", "default").Count(&rootCount)
	if rootCount != 1 {
		t.Fatalf("expected no new root task after quota rejection, got %d", rootCount)
	}
}

func TestListPocRulesFiltersMetadata(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.PocRule{
		TenantID:            "default",
		SourceFile:          "demo.yaml",
		Name:                "demo-poc",
		TargetProduct:       "DemoProduct",
		CVE:                 "CVE-2026-0003",
		CompatibilityStatus: "indexed",
		ExecutionClass:      db.PocExecutionClassVerification,
		RiskLevel:           db.PocRiskLevelHigh,
		Severity:            "high",
		Enabled:             true,
	}).Error; err != nil {
		t.Fatalf("seed poc rule: %v", err)
	}
	if err := store.Create(&db.PocRule{
		TenantID:            "default",
		SourceFile:          "other.yaml",
		Name:                "other-poc",
		TargetProduct:       "OtherProduct",
		CVE:                 "CVE-2026-9999",
		CompatibilityStatus: "unknown",
		ExecutionClass:      db.PocExecutionClassDetection,
		RiskLevel:           db.PocRiskLevelLow,
		Severity:            "low",
		Enabled:             true,
	}).Error; err != nil {
		t.Fatalf("seed other poc rule: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/poc-rules?product=demo&cve=2026-0003&compatibility_status=indexed&execution_class=verification&risk_level=high", "viewer", "1")
	ctx.Request = httptest.NewRequest(http.MethodGet, "/poc-rules?product=demo&cve=2026-0003&compatibility_status=indexed&execution_class=verification&risk_level=high", nil)
	listPocRules(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp []pocRuleResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp) != 1 || resp[0].Name != "demo-poc" || resp[0].CVE != "CVE-2026-0003" {
		t.Fatalf("unexpected filtered poc rules: %+v", resp)
	}
	if resp[0].ExecutionClass != db.PocExecutionClassVerification || resp[0].RiskLevel != db.PocRiskLevelHigh || !resp[0].RequiresConfirmation || !resp[0].RequiresSecondConfirmation {
		t.Fatalf("unexpected POC execution governance response: %+v", resp[0])
	}
}

func TestRBACRequiresUserEXPAuthorization(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.User{
		ID:            1,
		TenantID:      "tenant-a",
		Username:      "authorized",
		Role:          "operator",
		Status:        "active",
		ExpAuthorized: true,
	}).Error; err != nil {
		t.Fatalf("create authorized user: %v", err)
	}
	if err := store.Create(&db.User{
		ID:            2,
		TenantID:      "tenant-a",
		Username:      "plain",
		Role:          "operator",
		Status:        "active",
		ExpAuthorized: false,
	}).Error; err != nil {
		t.Fatalf("create plain user: %v", err)
	}

	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		name   string
		userID string
		want   int
	}{
		{name: "authorized user can view exp", userID: "1", want: http.StatusOK},
		{name: "unauthorized user is blocked", userID: "2", want: http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("tenant", "tenant-a")
				c.Set("role", "operator")
				c.Set("user_id", tt.userID)
				c.Next()
			})
			r.Use(RBACMiddleware())
			r.GET("/api/v1/exps", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/exps", nil)
			r.ServeHTTP(w, req)
			if w.Code != tt.want {
				t.Fatalf("expected status %d, got %d body=%s", tt.want, w.Code, w.Body.String())
			}
		})
	}
}

func TestNormalizeUserRoleAndStatus(t *testing.T) {
	if got, ok := normalizeUserRole(""); !ok || got != "viewer" {
		t.Fatalf("empty role should default to viewer, got %q ok=%v", got, ok)
	}
	if got, ok := normalizeUserRole("operator"); !ok || got != "operator" {
		t.Fatalf("operator role should be accepted, got %q ok=%v", got, ok)
	}
	if _, ok := normalizeUserRole("owner"); ok {
		t.Fatalf("unknown role should be rejected")
	}
	if got, ok := normalizeUserStatus("disabled"); !ok || got != "disabled" {
		t.Fatalf("disabled status should be accepted, got %q ok=%v", got, ok)
	}
	if _, ok := normalizeUserStatus("locked"); ok {
		t.Fatalf("unknown status should be rejected")
	}
}

func TestCurrentJWTSecretIsNotCompileTimeDefault(t *testing.T) {
	secret := string(currentJWTSecret())
	if secret == "" {
		t.Fatal("JWT secret must not be empty")
	}
	if secret == "P8-MUST-HAVE-SECRET-KEY" {
		t.Fatal("JWT secret must not use the compile-time default")
	}
	if os.Getenv("ARGUS_JWT_SECRET") == "" && len(secret) < 32 {
		t.Fatalf("ephemeral JWT secret too short: %d", len(secret))
	}
	if string(currentJWTSecret()) != secret {
		t.Fatal("JWT secret must be stable for the process lifetime")
	}
}

func TestValidateAgentSessionBindsTenantAndRejectsMismatch(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Node{
		TenantID:       "tenant-a",
		AgentID:        "agent-a",
		Token:          "session-token",
		Status:         "Alive",
		TokenExpiresAt: ptrTime(time.Now().Add(time.Hour)),
	}).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-a/commands", nil)
	c.Request.Header.Set("x-agent-id", "agent-a")
	c.Request.Header.Set("x-agent-token", "session-token")

	if !validateAgentSession(c) {
		t.Fatalf("expected valid agent session")
	}
	if got := c.GetString("tenant"); got != "tenant-a" {
		t.Fatalf("expected tenant-a, got %q", got)
	}
	if got := c.GetString("role"); got != agentSessionRole {
		t.Fatalf("expected agent session role %q, got %q", agentSessionRole, got)
	}
	if got, _ := c.Get("agent_internal"); got != true {
		t.Fatalf("expected agent_internal flag, got %#v", got)
	}

	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-b/commands", nil)
	c.Request.Header.Set("x-agent-id", "agent-a")
	c.Request.Header.Set("x-agent-token", "session-token")

	if validateAgentSession(c) {
		t.Fatalf("expected mismatched path agent id to be rejected")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for agent mismatch, got %d", w.Code)
	}

	if err := store.Model(&db.Node{}).Where("agent_id = ?", "agent-a").Updates(map[string]interface{}{
		"status": "Offline",
		"token":  "session-token",
	}).Error; err != nil {
		t.Fatalf("mark node offline: %v", err)
	}
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-a/commands", nil)
	c.Request.Header.Set("x-agent-id", "agent-a")
	c.Request.Header.Set("x-agent-token", "session-token")
	if validateAgentSession(c) {
		t.Fatalf("expected offline agent session to be rejected")
	}

	if err := store.Model(&db.Node{}).Where("agent_id = ?", "agent-a").Updates(map[string]interface{}{
		"status":           "Alive",
		"token":            "expired-token",
		"token_expires_at": time.Now().Add(-time.Minute),
		"token_revoked_at": nil,
	}).Error; err != nil {
		t.Fatalf("expire token: %v", err)
	}
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-a/commands", nil)
	c.Request.Header.Set("x-agent-id", "agent-a")
	c.Request.Header.Set("x-agent-token", "expired-token")
	if ok := validateAgentSession(c); ok {
		t.Fatalf("expected expired agent session to be rejected")
	}

	if err := store.Model(&db.Node{}).Where("agent_id = ?", "agent-a").Updates(map[string]interface{}{
		"token":            "revoked-token",
		"token_expires_at": time.Now().Add(time.Hour),
		"token_revoked_at": time.Now(),
	}).Error; err != nil {
		t.Fatalf("revoke token: %v", err)
	}
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/agents/agent-a/commands", nil)
	c.Request.Header.Set("x-agent-id", "agent-a")
	c.Request.Header.Set("x-agent-token", "revoked-token")
	if ok := validateAgentSession(c); ok {
		t.Fatalf("expected revoked agent session to be rejected")
	}
}

func TestRBACMiddlewareLimitsAgentInternalSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tt := range []struct {
		name string
		path string
		want int
	}{
		{name: "commands allowed", path: "/api/v1/agents/agent-a/commands", want: http.StatusOK},
		{name: "admin users blocked", path: "/api/v1/users", want: http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("tenant", "tenant-a")
				c.Set("role", agentSessionRole)
				c.Set("agent_internal", true)
				c.Next()
			})
			r.Use(RBACMiddleware())
			r.GET(tt.path, func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			r.ServeHTTP(w, req)
			if w.Code != tt.want {
				t.Fatalf("expected status %d, got %d body=%s", tt.want, w.Code, w.Body.String())
			}
		})
	}
}

func TestParseAgentSelectorRejectsNestedValues(t *testing.T) {
	if _, err := parseAgentSelector(json.RawMessage(`{"cloud":"aliyun","region":"cn-hangzhou"}`)); err != nil {
		t.Fatalf("expected flat selector to pass: %v", err)
	}
	if _, err := parseAgentSelector(json.RawMessage(`{"cloud":{"provider":"aliyun"}}`)); err == nil {
		t.Fatalf("expected nested selector to fail")
	}
}

func TestPreviewTaskSelectorUsesEffectiveTargetType(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "project-1", TenantID: "tenant-a", Status: "active"}).Error; err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := store.Create(&db.Node{
		TenantID:     "tenant-a",
		AgentID:      "agent-url",
		Status:       "Alive",
		Tags:         `{"cloud":"aliyun","target_type":"url"}`,
		Capacity:     3,
		RunningTasks: 1,
	}).Error; err != nil {
		t.Fatalf("create matching node: %v", err)
	}
	if err := store.Create(&db.Node{
		TenantID: "tenant-a",
		AgentID:  "agent-ip",
		Status:   "Alive",
		Tags:     `{"cloud":"aliyun","target_type":"ip"}`,
		Capacity: 3,
	}).Error; err != nil {
		t.Fatalf("create mismatching node: %v", err)
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("tenant", "tenant-a")
	c.Set("role", "admin")
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/tasks/preview-selector", strings.NewReader(`{
		"project_id":"project-1",
		"targets":"https://example.com",
		"config":{},
		"agent_selector":{"cloud":"aliyun"}
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	previewTaskSelector(c)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		MatchedNodes   int                 `json:"matched_nodes"`
		AvailableSlots int                 `json:"available_slots"`
		Selectors      []map[string]string `json:"effective_selectors"`
		Groups         []struct {
			TargetType     string            `json:"target_type"`
			TargetCount    int               `json:"target_count"`
			MatchedNodes   int               `json:"matched_nodes"`
			AvailableSlots int               `json:"available_slots"`
			Selector       map[string]string `json:"selector"`
			Reasons        []string          `json:"reasons"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode preview response: %v", err)
	}
	if resp.MatchedNodes != 1 || resp.AvailableSlots != 2 {
		t.Fatalf("expected one URL-capable node with two free slots, got %+v", resp)
	}
	if len(resp.Selectors) != 1 || resp.Selectors[0]["target_type"] != "url" || resp.Selectors[0]["cloud"] != "aliyun" {
		t.Fatalf("expected effective selector to include user selector and target_type=url, got %+v", resp.Selectors)
	}
	if len(resp.Groups) != 1 || resp.Groups[0].TargetType != "url" || resp.Groups[0].MatchedNodes != 1 || resp.Groups[0].AvailableSlots != 2 {
		t.Fatalf("expected grouped url preview with one node and two slots, got %+v", resp.Groups)
	}

	if err := store.Create(&db.Node{
		TenantID: "tenant-a",
		AgentID:  "agent-region",
		Status:   "Alive",
		Tags:     `{"cloud":"aliyun","target_type":"url","region":"cn-hangzhou"}`,
		Capacity: 1,
	}).Error; err != nil {
		t.Fatalf("create rules matching node: %v", err)
	}
	w = httptest.NewRecorder()
	c, _ = gin.CreateTestContext(w)
	c.Set("tenant", "tenant-a")
	c.Set("role", "admin")
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/tasks/preview-selector", strings.NewReader(`{
		"project_id":"project-1",
		"targets":"https://example.com",
		"config":{},
		"agent_selector":{"cloud":"aliyun"},
		"agent_selector_rules":{"match":{"region":["cn-hangzhou","cn-shanghai"]},"not_match":{"cloud":"tencent"}}
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	previewTaskSelector(c)
	if w.Code != http.StatusOK {
		t.Fatalf("expected rules preview status 200, got %d body=%s", w.Code, w.Body.String())
	}
	resp = struct {
		MatchedNodes   int                 `json:"matched_nodes"`
		AvailableSlots int                 `json:"available_slots"`
		Selectors      []map[string]string `json:"effective_selectors"`
		Groups         []struct {
			TargetType     string            `json:"target_type"`
			TargetCount    int               `json:"target_count"`
			MatchedNodes   int               `json:"matched_nodes"`
			AvailableSlots int               `json:"available_slots"`
			Selector       map[string]string `json:"selector"`
			Reasons        []string          `json:"reasons"`
		} `json:"groups"`
	}{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode rules preview response: %v", err)
	}
	if resp.MatchedNodes != 1 || resp.AvailableSlots != 1 {
		t.Fatalf("expected selector rules to narrow matching nodes to one free slot, got %+v", resp)
	}
}

func TestValidateTargetsReturnsValidAndInvalidEntries(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/tasks/validate-targets", strings.NewReader(`{
		"targets":"http://127.0.0.1:18080\ninvalid target",
		"config":{}
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	validateTargets(c)
	if w.Code != http.StatusOK {
		t.Fatalf("validate targets status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Valid   []string          `json:"valid"`
		Invalid []invalidTarget   `json:"invalid"`
		Summary taskTargetSummary `json:"summary"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode validate response: %v", err)
	}
	if len(resp.Valid) != 1 || resp.Valid[0] != "http://127.0.0.1:18080" || len(resp.Invalid) != 1 {
		t.Fatalf("unexpected validate response: %+v", resp)
	}
	if resp.Summary.Total != 2 || resp.Summary.URLs != 1 {
		t.Fatalf("unexpected validate summary: %+v", resp.Summary)
	}
}

func TestCreateTaskCanExplicitlySkipUnsupportedTargets(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "project-skip-targets", TenantID: "default", OwnerUserID: "1", Status: "active"}).Error; err != nil {
		t.Fatalf("create project: %v", err)
	}

	oldQueue := routerRuntime().TaskQueue
	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() {
		queue.Close()
		routerRuntime().TaskQueue = oldQueue
	})

	c, w := newTenantContextWithRole(http.MethodPost, "/tasks", "operator", "1")
	c.Request = httptest.NewRequest(http.MethodPost, "/tasks", strings.NewReader(`{
		"project_id":"project-skip-targets",
		"targets":"http://127.0.0.1:18080\ninvalid target",
		"config":{},
		"skip_unsupported":true
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	createTask(c)
	if w.Code != http.StatusOK {
		t.Fatalf("create task status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		TaskID         string          `json:"task_id"`
		SkippedTargets []invalidTarget `json:"skipped_targets"`
		BatchSummary   struct {
			TotalTargets int `json:"total_targets"`
		} `json:"batch_summary"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode create task response: %v", err)
	}
	if resp.TaskID == "" || resp.BatchSummary.TotalTargets != 1 || len(resp.SkippedTargets) != 1 || resp.SkippedTargets[0].Target != "invalid target" {
		t.Fatalf("unexpected create response: %+v", resp)
	}
}

func TestCreateTaskRejectsAllUnsupportedTargetsWhenSkipping(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "project-all-invalid", TenantID: "default", OwnerUserID: "1", Status: "active"}).Error; err != nil {
		t.Fatalf("create project: %v", err)
	}

	c, w := newTenantContextWithRole(http.MethodPost, "/tasks", "operator", "1")
	c.Request = httptest.NewRequest(http.MethodPost, "/tasks", strings.NewReader(`{
		"project_id":"project-all-invalid",
		"targets":"invalid target",
		"config":{},
		"skip_unsupported":true
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	createTask(c)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "targets is empty") {
		t.Fatalf("expected all-invalid request to fail, got %d (%s)", w.Code, w.Body.String())
	}
}

func TestCreateTaskUsesReducedURLBatchSize(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "project-url-batches", TenantID: "default", OwnerUserID: "1", Status: "active"}).Error; err != nil {
		t.Fatalf("create project: %v", err)
	}

	targets := make([]string, 51)
	for i := range targets {
		targets[i] = fmt.Sprintf("https://batch-%02d.example.test", i)
	}
	payload, err := json.Marshal(map[string]interface{}{
		"project_id": "project-url-batches",
		"targets":    strings.Join(targets, "\n"),
		"config":     map[string]interface{}{},
	})
	if err != nil {
		t.Fatalf("marshal task payload: %v", err)
	}

	oldQueue := routerRuntime().TaskQueue
	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() {
		queue.Close()
		routerRuntime().TaskQueue = oldQueue
	})

	c, w := newTenantContextWithRole(http.MethodPost, "/tasks", "operator", "1")
	c.Request = httptest.NewRequest(http.MethodPost, "/tasks", bytes.NewReader(payload))
	c.Request.Header.Set("Content-Type", "application/json")

	createTask(c)
	if w.Code != http.StatusOK {
		t.Fatalf("create task status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		TaskID       string `json:"task_id"`
		Dispatched   int    `json:"dispatched"`
		BatchSummary struct {
			TotalTargets int `json:"total_targets"`
			TotalBatches int `json:"total_batches"`
		} `json:"batch_summary"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode create task response: %v", err)
	}
	if resp.TaskID == "" || resp.Dispatched != 2 || resp.BatchSummary.TotalTargets != 51 || resp.BatchSummary.TotalBatches != 2 {
		t.Fatalf("unexpected create task response: %+v", resp)
	}
	if depth := queue.QueueDepth(context.Background())["memory"]; depth != 2 {
		t.Fatalf("queue depth = %d, want 2", depth)
	}
	var subtasks []db.SubTask
	if err := store.Where("root_task_id = ?", resp.TaskID).Order("id").Find(&subtasks).Error; err != nil {
		t.Fatalf("load subtasks: %v", err)
	}
	if len(subtasks) != 2 {
		t.Fatalf("subtask count = %d, want 2", len(subtasks))
	}
	var taskBatches []db.TaskBatch
	if err := store.Where("root_task_id = ?", resp.TaskID).Order("sequence").Find(&taskBatches).Error; err != nil {
		t.Fatalf("load task batches: %v", err)
	}
	if len(taskBatches) != 2 {
		t.Fatalf("task batch count = %d, want 2", len(taskBatches))
	}
	wantSizes := []int{50, 1}
	for i, sub := range subtasks {
		var chunk []string
		if err := json.Unmarshal([]byte(sub.ChunkTargets), &chunk); err != nil {
			t.Fatalf("decode subtask %s targets: %v", sub.ID, err)
		}
		if len(chunk) != wantSizes[i] || sub.Status != "Pending" {
			t.Fatalf("subtask %d = size:%d status:%s, want size:%d status:Pending", i, len(chunk), sub.Status, wantSizes[i])
		}
		if sub.TenantID != "default" || sub.ProjectID != "project-url-batches" || sub.ConfigVersion != 1 {
			t.Fatalf("subtask %d scope = tenant:%s project:%s", i, sub.TenantID, sub.ProjectID)
		}
		var selector map[string]string
		if err := json.Unmarshal([]byte(sub.AgentSelector), &selector); err != nil {
			t.Fatalf("decode subtask %s selector: %v", sub.ID, err)
		}
		if selector["target_type"] != "url" {
			t.Fatalf("subtask %d selector = %+v, want target_type=url", i, selector)
		}
		if sub.BatchID == "" || sub.AttemptNo != 1 || sub.ID != sub.BatchID+"-attempt-1" {
			t.Fatalf("subtask %d is not linked as attempt 1: %+v", i, sub)
		}
		batch := taskBatches[i]
		if batch.ID != sub.BatchID || batch.LatestAttemptID != sub.ID || batch.TargetCount != wantSizes[i] || batch.AttemptCount != 1 {
			t.Fatalf("batch %d does not match initial attempt: batch=%+v sub=%+v", i, batch, sub)
		}
	}
	var firstChunk, secondChunk []string
	_ = json.Unmarshal([]byte(subtasks[0].ChunkTargets), &firstChunk)
	_ = json.Unmarshal([]byte(subtasks[1].ChunkTargets), &secondChunk)
	if firstChunk[0] != targets[0] || firstChunk[49] != targets[49] || secondChunk[0] != targets[50] {
		t.Fatalf("URL order changed across batches: first=%q/%q second=%q", firstChunk[0], firstChunk[49], secondChunk[0])
	}
	var root db.RootTask
	if err := store.First(&root, "id = ?", resp.TaskID).Error; err != nil {
		t.Fatalf("load root task: %v", err)
	}
	if root.CurrentConfigVersion != 1 {
		t.Fatalf("root current config version = %d, want 1", root.CurrentConfigVersion)
	}
	var revision db.TaskConfigRevision
	if err := store.First(&revision, "root_task_id = ? AND version = ?", resp.TaskID, 1).Error; err != nil {
		t.Fatalf("load initial config revision: %v", err)
	}
	if revision.ConfigHash == "" || revision.TenantID != "default" || revision.ProjectID != "project-url-batches" {
		t.Fatalf("unexpected initial config revision: %+v", revision)
	}
}

func TestTaskConfigRevisionPreservesOldAttemptsAndAppliesToAppendedWork(t *testing.T) {
	store := setupAITestDB(t)
	project := db.Project{ID: "project-config", TenantID: "default", OwnerUserID: "1", Name: "Config project", Status: "active"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	root := db.RootTask{
		ID:                   "task-config",
		TenantID:             "default",
		ProjectID:            project.ID,
		UserID:               "1",
		Name:                 "Versioned config",
		Status:               "Running",
		Config:               `{"NoPoc":true,"WebTimeout":10}`,
		Priority:             1,
		TimeoutSec:           60,
		CurrentConfigVersion: 1,
	}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	revision := db.NewTaskConfigRevision(root, 1, `{}`, `{}`, "1", "initial")
	if err := store.Create(&revision).Error; err != nil {
		t.Fatalf("seed revision: %v", err)
	}
	oldSub := db.SubTask{
		ID: "task-config-batch-0-url", TenantID: "default", ProjectID: project.ID, RootTaskID: root.ID,
		ChunkTargets: `["https://old.example.test"]`, Status: "Finished", Config: root.Config,
		Priority: 1, TimeoutSec: 60, ConfigVersion: 1, AgentSelector: `{"target_type":"url"}`, AgentSelectorRules: `{"match":{"target_type":["url"]}}`,
	}
	if err := store.Create(&oldSub).Error; err != nil {
		t.Fatalf("seed old subtask: %v", err)
	}

	body := `{
		"config":{"NoPoc":true,"WebTimeout":15},
		"priority":2,
		"timeout_sec":120,
		"agent_selector":{"network_zone":"office"},
		"agent_selector_rules":{"not_match":{"maintenance":"true"}},
		"change_note":"tune future batches"
	}`
	ctx, recorder := newTenantContextWithRole(http.MethodPut, "/tasks/"+root.ID+"/config", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: root.ID}}
	ctx.Request = httptest.NewRequest(http.MethodPut, "/tasks/"+root.ID+"/config", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	updateTaskConfig(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("update config status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var updateResp struct {
		Unchanged bool `json:"unchanged"`
		Version   int  `json:"current_config_version"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &updateResp); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if updateResp.Unchanged || updateResp.Version != 2 {
		t.Fatalf("unexpected update response: %+v", updateResp)
	}

	if err := store.First(&root, "id = ?", root.ID).Error; err != nil {
		t.Fatalf("reload root: %v", err)
	}
	if root.CurrentConfigVersion != 2 || root.Priority != 2 || root.TimeoutSec != 120 || !strings.Contains(root.Config, `"WebTimeout":15`) {
		t.Fatalf("root current config not advanced: %+v", root)
	}
	if err := store.First(&oldSub, "id = ?", oldSub.ID).Error; err != nil {
		t.Fatalf("reload old subtask: %v", err)
	}
	if oldSub.ConfigVersion != 1 || oldSub.Priority != 1 || oldSub.TimeoutSec != 60 || !strings.Contains(oldSub.Config, `"WebTimeout":10`) {
		t.Fatalf("old attempt snapshot changed: %+v", oldSub)
	}
	var revisionCount int64
	store.Model(&db.TaskConfigRevision{}).Where("root_task_id = ?", root.ID).Count(&revisionCount)
	if revisionCount != 2 {
		t.Fatalf("revision count = %d, want 2", revisionCount)
	}
	var audit db.TaskAudit
	if err := store.First(&audit, "root_task_id = ? AND action = ?", root.ID, "config_update").Error; err != nil {
		t.Fatalf("load config audit: %v", err)
	}
	if audit.OperatorID != "1" || !strings.Contains(audit.Details, `"to_version":2`) {
		t.Fatalf("unexpected config audit: %+v", audit)
	}

	// Repeating the same desired configuration is idempotent at the revision layer.
	ctx, recorder = newTenantContextWithRole(http.MethodPut, "/tasks/"+root.ID+"/config", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: root.ID}}
	ctx.Request = httptest.NewRequest(http.MethodPut, "/tasks/"+root.ID+"/config", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	updateTaskConfig(ctx)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"unchanged":true`) {
		t.Fatalf("identical config should be unchanged, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	store.Model(&db.TaskConfigRevision{}).Where("root_task_id = ?", root.ID).Count(&revisionCount)
	if revisionCount != 2 {
		t.Fatalf("identical update created a revision, count=%d", revisionCount)
	}

	oldQueue := routerRuntime().TaskQueue
	queue := scheduler.NewTaskQueue("")
	routerRuntime().TaskQueue = queue
	t.Cleanup(func() {
		queue.Close()
		routerRuntime().TaskQueue = oldQueue
	})
	ctx, recorder = newTenantContextWithRole(http.MethodPost, "/tasks/"+root.ID+"/append", "operator", "1")
	ctx.Params = gin.Params{{Key: "id", Value: root.ID}}
	ctx.Request = httptest.NewRequest(http.MethodPost, "/tasks/"+root.ID+"/append", strings.NewReader(`{"targets":"https://new.example.test"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	appendTargets(ctx)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"config_version":2`) {
		t.Fatalf("append status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var newSub db.SubTask
	if err := store.Where("root_task_id = ? AND id <> ?", root.ID, oldSub.ID).First(&newSub).Error; err != nil {
		t.Fatalf("load appended subtask: %v", err)
	}
	if newSub.ConfigVersion != 2 || newSub.Priority != 2 || newSub.TimeoutSec != 120 || !strings.Contains(newSub.Config, `"WebTimeout":15`) {
		t.Fatalf("appended work did not use current revision: %+v", newSub)
	}
	var appendedBatch db.TaskBatch
	if err := store.First(&appendedBatch, "id = ?", newSub.BatchID).Error; err != nil {
		t.Fatalf("load appended batch: %v", err)
	}
	if appendedBatch.ConfigVersion != 2 || appendedBatch.LatestAttemptID != newSub.ID || appendedBatch.TargetCount != 1 {
		t.Fatalf("appended batch snapshot mismatch: %+v", appendedBatch)
	}
	var selector map[string]string
	if err := json.Unmarshal([]byte(newSub.AgentSelector), &selector); err != nil {
		t.Fatalf("decode appended selector: %v", err)
	}
	if selector["target_type"] != "url" || selector["network_zone"] != "office" {
		t.Fatalf("appended selector lost current revision: %+v", selector)
	}

	ctx, recorder = newTenantContextWithRole(http.MethodGet, "/tasks/"+root.ID+"/config-revisions", "viewer", "1")
	ctx.Params = gin.Params{{Key: "id", Value: root.ID}}
	getTaskConfigRevisions(ctx)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"current_config_version":2`) {
		t.Fatalf("list revisions status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestTaskConfigRevisionEnforcesProjectAndArchiveBoundaries(t *testing.T) {
	store := setupAITestDB(t)
	archivedAt := time.Now().UTC()
	projects := []db.Project{
		{ID: "project-private-config", TenantID: "default", OwnerUserID: "99", Status: "active"},
		{ID: "project-archived-config", TenantID: "default", OwnerUserID: "1", Status: "active"},
	}
	if err := store.Create(&projects).Error; err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	tasks := []db.RootTask{
		{ID: "private-config", TenantID: "default", ProjectID: projects[0].ID, Status: "Finished", Config: `{}`, CurrentConfigVersion: 1},
		{ID: "archived-config", TenantID: "default", ProjectID: projects[1].ID, Status: "Finished", Config: `{}`, CurrentConfigVersion: 1, ArchivedAt: &archivedAt},
		{ID: "other-tenant-config", TenantID: "tenant-b", ProjectID: projects[1].ID, Status: "Finished", Config: `{}`, CurrentConfigVersion: 1},
	}
	if err := store.Create(&tasks).Error; err != nil {
		t.Fatalf("seed tasks: %v", err)
	}

	for _, tc := range []struct {
		id   string
		want int
	}{
		{id: "private-config", want: http.StatusForbidden},
		{id: "archived-config", want: http.StatusConflict},
		{id: "other-tenant-config", want: http.StatusNotFound},
	} {
		ctx, recorder := newTenantContextWithRole(http.MethodPut, "/tasks/"+tc.id+"/config", "operator", "1")
		ctx.Params = gin.Params{{Key: "id", Value: tc.id}}
		ctx.Request = httptest.NewRequest(http.MethodPut, "/tasks/"+tc.id+"/config", strings.NewReader(`{"priority":2}`))
		ctx.Request.Header.Set("Content-Type", "application/json")
		updateTaskConfig(ctx)
		if recorder.Code != tc.want {
			t.Fatalf("task %s status = %d, want %d (%s)", tc.id, recorder.Code, tc.want, recorder.Body.String())
		}
	}
	var count int64
	store.Model(&db.TaskConfigRevision{}).Count(&count)
	if count != 0 {
		t.Fatalf("unauthorized or archived updates created %d revisions", count)
	}
}

func TestTaskDetailIncludesReasonStats(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "project-1", TenantID: "default", Status: "active"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	root := db.RootTask{
		ID:              "task-reasons",
		TenantID:        "default",
		ProjectID:       "project-1",
		Name:            "reason stats",
		Status:          "PartialDone",
		OriginalTargets: `["https://a","https://b","https://c"]`,
		Config:          `{}`,
		TotalChunks:     3,
		TotalTargets:    3,
	}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	subTasks := []db.SubTask{
		{ID: "sub-failed", TenantID: "default", ProjectID: "project-1", RootTaskID: root.ID, Status: "Failed", ChunkTargets: `["https://a"]`, TimeoutSec: 60},
		{ID: "sub-timeout", TenantID: "default", ProjectID: "project-1", RootTaskID: root.ID, Status: "Timeout", ChunkTargets: `["https://b","https://c"]`, TimeoutSec: 60},
	}
	if err := store.Create(&subTasks).Error; err != nil {
		t.Fatalf("seed subtasks: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/tasks/"+root.ID)
	ctx.Params = gin.Params{{Key: "id", Value: root.ID}}
	getTaskDetail(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected detail response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		ReasonStats []struct {
			Status      string `json:"status"`
			Reason      string `json:"reason"`
			Count       int    `json:"count"`
			TargetCount int    `json:"target_count"`
		} `json:"reason_stats"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode task detail: %v", err)
	}
	if len(resp.ReasonStats) != 2 {
		t.Fatalf("expected failed and timeout reason stats, got %+v", resp.ReasonStats)
	}
	if resp.ReasonStats[0].Count == 0 || resp.ReasonStats[1].TargetCount == 0 {
		t.Fatalf("expected reason stats to include batch and target counts, got %+v", resp.ReasonStats)
	}
}

func TestTaskDetailSeparatesCurrentBatchStateFromAttemptHistory(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Project{ID: "project-history", TenantID: "default", Status: "active"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	root := db.RootTask{ID: "task-history", TenantID: "default", ProjectID: "project-history", Name: "history", Status: "FINISHED", Config: `{}`}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	finished := time.Now()
	attempts := []db.SubTask{
		{ID: "batch-history-attempt-1", BatchID: "batch-history", AttemptNo: 1, Trigger: db.AttemptTriggerInitial, TenantID: "default", ProjectID: root.ProjectID, RootTaskID: root.ID, Status: "Failed", AgentID: "agent-old", FailureReason: "connection reset", ChunkTargets: `["https://one.test"]`, FinishedAt: &finished},
		{ID: "batch-history-attempt-2", BatchID: "batch-history", AttemptNo: 2, ParentAttemptID: "batch-history-attempt-1", Trigger: db.AttemptTriggerAutomaticRetry, TenantID: "default", ProjectID: root.ProjectID, RootTaskID: root.ID, Status: "Done", AgentID: "agent-new", ChunkTargets: `["https://one.test"]`, FinishedAt: &finished},
	}
	if err := store.Create(&attempts).Error; err != nil {
		t.Fatalf("seed attempts: %v", err)
	}
	if err := store.Create(&db.TaskBatch{ID: "batch-history", TenantID: "default", ProjectID: root.ProjectID, RootTaskID: root.ID, Sequence: 0, Status: "Done", Targets: `["https://one.test"]`, TargetCount: 1, CurrentAttemptNo: 2, AttemptCount: 2, LatestAttemptID: attempts[1].ID}).Error; err != nil {
		t.Fatalf("seed batch: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/tasks/"+root.ID)
	ctx.Params = gin.Params{{Key: "id", Value: root.ID}}
	getTaskDetail(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("task detail status = %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		SubTasks []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"sub_tasks"`
		Attempts []struct {
			ID              string `json:"id"`
			AgentID         string `json:"agent_id"`
			FailureReason   string `json:"failure_reason"`
			ParentAttemptID string `json:"parent_attempt_id"`
		} `json:"attempts"`
		StatusDistribution map[string]int `json:"status_distribution"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode task detail: %v", err)
	}
	if len(resp.SubTasks) != 1 || resp.SubTasks[0].ID != attempts[1].ID || resp.SubTasks[0].Status != "Done" {
		t.Fatalf("current batch view includes stale attempts: %+v", resp.SubTasks)
	}
	if len(resp.Attempts) != 2 || resp.Attempts[0].AgentID != "agent-old" || resp.Attempts[0].FailureReason != "connection reset" || resp.Attempts[1].ParentAttemptID != attempts[0].ID {
		t.Fatalf("attempt history missing execution evidence: %+v", resp.Attempts)
	}
	if resp.StatusDistribution["Done"] != 1 || resp.StatusDistribution["Failed"] != 0 {
		t.Fatalf("status distribution counted historical failures: %+v", resp.StatusDistribution)
	}
}

func TestBuildJobHelpers(t *testing.T) {
	if !isSupportedBuildTarget("linux", "arm64") || isSupportedBuildTarget("linux", "386") {
		t.Fatalf("unexpected linux build target validation")
	}
	if got := expectedBuildArtifact("windows", "amd64"); got != "argus-agent-windows-amd64.exe" {
		t.Fatalf("unexpected windows artifact name: %s", got)
	}
	if got := truncateBuildLog("abcdef", 3); got != "def" {
		t.Fatalf("unexpected truncated log: %s", got)
	}
	components, err := normalizeBuildComponents([]string{"server-ui", "argus-server", "argus-server"})
	if err != nil {
		t.Fatalf("normalize components: %v", err)
	}
	if strings.Join(components, ",") != "server-ui,argus-server" {
		t.Fatalf("unexpected normalized components: %+v", components)
	}
	artifacts := expectedBuildArtifacts([]string{"argus-agent", "server-ui"}, "linux", "amd64")
	if strings.Join(artifacts, ",") != "argus-agent-linux-amd64,server-ui-dist.tar.gz" {
		t.Fatalf("unexpected multi-component artifacts: %+v", artifacts)
	}
}

func TestCreateBuildJobIfIdleRejectsQueuedJob(t *testing.T) {
	setupAITestDB(t)

	first, err := createBuildJobIfIdle("linux", "amd64", false)
	if err != nil {
		t.Fatalf("first build job should be queued: %v", err)
	}
	if first.Status != "queued" {
		t.Fatalf("expected first job to be queued, got %q", first.Status)
	}

	if _, err := createBuildJobIfIdle("linux", "arm64", false); !errors.Is(err, errBuildAlreadyQueued) {
		t.Fatalf("expected duplicate queued job to be rejected, got %v", err)
	}
}

func TestCreateBuildJobIfIdleAllowsOnlyOneConcurrentJob(t *testing.T) {
	setupAITestDB(t)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := createBuildJobIfIdle("linux", "amd64", false)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	successes := 0
	conflicts := 0
	for err := range errs {
		if err == nil {
			successes++
			continue
		}
		if errors.Is(err, errBuildAlreadyQueued) {
			conflicts++
			continue
		}
		t.Fatalf("unexpected create error: %v", err)
	}
	if successes != 1 || conflicts != 7 {
		t.Fatalf("expected 1 success and 7 conflicts, got %d success %d conflicts", successes, conflicts)
	}
}

func TestBuildJobLogsReturnsFullLog(t *testing.T) {
	setupAITestDB(t)
	job := db.BuildJob{Platform: "linux", Arch: "amd64", Status: "failed", LogTail: "tail", LogText: "full log"}
	if err := db.DB.Create(&job).Error; err != nil {
		t.Fatalf("seed build job: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/build/jobs/1/logs")
	ctx.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(job.ID))}}
	getBuildJobLogs(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected logs response, got %d", recorder.Code)
	}
	if recorder.Body.String() != "full log" {
		t.Fatalf("expected full log, got %q", recorder.Body.String())
	}
}

func TestCancelBuildJobMarksQueuedJobCanceled(t *testing.T) {
	setupAITestDB(t)
	job, err := createBuildJobIfIdle("linux", "amd64", false)
	if err != nil {
		t.Fatalf("seed queued job: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodPost, "/build/jobs/1/cancel")
	ctx.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(job.ID))}}
	cancelBuildJob(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected cancel response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var updated db.BuildJob
	if err := db.DB.First(&updated, job.ID).Error; err != nil {
		t.Fatalf("load updated job: %v", err)
	}
	if updated.Status != "canceled" || updated.Error == "" || updated.FinishedAt == nil {
		t.Fatalf("expected canceled job with finished metadata, got %+v", updated)
	}
}

func TestRetryBuildJobCreatesNewQueuedJob(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("build job fixture is a POSIX shell script; release builds run build.sh in Linux CI")
	}
	setupAITestDB(t)
	t.Chdir(t.TempDir())
	if err := os.WriteFile("build.sh", []byte("#!/bin/sh\nmkdir -p release\ntouch release/argus-agent-linux-amd64\n"), 0o755); err != nil {
		t.Fatalf("write build script: %v", err)
	}
	oldRunner := routerRuntime().Build.runner
	routerRuntime().Build.runner = func(uint) {}
	t.Cleanup(func() { routerRuntime().Build.runner = oldRunner })
	oldJob := db.BuildJob{Platform: "linux", Arch: "amd64", Status: "failed", Error: "boom"}
	if err := db.DB.Create(&oldJob).Error; err != nil {
		t.Fatalf("seed failed build job: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodPost, "/build/jobs/1/retry")
	ctx.Params = gin.Params{{Key: "id", Value: strconv.Itoa(int(oldJob.ID))}}
	retryBuildJob(ctx)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("expected retry response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var count int64
	if err := db.DB.Model(&db.BuildJob{}).Count(&count).Error; err != nil {
		t.Fatalf("count build jobs: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected retry to create a second build job, got %d", count)
	}
}

func TestRunBuildJobStoresFullLogAndArtifact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("build job fixture is a POSIX shell script; release builds run build.sh in Linux CI")
	}
	setupAITestDB(t)
	t.Chdir(t.TempDir())
	if err := os.WriteFile("build.sh", []byte("#!/bin/sh\necho full-build-log\nmkdir -p release\ntouch release/argus-agent-linux-amd64\n"), 0o755); err != nil {
		t.Fatalf("write build script: %v", err)
	}
	job, err := createBuildJobIfIdle("linux", "amd64", false)
	if err != nil {
		t.Fatalf("seed queued job: %v", err)
	}

	runBuildJob(job.ID)

	var updated db.BuildJob
	if err := db.DB.First(&updated, job.ID).Error; err != nil {
		t.Fatalf("load updated job: %v", err)
	}
	if updated.Status != "success" || updated.Artifact != "argus-agent-linux-amd64" {
		t.Fatalf("expected successful build artifact, got %+v", updated)
	}
	if !strings.Contains(updated.LogText, "full-build-log") || !strings.Contains(updated.LogTail, "full-build-log") {
		t.Fatalf("expected full and tail logs to include build output, got log_text=%q log_tail=%q", updated.LogText, updated.LogTail)
	}
}

func TestAgentLogSummaryAndRetentionCleanup(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.AgentLog{}); err != nil {
		t.Fatalf("migrate agent logs: %v", err)
	}
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-1", Status: "Alive"}).Error; err != nil {
		t.Fatalf("seed tenant node: %v", err)
	}
	if err := store.Create(&db.Node{TenantID: "other", AgentID: "agent-2", Status: "Alive"}).Error; err != nil {
		t.Fatalf("seed other tenant node: %v", err)
	}
	oldTime := time.Now().AddDate(0, 0, -30)
	nowMs := time.Now().UnixMilli()
	logs := []db.AgentLog{
		{AgentID: "agent-1", Level: "ERROR", Message: "expired", Timestamp: oldTime.UnixMilli(), CreatedAt: oldTime},
		{AgentID: "agent-1", Level: "ERROR", Message: "recent", Timestamp: nowMs, CreatedAt: time.Now()},
		{AgentID: "agent-2", Level: "ERROR", Message: "other tenant", Timestamp: nowMs, CreatedAt: time.Now()},
	}
	if err := store.Create(&logs).Error; err != nil {
		t.Fatalf("seed logs: %v", err)
	}

	deleted, err := cleanupAgentLogsOnce(7)
	if err != nil {
		t.Fatalf("cleanup logs: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected one expired log to be deleted, got %d", deleted)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/agent-logs/summary?agent_id=agent-1")
	getAgentLogSummary(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected summary response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		LevelCounts []agentLogLevelCount `json:"level_counts"`
		RecentErrs  []db.AgentLog        `json:"recent_errors"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if len(resp.LevelCounts) != 1 || resp.LevelCounts[0].Level != "ERROR" || resp.LevelCounts[0].Count != 1 {
		t.Fatalf("expected tenant scoped ERROR count, got %+v", resp.LevelCounts)
	}
	if len(resp.RecentErrs) != 1 || resp.RecentErrs[0].AgentID != "agent-1" {
		t.Fatalf("expected tenant scoped recent errors, got %+v", resp.RecentErrs)
	}
}

func TestGetAgentLogsUsesAgentIDPrimaryKeyAndTenantScope(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.AgentLog{}); err != nil {
		t.Fatalf("migrate agent logs: %v", err)
	}
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-1", Status: "Alive"}).Error; err != nil {
		t.Fatalf("seed default node: %v", err)
	}
	if err := store.Create(&db.Node{TenantID: "other", AgentID: "agent-2", Status: "Alive"}).Error; err != nil {
		t.Fatalf("seed other tenant node: %v", err)
	}
	nowMs := time.Now().UnixMilli()
	if err := store.Create(&[]db.AgentLog{
		{AgentID: "agent-1", Level: "INFO", Message: "default tenant log", Timestamp: nowMs, CreatedAt: time.Now()},
		{AgentID: "agent-2", Level: "INFO", Message: "other tenant log", Timestamp: nowMs, CreatedAt: time.Now()},
	}).Error; err != nil {
		t.Fatalf("seed logs: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/agents/agent-1/logs?limit=10")
	ctx.Params = gin.Params{{Key: "id", Value: "agent-1"}}
	getAgentLogs(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected logs response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var logs []db.AgentLog
	if err := json.Unmarshal(recorder.Body.Bytes(), &logs); err != nil {
		t.Fatalf("decode logs: %v", err)
	}
	if len(logs) != 1 || logs[0].AgentID != "agent-1" || logs[0].Message != "default tenant log" {
		t.Fatalf("expected default tenant agent log, got %+v", logs)
	}

	ctx, recorder = newTenantContext(http.MethodGet, "/agents/missing/logs")
	ctx.Params = gin.Params{{Key: "id", Value: "missing"}}
	getAgentLogs(ctx)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected missing agent 404, got %d (%s)", recorder.Code, recorder.Body.String())
	}

	ctx, recorder = newTenantContext(http.MethodGet, "/agents/agent-2/logs")
	ctx.Params = gin.Params{{Key: "id", Value: "agent-2"}}
	getAgentLogs(ctx)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected cross-tenant agent 404, got %d (%s)", recorder.Code, recorder.Body.String())
	}
}

func TestGetAgentLogsReturnsHistoricalLogsWithoutNode(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.AgentLog{}); err != nil {
		t.Fatalf("migrate agent logs: %v", err)
	}
	nowMs := time.Now().UnixMilli()
	if err := store.Create(&db.AgentLog{
		AgentID:   "agent-history",
		Level:     "INFO",
		Message:   "historical log without node",
		Timestamp: nowMs,
		CreatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("seed historical log: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/agents/agent-history/logs?limit=10")
	ctx.Params = gin.Params{{Key: "id", Value: "agent-history"}}
	getAgentLogs(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected historical logs response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var logs []db.AgentLog
	if err := json.Unmarshal(recorder.Body.Bytes(), &logs); err != nil {
		t.Fatalf("decode logs: %v", err)
	}
	if len(logs) != 1 || logs[0].Message != "historical log without node" {
		t.Fatalf("expected historical log without node, got %+v", logs)
	}
}

func TestAgentLogSummaryIncludesHistoricalLogAgents(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.AgentLog{}); err != nil {
		t.Fatalf("migrate agent logs: %v", err)
	}
	if err := store.Create(&db.AgentLog{
		AgentID:   "agent-history",
		Level:     "INFO",
		Message:   "historical summary log",
		Timestamp: time.Now().UnixMilli(),
		CreatedAt: time.Now(),
	}).Error; err != nil {
		t.Fatalf("seed historical log: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/agent-logs/summary?agent_id=agent-history")
	getAgentLogSummary(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected summary response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		LevelCounts []agentLogLevelCount `json:"level_counts"`
		Agents      []string             `json:"agents"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if len(resp.LevelCounts) != 1 || resp.LevelCounts[0].Level != "INFO" || resp.LevelCounts[0].Count != 1 {
		t.Fatalf("expected historical INFO count, got %+v", resp.LevelCounts)
	}
	if len(resp.Agents) != 1 || resp.Agents[0] != "agent-history" {
		t.Fatalf("expected historical agent in summary, got %+v", resp.Agents)
	}
}

func TestAgentLogSummaryReturnsEmptyArraysForNodeWithoutLogs(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.AgentLog{}); err != nil {
		t.Fatalf("migrate agent logs: %v", err)
	}
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-empty", Status: "Alive"}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/agent-logs/summary?agent_id=agent-empty")
	getAgentLogSummary(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected summary response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, `"level_counts":null`) || strings.Contains(body, `"recent_errors":null`) {
		t.Fatalf("expected empty arrays instead of null arrays, got %s", body)
	}
	var resp struct {
		LevelCounts []agentLogLevelCount `json:"level_counts"`
		RecentErrs  []db.AgentLog        `json:"recent_errors"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if len(resp.LevelCounts) != 0 || len(resp.RecentErrs) != 0 {
		t.Fatalf("expected empty summary arrays, got %+v", resp)
	}
}

func TestResultEndpointsPaginateAndRespectTaskProjectTenantScope(t *testing.T) {
	store := setupAITestDB(t)
	now := time.Now()
	if err := store.Create(&[]db.Project{
		{ID: "project-1", TenantID: "default", Name: "Project 1", Status: "active"},
		{ID: "project-2", TenantID: "default", Name: "Project 2", Status: "active"},
		{ID: "project-other", TenantID: "other", Name: "Other", Status: "active"},
	}).Error; err != nil {
		t.Fatalf("seed projects: %v", err)
	}
	if err := store.Create(&db.RootTask{ID: "root-1", TenantID: "default", ProjectID: "project-1", Name: "root", Status: "Running"}).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	if err := store.Create(&db.SubTask{ID: "sub-1", TenantID: "default", ProjectID: "project-1", RootTaskID: "root-1", Status: "Done"}).Error; err != nil {
		t.Fatalf("seed sub task: %v", err)
	}
	for i := 0; i < 3; i++ {
		createdAt := now.Add(time.Duration(i) * time.Minute)
		if err := store.Create(&db.Vulnerability{
			TenantID: "default", ProjectID: "project-1", TaskID: "sub-1", RootTaskID: "root-1",
			Target: "https://target-" + strconv.Itoa(i) + ".example", Plugin: "poc-" + strconv.Itoa(i),
			Severity: "high", CreatedAt: createdAt, UpdatedAt: createdAt,
		}).Error; err != nil {
			t.Fatalf("seed vuln %d: %v", i, err)
		}
		if err := store.Create(&db.Asset{
			TenantID: "default", ProjectID: "project-1", TaskID: "sub-1", RootTaskID: "root-1",
			Target: "10.0.0." + strconv.Itoa(i+1), Protocol: "Web", Port: 80 + i,
			CreatedAt: createdAt, UpdatedAt: createdAt,
		}).Error; err != nil {
			t.Fatalf("seed asset %d: %v", i, err)
		}
		if err := store.Create(&db.FingerprintHit{
			TenantID: "default", ProjectID: "project-1", TaskID: "sub-1", RootTaskID: "root-1",
			Target: "https://fp-" + strconv.Itoa(i) + ".example", ProductName: "product-" + strconv.Itoa(i),
			RuleName: "rule-" + strconv.Itoa(i), CreatedAt: createdAt, UpdatedAt: createdAt,
		}).Error; err != nil {
			t.Fatalf("seed fingerprint %d: %v", i, err)
		}
	}
	if err := store.Create(&db.Vulnerability{
		TenantID: "default", ProjectID: "project-2", TaskID: "other-default",
		Target: "https://project-2.example", Plugin: "poc-project-2", CreatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed other project vuln: %v", err)
	}
	if err := store.Create(&db.Vulnerability{
		TenantID: "other", ProjectID: "project-other", TaskID: "other-tenant",
		Target: "https://other-tenant.example", Plugin: "poc-other", CreatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed other tenant vuln: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/vulns?project_id=project-1&task_id=root-1&page=2&page_size=2")
	getVulns(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected paged vulns, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var vulnResp struct {
		Items    []db.Vulnerability `json:"items"`
		Total    int64              `json:"total"`
		Page     int                `json:"page"`
		PageSize int                `json:"page_size"`
		HasMore  bool               `json:"has_more"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &vulnResp); err != nil {
		t.Fatalf("decode vuln response: %v", err)
	}
	if vulnResp.Total != 3 || vulnResp.Page != 2 || vulnResp.PageSize != 2 || vulnResp.HasMore || len(vulnResp.Items) != 1 {
		t.Fatalf("unexpected vuln pagination: %+v", vulnResp)
	}
	if vulnResp.Items[0].ProjectID != "project-1" || vulnResp.Items[0].TaskID != "sub-1" || vulnResp.Items[0].TenantID != "default" {
		t.Fatalf("unexpected scoped vuln item: %+v", vulnResp.Items[0])
	}

	ctx, recorder = newTenantContext(http.MethodGet, "/assets?project_id=project-1&task_id=root-1&page=1&page_size=2")
	getAssets(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected paged assets, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var assetResp struct {
		Items    []db.Asset `json:"items"`
		Total    int64      `json:"total"`
		Page     int        `json:"page"`
		PageSize int        `json:"page_size"`
		HasMore  bool       `json:"has_more"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &assetResp); err != nil {
		t.Fatalf("decode asset response: %v", err)
	}
	if assetResp.Total != 3 || assetResp.Page != 1 || assetResp.PageSize != 2 || !assetResp.HasMore || len(assetResp.Items) != 2 {
		t.Fatalf("unexpected asset pagination: %+v", assetResp)
	}

	ctx, recorder = newTenantContext(http.MethodGet, "/fingerprints?project_id=project-1&task_id=root-1&page=1&page_size=2000")
	getFingerprints(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected paged fingerprints, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var fpResp struct {
		Items    []db.FingerprintHit `json:"items"`
		Total    int64               `json:"total"`
		Page     int                 `json:"page"`
		PageSize int                 `json:"page_size"`
		HasMore  bool                `json:"has_more"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &fpResp); err != nil {
		t.Fatalf("decode fingerprint response: %v", err)
	}
	if fpResp.Total != 3 || fpResp.Page != 1 || fpResp.PageSize != 200 || fpResp.HasMore || len(fpResp.Items) != 3 {
		t.Fatalf("unexpected fingerprint pagination: %+v", fpResp)
	}
}

func TestGetFingerprintsCanGroupByProductWithAllTargets(t *testing.T) {
	store := setupAITestDB(t)
	now := time.Now()
	if err := store.Create(&db.Project{ID: "project-1", TenantID: "default", Name: "Project 1", Status: "active"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := store.Create(&db.RootTask{ID: "root-1", TenantID: "default", ProjectID: "project-1", Name: "root", Status: "Running"}).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	if err := store.Create(&db.SubTask{ID: "sub-1", TenantID: "default", ProjectID: "project-1", RootTaskID: "root-1", Status: "Done"}).Error; err != nil {
		t.Fatalf("seed sub task: %v", err)
	}
	rows := []db.FingerprintHit{
		{
			TenantID: "default", ProjectID: "project-1", TaskID: "sub-1", RootTaskID: "root-1",
			Target: "https://a.example", ProductName: "nginx", RuleName: "rule-a",
			Evidence: `{"title":"A"}`, CreatedAt: now, UpdatedAt: now.Add(time.Minute),
		},
		{
			TenantID: "default", ProjectID: "project-1", TaskID: "sub-1", RootTaskID: "root-1",
			Target: "https://b.example", ProductName: "nginx", RuleName: "rule-b",
			Evidence: `{"title":"B"}`, CreatedAt: now.Add(2 * time.Minute), UpdatedAt: now.Add(3 * time.Minute),
		},
		{
			TenantID: "default", ProjectID: "project-1", TaskID: "sub-1", RootTaskID: "root-1",
			Target: "https://tomcat.example", ProductName: "tomcat", RuleName: "rule-c",
			CreatedAt: now, UpdatedAt: now,
		},
	}
	if err := store.Create(&rows).Error; err != nil {
		t.Fatalf("seed fingerprint hits: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/fingerprints?project_id=project-1&task_id=root-1&group_by=product&page=1&page_size=1")
	getFingerprints(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected grouped fingerprints response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Items []struct {
			ProductName string `json:"ProductName"`
			TargetCount int64  `json:"TargetCount"`
			Targets     []struct {
				Target   string `json:"Target"`
				RuleName string `json:"RuleName"`
			} `json:"Targets"`
		} `json:"items"`
		Total    int64 `json:"total"`
		Page     int   `json:"page"`
		PageSize int   `json:"page_size"`
		HasMore  bool  `json:"has_more"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode grouped fingerprints response: %v; body=%s", err, recorder.Body.String())
	}
	if resp.Total != 2 || resp.Page != 1 || resp.PageSize != 1 || !resp.HasMore || len(resp.Items) != 1 {
		t.Fatalf("unexpected grouped pagination metadata: %+v", resp)
	}
	if resp.Items[0].ProductName != "nginx" || resp.Items[0].TargetCount != 2 || len(resp.Items[0].Targets) != 2 {
		t.Fatalf("expected nginx group with both targets, got %+v", resp.Items[0])
	}
	if resp.Items[0].Targets[0].Target != "https://a.example" || resp.Items[0].Targets[1].Target != "https://b.example" {
		t.Fatalf("unexpected grouped targets: %+v", resp.Items[0].Targets)
	}
}

func TestGetFingerprintsGroupsSearchAndMarkDirectorySource(t *testing.T) {
	store := setupAITestDB(t)
	now := time.Now()
	if err := store.Create(&db.Project{ID: "project-1", TenantID: "default", Name: "Project 1", Status: "active"}).Error; err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := store.Create(&db.RootTask{ID: "root-1", TenantID: "default", ProjectID: "project-1", Name: "root", Status: "Running"}).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	if err := store.Create(&db.SubTask{ID: "sub-1", TenantID: "default", ProjectID: "project-1", RootTaskID: "root-1", Status: "Done"}).Error; err != nil {
		t.Fatalf("seed sub task: %v", err)
	}
	rows := []db.FingerprintHit{
		{
			TenantID: "default", ProjectID: "project-1", TaskID: "sub-1", RootTaskID: "root-1",
			Target: "https://jenkins.example:443", ProductName: "Jenkins", RuleName: "Active-Finger",
			Evidence:  `{"type":"Active-Finger","uri":"https://jenkins.example/jenkins/login","finger":["Jenkins"]}`,
			CreatedAt: now, UpdatedAt: now,
		},
		{
			TenantID: "default", ProjectID: "project-1", TaskID: "sub-1", RootTaskID: "root-1",
			Target: "https://nginx.example:443", ProductName: "nginx", RuleName: "Finger",
			Evidence:  `{"type":"Finger","uri":"https://nginx.example/","finger":["nginx"]}`,
			CreatedAt: now, UpdatedAt: now,
		},
		{
			TenantID: "default", ProjectID: "project-1", TaskID: "sub-1", RootTaskID: "root-1",
			Target: "https://shiro.example:8080", ProductName: "APACHE-Shiro", RuleName: "behavior-probe",
			Evidence:  `{"type":"Active-Finger","uri":"https://shiro.example:8080","am":"[behavior-probe:shiro-detect]"}`,
			CreatedAt: now, UpdatedAt: now,
		},
	}
	if err := store.Create(&rows).Error; err != nil {
		t.Fatalf("seed fingerprint hits: %v", err)
	}

	ctx, recorder := newTenantContext(http.MethodGet, "/fingerprints?project_id=project-1&task_id=root-1&group_by=product&search=jenkins")
	getFingerprints(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected search response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var searchResp struct {
		Items []struct {
			ProductName  string   `json:"ProductName"`
			Sources      []string `json:"Sources"`
			SourceLabels []string `json:"SourceLabels"`
			Targets      []struct {
				Target      string `json:"Target"`
				MatchedURL  string `json:"MatchedURL"`
				Source      string `json:"Source"`
				SourceLabel string `json:"SourceLabel"`
			} `json:"Targets"`
		} `json:"items"`
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &searchResp); err != nil {
		t.Fatalf("decode search response: %v; body=%s", err, recorder.Body.String())
	}
	if searchResp.Total != 1 || len(searchResp.Items) != 1 || searchResp.Items[0].ProductName != "Jenkins" {
		t.Fatalf("expected Jenkins search hit, got %+v", searchResp)
	}
	if len(searchResp.Items[0].Sources) != 1 || searchResp.Items[0].Sources[0] != db.FingerprintSourceDirectory {
		t.Fatalf("expected directory source on Jenkins group, got %+v", searchResp.Items[0])
	}
	if searchResp.Items[0].SourceLabels[0] != "主动指纹（目录扫描）" {
		t.Fatalf("expected directory source label, got %+v", searchResp.Items[0].SourceLabels)
	}
	if searchResp.Items[0].Targets[0].MatchedURL != "https://jenkins.example/jenkins/login" || searchResp.Items[0].Targets[0].Source != db.FingerprintSourceDirectory {
		t.Fatalf("expected directory target metadata, got %+v", searchResp.Items[0].Targets[0])
	}

	ctx, recorder = newTenantContext(http.MethodGet, "/fingerprints?project_id=project-1&task_id=root-1&group_by=product&source=directory")
	getFingerprints(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected source filter response, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &searchResp); err != nil {
		t.Fatalf("decode source filter response: %v; body=%s", err, recorder.Body.String())
	}
	if searchResp.Total != 1 || len(searchResp.Items) != 1 || searchResp.Items[0].ProductName != "Jenkins" {
		t.Fatalf("expected only directory fingerprints, got %+v", searchResp)
	}
}

func TestCopilotProfileAndContextCompaction(t *testing.T) {
	profile := resolveCopilotProfile("poc_inline")
	if profile.MaxTurns <= 4 || len(profile.Tools) != 4 {
		t.Fatalf("expected poc profile to enable 4 focused tools (incl node_capacity), got %+v", profile)
	}
	if !strings.Contains(profile.SystemPrompt, "POC 编辑模式") {
		t.Fatalf("expected poc profile to load prompt section from registry, got %s", profile.SystemPrompt)
	}
	expBuilderProfile := resolveCopilotProfile("exp_builder")
	if expBuilderProfile.MaxTurns <= 4 {
		t.Fatalf("expected exp_builder profile to allow extended turns, got %+v", expBuilderProfile)
	}
	if !strings.Contains(expBuilderProfile.SystemPrompt, "Yaksha EXP 生成模式") || !strings.Contains(expBuilderProfile.SystemPrompt, "fenced yak") || !strings.Contains(expBuilderProfile.SystemPrompt, "main.yak") || !strings.Contains(expBuilderProfile.SystemPrompt, "cli.String") || !strings.Contains(expBuilderProfile.SystemPrompt, "cli.check()") {
		t.Fatalf("expected exp_builder prompt to enforce complete Yaklang output, got %s", expBuilderProfile.SystemPrompt)
	}
	if strings.Contains(expBuilderProfile.SystemPrompt, "cli.App") || strings.Contains(expBuilderProfile.SystemPrompt, "cli.Get") {
		t.Fatalf("exp_builder prompt contains unsupported Yaksha CLI APIs: %s", expBuilderProfile.SystemPrompt)
	}

	compact := compactPageContext(map[string]interface{}{
		"module":    "poc_inline",
		"api_key":   "secret",
		"raw_data":  map[string]interface{}{"authorization": "Bearer token"},
		"long_text": strings.Repeat("x", 7000),
	})
	if compact["api_key"] != "[redacted]" {
		t.Fatalf("expected api_key redaction, got %+v", compact["api_key"])
	}
	raw, ok := compact["raw_data"].(map[string]interface{})
	if !ok || raw["authorization"] != "[redacted]" {
		t.Fatalf("expected nested authorization redaction, got %+v", compact["raw_data"])
	}
	if got, ok := compact["long_text"].(string); !ok || len(got) >= 7000 {
		t.Fatalf("expected long text truncation")
	}
}

func TestCopilotPromptRegistryEndpoint(t *testing.T) {
	registry, err := loadCopilotPromptRegistry()
	if err != nil {
		t.Fatalf("load copilot prompt registry: %v", err)
	}
	if registry.Version == 0 || registry.Base == "" {
		t.Fatalf("expected embedded copilot prompt registry to include version and base prompt")
	}
	if registry.aliasByID["poc_inline"] != "poc_list" {
		t.Fatalf("expected poc_inline alias to resolve to poc_list, got %q", registry.aliasByID["poc_inline"])
	}

	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/ai/copilot/prompts", nil)

	getCopilotPromptProfiles(c)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}

	var resp copilotPromptRegistryResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode copilot prompt registry response: %v", err)
	}
	if resp.Source != "server/internal/api/prompts/copilot_profiles.yaml" {
		t.Fatalf("expected registry source to be exposed, got %q", resp.Source)
	}
	if len(resp.Profiles) == 0 || resp.Default.SystemPrompt == "" {
		t.Fatalf("expected prompt registry response to include profiles and default prompt: %+v", resp)
	}
	foundExpBuilder := false
	for _, profile := range resp.Profiles {
		if profile.Module == "exp_builder" {
			foundExpBuilder = true
			break
		}
	}
	if !foundExpBuilder {
		t.Fatalf("expected prompt registry response to include exp_builder profile: %+v", resp.Profiles)
	}
	foundExpAction := false
	for _, action := range resp.Actions {
		if action.ActionType == "create_exp_draft" {
			foundExpAction = action.RiskLevel == "low" && action.RequiredRole == "operator" && len(action.Params) == 3
			break
		}
	}
	if !foundExpAction {
		t.Fatalf("expected prompt registry response to include create_exp_draft action, got %+v", resp.Actions)
	}
}

func TestCopilotLayeredContextCompactionAndInjection(t *testing.T) {
	pageContext := map[string]interface{}{
		"_identity": map[string]interface{}{
			"tenant_id": "t1",
			"username":  "alice",
			"api_key":   "should-not-leak",
		},
		"_focus": map[string]interface{}{
			"module":         "task_results",
			"route":          "/tasks/t1/results",
			"entity_type":    "vuln",
			"entity_summary": "high nuclei hit",
		},
		"data": map[string]interface{}{
			"selected_vuln": map[string]interface{}{
				"plugin":   "test-poc",
				"response": strings.Repeat("x", 7000),
			},
			"authorization": "Bearer should-not-leak",
		},
		"_ambient": map[string]interface{}{
			"queue": map[string]interface{}{"total_depth": 3},
		},
	}

	compact := compactPageContext(pageContext)
	if got := resolveCopilotModule(compact); got != "task_results" {
		t.Fatalf("expected layered _focus module, got %q", got)
	}
	identity, ok := compact["_identity"].(map[string]interface{})
	if !ok || identity["api_key"] != "[redacted]" {
		t.Fatalf("expected identity secrets to be redacted, got %+v", compact["_identity"])
	}
	data, ok := compact["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected compacted data layer, got %+v", compact["data"])
	}
	if data["authorization"] != "[redacted]" {
		t.Fatalf("expected data authorization to be redacted, got %+v", data["authorization"])
	}
	selected, ok := data["selected_vuln"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected selected_vuln map, got %+v", data["selected_vuln"])
	}
	if got, ok := selected["response"].(string); !ok || len(got) >= 7000 {
		t.Fatalf("expected nested response truncation, got len=%d", len(got))
	}

	messages := []aipkg.ChatMessage{}
	injectCopilotContext(&messages, compact)
	if len(messages) != 4 {
		t.Fatalf("expected identity/focus/data/ambient system messages, got %d", len(messages))
	}
	joined := messages[0].Content + messages[1].Content + messages[2].Content + messages[3].Content
	for _, want := range []string{"【用户身份】", "【页面焦点】", "【页面数据】", "【全局态势】", "test-poc"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected injected context to contain %q, got %s", want, joined)
		}
	}
	if strings.Contains(joined, "should-not-leak") {
		t.Fatalf("sensitive context leaked into injected messages: %s", joined)
	}
}

func TestCopilotProfileNodeCapacityGlobal(t *testing.T) {
	// node_capacity should be available in ALL profiles
	modules := []string{"global", "poc_list", "poc_inline", "exp_list", "exploit_list", "exp_builder", "task_list", "task_results", "node_list", "asset_list", "workflow_list", "fingerprint_list", "dir_list", "dict_list", "dashboard", "unknown_module"}
	for _, mod := range modules {
		profile := resolveCopilotProfile(mod)
		found := false
		for _, tool := range profile.Tools {
			if tool == "node_capacity" {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("module %q should include node_capacity tool, got tools: %v", mod, profile.Tools)
		}
	}
}

func TestIsAgentInternalEndpoint(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{name: "agent commands is internal", method: "GET", path: "/api/v1/agents/a1/commands", want: true},
		{name: "manifest is internal", method: "GET", path: "/api/v1/arsenals/manifest", want: true},
		{name: "arsenal db is internal", method: "GET", path: "/api/v1/arsenals/db", want: true},
		{name: "arsenal db hash is internal", method: "GET", path: "/api/v1/arsenals/db/hash", want: true},
		{name: "arsenal db stats is internal", method: "GET", path: "/api/v1/arsenals/db/stats", want: true},
		{name: "workflow page arsenal list is NOT internal", method: "GET", path: "/api/v1/arsenals/poc", want: false},
		{name: "non GET should not be internal", method: "POST", path: "/api/v1/arsenals/db", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(tt.method, tt.path, nil)
			if got := isAgentInternalEndpoint(c); got != tt.want {
				t.Fatalf("%s %s expected %v, got %v", tt.method, tt.path, tt.want, got)
			}
		})
	}
}
