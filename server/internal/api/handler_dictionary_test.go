package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-server/internal/db"
	grpcpkg "github.com/user/dddd-server/internal/grpc"
	"google.golang.org/grpc/metadata"
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

func TestGetAgentAPIConfigReturnsApprovedYAML(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "apiconfig", "api-config.yaml"),
		TenantID: "default",
		Type:     "apiconfig",
		FileName: "api-config.yaml",
		Content:  "quake:\n  - secret-key\n",
		Hash:     "api-config-hash",
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed api config: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/agents/config/api-keys", "admin", "agent-1")
	ctx.Request = httptest.NewRequest(http.MethodGet, "/agents/config/api-keys", nil)
	getAgentAPIConfig(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected agent api config 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	if recorder.Body.String() != "quake:\n  - secret-key\n" {
		t.Fatalf("unexpected api config body: %q", recorder.Body.String())
	}
}

func TestSaveAPIKeysConfigDoesNotBumpRuleVersionAndBroadcastsAPIConfig(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.SystemConfig{Key: "rule_version", Value: "v-stable"}).Error; err != nil {
		t.Fatalf("seed rule version: %v", err)
	}

	oldHub := notifyHub
	hub := grpcpkg.NewNotifyHub()
	stream := &fakeAPIConfigNotifyStream{sentCh: make(chan string, 1)}
	hub.Register("agent-1", stream, 1, nil)
	notifyHub = hub
	t.Cleanup(func() { notifyHub = oldHub })

	ctx, recorder := newTenantContextWithRole(http.MethodPut, "/config/api-keys", "admin", "9")
	ctx.Request = httptest.NewRequest(http.MethodPut, "/config/api-keys", strings.NewReader(`[{"provider":"quake","keys":["active-key"]}]`))
	saveApiKeysConfig(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected save API keys 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	var arsenal db.Arsenal
	if err := store.First(&arsenal, "tenant_id = ? AND type = ? AND file_name = ?", "default", "apiconfig", "api-config.yaml").Error; err != nil {
		t.Fatalf("expected apiconfig arsenal: %v", err)
	}
	if !strings.Contains(arsenal.Content, "active-key") || arsenal.Hash == "" {
		t.Fatalf("unexpected apiconfig content/hash: content=%q hash=%q", arsenal.Content, arsenal.Hash)
	}
	var cfg db.SystemConfig
	if err := store.First(&cfg, "key = ?", "rule_version").Error; err != nil {
		t.Fatalf("load rule version: %v", err)
	}
	if cfg.Value != "v-stable" {
		t.Fatalf("save api-config should not bump rule_version, got %q", cfg.Value)
	}
	select {
	case got := <-stream.sentCh:
		if got != "api_config_updated" {
			t.Fatalf("notify type = %q, want api_config_updated", got)
		}
	default:
		t.Fatalf("expected api_config_updated notification")
	}
}

func TestSaveAPIKeysConfigBroadcastsOnlyCurrentTenant(t *testing.T) {
	setupAITestDB(t)

	oldHub := notifyHub
	hub := grpcpkg.NewNotifyHub()
	tenantAStream := &fakeAPIConfigNotifyStream{sentCh: make(chan string, 1)}
	tenantBStream := &fakeAPIConfigNotifyStream{sentCh: make(chan string, 1)}
	hub.Register("agent-a", tenantAStream, 1, map[string]string{"tenant_id": "tenant-a"})
	hub.Register("agent-b", tenantBStream, 1, map[string]string{"tenant_id": "tenant-b"})
	notifyHub = hub
	t.Cleanup(func() { notifyHub = oldHub })

	ctx, recorder := newTenantContextWithRole(http.MethodPut, "/config/api-keys", "admin", "9")
	ctx.Set("tenant", "tenant-a")
	ctx.Request = httptest.NewRequest(http.MethodPut, "/config/api-keys", strings.NewReader(`[{"provider":"quake","keys":["tenant-a-key"]}]`))
	saveApiKeysConfig(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected save API keys 200, got %d (%s)", recorder.Code, recorder.Body.String())
	}
	select {
	case got := <-tenantAStream.sentCh:
		if got != "api_config_updated" {
			t.Fatalf("tenant-a notify type = %q, want api_config_updated", got)
		}
	default:
		t.Fatalf("expected tenant-a agent to receive api_config_updated")
	}
	select {
	case got := <-tenantBStream.sentCh:
		t.Fatalf("tenant-b agent should not receive tenant-a update, got %q", got)
	default:
	}
}

type fakeAPIConfigNotifyStream struct {
	sentCh chan string
}

func (s *fakeAPIConfigNotifyStream) Send(msg *pb.TaskNotify) error {
	if s.sentCh != nil {
		s.sentCh <- msg.NotifyType
	}
	return nil
}

func (s *fakeAPIConfigNotifyStream) Recv() (*pb.AgentSignal, error) { return nil, io.EOF }
func (s *fakeAPIConfigNotifyStream) SetHeader(metadata.MD) error    { return nil }
func (s *fakeAPIConfigNotifyStream) SendHeader(metadata.MD) error   { return nil }
func (s *fakeAPIConfigNotifyStream) SetTrailer(metadata.MD)         {}
func (s *fakeAPIConfigNotifyStream) Context() context.Context       { return context.Background() }
func (s *fakeAPIConfigNotifyStream) SendMsg(interface{}) error      { return nil }
func (s *fakeAPIConfigNotifyStream) RecvMsg(interface{}) error      { return io.EOF }

func TestFingerprintDictMergesMaterializedRules(t *testing.T) {
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
	if err := store.Create(&db.FingerprintRule{
		TenantID:    "default",
		ProductName: "StructuredProduct",
		RuleExpr:    `body="structured"`,
		Category:    "web",
		State:       "Approved",
		Enabled:     true,
	}).Error; err != nil {
		t.Fatalf("seed structured fingerprint rule: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/dictionaries/fingerprint", "operator", "9")
	ctx.Request = httptest.NewRequest(http.MethodGet, "/dictionaries/fingerprint", nil)
	getFingerprintDict(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("fingerprint dict response = %d %q, want 200", recorder.Code, recorder.Body.String())
	}
	var resp []FingerprintItem
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode fingerprint response: %v", err)
	}
	if len(resp) != 1 || resp[0].Product != "StructuredProduct" || len(resp[0].Rules) != 1 || resp[0].Rules[0] != `body="structured"` {
		t.Fatalf("expected materialized fingerprint rule in full dictionary, got %+v", resp)
	}
}

func TestWorkflowDictLiteUsesSummaryPagination(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.WorkflowProductSummary{}); err != nil {
		t.Fatalf("automigrate summary: %v", err)
	}
	if err := store.Create(&db.WorkflowProductSummary{
		TenantID:             "default",
		ProductName:          "DemoProduct",
		MatchTypes:           `["root"]`,
		PocNames:             `["demo-poc"]`,
		PocCount:             1,
		MissingPocNames:      `[]`,
		MissingPocCount:      0,
		FingerprintBound:     true,
		FingerprintRuleCount: 2,
		State:                "Approved",
		Enabled:              true,
		Version:              3,
	}).Error; err != nil {
		t.Fatalf("seed summary: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/dictionaries/workflow?lite=1&page=1&page_size=1&q=demo", "operator", "9")
	getWorkflowDict(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("workflow lite status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Items []workflowSummaryResponse `json:"items"`
		Total int64                     `json:"total"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Total != 1 || len(resp.Items) != 1 || resp.Items[0].Product != "DemoProduct" || !resp.Items[0].FingerprintBound {
		t.Fatalf("unexpected workflow lite response: %+v", resp)
	}
}

func TestWorkflowDictLiteStatsUseAllMatchingRows(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.WorkflowProductSummary{}); err != nil {
		t.Fatalf("automigrate summary: %v", err)
	}
	rows := []db.WorkflowProductSummary{
		{
			TenantID:             "default",
			ProductName:          "Alpha",
			MatchTypes:           `["root"]`,
			PocNames:             `["alpha-a","alpha-b"]`,
			PocCount:             2,
			MissingPocNames:      `[]`,
			MissingPocCount:      0,
			FingerprintBound:     true,
			FingerprintRuleCount: 4,
			State:                "Approved",
			Enabled:              true,
		},
		{
			TenantID:             "default",
			ProductName:          "Beta",
			MatchTypes:           `["root"]`,
			PocNames:             `["beta-a","beta-b","beta-c"]`,
			PocCount:             3,
			MissingPocNames:      `["beta-c"]`,
			MissingPocCount:      1,
			FingerprintBound:     false,
			FingerprintRuleCount: 0,
			State:                "Approved",
			Enabled:              true,
		},
		{
			TenantID:             "default",
			ProductName:          "Gamma",
			MatchTypes:           `["base"]`,
			PocNames:             `["gamma-a"]`,
			PocCount:             1,
			MissingPocNames:      `["gamma-a"]`,
			MissingPocCount:      1,
			FingerprintBound:     false,
			FingerprintRuleCount: 0,
			State:                "Approved",
			Enabled:              true,
		},
	}
	if err := store.Create(&rows).Error; err != nil {
		t.Fatalf("seed summaries: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/dictionaries/workflow?lite=1&page=1&page_size=1&scope=specific", "operator", "9")
	getWorkflowDict(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("workflow lite status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Items []workflowSummaryResponse    `json:"items"`
		Total int64                        `json:"total"`
		Stats workflowSummaryStatsResponse `json:"stats"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Items) != 1 || resp.Total != 3 {
		t.Fatalf("expected first page of 3 matching rows, got %+v", resp)
	}
	if resp.Stats.Total != 3 || resp.Stats.FingerprintMissing != 2 || resp.Stats.POCMissing != 2 || resp.Stats.TotalPOCs != 6 || resp.Stats.FingerprintRules != 4 {
		t.Fatalf("expected all-row workflow stats, got %+v", resp.Stats)
	}
}

func TestGetArsenalReturnsSingleContent(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.Create(&db.Arsenal{
		ID:       db.BuildTenantArsenalID("default", "poc", "demo.yaml"),
		TenantID: "default",
		Type:     "poc",
		FileName: "demo.yaml",
		Content:  "id: demo\n",
		Hash:     "hash",
		State:    "Draft",
		Version:  2,
	}).Error; err != nil {
		t.Fatalf("seed arsenal: %v", err)
	}

	ctx, recorder := newTenantContextWithRole(http.MethodGet, "/arsenals/poc/demo.yaml", "operator", "9")
	ctx.Params = gin.Params{{Key: "type", Value: "poc"}, {Key: "filename", Value: "demo.yaml"}}
	getArsenal(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("get arsenal status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp db.Arsenal
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode arsenal: %v", err)
	}
	if resp.Content != "id: demo\n" || resp.FileName != "demo.yaml" {
		t.Fatalf("unexpected arsenal: %+v", resp)
	}
}
