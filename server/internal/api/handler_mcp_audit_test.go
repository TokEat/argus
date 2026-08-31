package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	argusmcp "github.com/P0lar1ght/argus/mcp"
	"github.com/P0lar1ght/argus/server/internal/db"
)

func TestRecordMCPToolInvocationPersistsRedactedArgs(t *testing.T) {
	store := setupAITestDB(t)
	recordMCPToolInvocation(mcpHTTPToolAuditor{
		tenantID: "default",
		userID:   "u1",
		role:     "operator",
		clientID: "cursor",
	}, argusmcp.ToolCallRecord{
		ToolName: "argus_debug_behavior_probe",
		Args: map[string]interface{}{
			"agent_id":   "agent-1",
			"target_url": "http://authorized.example/",
			"content":    "id: probe\n",
			"cookie":     "session=abc",
		},
		Duration: 12 * time.Millisecond,
	})

	var row db.MCPToolInvocation
	if err := store.Where("tool_name = ?", "argus_debug_behavior_probe").First(&row).Error; err != nil {
		t.Fatalf("expected invocation row: %v", err)
	}
	if row.TenantID != "default" || row.UserID != "u1" || row.ClientID != "cursor" || row.AgentID != "agent-1" {
		t.Fatalf("unexpected identity fields: %+v", row)
	}
	if row.Status != "ok" || row.Target != "http://authorized.example/" {
		t.Fatalf("unexpected status/target: %+v", row)
	}
	if !strings.Contains(row.Args, "id: probe") || !strings.Contains(row.Args, `"cookie":"[redacted]"`) {
		t.Fatalf("expected redacted full args, got %s", row.Args)
	}
}

func TestHelpAndInspectAreNotPersisted(t *testing.T) {
	store := setupAITestDB(t)
	recordMCPToolInvocation(mcpHTTPToolAuditor{tenantID: "default", userID: "u1", clientID: "cursor"}, argusmcp.ToolCallRecord{
		ToolName: "argus_help",
		Args:     map[string]interface{}{"action": "help"},
	})
	recordMCPToolInvocation(mcpHTTPToolAuditor{tenantID: "default", userID: "u1", clientID: "cursor"}, argusmcp.ToolCallRecord{
		ToolName: "argus_yaksha_exp",
		Args:     map[string]interface{}{"action": "inspect"},
	})
	var count int64
	if err := store.Model(&db.MCPToolInvocation{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected no rows for help/inspect, got %d", count)
	}
}

func TestMCPAdminListInvocationsIsTenantScoped(t *testing.T) {
	store := setupAITestDB(t)
	now := time.Now()
	if err := store.Create([]db.MCPToolInvocation{
		{ID: "inv-1", TenantID: "default", UserID: "u1", ClientID: "cursor", ToolName: "argus_scan_create", Status: "ok", Args: `{"plan_hash":"a"}`, CreatedAt: now},
		{ID: "inv-2", TenantID: "other", UserID: "u9", ClientID: "cursor", ToolName: "argus_scan_create", Status: "ok", Args: `{"plan_hash":"b"}`, CreatedAt: now},
	}).Error; err != nil {
		t.Fatalf("seed invocations: %v", err)
	}

	recorder := callMCPAdminJSON(t, http.MethodGet, "/mcp/admin/invocations", "default", "admin", "9", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("list invocations status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Total int `json:"total"`
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if body.Total != 1 || len(body.Items) != 1 || body.Items[0].ID != "inv-1" {
		t.Fatalf("expected only default tenant row, got %+v body=%s", body, recorder.Body.String())
	}
}
