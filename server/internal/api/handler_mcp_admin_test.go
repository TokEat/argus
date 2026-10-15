package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	argusmcp "github.com/P0lar1ght/argus/mcp"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

func callMCPAdminJSON(t *testing.T, method, path, tenant, role, userID string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	ctx, recorder := newTenantContextWithRole(method, path, role, userID)
	ctx.Set("tenant", tenant)
	if reader != nil {
		ctx.Request = httptest.NewRequest(method, path, reader)
		ctx.Request.Header.Set("Content-Type", "application/json")
		ctx.Set("tenant", tenant)
		ctx.Set("role", role)
		ctx.Set("user_id", userID)
	}
	if strings.Contains(path, "/clients/") {
		parts := strings.Split(path, "/")
		for i, part := range parts {
			if part == "clients" && i+1 < len(parts) {
				ctx.Params = gin.Params{{Key: "id", Value: parts[i+1]}}
				break
			}
		}
	}
	switch {
	case method == http.MethodGet && strings.HasSuffix(path, "/status"):
		mcpAdminGetStatus(ctx)
	case method == http.MethodPut && strings.HasSuffix(path, "/status"):
		mcpAdminPutStatus(ctx)
	case method == http.MethodGet && strings.HasSuffix(path, "/clients"):
		mcpAdminListClients(ctx)
	case strings.HasSuffix(path, "/revoke") && strings.Contains(path, "/clients/"):
		mcpAdminRevokeClient(ctx)
	case strings.HasSuffix(path, "/disable"):
		mcpAdminDisableClient(ctx)
	case strings.HasSuffix(path, "/enable"):
		mcpAdminEnableClient(ctx)
	case method == http.MethodDelete && strings.Contains(path, "/clients/"):
		mcpAdminDeleteClient(ctx)
	case method == http.MethodGet && strings.HasSuffix(path, "/sessions"):
		mcpAdminListSessions(ctx)
	case method == http.MethodPost && strings.HasSuffix(path, "/sessions/revoke"):
		mcpAdminRevokeSessions(ctx)
	case method == http.MethodGet && strings.HasSuffix(path, "/invocations"):
		mcpAdminListInvocations(ctx)
	case method == http.MethodGet && strings.Contains(path, "/admin/events"):
		mcpAdminListEvents(ctx)
	case method == http.MethodGet && strings.HasSuffix(path, "/admin/tools"):
		mcpAdminListTools(ctx)
	default:
		t.Fatalf("unhandled test path %s %s", method, path)
	}
	return recorder
}

func TestMCPAdminStatusDisableRevokesTenantSessionsOnly(t *testing.T) {
	setupAITestDB(t)
	_ = ensureBuiltinOAuthClients()
	now := time.Now()
	if err := db.DB.Create(&db.OAuthRefreshToken{
		TokenHash: "aaaa",
		ClientID:  "cursor",
		UserID:    "1",
		TenantID:  "default",
		Role:      "operator",
		Resource:  "http://example/mcp",
		ExpiresAt: now.Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Create(&db.OAuthRefreshToken{
		TokenHash: "bbbb",
		ClientID:  "cursor",
		UserID:    "2",
		TenantID:  "other",
		Role:      "operator",
		Resource:  "http://example/mcp",
		ExpiresAt: now.Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}

	denied := callMCPAdminJSON(t, http.MethodPut, "/mcp/admin/status", "default", "admin", "9", map[string]any{"enabled": false})
	if denied.Code != http.StatusBadRequest {
		t.Fatalf("disable without confirm: %d %s", denied.Code, denied.Body.String())
	}

	recorder := callMCPAdminJSON(t, http.MethodPut, "/mcp/admin/status", "default", "admin", "9", map[string]any{"enabled": false, "confirm": true})
	if recorder.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", recorder.Code, recorder.Body.String())
	}
	if tenantMCPEnabled("default") {
		t.Fatal("default tenant should be disabled")
	}
	if !tenantMCPEnabled("other") {
		t.Fatal("other tenant must stay enabled")
	}

	var defaultRow, otherRow db.OAuthRefreshToken
	if err := db.DB.Where("token_hash = ?", "aaaa").First(&defaultRow).Error; err != nil || defaultRow.RevokedAt == nil {
		t.Fatalf("default session should be revoked: %+v err=%v", defaultRow, err)
	}
	if err := db.DB.Where("token_hash = ?", "bbbb").First(&otherRow).Error; err != nil || otherRow.RevokedAt != nil {
		t.Fatalf("other tenant session must remain: %+v err=%v", otherRow, err)
	}

	status := callMCPAdminJSON(t, http.MethodGet, "/mcp/admin/status", "default", "admin", "9", nil)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"enabled":false`) {
		t.Fatalf("status after disable: %s", status.Body.String())
	}
}

func TestMCPAdminCannotDeleteCursorClient(t *testing.T) {
	setupAITestDB(t)
	_ = ensureBuiltinOAuthClients()
	recorder := callMCPAdminJSON(t, http.MethodDelete, "/mcp/admin/clients/cursor", "default", "admin", "9", map[string]any{"confirm": true})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "cannot be deleted") {
		t.Fatalf("delete cursor: %d %s", recorder.Code, recorder.Body.String())
	}
	var count int64
	db.DB.Model(&db.OAuthClient{}).Where("client_id = ?", "cursor").Count(&count)
	if count != 1 {
		t.Fatalf("cursor client must remain, count=%d", count)
	}
}

func TestMCPAdminDisableClientBlocksTenantAndDeletesUnusedDCR(t *testing.T) {
	setupAITestDB(t)
	_ = ensureBuiltinOAuthClients()
	if err := db.DB.Create(&db.OAuthClient{ClientID: "dcr-1", RedirectURIs: `["http://127.0.0.1:1/cb"]`, Public: true}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Create(&db.OAuthRefreshToken{
		TokenHash: "cccc",
		ClientID:  "dcr-1",
		UserID:    "1",
		TenantID:  "default",
		Role:      "admin",
		Resource:  "http://example/mcp",
		ExpiresAt: time.Now().Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}

	disabled := callMCPAdminJSON(t, http.MethodPost, "/mcp/admin/clients/dcr-1/disable", "default", "admin", "9", map[string]any{"confirm": true})
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable dcr: %d %s", disabled.Code, disabled.Body.String())
	}
	if !tenantMCPClientBlocked("default", "dcr-1") {
		t.Fatal("expected tenant block")
	}

	deleted := callMCPAdminJSON(t, http.MethodDelete, "/mcp/admin/clients/dcr-1", "default", "admin", "9", map[string]any{"confirm": true})
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), `"row_deleted":true`) {
		t.Fatalf("delete unused dcr: %d %s", deleted.Code, deleted.Body.String())
	}
	var count int64
	db.DB.Model(&db.OAuthClient{}).Where("client_id = ?", "dcr-1").Count(&count)
	if count != 0 {
		t.Fatalf("unused DCR client should be deleted, count=%d", count)
	}
}

func TestMCPAdminSessionsHideTokenHash(t *testing.T) {
	setupAITestDB(t)
	if err := db.DB.Create(&db.OAuthRefreshToken{
		TokenHash: "secret-hash",
		ClientID:  "cursor",
		UserID:    "7",
		TenantID:  "default",
		Role:      "admin",
		Resource:  "http://example/mcp",
		ExpiresAt: time.Now().Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}
	recorder := callMCPAdminJSON(t, http.MethodGet, "/mcp/admin/sessions", "default", "admin", "9", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("sessions: %d %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "secret-hash") {
		t.Fatalf("token hash leaked: %s", recorder.Body.String())
	}
	var sessions []mcpAdminSessionResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &sessions); err != nil || len(sessions) != 1 {
		t.Fatalf("decode sessions: %v %s", err, recorder.Body.String())
	}
	revoked := callMCPAdminJSON(t, http.MethodPost, "/mcp/admin/sessions/revoke", "default", "admin", "9", map[string]any{
		"confirm":    true,
		"session_id": sessions[0].SessionID,
	})
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke session: %d %s", revoked.Code, revoked.Body.String())
	}
	var row db.OAuthRefreshToken
	if err := db.DB.Where("token_hash = ?", "secret-hash").First(&row).Error; err != nil || row.RevokedAt == nil {
		t.Fatalf("session should be revoked: %+v err=%v", row, err)
	}
}

func TestMCPAdminRevokeSessionsByUser(t *testing.T) {
	setupAITestDB(t)
	now := time.Now()
	if err := db.DB.Create(&db.OAuthRefreshToken{
		TokenHash: "user-a-1",
		ClientID:  "cursor",
		UserID:    "7",
		TenantID:  "default",
		Role:      "operator",
		Resource:  "http://example/mcp",
		ExpiresAt: now.Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.DB.Create(&db.OAuthRefreshToken{
		TokenHash: "user-a-2",
		ClientID:  "cursor",
		UserID:    "8",
		TenantID:  "default",
		Role:      "operator",
		Resource:  "http://example/mcp",
		ExpiresAt: now.Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}
	revoked := callMCPAdminJSON(t, http.MethodPost, "/mcp/admin/sessions/revoke", "default", "admin", "9", map[string]any{
		"confirm": true,
		"user_id": "7",
	})
	if revoked.Code != http.StatusOK || !strings.Contains(revoked.Body.String(), `"revoked_sessions":1`) {
		t.Fatalf("revoke by user: %d %s", revoked.Code, revoked.Body.String())
	}
	var kept db.OAuthRefreshToken
	if err := db.DB.Where("token_hash = ?", "user-a-2").First(&kept).Error; err != nil || kept.RevokedAt != nil {
		t.Fatalf("other user session must remain: %+v err=%v", kept, err)
	}
}

func TestMCPAdminListEventsIsTenantScoped(t *testing.T) {
	store := setupAITestDB(t)
	recordMCPAdminEvent("default", "9", "disable", "", map[string]interface{}{"revoked_sessions": 2})
	recordMCPAdminEvent("other", "9", "disable", "", map[string]interface{}{"revoked_sessions": 9})
	recordMCPAdminEvent("default", "9", "enable", "cursor", map[string]interface{}{})

	recorder := callMCPAdminJSON(t, http.MethodGet, "/mcp/admin/events", "default", "admin", "9", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("list events: %d %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Total int `json:"total"`
		Items []struct {
			Action  string                 `json:"action"`
			Details map[string]interface{} `json:"details"`
		} `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if body.Total != 2 || len(body.Items) != 2 {
		t.Fatalf("expected two default tenant events, got %+v %s", body, recorder.Body.String())
	}
	filtered := callMCPAdminJSON(t, http.MethodGet, "/mcp/admin/events?action=disable", "default", "admin", "9", nil)
	if err := json.Unmarshal(filtered.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse filtered: %v", err)
	}
	if body.Total != 1 || len(body.Items) != 1 || body.Items[0].Action != "disable" {
		t.Fatalf("expected one disable event, got %+v %s", body, filtered.Body.String())
	}
	if body.Items[0].Details["revoked_sessions"] != float64(2) {
		t.Fatalf("details should keep revoked_sessions, got %#v", body.Items[0].Details)
	}
	var otherCount int64
	store.Model(&db.MCPAdminEvent{}).Where("tenant_id = ?", "other").Count(&otherCount)
	if otherCount != 1 {
		t.Fatalf("other tenant event should remain, count=%d", otherCount)
	}
}

func TestMCPAdminListToolsReturnsCatalog(t *testing.T) {
	recorder := callMCPAdminJSON(t, http.MethodGet, "/mcp/admin/tools", "default", "admin", "9", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("list tools: %d %s", recorder.Code, recorder.Body.String())
	}
	var tools []argusmcp.ToolCatalogEntry
	if err := json.Unmarshal(recorder.Body.Bytes(), &tools); err != nil {
		t.Fatalf("parse: %v %s", err, recorder.Body.String())
	}
	if len(tools) == 0 {
		t.Fatal("expected tool catalog")
	}
	found := false
	for _, tool := range tools {
		if tool.Name == "argus_scan_create" {
			found = true
			if tool.Category != "scan" || !tool.Auditable {
				t.Fatalf("scan_create catalog %#v", tool)
			}
			if tool.ExampleCall.Method != "tools/call" || tool.ExampleCall.Params.Name != "argus_scan_create" {
				t.Fatalf("scan_create example %#v", tool.ExampleCall)
			}
			if _, ok := tool.ExampleCall.Params.Arguments["plan_hash"]; !ok {
				t.Fatalf("scan_create example should include required plan_hash: %#v", tool.ExampleCall.Params.Arguments)
			}
		}
		if strings.Contains(strings.ToLower(tool.Description), "token") && strings.Contains(tool.Description, "sk-") {
			t.Fatalf("catalog must not include secrets: %#v", tool)
		}
	}
	if !found {
		t.Fatal("missing argus_scan_create")
	}
}
