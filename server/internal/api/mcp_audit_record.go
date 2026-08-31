package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	argusmcp "github.com/P0lar1ght/argus/mcp"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type mcpHTTPToolAuditor struct {
	tenantID string
	userID   string
	role     string
	clientID string
}

func (a mcpHTTPToolAuditor) Record(_ context.Context, rec argusmcp.ToolCallRecord) {
	recordMCPToolInvocation(a, rec)
}

func recordMCPToolInvocation(identity mcpHTTPToolAuditor, rec argusmcp.ToolCallRecord) {
	if db.DB == nil {
		return
	}
	tenantID := normalizeTenantID(identity.tenantID)
	if tenantID == "" {
		return
	}
	action, ok := argusmcp.AuditableToolAction(rec.ToolName, rec.Args)
	if !ok {
		return
	}
	payload, _ := marshalMCPAuditArgs(rec.Args)
	status := "ok"
	errorSummary := ""
	if rec.Err != nil {
		status = "error"
		errorSummary = truncateString(rec.Err.Error(), 1000)
	}
	_ = db.DB.Create(&db.MCPToolInvocation{
		ID:           uuid.NewString(),
		TenantID:     tenantID,
		UserID:       strings.TrimSpace(identity.userID),
		Role:         strings.TrimSpace(identity.role),
		ClientID:     strings.TrimSpace(identity.clientID),
		ToolName:     strings.TrimSpace(rec.ToolName),
		Action:       action,
		Args:         payload,
		AgentID:      truncateString(mcpAuditLookupString(rec.Args, "agent_id"), 255),
		Target:       truncateString(mcpAuditLookupString(rec.Args, "target_url", "target"), 2000),
		DurationMS:   rec.Duration.Milliseconds(),
		Status:       status,
		ErrorSummary: errorSummary,
		CreatedAt:    time.Now(),
	}).Error
}

type mcpAdminInvocationResponse struct {
	ID           string      `json:"id"`
	UserID       string      `json:"user_id"`
	Role         string      `json:"role"`
	ClientID     string      `json:"client_id"`
	ToolName     string      `json:"tool_name"`
	Action       string      `json:"action,omitempty"`
	Args         interface{} `json:"args"`
	AgentID      string      `json:"agent_id,omitempty"`
	Target       string      `json:"target,omitempty"`
	DurationMS   int64       `json:"duration_ms"`
	Status       string      `json:"status"`
	ErrorSummary string      `json:"error_summary,omitempty"`
	CreatedAt    string      `json:"created_at"`
}

func mcpAdminListInvocations(c *gin.Context) {
	limit := clampQueryInt(c.Query("limit"), 50, 1, 200)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 10000)
	query := db.DB.Model(&db.MCPToolInvocation{}).Where("tenant_id = ?", currentTenantID(c))
	if toolName := strings.TrimSpace(c.Query("tool_name")); toolName != "" {
		query = query.Where("tool_name = ?", toolName)
	}
	if userID := strings.TrimSpace(c.Query("user_id")); userID != "" {
		query = query.Where("user_id = ?", userID)
	}
	if clientID := strings.TrimSpace(c.Query("client_id")); clientID != "" {
		query = query.Where("client_id = ?", clientID)
	}
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		query = query.Where("status = ?", status)
	}
	if since := strings.TrimSpace(c.Query("since")); since != "" {
		if parsed, err := time.Parse(time.RFC3339, since); err == nil {
			query = query.Where("created_at >= ?", parsed)
		}
	}
	if until := strings.TrimSpace(c.Query("until")); until != "" {
		if parsed, err := time.Parse(time.RFC3339, until); err == nil {
			query = query.Where("created_at <= ?", parsed)
		}
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list MCP invocations"})
		return
	}
	var rows []db.MCPToolInvocation
	if err := query.Order("created_at desc").Limit(limit).Offset(offset).Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list MCP invocations"})
		return
	}
	items := make([]mcpAdminInvocationResponse, 0, len(rows))
	for _, row := range rows {
		var args interface{}
		if strings.TrimSpace(row.Args) == "" {
			args = map[string]interface{}{}
		} else if err := json.Unmarshal([]byte(row.Args), &args); err != nil {
			args = row.Args
		}
		items = append(items, mcpAdminInvocationResponse{
			ID:           row.ID,
			UserID:       row.UserID,
			Role:         row.Role,
			ClientID:     row.ClientID,
			ToolName:     row.ToolName,
			Action:       row.Action,
			Args:         args,
			AgentID:      row.AgentID,
			Target:       row.Target,
			DurationMS:   row.DurationMS,
			Status:       row.Status,
			ErrorSummary: row.ErrorSummary,
			CreatedAt:    row.CreatedAt.Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, gin.H{"total": total, "items": items})
}
