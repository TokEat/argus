package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	argusmcp "github.com/TokEat/argus/mcp"
	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

type mcpAdminStatusResponse struct {
	Enabled      bool   `json:"enabled"`
	MCPURL       string `json:"mcp_url"`
	PublicURL    string `json:"public_url"`
	Transport    string `json:"transport"`
	SessionCount int64  `json:"session_count"`
}

type mcpAdminClientResponse struct {
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
	Builtin      bool     `json:"builtin"`
	Blocked      bool     `json:"blocked"`
	SessionCount int64    `json:"session_count"`
	LastUsedAt   string   `json:"last_used_at,omitempty"`
	CreatedAt    string   `json:"created_at,omitempty"`
}

type mcpAdminSessionResponse struct {
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	ClientID  string `json:"client_id"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

type mcpAdminEventResponse struct {
	ID        string      `json:"id"`
	ActorID   string      `json:"actor_id"`
	Action    string      `json:"action"`
	ClientID  string      `json:"client_id,omitempty"`
	Details   interface{} `json:"details"`
	CreatedAt string      `json:"created_at"`
}

func mcpAdminGetStatus(c *gin.Context) {
	tenantID := currentTenantID(c)
	c.JSON(http.StatusOK, mcpAdminStatusResponse{
		Enabled:      tenantMCPEnabled(tenantID),
		MCPURL:       mcpResourceURI(),
		PublicURL:    publicAPIBase(),
		Transport:    "streamable-http-stateless-json",
		SessionCount: countActiveTenantSessions(tenantID, ""),
	})
}

func mcpAdminPutStatus(c *gin.Context) {
	var req struct {
		Enabled bool `json:"enabled"`
		Confirm bool `json:"confirm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if !req.Enabled && !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "disabling MCP for this tenant requires confirm=true"})
		return
	}
	tenantID := currentTenantID(c)
	actorID := currentUserID(c)
	if err := upsertTenantMCPSettings(tenantID, actorID, req.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update MCP status"})
		return
	}
	revoked := int64(0)
	if !req.Enabled {
		n, err := revokeTenantRefreshTokens(tenantID, "")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke MCP sessions"})
			return
		}
		revoked = n
	}
	action := "enable"
	if !req.Enabled {
		action = "disable"
	}
	recordMCPAdminEvent(tenantID, actorID, action, "", map[string]interface{}{"revoked_sessions": revoked})
	c.JSON(http.StatusOK, gin.H{
		"status":           "ok",
		"enabled":          req.Enabled,
		"revoked_sessions": revoked,
	})
}

func mcpAdminListClients(c *gin.Context) {
	tenantID := currentTenantID(c)
	_ = ensureBuiltinOAuthClients()

	ids := map[string]struct{}{oauthCursorClientID: {}}
	var tokenClients []string
	db.DB.Model(&db.OAuthRefreshToken{}).
		Where("tenant_id = ?", tenantID).
		Distinct("client_id").
		Pluck("client_id", &tokenClients)
	for _, id := range tokenClients {
		if strings.TrimSpace(id) != "" {
			ids[id] = struct{}{}
		}
	}
	var blocked []db.OAuthTenantClientBlock
	db.DB.Where("tenant_id = ?", tenantID).Find(&blocked)
	blockedSet := map[string]bool{}
	for _, row := range blocked {
		ids[row.ClientID] = struct{}{}
		blockedSet[row.ClientID] = true
	}

	clients := make([]mcpAdminClientResponse, 0, len(ids))
	for clientID := range ids {
		item := mcpAdminClientResponse{
			ClientID:     clientID,
			RedirectURIs: []string{},
			Builtin:      clientID == oauthCursorClientID,
			Blocked:      blockedSet[clientID],
			SessionCount: countActiveTenantSessions(tenantID, clientID),
		}
		if client, err := loadOAuthClientByID(clientID); err == nil {
			item.CreatedAt = client.CreatedAt.Format(time.RFC3339)
			var uris []string
			if json.Unmarshal([]byte(client.RedirectURIs), &uris) == nil {
				item.RedirectURIs = uris
			}
		}
		var lastUsed time.Time
		if err := db.DB.Model(&db.OAuthRefreshToken{}).
			Select("MAX(created_at)").
			Where("tenant_id = ? AND client_id = ?", tenantID, clientID).
			Scan(&lastUsed).Error; err == nil && !lastUsed.IsZero() {
			item.LastUsedAt = lastUsed.Format(time.RFC3339)
		}
		clients = append(clients, item)
	}
	c.JSON(http.StatusOK, clients)
}

func mcpAdminRevokeClient(c *gin.Context) {
	var req struct {
		Confirm bool `json:"confirm"`
	}
	_ = c.ShouldBindJSON(&req)
	if !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "revoking client sessions requires confirm=true"})
		return
	}
	clientID := strings.TrimSpace(c.Param("id"))
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id is required"})
		return
	}
	tenantID := currentTenantID(c)
	n, err := revokeTenantRefreshTokens(tenantID, clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke sessions"})
		return
	}
	recordMCPAdminEvent(tenantID, currentUserID(c), "revoke_client", clientID, map[string]interface{}{"revoked_sessions": n})
	c.JSON(http.StatusOK, gin.H{"status": "ok", "revoked_sessions": n})
}

func mcpAdminDisableClient(c *gin.Context) {
	var req struct {
		Confirm bool `json:"confirm"`
	}
	_ = c.ShouldBindJSON(&req)
	if !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "disabling a client requires confirm=true"})
		return
	}
	clientID := strings.TrimSpace(c.Param("id"))
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id is required"})
		return
	}
	tenantID := currentTenantID(c)
	if err := setTenantClientBlock(tenantID, clientID, currentUserID(c), true); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable client"})
		return
	}
	n, err := revokeTenantRefreshTokens(tenantID, clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke sessions"})
		return
	}
	recordMCPAdminEvent(tenantID, currentUserID(c), "disable_client", clientID, map[string]interface{}{"revoked_sessions": n})
	c.JSON(http.StatusOK, gin.H{"status": "ok", "revoked_sessions": n})
}

func mcpAdminEnableClient(c *gin.Context) {
	clientID := strings.TrimSpace(c.Param("id"))
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id is required"})
		return
	}
	tenantID := currentTenantID(c)
	if err := setTenantClientBlock(tenantID, clientID, currentUserID(c), false); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enable client"})
		return
	}
	recordMCPAdminEvent(tenantID, currentUserID(c), "enable_client", clientID, map[string]interface{}{})
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func mcpAdminDeleteClient(c *gin.Context) {
	var req struct {
		Confirm bool `json:"confirm"`
	}
	_ = c.ShouldBindJSON(&req)
	if !req.Confirm && !parseBoolQuery(c.Query("confirm")) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "deleting a client requires confirm=true"})
		return
	}
	clientID := strings.TrimSpace(c.Param("id"))
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id is required"})
		return
	}
	if clientID == oauthCursorClientID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "the built-in cursor client cannot be deleted"})
		return
	}
	tenantID := currentTenantID(c)
	if err := setTenantClientBlock(tenantID, clientID, currentUserID(c), true); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable client"})
		return
	}
	n, err := revokeTenantRefreshTokens(tenantID, clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke sessions"})
		return
	}
	deleted := false
	if !clientUsedByOtherTenants(clientID, tenantID) {
		if err := db.DB.Where("client_id = ?", clientID).Delete(&db.OAuthClient{}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete client"})
			return
		}
		deleted = true
	}
	recordMCPAdminEvent(tenantID, currentUserID(c), "delete_client", clientID, map[string]interface{}{
		"revoked_sessions": n,
		"row_deleted":      deleted,
	})
	c.JSON(http.StatusOK, gin.H{"status": "ok", "revoked_sessions": n, "row_deleted": deleted})
}

func mcpAdminListSessions(c *gin.Context) {
	tenantID := currentTenantID(c)
	var rows []db.OAuthRefreshToken
	db.DB.Where("tenant_id = ? AND revoked_at IS NULL AND expires_at > ?", tenantID, time.Now()).
		Order("created_at DESC").
		Find(&rows)
	out := make([]mcpAdminSessionResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, mcpAdminSessionResponse{
			SessionID: mcpSessionID(row.TokenHash),
			UserID:    row.UserID,
			ClientID:  row.ClientID,
			CreatedAt: row.CreatedAt.Format(time.RFC3339),
			ExpiresAt: row.ExpiresAt.Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, out)
}

func mcpAdminRevokeSessions(c *gin.Context) {
	var req struct {
		Confirm   bool   `json:"confirm"`
		SessionID string `json:"session_id"`
		UserID    string `json:"user_id"`
		ClientID  string `json:"client_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "revoking sessions requires confirm=true"})
		return
	}
	tenantID := currentTenantID(c)
	now := time.Now()
	revoked := int64(0)
	if strings.TrimSpace(req.SessionID) != "" {
		row, ok := findTenantRefreshBySessionID(tenantID, strings.TrimSpace(req.SessionID))
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
			return
		}
		if row.RevokedAt == nil {
			if err := db.DB.Model(&row).Update("revoked_at", now).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke session"})
				return
			}
			revoked = 1
		}
		recordMCPAdminEvent(tenantID, currentUserID(c), "revoke_session", row.ClientID, map[string]interface{}{
			"user_id": row.UserID,
		})
		c.JSON(http.StatusOK, gin.H{"status": "ok", "revoked_sessions": revoked})
		return
	}
	if strings.TrimSpace(req.UserID) == "" && strings.TrimSpace(req.ClientID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "session_id or user_id/client_id is required"})
		return
	}
	query := db.DB.Model(&db.OAuthRefreshToken{}).
		Where("tenant_id = ? AND revoked_at IS NULL", tenantID)
	if strings.TrimSpace(req.UserID) != "" {
		query = query.Where("user_id = ?", strings.TrimSpace(req.UserID))
	}
	if strings.TrimSpace(req.ClientID) != "" {
		query = query.Where("client_id = ?", strings.TrimSpace(req.ClientID))
	}
	result := query.Update("revoked_at", now)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke sessions"})
		return
	}
	revoked = result.RowsAffected
	recordMCPAdminEvent(tenantID, currentUserID(c), "revoke_sessions", strings.TrimSpace(req.ClientID), map[string]interface{}{
		"user_id":          strings.TrimSpace(req.UserID),
		"revoked_sessions": revoked,
	})
	c.JSON(http.StatusOK, gin.H{"status": "ok", "revoked_sessions": revoked})
}

func parseBoolQuery(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func mcpAdminListEvents(c *gin.Context) {
	limit := clampQueryInt(c.Query("limit"), 50, 1, 200)
	offset := clampQueryInt(c.Query("offset"), 0, 0, 10000)
	query := db.DB.Model(&db.MCPAdminEvent{}).Where("tenant_id = ?", currentTenantID(c))
	if action := strings.TrimSpace(c.Query("action")); action != "" {
		query = query.Where("action = ?", action)
	}
	if actorID := strings.TrimSpace(c.Query("actor_id")); actorID != "" {
		query = query.Where("actor_id = ?", actorID)
	}
	if clientID := strings.TrimSpace(c.Query("client_id")); clientID != "" {
		query = query.Where("client_id = ?", clientID)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list MCP admin events"})
		return
	}
	var rows []db.MCPAdminEvent
	if err := query.Order("created_at desc").Limit(limit).Offset(offset).Find(&rows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list MCP admin events"})
		return
	}
	items := make([]mcpAdminEventResponse, 0, len(rows))
	for _, row := range rows {
		items = append(items, mcpAdminEventResponse{
			ID:        row.ID,
			ActorID:   row.ActorID,
			Action:    row.Action,
			ClientID:  row.ClientID,
			Details:   decodeMCPAdminEventDetails(row.Details),
			CreatedAt: row.CreatedAt.Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, gin.H{"total": total, "items": items})
}

func decodeMCPAdminEventDetails(raw string) interface{} {
	if strings.TrimSpace(raw) == "" {
		return map[string]interface{}{}
	}
	var details interface{}
	if err := json.Unmarshal([]byte(raw), &details); err != nil {
		return map[string]interface{}{}
	}
	return details
}

func mcpAdminListTools(c *gin.Context) {
	c.JSON(http.StatusOK, argusmcp.ToolCatalog())
}
