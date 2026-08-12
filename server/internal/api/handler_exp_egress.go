package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	egresspkg "github.com/P0lar1ght/argus/server/internal/egress"
	"github.com/gin-gonic/gin"
)

type createExpEgressRouteRequest struct {
	AgentID        string   `json:"agent_id" binding:"required"`
	NetworkTargets []string `json:"network_targets" binding:"required"`
	TimeoutMS      int      `json:"timeout_ms"`
	RiskConfirmed  bool     `json:"risk_confirmed"`
}

func createExpEgressRoute(c *gin.Context) {
	if !currentUserHasEXPAuthorization(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "EXP access requires user-level authorization"})
		return
	}
	var req createExpEgressRouteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !req.RiskConfirmed {
		c.JSON(http.StatusBadRequest, gin.H{"error": "risk_confirmed=true is required for Agent egress"})
		return
	}
	broker := routerRuntime().EgressBroker
	if broker == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Agent Egress Unavailable"})
		return
	}
	agentID := strings.TrimSpace(req.AgentID)
	var node db.Node
	if err := scopedNodeQuery(currentTenantID(c)).Select("agent_id", "tenant_id", "status", "token", "token_expires_at", "token_revoked_at").Where("agent_id = ?", agentID).First(&node).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found or not accessible"})
		return
	}
	if !strings.EqualFold(node.Status, "Alive") || strings.TrimSpace(node.Token) == "" || node.TokenRevokedAt != nil || (node.TokenExpiresAt != nil && time.Now().After(*node.TokenExpiresAt)) || !broker.AgentOnline(agentID) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Agent Egress Unavailable: agent tunnel is offline"})
		return
	}
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if req.TimeoutMS < 0 || timeout > egresspkg.MaxRouteDuration {
		c.JSON(http.StatusBadRequest, gin.H{"error": "timeout_ms must be between 0 and 120000"})
		return
	}
	snapshot, err := broker.CreateRoute(c.Request.Context(), egresspkg.RouteRequest{TenantID: currentTenantID(c), OperatorID: currentUserID(c), AgentID: agentID, NetworkTargets: req.NetworkTargets, Timeout: timeout})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	snapshot.TenantID = ""
	c.JSON(http.StatusCreated, snapshot)
}

func revokeExpEgressRoute(c *gin.Context) {
	broker := routerRuntime().EgressBroker
	if broker == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Agent Egress Unavailable"})
		return
	}
	snapshot, err := broker.Revoke(currentTenantID(c), c.Param("route_id"), "revoked_by_operator")
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	snapshot.TenantID = ""
	c.JSON(http.StatusOK, snapshot)
}

func listExpEgressAudits(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	query := db.DB.Model(&db.ExpEgressAudit{}).Where("tenant_id = ?", currentTenantID(c))
	if agentID := strings.TrimSpace(c.Query("agent_id")); agentID != "" {
		query = query.Where("agent_id = ?", agentID)
	}
	var total int64
	query.Count(&total)
	var items []db.ExpEgressAudit
	if err := query.Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list egress audits"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total, "page": page, "page_size": pageSize})
}

func getExpEgressAudit(c *gin.Context) {
	var item db.ExpEgressAudit
	if err := db.DB.Where("tenant_id = ? AND route_id = ?", currentTenantID(c), c.Param("route_id")).First(&item).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "egress audit not found"})
		return
	}
	c.JSON(http.StatusOK, item)
}
