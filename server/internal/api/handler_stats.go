package api

import (
	"net/http"
	"strconv"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

func getStats(c *gin.Context) {
	tenantID := currentTenantID(c)
	var taskCount, nodeCount, assetCount, fpCount, vulnCount int64

	taskQ := db.DB.Model(&db.RootTask{}).Where("tenant_id = ? AND archived_at IS NULL", tenantID)
	taskQ, _ = applyProjectScope(c, taskQ, "project_id")
	taskQ.Count(&taskCount)

	scopedNodeQuery(tenantID).Model(&db.Node{}).Count(&nodeCount)

	assetQ := db.DB.Model(&db.Asset{}).Where("tenant_id = ?", tenantID)
	assetQ, _ = applyProjectScope(c, assetQ, "project_id")
	assetQ.Count(&assetCount)

	fpQ := db.DB.Model(&db.FingerprintHit{}).Where("tenant_id = ?", tenantID)
	fpQ, _ = applyProjectScope(c, fpQ, "project_id")
	fpQ.Count(&fpCount)

	vulnQ := db.DB.Model(&db.Vulnerability{}).Where("tenant_id = ?", tenantID)
	vulnQ, _ = applyProjectScope(c, vulnQ, "project_id")
	vulnQ.Count(&vulnCount)

	c.JSON(http.StatusOK, gin.H{
		"tasks":        taskCount,
		"nodes":        nodeCount,
		"assets":       assetCount,
		"fingerprints": fpCount,
		"vulns":        vulnCount,
	})
}

func getVulnTrends(c *gin.Context) {
	tenantID := currentTenantID(c)
	projectID, ok := statsProjectID(c)
	if !ok {
		c.JSON(http.StatusOK, []db.TrendPoint{})
		return
	}
	days := 30
	if d := c.Query("days"); d != "" {
		if v, err := strconv.Atoi(d); err == nil && v > 0 {
			days = v
		}
	}
	c.JSON(http.StatusOK, db.GetVulnTrends(tenantID, projectID, days))
}

func getSeverityDistribution(c *gin.Context) {
	projectID, ok := statsProjectID(c)
	if !ok {
		c.JSON(http.StatusOK, []db.SeverityCount{})
		return
	}
	c.JSON(http.StatusOK, db.GetSeverityDistribution(currentTenantID(c), projectID))
}

func getTaskResultStats(c *gin.Context) {
	tenantID := currentTenantID(c)
	projectID, ok := statsProjectID(c)
	if !ok {
		c.JSON(http.StatusOK, []db.TaskStats{})
		return
	}
	limit := 20
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	c.JSON(http.StatusOK, db.GetTaskResultStats(tenantID, projectID, limit))
}

func getRecentHighVulns(c *gin.Context) {
	tenantID := currentTenantID(c)
	projectID, ok := statsProjectID(c)
	if !ok {
		c.JSON(http.StatusOK, []db.Vulnerability{})
		return
	}
	limit := 10
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	c.JSON(http.StatusOK, db.GetRecentHighVulns(tenantID, projectID, limit))
}
