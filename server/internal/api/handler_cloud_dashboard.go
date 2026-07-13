package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
)

func (h *CloudHandler) cloudDashboard(c *gin.Context) {
	tenantID := currentTenantID(c)

	var totalAccounts int64
	h.cloudAccountQuery(requestActor(c)).Model(&db.CloudAccount{}).Where("status = ?", "active").Count(&totalAccounts)

	var enabledPolicies int64
	h.DB.
		Model(&db.CloudScalingPolicy{}).Where("tenant_id = ? AND cloud_account_id IN (?) AND enabled = ?", tenantID, h.accessibleCloudAccountSubquery(requestActor(c)), true).Count(&enabledPolicies)

	var runningInstances int64
	h.DB.
		Model(&db.CloudInstance{}).Where("tenant_id = ? AND cloud_account_id IN (?) AND status IN ?", tenantID, h.accessibleCloudAccountSubquery(requestActor(c)), []string{
		db.CloudStatusProvisioning, db.CloudStatusWaitingReady, db.CloudStatusRunning,
	}).Count(&runningInstances)

	var totalInstances int64
	h.DB.
		Model(&db.CloudInstance{}).Where("tenant_id = ? AND cloud_account_id IN (?)", tenantID, h.accessibleCloudAccountSubquery(requestActor(c))).Count(&totalInstances)

	// 最近 10 条实例事件
	var recentInstances []db.CloudInstance
	h.DB.
		Where("tenant_id = ? AND cloud_account_id IN (?)", tenantID, h.accessibleCloudAccountSubquery(requestActor(c))).Order("updated_at DESC").Limit(10).Find(&recentInstances)

	c.JSON(http.StatusOK, gin.H{
		"active_accounts":   totalAccounts,
		"enabled_policies":  enabledPolicies,
		"running_instances": runningInstances,
		"total_instances":   totalInstances,
		"recent_events":     recentInstances,
	})
}
