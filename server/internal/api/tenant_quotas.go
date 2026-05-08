package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
)

type tenantQuotaResp struct {
	TenantID           string              `json:"tenant_id"`
	MaxConcurrentTasks int                 `json:"max_concurrent_tasks"`
	MaxRunningSubTasks int                 `json:"max_running_sub_tasks"`
	DailyTaskLimit     int                 `json:"daily_task_limit"`
	Usage              db.TenantQuotaUsage `json:"usage"`
	CreatedAt          string              `json:"created_at,omitempty"`
	UpdatedAt          string              `json:"updated_at,omitempty"`
}

func getTenantQuota(c *gin.Context) {
	tenantID, ok := tenantQuotaPathTenant(c)
	if !ok {
		return
	}
	quota, err := db.GetTenantQuota(db.DB, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load tenant quota"})
		return
	}
	usage, err := db.TenantQuotaUsageFor(db.DB, tenantID, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load tenant quota usage"})
		return
	}
	c.JSON(http.StatusOK, tenantQuotaResponse(quota, usage))
}

func updateTenantQuota(c *gin.Context) {
	tenantID, ok := tenantQuotaPathTenant(c)
	if !ok {
		return
	}
	var req struct {
		MaxConcurrentTasks int `json:"max_concurrent_tasks"`
		MaxRunningSubTasks int `json:"max_running_sub_tasks"`
		DailyTaskLimit     int `json:"daily_task_limit"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	quota, err := db.UpsertTenantQuota(db.DB, db.TenantQuota{
		TenantID:           tenantID,
		MaxConcurrentTasks: req.MaxConcurrentTasks,
		MaxRunningSubTasks: req.MaxRunningSubTasks,
		DailyTaskLimit:     req.DailyTaskLimit,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	usage, err := db.TenantQuotaUsageFor(db.DB, tenantID, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load tenant quota usage"})
		return
	}
	c.JSON(http.StatusOK, tenantQuotaResponse(quota, usage))
}

func tenantQuotaPathTenant(c *gin.Context) (string, bool) {
	current := currentTenantID(c)
	tenantID := c.Param("id")
	if tenantID == "" || tenantID == "current" {
		tenantID = current
	}
	if tenantID != current {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot manage quota for another tenant"})
		return "", false
	}
	return tenantID, true
}

func tenantQuotaResponse(quota db.TenantQuota, usage db.TenantQuotaUsage) tenantQuotaResp {
	return tenantQuotaResp{
		TenantID:           db.NormalizeTenantID(quota.TenantID),
		MaxConcurrentTasks: quota.MaxConcurrentTasks,
		MaxRunningSubTasks: quota.MaxRunningSubTasks,
		DailyTaskLimit:     quota.DailyTaskLimit,
		Usage:              usage,
		CreatedAt:          formatQuotaTime(quota.CreatedAt),
		UpdatedAt:          formatQuotaTime(quota.UpdatedAt),
	}
}

func writeTenantQuotaError(c *gin.Context, err error) bool {
	var quotaErr *db.TenantQuotaError
	if errors.As(err, &quotaErr) {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error": quotaErr.Message,
			"code":  quotaErr.Code,
		})
		return true
	}
	return false
}

func formatQuotaTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
