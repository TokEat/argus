package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
)

func listCloudPolicies(c *gin.Context) {
	tenantID := currentTenantID(c)
	var policies []db.CloudScalingPolicy
	db.DB.Where("tenant_id = ? AND cloud_account_id IN (?)", tenantID, accessibleCloudAccountSubquery(c)).
		Order("created_at DESC").
		Find(&policies)
	c.JSON(http.StatusOK, policies)
}

func createCloudPolicy(c *gin.Context) {
	var req db.CloudScalingPolicy
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tenantID := currentTenantID(c)
	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Policy name is required"})
		return
	}
	if strings.TrimSpace(req.CloudAccountID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cloud account is required"})
		return
	}
	if _, ok := loadCloudAccountForUse(c, req.CloudAccountID, false); !ok {
		return
	}

	req.ID = fmt.Sprintf("cp-%d", time.Now().UnixNano())
	req.TenantID = tenantID
	if req.MaxInstances <= 0 {
		req.MaxInstances = 5
	}
	if req.CooldownSeconds <= 0 {
		req.CooldownSeconds = 300
	}
	if req.InstanceTTLMinutes <= 0 {
		req.InstanceTTLMinutes = 120
	}
	if req.SpotStrategy == "" {
		req.SpotStrategy = "SpotAsPriceGo" // 默认使用抢占式实例，节省 70-90%
	}

	if err := db.DB.Create(&req).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "id": req.ID})
}

func updateCloudPolicy(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 不允许通过此接口修改 ID 和 tenant_id
	delete(req, "id")
	delete(req, "tenant_id")
	delete(req, "created_at")
	delete(req, "updated_at")
	if accountID, ok := req["cloud_account_id"].(string); ok && strings.TrimSpace(accountID) != "" {
		if _, ok := loadCloudAccountForUse(c, accountID, false); !ok {
			return
		}
	}

	result := db.DB.Model(&db.CloudScalingPolicy{}).
		Where("id = ? AND tenant_id = ? AND cloud_account_id IN (?)", id, tenantID, accessibleCloudAccountSubquery(c)).
		Updates(req)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func deleteCloudPolicy(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var activeInstances int64
	db.DB.Model(&db.CloudInstance{}).
		Where("policy_id = ? AND tenant_id = ? AND cloud_account_id IN (?) AND deleted_at IS NULL AND status NOT IN ?", id, tenantID, accessibleCloudAccountSubquery(c), []string{db.CloudStatusTerminated, db.CloudStatusTerminating}).
		Count(&activeInstances)
	if activeInstances > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Policy still has %d active instance(s); terminate them before deletion", activeInstances),
		})
		return
	}

	result := db.DB.Where("id = ? AND tenant_id = ? AND cloud_account_id IN (?)", id, tenantID, accessibleCloudAccountSubquery(c)).Delete(&db.CloudScalingPolicy{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": result.Error.Error()})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func toggleCloudPolicy(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var policy db.CloudScalingPolicy
	if err := db.DB.Where("id = ? AND tenant_id = ? AND cloud_account_id IN (?)", id, tenantID, accessibleCloudAccountSubquery(c)).First(&policy).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	newEnabled := !policy.Enabled
	db.DB.Model(&policy).Update("enabled", newEnabled)

	c.JSON(http.StatusOK, gin.H{"status": "ok", "enabled": newEnabled})
}
