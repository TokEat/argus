package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/gin-gonic/gin"
)

func (h *CloudHandler) listCloudPolicies(c *gin.Context) {
	tenantID := currentTenantID(c)
	var policies []db.CloudScalingPolicy
	h.DB.
		Where("tenant_id = ? AND cloud_account_id IN (?)", tenantID, h.accessibleCloudAccountSubquery(requestActor(c))).
		Order("created_at DESC").
		Find(&policies)
	c.JSON(http.StatusOK, policies)
}

func (h *CloudHandler) createCloudPolicy(c *gin.Context) {
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
	if _, ok := h.loadCloudAccountForUse(c, req.CloudAccountID, false); !ok {
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

	if err := h.DB.Create(&req).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "id": req.ID})
}

func (h *CloudHandler) updateCloudPolicy(c *gin.Context) {
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
		if _, ok := h.loadCloudAccountForUse(c, accountID, false); !ok {
			return
		}
	}

	result := h.DB.Model(&db.CloudScalingPolicy{}).
		Where("id = ? AND tenant_id = ? AND cloud_account_id IN (?)", id, tenantID, h.accessibleCloudAccountSubquery(requestActor(c))).
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

func (h *CloudHandler) deleteCloudPolicy(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var activeInstances int64
	h.DB.
		Model(&db.CloudInstance{}).
		Where("policy_id = ? AND tenant_id = ? AND cloud_account_id IN (?) AND deleted_at IS NULL AND status NOT IN ?", id, tenantID, h.accessibleCloudAccountSubquery(requestActor(c)), []string{db.CloudStatusTerminated, db.CloudStatusTerminating}).
		Count(&activeInstances)
	if activeInstances > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Policy still has %d active instance(s); terminate them before deletion", activeInstances),
		})
		return
	}

	result := h.DB.Where("id = ? AND tenant_id = ? AND cloud_account_id IN (?)", id, tenantID, h.accessibleCloudAccountSubquery(requestActor(c))).Delete(&db.CloudScalingPolicy{})
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

func (h *CloudHandler) toggleCloudPolicy(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var policy db.CloudScalingPolicy
	if err := h.DB.Where("id = ? AND tenant_id = ? AND cloud_account_id IN (?)", id, tenantID, h.accessibleCloudAccountSubquery(requestActor(c))).First(&policy).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	newEnabled := !policy.Enabled
	h.DB.
		Model(&policy).Update("enabled", newEnabled)

	c.JSON(http.StatusOK, gin.H{"status": "ok", "enabled": newEnabled})
}
