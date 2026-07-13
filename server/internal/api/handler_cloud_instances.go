package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/cloud"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

func (h *CloudHandler) listCloudInstancesReal(c *gin.Context) {
	tenantID := currentTenantID(c)
	var instances []db.CloudInstance
	h.DB.
		Where("tenant_id = ? AND cloud_account_id IN (?) AND deleted_at IS NULL", tenantID, h.accessibleCloudAccountSubquery(requestActor(c))).
		Order("created_at DESC").
		Find(&instances)
	c.JSON(http.StatusOK, instances)
}

func (h *CloudHandler) createCloudInstanceManual(c *gin.Context) {
	var req struct {
		AccountID    string `json:"account_id" binding:"required"`
		Count        int    `json:"count"`
		InstanceType string `json:"instance_type"` // 可选：覆盖凭证默认规格
		Region       string `json:"region"`        // 可选：覆盖凭证默认地域
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Count <= 0 {
		req.Count = 1
	}
	if req.Count > 10 {
		req.Count = 10 // 单次上限
	}

	tenantID := currentTenantID(c)

	account, ok := h.loadCloudAccountForUse(c, req.AccountID, true)
	if !ok {
		return
	}

	if h.AutoScaler == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AutoScaler not initialized"})
		return
	}

	var policy db.CloudScalingPolicy
	if err := h.DB.Where("cloud_account_id = ? AND tenant_id = ? AND cloud_account_id IN (?)", req.AccountID, tenantID, h.accessibleCloudAccountSubquery(requestActor(c))).First(&policy).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该凭证尚未绑定 AutoScaler 策略。请先配置策略以获取 Cloud-Init 等参数。"})
		return
	}

	// 异步调用手动扩容
	go h.AutoScaler.ScaleUpManual(context.Background(), &policy, req.Count, req.InstanceType, req.Region)

	c.JSON(http.StatusOK, gin.H{
		"status":  "accepted",
		"message": fmt.Sprintf("Creating %d instance(s) with account %s", req.Count, account.Name),
	})
}

func (h *CloudHandler) deleteCloudInstanceReal(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var inst db.CloudInstance
	if err := h.DB.Where("id = ? AND tenant_id = ? AND cloud_account_id IN (?)", id, tenantID, h.accessibleCloudAccountSubquery(requestActor(c))).First(&inst).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found"})
		return
	}

	// 已终止/错误/无云端ID的实例 → 直接从数据库删除
	needsCloudTerminate := inst.ProviderInstanceID != "" &&
		inst.Status != db.CloudStatusTerminated &&
		inst.Status != db.CloudStatusError

	if !needsCloudTerminate {
		h.DB.
			Delete(&inst)
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"message": fmt.Sprintf("实例 %s 已从数据库清理（状态: %s）", id, inst.Status),
		})
		return
	}

	if inst.Status == db.CloudStatusTerminating {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Instance is already terminating"})
		return
	}

	// 异步销毁有云端ID的活跃实例
	go func() {
		var account db.CloudAccount
		if err := h.DB.First(&account, "id = ? AND tenant_id = ?", inst.CloudAccountID, inst.TenantID).Error; err != nil {
			h.DB.
				Model(&inst).Updates(map[string]interface{}{"status": db.CloudStatusTerminated})
			return
		}
		provider, err := h.ProviderFactory(&account)
		if err != nil {
			h.DB.
				Model(&inst).Updates(map[string]interface{}{"status": db.CloudStatusTerminated})
			return
		}
		rm := cloud.NewResourceManager(provider)
		rm.SetDB(h.DB)
		_ = rm.TerminateInstance(context.Background(), &inst)
	}()

	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": fmt.Sprintf("Instance %s is being terminated", id)})
}

type cleanupCloudInstancesRequest struct {
	Confirm bool   `json:"confirm"`
	Reason  string `json:"reason"`
}

func (h *CloudHandler) cleanupCloudInstances(c *gin.Context) {
	tenantID := currentTenantID(c)
	var req cleanupCloudInstancesRequest
	if err := json.NewDecoder(c.Request.Body).Decode(&req); err != nil || !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm=true is required"})
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "manual cloud instance cleanup"
	}

	var cleaned int64
	if err := h.DB.Transaction(func(tx *gorm.DB) error {
		res := tx.Where("tenant_id = ? AND cloud_account_id IN (?) AND status IN ?",
			tenantID, h.accessibleCloudAccountSubquery(requestActor(c)), []string{db.CloudStatusTerminated, db.CloudStatusError},
		).Delete(&db.CloudInstance{})
		if res.Error != nil {
			return res.Error
		}
		cleaned = res.RowsAffected

		payload, err := json.Marshal(map[string]interface{}{
			"count":       cleaned,
			"operator_id": currentUserID(c),
			"reason":      reason,
			"statuses":    []string{db.CloudStatusTerminated, db.CloudStatusError},
		})
		if err != nil {
			return err
		}
		return tx.Create(&db.WSEventLog{
			TenantID:   tenantID,
			EventType:  "cloud.instances.cleanup",
			Payload:    string(payload),
			OccurredAt: time.Now().UTC(),
		}).Error
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[Cloud] cleaned %d terminal instance records tenant=%s operator=%s reason=%q", cleaned, tenantID, currentUserID(c), reason)
	c.JSON(http.StatusOK, gin.H{
		"status": "cleaned",
		"count":  cleaned,
	})
}

func (h *CloudHandler) rebootCloudInstance(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var inst db.CloudInstance
	if err := h.DB.Where("id = ? AND tenant_id = ? AND cloud_account_id IN (?)", id, tenantID, h.accessibleCloudAccountSubquery(requestActor(c))).First(&inst).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found"})
		return
	}

	// 只允许对 Running / Error / WaitingReady 状态的实例执行重启
	allowed := map[string]bool{
		db.CloudStatusRunning:      true,
		db.CloudStatusError:        true,
		db.CloudStatusWaitingReady: true,
	}
	if !allowed[inst.Status] {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Cannot reboot instance in %s status", inst.Status),
		})
		return
	}

	if inst.ProviderInstanceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Instance has no provider ID yet"})
		return
	}

	// 异步执行重启
	go func() {
		var account db.CloudAccount
		if err := h.DB.First(&account, "id = ? AND tenant_id = ?", inst.CloudAccountID, inst.TenantID).Error; err != nil {
			return
		}
		provider, err := h.ProviderFactory(&account)
		if err != nil {
			return
		}
		rm := cloud.NewResourceManager(provider)
		rm.SetDB(h.DB)
		_ = rm.RebootInstance(context.Background(), &inst)
	}()

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": fmt.Sprintf("Instance %s reboot initiated", id),
	})
}
