package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/cloud"
	"github.com/user/dddd-server/internal/db"
)

// ============================================================================
// Cloud Resource Management API Handlers
//
// 替换原有的 mock 云实例接口，提供完整的凭证、策略、实例管理能力。
// ============================================================================

// cloudAutoScaler 由 main.go 通过 SetAutoScaler 注入
var cloudAutoScaler *cloud.AutoScaler

// SetAutoScaler 注入 AutoScaler 实例
func SetAutoScaler(as *cloud.AutoScaler) {
	cloudAutoScaler = as
}

// ==================== 云账号凭证管理 ====================

func listCloudAccounts(c *gin.Context) {
	tenantID := currentTenantID(c)
	var accounts []db.CloudAccount
	db.DB.Where("tenant_id = ?", tenantID).Order("created_at DESC").Find(&accounts)

	type AccountResp struct {
		ID                   string `json:"id"`
		Name                 string `json:"name"`
		Provider             string `json:"provider"`
		AccessKeyID          string `json:"access_key_id"`
		Region               string `json:"region"`
		DefaultImageID       string `json:"default_image_id"`
		DefaultInstanceType  string `json:"default_instance_type"`
		DefaultSecurityGroup string `json:"default_security_group"`
		DefaultVSwitch       string `json:"default_v_switch"`
		OSSBucket            string `json:"oss_bucket"`
		OSSEndpoint          string `json:"oss_endpoint"`
		Status               string `json:"status"`
		CreatedAt            string `json:"created_at"`
	}

	resp := make([]AccountResp, 0, len(accounts))
	for _, a := range accounts {
		// 解密 AK ID 后脱敏
		akID, _ := cloud.DecryptSecret(a.AccessKeyID)
		resp = append(resp, AccountResp{
			ID:                   a.ID,
			Name:                 a.Name,
			Provider:             a.Provider,
			AccessKeyID:          cloud.MaskSecret(akID),
			Region:               a.Region,
			DefaultImageID:       a.DefaultImageID,
			DefaultInstanceType:  a.DefaultInstanceType,
			DefaultSecurityGroup: a.DefaultSecurityGroup,
			DefaultVSwitch:       a.DefaultVSwitch,
			OSSBucket:            a.OSSBucket,
			OSSEndpoint:          a.OSSEndpoint,
			Status:               a.Status,
			CreatedAt:            a.CreatedAt.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, resp)
}

func createCloudAccount(c *gin.Context) {
	var req struct {
		Name                 string `json:"name" binding:"required"`
		Provider             string `json:"provider" binding:"required"`
		AccessKeyID          string `json:"access_key_id" binding:"required"`
		AccessKeySecret      string `json:"access_key_secret" binding:"required"`
		Region               string `json:"region" binding:"required"`
		DefaultImageID       string `json:"default_image_id"`
		DefaultInstanceType  string `json:"default_instance_type"`
		DefaultSecurityGroup string `json:"default_security_group"`
		DefaultVSwitch       string `json:"default_v_switch"`
		OSSBucket            string `json:"oss_bucket"`
		OSSEndpoint          string `json:"oss_endpoint"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 加密凭证
	encAKID, err := cloud.EncryptSecret(req.AccessKeyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt credentials"})
		return
	}
	encAKSecret, err := cloud.EncryptSecret(req.AccessKeySecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt credentials"})
		return
	}

	account := db.CloudAccount{
		ID:                   fmt.Sprintf("ca-%d", time.Now().UnixNano()),
		TenantID:             currentTenantID(c),
		Name:                 req.Name,
		Provider:             req.Provider,
		AccessKeyID:          encAKID,
		AccessKeySecret:      encAKSecret,
		Region:               req.Region,
		DefaultImageID:       req.DefaultImageID,
		DefaultInstanceType:  req.DefaultInstanceType,
		DefaultSecurityGroup: req.DefaultSecurityGroup,
		DefaultVSwitch:       req.DefaultVSwitch,
		OSSBucket:            req.OSSBucket,
		OSSEndpoint:          req.OSSEndpoint,
		Status:               "active",
	}

	if err := db.DB.Create(&account).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "id": account.ID})
}

func updateCloudAccount(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var req struct {
		Name                 string `json:"name"`
		Region               string `json:"region"`
		DefaultImageID       string `json:"default_image_id"`
		DefaultInstanceType  string `json:"default_instance_type"`
		DefaultSecurityGroup string `json:"default_security_group"`
		DefaultVSwitch       string `json:"default_v_switch"`
		AccessKeyID          string `json:"access_key_id"`
		AccessKeySecret      string `json:"access_key_secret"`
		OSSBucket            string `json:"oss_bucket"`
		OSSEndpoint          string `json:"oss_endpoint"`
		Status               string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Region != "" {
		updates["region"] = req.Region
	}
	if req.DefaultImageID != "" {
		updates["default_image_id"] = req.DefaultImageID
	}
	if req.DefaultInstanceType != "" {
		updates["default_instance_type"] = req.DefaultInstanceType
	}
	if req.DefaultSecurityGroup != "" {
		updates["default_security_group"] = req.DefaultSecurityGroup
	}
	if req.DefaultVSwitch != "" {
		updates["default_v_switch"] = req.DefaultVSwitch
	}
	if req.Status != "" {
		updates["status"] = req.Status
	}
	if req.AccessKeyID != "" {
		enc, _ := cloud.EncryptSecret(req.AccessKeyID)
		updates["access_key_id"] = enc
	}
	if req.AccessKeySecret != "" {
		enc, _ := cloud.EncryptSecret(req.AccessKeySecret)
		updates["access_key_secret"] = enc
	}
	if req.OSSBucket != "" {
		updates["oss_bucket"] = req.OSSBucket
	}
	if req.OSSEndpoint != "" {
		updates["oss_endpoint"] = req.OSSEndpoint
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	if err := db.DB.Model(&db.CloudAccount{}).Where("id = ? AND tenant_id = ?", id, tenantID).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 如果凭证被更新，清除 AutoScaler 中缓存的旧 Provider
	if _, hasAK := updates["access_key_id"]; hasAK {
		if cloudAutoScaler != nil {
			cloudAutoScaler.InvalidateManager(id)
		}
	}
	if _, hasSK := updates["access_key_secret"]; hasSK {
		if cloudAutoScaler != nil {
			cloudAutoScaler.InvalidateManager(id)
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func deleteCloudAccount(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).Delete(&db.CloudAccount{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func testCloudAccount(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var account db.CloudAccount
	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	// 尝试创建 Provider 并调用 ListInstances 验证连通性
	provider, err := cloud.NewProviderFromAccount(&account)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
		return
	}

	_, err = provider.ListInstances(map[string]string{"argus:managed": "true"})
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "Connection successful"})
}

// ==================== 伸缩策略管理 ====================

func listCloudPolicies(c *gin.Context) {
	tenantID := currentTenantID(c)
	var policies []db.CloudScalingPolicy
	db.DB.Where("tenant_id = ?", tenantID).Order("created_at DESC").Find(&policies)
	c.JSON(http.StatusOK, policies)
}

func createCloudPolicy(c *gin.Context) {
	var req db.CloudScalingPolicy
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	req.ID = fmt.Sprintf("cp-%d", time.Now().UnixNano())
	req.TenantID = currentTenantID(c)
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
		req.SpotStrategy = "NoSpot"
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

	if err := db.DB.Model(&db.CloudScalingPolicy{}).Where("id = ? AND tenant_id = ?", id, tenantID).Updates(req).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func deleteCloudPolicy(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).Delete(&db.CloudScalingPolicy{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func toggleCloudPolicy(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var policy db.CloudScalingPolicy
	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&policy).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	newEnabled := !policy.Enabled
	db.DB.Model(&policy).Update("enabled", newEnabled)

	c.JSON(http.StatusOK, gin.H{"status": "ok", "enabled": newEnabled})
}

// ==================== 云实例管理 ====================

func listCloudInstancesReal(c *gin.Context) {
	tenantID := currentTenantID(c)
	var instances []db.CloudInstance
	db.DB.Where("tenant_id = ? AND deleted_at IS NULL", tenantID).Order("created_at DESC").Find(&instances)
	c.JSON(http.StatusOK, instances)
}

func createCloudInstanceManual(c *gin.Context) {
	var req struct {
		AccountID string `json:"account_id" binding:"required"`
		Count     int    `json:"count"`
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

	var account db.CloudAccount
	if err := db.DB.Where("id = ? AND tenant_id = ? AND status = ?", req.AccountID, tenantID, "active").First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Cloud account not found or disabled"})
		return
	}

	if cloudAutoScaler == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "AutoScaler not initialized"})
		return
	}

	var policy db.CloudScalingPolicy
	if err := db.DB.Where("cloud_account_id = ? AND tenant_id = ?", req.AccountID, tenantID).First(&policy).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该凭证尚未绑定 AutoScaler 策略。请先配置策略以获取 Cloud-Init 等参数。"})
		return
	}

	// 异步调用手动扩容
	go cloudAutoScaler.ScaleUpManual(context.Background(), &policy, req.Count)

	c.JSON(http.StatusOK, gin.H{
		"status":  "accepted",
		"message": fmt.Sprintf("Creating %d instance(s) with account %s", req.Count, account.Name),
	})
}

func deleteCloudInstanceReal(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var inst db.CloudInstance
	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&inst).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Instance not found"})
		return
	}

	if inst.Status == db.CloudStatusTerminated || inst.Status == db.CloudStatusTerminating {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Instance already terminated or terminating"})
		return
	}

	// 异步销毁
	go func() {
		var account db.CloudAccount
		if err := db.DB.First(&account, "id = ?", inst.CloudAccountID).Error; err != nil {
			return
		}
		provider, err := cloud.NewProviderFromAccount(&account)
		if err != nil {
			return
		}
		rm := cloud.NewResourceManager(provider)
		rm.SetDB(db.DB)
		_ = rm.TerminateInstance(nil, &inst)
	}()

	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": fmt.Sprintf("Instance %s is being terminated", id)})
}

func rebootCloudInstance(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var inst db.CloudInstance
	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&inst).Error; err != nil {
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
		if err := db.DB.First(&account, "id = ?", inst.CloudAccountID).Error; err != nil {
			return
		}
		provider, err := cloud.NewProviderFromAccount(&account)
		if err != nil {
			return
		}
		rm := cloud.NewResourceManager(provider)
		rm.SetDB(db.DB)
		_ = rm.RebootInstance(nil, &inst)
	}()

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": fmt.Sprintf("Instance %s reboot initiated", id),
	})
}

// ==================== 云仪表盘 ====================

func cloudDashboard(c *gin.Context) {
	tenantID := currentTenantID(c)

	var totalAccounts int64
	db.DB.Model(&db.CloudAccount{}).Where("tenant_id = ? AND status = ?", tenantID, "active").Count(&totalAccounts)

	var enabledPolicies int64
	db.DB.Model(&db.CloudScalingPolicy{}).Where("tenant_id = ? AND enabled = ?", tenantID, true).Count(&enabledPolicies)

	var runningInstances int64
	db.DB.Model(&db.CloudInstance{}).Where("tenant_id = ? AND status IN ?", tenantID, []string{
		db.CloudStatusProvisioning, db.CloudStatusWaitingReady, db.CloudStatusRunning,
	}).Count(&runningInstances)

	var totalInstances int64
	db.DB.Model(&db.CloudInstance{}).Where("tenant_id = ?", tenantID).Count(&totalInstances)

	// 最近 10 条实例事件
	var recentInstances []db.CloudInstance
	db.DB.Where("tenant_id = ?", tenantID).Order("updated_at DESC").Limit(10).Find(&recentInstances)

	c.JSON(http.StatusOK, gin.H{
		"active_accounts":   totalAccounts,
		"enabled_policies":  enabledPolicies,
		"running_instances": runningInstances,
		"total_instances":   totalInstances,
		"recent_events":     recentInstances,
	})
}

// ==================== OSS Agent 分发 ====================

// uploadAgentToOSS 将 release 目录中的 Agent 二进制上传到指定账号的 OSS 存储桶
func uploadAgentToOSS(c *gin.Context) {
	accountID := c.Param("id")
	tenantID := currentTenantID(c)

	var account db.CloudAccount
	if err := db.DB.Where("id = ? AND tenant_id = ?", accountID, tenantID).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	if account.OSSBucket == "" || account.OSSEndpoint == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OSS not configured for this account. Please set oss_bucket and oss_endpoint."})
		return
	}

	uploader, err := cloud.NewOSSFromAccount(&account)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create OSS client: %v", err)})
		return
	}

	releaseDir := "./release"
	results, err := uploader.UploadAgentBinaries(releaseDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Upload failed: %v", err)})
		return
	}

	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": fmt.Sprintf("Uploaded %d/%d agent binaries to OSS", successCount, len(results)),
		"results": results,
	})
}

// testOSSConnection 测试指定账号的 OSS 连通性
func testOSSConnection(c *gin.Context) {
	accountID := c.Param("id")
	tenantID := currentTenantID(c)

	var account db.CloudAccount
	if err := db.DB.Where("id = ? AND tenant_id = ?", accountID, tenantID).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	if account.OSSBucket == "" || account.OSSEndpoint == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OSS not configured"})
		return
	}

	uploader, err := cloud.NewOSSFromAccount(&account)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "error", "message": fmt.Sprintf("Failed to create OSS client: %v", err)})
		return
	}

	if err := uploader.TestConnection(); err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "error", "message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "OSS connection successful"})
}

// discoverCloudResources 通过 AK/SK 自动发现该地域下可用的云资源
func discoverCloudResources(c *gin.Context) {
	accountID := c.Param("id")
	tenantID := currentTenantID(c)

	var account db.CloudAccount
	if err := db.DB.Where("id = ? AND tenant_id = ?", accountID, tenantID).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	provider, err := cloud.NewProviderFromAccount(&account)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("创建 Provider 失败: %v", err)})
		return
	}

	// 类型断言为 ECSProvider 以调用 DiscoverResources
	type discoverer interface {
		DiscoverResources() (interface{}, error)
	}
	disc, ok := provider.(discoverer)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该 Provider 不支持资源发现"})
		return
	}

	result, err := disc.DiscoverResources()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("资源发现失败: %v", err)})
		return
	}

	c.JSON(http.StatusOK, result)
}

// autoConfigureCloudAccount 将用户选择的发现结果写入 CloudAccount 配置
func autoConfigureCloudAccount(c *gin.Context) {
	accountID := c.Param("id")
	tenantID := currentTenantID(c)

	var req struct {
		DefaultInstanceType  string `json:"default_instance_type"`
		DefaultImageID       string `json:"default_image_id"`
		DefaultSecurityGroup string `json:"default_security_group"`
		DefaultVSwitch       string `json:"default_v_switch"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{}
	if req.DefaultInstanceType != "" {
		updates["default_instance_type"] = req.DefaultInstanceType
	}
	if req.DefaultImageID != "" {
		updates["default_image_id"] = req.DefaultImageID
	}
	if req.DefaultSecurityGroup != "" {
		updates["default_security_group"] = req.DefaultSecurityGroup
	}
	if req.DefaultVSwitch != "" {
		updates["default_v_switch"] = req.DefaultVSwitch
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "没有需要更新的字段"})
		return
	}

	if err := db.DB.Model(&db.CloudAccount{}).Where("id = ? AND tenant_id = ?", accountID, tenantID).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "配置已更新"})
}
