package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/cloud"
	"github.com/user/dddd-server/internal/cloud/aliyun"
	"github.com/user/dddd-server/internal/db"
)

// ============================================================================
// Cloud Resource Management API Handlers
//
// 替换原有的 mock 云实例接口，提供完整的凭证、策略、实例管理能力。
// ============================================================================

// cloudAutoScaler 由 main.go 通过 SetAutoScaler 注入
var cloudAutoScaler *cloud.AutoScaler

const requiredAgentObjectKey = "argus/agent/dddd-agent-linux-amd64"

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
		Region               string `json:"region"`
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

	var account db.CloudAccount
	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	var activeInstances int64
	db.DB.Model(&db.CloudInstance{}).
		Where("cloud_account_id = ? AND tenant_id = ? AND deleted_at IS NULL AND status <> ?", id, tenantID, db.CloudStatusTerminated).
		Count(&activeInstances)
	if activeInstances > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Cloud account still has %d active instance(s); terminate them before deletion", activeInstances),
		})
		return
	}

	var boundPolicies int64
	db.DB.Model(&db.CloudScalingPolicy{}).
		Where("cloud_account_id = ? AND tenant_id = ?", id, tenantID).
		Count(&boundPolicies)
	if boundPolicies > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Cloud account still has %d scaling policy/policies; delete them before deletion", boundPolicies),
		})
		return
	}

	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).Delete(&db.CloudAccount{}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if cloudAutoScaler != nil {
		cloudAutoScaler.InvalidateManager(account.ID)
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

	// 尝试创建 Provider 并验证连通性
	// 如果未配置 Region，使用 DescribeRegions（全局 API）验证 AK/SK 有效性
	provider, err := cloud.NewProviderFromAccount(&account)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	if account.Region == "" {
		// 无 Region 时用 DescribeRegions 验证凭证
		type regionDiscoverer interface {
			DiscoverRegions() ([]aliyun.RegionInfo, error)
		}
		if rd, ok := provider.(regionDiscoverer); ok {
			_, err = rd.DiscoverRegions()
		} else {
			_, err = provider.ListInstances(map[string]string{"argus:managed": "true"})
		}
	} else {
		_, err = provider.ListInstances(map[string]string{"argus:managed": "true"})
	}
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
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

	tenantID := currentTenantID(c)
	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Policy name is required"})
		return
	}
	if strings.TrimSpace(req.CloudAccountID) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cloud account is required"})
		return
	}
	var account db.CloudAccount
	if err := db.DB.Select("id").Where("id = ? AND tenant_id = ?", req.CloudAccountID, tenantID).First(&account).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cloud account not found"})
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
		var account db.CloudAccount
		if err := db.DB.Select("id").Where("id = ? AND tenant_id = ?", accountID, tenantID).First(&account).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Cloud account not found"})
			return
		}
	}

	result := db.DB.Model(&db.CloudScalingPolicy{}).Where("id = ? AND tenant_id = ?", id, tenantID).Updates(req)
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
		Where("policy_id = ? AND tenant_id = ? AND deleted_at IS NULL AND status NOT IN ?", id, tenantID, []string{db.CloudStatusTerminated, db.CloudStatusTerminating}).
		Count(&activeInstances)
	if activeInstances > 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Policy still has %d active instance(s); terminate them before deletion", activeInstances),
		})
		return
	}

	result := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).Delete(&db.CloudScalingPolicy{})
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
	go cloudAutoScaler.ScaleUpManual(context.Background(), &policy, req.Count, req.InstanceType, req.Region)

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

	// 已终止/错误/无云端ID的实例 → 直接从数据库删除
	needsCloudTerminate := inst.ProviderInstanceID != "" &&
		inst.Status != db.CloudStatusTerminated &&
		inst.Status != db.CloudStatusError

	if !needsCloudTerminate {
		// 直接删除数据库记录
		db.DB.Delete(&inst)
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
		if err := db.DB.First(&account, "id = ?", inst.CloudAccountID).Error; err != nil {
			// 凭证也找不到，直接标记终止
			db.DB.Model(&inst).Updates(map[string]interface{}{"status": db.CloudStatusTerminated})
			return
		}
		provider, err := cloud.NewProviderFromAccount(&account)
		if err != nil {
			db.DB.Model(&inst).Updates(map[string]interface{}{"status": db.CloudStatusTerminated})
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
		_ = rm.RebootInstance(context.Background(), &inst)
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

// listReleaseFiles 列出服务器端 ./release 目录中的 Agent 二进制文件
func listReleaseFiles(c *gin.Context) {
	releaseDir := "./release"

	if _, err := os.Stat(releaseDir); os.IsNotExist(err) {
		c.JSON(http.StatusOK, gin.H{"files": []interface{}{}, "release_dir": releaseDir})
		return
	}

	entries, err := os.ReadDir(releaseDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("读取 release 目录失败: %v", err)})
		return
	}

	type fileInfo struct {
		Name     string    `json:"name"`
		Size     int64     `json:"size"`
		Modified time.Time `json:"modified"`
	}

	var files []fileInfo
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, fileInfo{
			Name:     entry.Name(),
			Size:     info.Size(),
			Modified: info.ModTime(),
		})
	}

	if files == nil {
		files = []fileInfo{}
	}

	c.JSON(http.StatusOK, gin.H{"files": files, "release_dir": releaseDir})
}

// uploadAgentToOSS 将 release 目录中的 Agent 二进制上传到指定账号的 OSS 存储桶
// 支持可选的 files 参数来指定要上传的文件名列表
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

	// 解析可选的 files 参数
	var req struct {
		Files []string `json:"files"`
	}
	_ = c.ShouldBindJSON(&req) // 忽略解析错误，兼容无 body 的请求

	releaseDir := "./release"
	if _, err := os.Stat(releaseDir); os.IsNotExist(err) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "服务器本地不存在 ./release 目录，请先构建 Agent 二进制或将制品放置到该目录下"})
		return
	}

	// 如果指定了 files 列表，只上传指定文件
	if len(req.Files) > 0 {
		filterSet := make(map[string]bool)
		for _, f := range req.Files {
			filterSet[f] = true
		}

		var results []cloud.OSSUploadResult
		for _, fname := range req.Files {
			localPath := filepath.Join(releaseDir, fname)
			objectKey := fmt.Sprintf("argus/agent/%s", fname)

			info, err := os.Stat(localPath)
			if err != nil {
				results = append(results, cloud.OSSUploadResult{
					Filename:  fname,
					ObjectKey: objectKey,
					Error:     fmt.Sprintf("文件不存在: %v", err),
				})
				continue
			}

			result := cloud.OSSUploadResult{
				Filename:  fname,
				ObjectKey: objectKey,
				Size:      info.Size(),
			}
			if err := uploader.UploadFile(localPath, objectKey); err != nil {
				result.Error = err.Error()
			} else {
				result.Success = true
			}
			results = append(results, result)
		}

		successCount := 0
		for _, r := range results {
			if r.Success {
				successCount++
			}
		}
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"message": fmt.Sprintf("已上传 %d/%d 个文件到 OSS", successCount, len(results)),
			"results": results,
		})
		return
	}

	// 默认行为：上传全部 agent 二进制
	results, err := uploader.UploadAgentBinaries(releaseDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Upload failed: %v", err)})
		return
	}

	successCount := 0
	failedCount := 0
	requiredFound := false
	requiredUploaded := false
	for _, r := range results {
		if r.Success {
			successCount++
		} else {
			failedCount++
		}
		if r.ObjectKey == requiredAgentObjectKey {
			requiredFound = true
			requiredUploaded = r.Success
		}
	}
	if len(results) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "./release 目录下未找到 Agent 二进制文件（dddd-agent-*），请先构建 Agent"})
		return
	}
	if !requiredFound {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Required agent binary %s was not found in ./release", requiredAgentObjectKey)})
		return
	}
	if !requiredUploaded {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   fmt.Sprintf("Agent 核心制品未上传成功，当前成功 %d/%d", successCount, len(results)),
			"results": results,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":       "ok",
		"message":      fmt.Sprintf("Agent 制品已在 OSS 就绪（成功上传 %d/%d，非关键文件失败 %d 个）", successCount, len(results), failedCount),
		"failed_count": failedCount,
		"results":      results,
	})
}

// uploadLocalAgentToOSS 接收本地上传的文件，保存到 ./release 目录并推送到 OSS
func uploadLocalAgentToOSS(c *gin.Context) {
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

	// 确保 ./release 目录存在
	releaseDir := "./release"
	if err := os.MkdirAll(releaseDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("创建 release 目录失败: %v", err)})
		return
	}

	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("解析上传表单失败: %v", err)})
		return
	}

	uploadedFiles := form.File["files"]
	if len(uploadedFiles) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未提供上传文件"})
		return
	}

	var results []cloud.OSSUploadResult
	for _, fileHeader := range uploadedFiles {
		filename := filepath.Base(fileHeader.Filename) // 防止路径穿越
		localPath := filepath.Join(releaseDir, filename)
		objectKey := fmt.Sprintf("argus/agent/%s", filename)

		result := cloud.OSSUploadResult{
			Filename:  filename,
			ObjectKey: objectKey,
			Size:      fileHeader.Size,
		}

		// 保存到 ./release
		if err := c.SaveUploadedFile(fileHeader, localPath); err != nil {
			result.Error = fmt.Sprintf("保存文件失败: %v", err)
			results = append(results, result)
			continue
		}

		// 推送到 OSS
		if err := uploader.UploadFile(localPath, objectKey); err != nil {
			result.Error = fmt.Sprintf("OSS 上传失败: %v", err)
		} else {
			result.Success = true
		}
		results = append(results, result)
	}

	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": fmt.Sprintf("%d/%d 个文件已保存到服务器并上传到 OSS", successCount, len(results)),
		"results": results,
	})
}

// listOSSFiles 列出 OSS 存储桶中 argus/agent/ 前缀下的所有文件
func listOSSFiles(c *gin.Context) {
	accountID := c.Param("id")
	tenantID := currentTenantID(c)

	var account db.CloudAccount
	if err := db.DB.Where("id = ? AND tenant_id = ?", accountID, tenantID).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	if account.OSSBucket == "" || account.OSSEndpoint == "" {
		c.JSON(http.StatusOK, gin.H{"files": []interface{}{}, "bucket": "", "prefix": "argus/agent/"})
		return
	}

	uploader, err := cloud.NewOSSFromAccount(&account)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("创建 OSS 客户端失败: %v", err)})
		return
	}

	prefix := c.DefaultQuery("prefix", "argus/agent/")
	files, err := uploader.ListFiles(prefix)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("列出 OSS 文件失败: %v", err)})
		return
	}

	if files == nil {
		files = []cloud.OSSFileInfo{}
	}

	c.JSON(http.StatusOK, gin.H{
		"files":  files,
		"bucket": account.OSSBucket,
		"prefix": prefix,
	})
}

// deleteOSSFile 从 OSS 存储桶中删除指定文件
func deleteOSSFile(c *gin.Context) {
	accountID := c.Param("id")
	tenantID := currentTenantID(c)

	var account db.CloudAccount
	if err := db.DB.Where("id = ? AND tenant_id = ?", accountID, tenantID).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	var req struct {
		ObjectKey string `json:"object_key" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请指定要删除的文件 object_key"})
		return
	}

	// 安全检查：只允许删除 argus/agent/ 前缀的文件
	if !strings.HasPrefix(req.ObjectKey, "argus/agent/") {
		c.JSON(http.StatusForbidden, gin.H{"error": "只允许删除 argus/agent/ 前缀下的文件"})
		return
	}

	uploader, err := cloud.NewOSSFromAccount(&account)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("创建 OSS 客户端失败: %v", err)})
		return
	}

	if err := uploader.DeleteFile(req.ObjectKey); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("删除文件失败: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": fmt.Sprintf("已从 OSS 删除: %s", req.ObjectKey)})
}

// testOSSConnection 测试指定账号的 OSS 连通性，返回详细检测报告
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
		c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("Failed to create OSS client: %v", err)})
		return
	}

	// 测试连通性
	connOK := true
	connErr := ""
	if err := uploader.TestConnection(); err != nil {
		connOK = false
		connErr = err.Error()
	}

	// 列出 agent 前缀下的文件
	var fileCount int
	var totalSize int64
	var agentFound bool
	var fileDetails []map[string]interface{}

	if connOK {
		files, err := uploader.ListFiles("argus/agent/")
		if err == nil {
			fileCount = len(files)
			for _, f := range files {
				totalSize += f.Size
				if f.Key == requiredAgentObjectKey {
					agentFound = true
				}
				fileDetails = append(fileDetails, map[string]interface{}{
					"key":  f.Key,
					"size": f.Size,
				})
			}
		}
	}

	result := gin.H{
		"status":         "ok",
		"connection":     connOK,
		"connection_err": connErr,
		"bucket":         account.OSSBucket,
		"endpoint":       account.OSSEndpoint,
		"file_count":     fileCount,
		"total_size":     totalSize,
		"agent_ready":    agentFound,
		"required_agent": requiredAgentObjectKey,
		"files":          fileDetails,
	}

	if !connOK {
		result["status"] = "error"
		result["message"] = fmt.Sprintf("OSS 连接失败: %s", connErr)
		c.JSON(http.StatusOK, result) // 返回 200 但 status=error，让前端解析详情
		return
	}

	result["message"] = "OSS 连通性测试通过"
	c.JSON(http.StatusOK, result)
}

// listCloudRegions 通过 AK/SK 自动获取所有可用地域列表
func listCloudRegions(c *gin.Context) {
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

	type regionDiscoverer interface {
		DiscoverRegions() ([]aliyun.RegionInfo, error)
	}
	rd, ok := provider.(regionDiscoverer)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该 Provider 不支持地域发现"})
		return
	}

	regions, err := rd.DiscoverRegions()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("地域发现失败: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"regions": regions})
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

// oneClickSetup 一键配置：自动发现资源 → 选择最优默认值 → 写入凭证 → 创建策略
func oneClickSetup(c *gin.Context) {
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

	type discoverer interface {
		DiscoverResources() (interface{}, error)
	}
	type networkBuilder interface {
		AutoCreateNetwork() (sgID string, vswID string, err error)
		AutoCreateOSS(accountID string) (bucketName string, endpoint string, err error)
	}

	disc, ok := provider.(discoverer)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该 Provider 不支持资源发现"})
		return
	}

	rawResult, err := disc.DiscoverResources()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("资源发现失败: %v", err)})
		return
	}

	type resourceItem struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Desc string `json:"desc"`
	}
	type instanceTypeItem struct {
		ID     string  `json:"id"`
		CPU    int     `json:"cpu"`
		Memory float64 `json:"memory_gb"`
		Family string  `json:"family"`
	}
	type discoveryResult struct {
		SecurityGroups []resourceItem     `json:"security_groups"`
		VSwitches      []resourceItem     `json:"v_switches"`
		Images         []resourceItem     `json:"images"`
		InstanceTypes  []instanceTypeItem `json:"instance_types"`
	}

	jsonBytes, _ := json.Marshal(rawResult)
	var result discoveryResult
	json.Unmarshal(jsonBytes, &result)

	var warnings []string
	updates := map[string]interface{}{}
	chosen := map[string]string{}

	// 如果没有安全组或交换机，尝试自动创建
	if len(result.SecurityGroups) == 0 || len(result.VSwitches) == 0 {
		if nb, ok := provider.(networkBuilder); ok {
			sgID, vswID, autoErr := nb.AutoCreateNetwork()
			if autoErr == nil {
				if len(result.SecurityGroups) == 0 && sgID != "" {
					result.SecurityGroups = []resourceItem{{ID: sgID, Name: "argus-auto-sg", Desc: "Auto created"}}
				}
				if len(result.VSwitches) == 0 && vswID != "" {
					result.VSwitches = []resourceItem{{ID: vswID, Name: "argus-auto-vsw", Desc: "Auto created"}}
				}
			} else {
				warnings = append(warnings, fmt.Sprintf("自动创建网络资源失败: %v", autoErr))
			}
		}
	}

	// 实例规格：总是覆盖，优先 ecs.c6.large
	if len(result.InstanceTypes) > 0 {
		pick := result.InstanceTypes[0].ID
		for _, it := range result.InstanceTypes {
			if it.ID == "ecs.c6.large" {
				pick = it.ID
				break
			}
		}
		updates["default_instance_type"] = pick
		chosen["instance_type"] = pick
	} else {
		warnings = append(warnings, "未发现可用的实例规格（可能缺少 DescribeInstanceTypes 权限）")
	}

	// 镜像：总是覆盖，优先 ubuntu 22
	if len(result.Images) > 0 {
		pick := result.Images[0].ID
		pickName := result.Images[0].Name
		for _, img := range result.Images {
			if containsIgnoreCase(img.Name, "ubuntu") && containsIgnoreCase(img.Name, "22") {
				pick = img.ID
				pickName = img.Name
				break
			}
		}
		updates["default_image_id"] = pick
		chosen["image_id"] = pick
		chosen["image_name"] = pickName
	} else {
		warnings = append(warnings, "未发现可用的系统镜像（可能缺少 DescribeImages 权限）")
	}

	// 安全组：总是覆盖
	if len(result.SecurityGroups) > 0 {
		updates["default_security_group"] = result.SecurityGroups[0].ID
		chosen["security_group"] = result.SecurityGroups[0].ID
		chosen["security_group_name"] = result.SecurityGroups[0].Name
	} else {
		warnings = append(warnings, "未发现安全组。请确认: 1) AK/SK 有 DescribeSecurityGroups 权限 2) 该地域下已创建 VPC 和安全组")
	}

	// 交换机：总是覆盖
	if len(result.VSwitches) > 0 {
		updates["default_v_switch"] = result.VSwitches[0].ID
		chosen["v_switch"] = result.VSwitches[0].ID
		chosen["v_switch_name"] = result.VSwitches[0].Name
	} else {
		warnings = append(warnings, "未发现交换机 (VSwitch)。请确认: 1) AK/SK 有 DescribeVSwitches 权限 2) 该地域下已创建 VPC 和交换机")
	}

	// OSS 存储桶：如果缺失，则尝试自动创建并配置
	if account.OSSBucket == "" || account.OSSEndpoint == "" {
		if nb, ok := provider.(networkBuilder); ok {
			bucketName, endpoint, autoErr := nb.AutoCreateOSS(accountID)
			if autoErr == nil {
				updates["oss_bucket"] = bucketName
				updates["oss_endpoint"] = endpoint
				chosen["oss_bucket"] = bucketName
				chosen["oss_endpoint"] = endpoint

				account.OSSBucket = bucketName
				account.OSSEndpoint = endpoint
			} else {
				warnings = append(warnings, fmt.Sprintf("自动创建 OSS 存储桶失败: %v", autoErr))
			}
		}
	}

	configuredAccount := account
	if bucket, ok := updates["oss_bucket"].(string); ok && bucket != "" {
		configuredAccount.OSSBucket = bucket
	}
	if endpoint, ok := updates["oss_endpoint"].(string); ok && endpoint != "" {
		configuredAccount.OSSEndpoint = endpoint
	}

	if configuredAccount.OSSBucket != "" && configuredAccount.OSSEndpoint != "" {
		if err := ensureRequiredAgentArtifact(&configuredAccount); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("Agent binary is not ready for OSS distribution: %v", err),
			})
			return
		}
	}

	if len(updates) > 0 {
		if err := db.DB.Model(&db.CloudAccount{}).Where("id = ? AND tenant_id = ?", accountID, tenantID).Updates(updates).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	policyCreated := false
	var existingPolicy db.CloudScalingPolicy
	if err := db.DB.Where("cloud_account_id = ? AND tenant_id = ?", accountID, tenantID).First(&existingPolicy).Error; err != nil {
		newPolicy := db.CloudScalingPolicy{
			ID:                 fmt.Sprintf("cp-%d", time.Now().UnixNano()),
			TenantID:           tenantID,
			CloudAccountID:     accountID,
			Name:               fmt.Sprintf("经济型弹性扫描策略 - %s", account.Name),
			Enabled:            false,
			MinInstances:       0,               // 零保底：空闲时零成本
			MaxInstances:       5,               // 硬性上限：防止账单爆炸
			ScaleUpThreshold:   50,              // 队列 > 50 时扩容
			ScaleDownThreshold: 0,               // 队列清空立刻缩容（最激进省钱）
			CooldownSeconds:    180,             // 3 分钟冷却
			InstanceTTLMinutes: 60,              // 1 小时强制回收
			SpotStrategy:       "SpotAsPriceGo", // 竞价实例，节省 70-90%
		}
		if err := db.DB.Create(&newPolicy).Error; err == nil {
			policyCreated = true
		}
	}

	// 重新读取最新配置
	db.DB.Where("id = ?", accountID).First(&account)

	c.JSON(http.StatusOK, gin.H{
		"status":         "ok",
		"message":        "一键配置完成",
		"chosen":         chosen,
		"warnings":       warnings,
		"policy_created": policyCreated,
		"current_config": gin.H{
			"region":         account.Region,
			"instance_type":  account.DefaultInstanceType,
			"image_id":       account.DefaultImageID,
			"security_group": account.DefaultSecurityGroup,
			"v_switch":       account.DefaultVSwitch,
			"oss_bucket":     account.OSSBucket,
			"oss_endpoint":   account.OSSEndpoint,
		},
		"discovery": gin.H{
			"security_groups": len(result.SecurityGroups),
			"v_switches":      len(result.VSwitches),
			"images":          len(result.Images),
			"instance_types":  len(result.InstanceTypes),
		},
	})
}

func containsIgnoreCase(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func ensureRequiredAgentArtifact(account *db.CloudAccount) error {
	uploader, err := cloud.NewOSSFromAccount(account)
	if err != nil {
		return fmt.Errorf("create OSS client: %w", err)
	}

	exists, err := ossObjectExists(uploader, requiredAgentObjectKey)
	if err != nil {
		return fmt.Errorf("check existing agent artifact: %w", err)
	}
	if exists {
		return nil
	}

	results, err := uploader.UploadAgentBinaries("./release")
	if err != nil {
		return fmt.Errorf("upload agent binaries: %w", err)
	}
	if len(results) == 0 {
		return fmt.Errorf("no agent binaries found in ./release")
	}

	requiredFound := false
	for _, result := range results {
		if result.ObjectKey != requiredAgentObjectKey {
			continue
		}
		requiredFound = true
		if !result.Success {
			return fmt.Errorf("upload %s failed: %s", requiredAgentObjectKey, result.Error)
		}
	}
	if !requiredFound {
		return fmt.Errorf("required agent binary %s is missing from ./release", requiredAgentObjectKey)
	}

	exists, err = ossObjectExists(uploader, requiredAgentObjectKey)
	if err != nil {
		return fmt.Errorf("verify uploaded agent artifact: %w", err)
	}
	if !exists {
		return fmt.Errorf("required agent artifact %s is still missing from OSS after upload", requiredAgentObjectKey)
	}

	return nil
}

func ossObjectExists(uploader cloud.OSSUploader, objectKey string) (bool, error) {
	files, err := uploader.ListFiles("argus/agent/")
	if err != nil {
		return false, err
	}
	for _, file := range files {
		if file.Key == objectKey {
			return true, nil
		}
	}
	return false, nil
}

// ==================== AK/SK 权限检查 ====================

// checkCloudPermissions 检查指定凭证的 AK/SK 拥有的所有权限
func checkCloudPermissions(c *gin.Context) {
	accountID := c.Param("id")
	tenantID := currentTenantID(c)

	var account db.CloudAccount
	if err := db.DB.Where("id = ? AND tenant_id = ?", accountID, tenantID).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	// 解密凭证
	akID, err := cloud.DecryptSecret(account.AccessKeyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "解密 AccessKeyID 失败"})
		return
	}
	akSecret, err := cloud.DecryptSecret(account.AccessKeySecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "解密 AccessKeySecret 失败"})
		return
	}

	// 调用权限检查模块
	result, err := aliyun.CheckPermissions(akID, akSecret, account.Region)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("权限检查失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"data":   result,
	})
}

// ==================== 价格查询 ====================

func queryCloudPrice(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var account db.CloudAccount
	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "凭证不存在"})
		return
	}

	if account.Region == "" || account.DefaultInstanceType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "凭证未配置地域或实例规格，无法查询价格"})
		return
	}

	// 解密凭证
	akID, err := cloud.DecryptSecret(account.AccessKeyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "凭证解密失败"})
		return
	}
	akSecret, err := cloud.DecryptSecret(account.AccessKeySecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "凭证解密失败"})
		return
	}

	// 获取关联策略的竞价策略
	spotStrategy := "SpotAsPriceGo"
	var policy db.CloudScalingPolicy
	if err := db.DB.Where("cloud_account_id = ? AND tenant_id = ?", id, tenantID).First(&policy).Error; err == nil {
		if policy.SpotStrategy != "" {
			spotStrategy = policy.SpotStrategy
		}
	}

	// 允许 query 参数覆盖
	if qs := c.Query("spot_strategy"); qs != "" {
		spotStrategy = qs
	}
	instanceType := account.DefaultInstanceType
	if qt := c.Query("instance_type"); qt != "" {
		instanceType = qt
	}
	region := account.Region
	if qr := c.Query("region"); qr != "" {
		region = qr
	}

	provider, err := aliyun.NewECSProvider(akID, akSecret, region)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("创建 Provider 失败: %v", err)})
		return
	}

	priceInfo, err := provider.QueryPrice(instanceType, spotStrategy)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"status":  "error",
			"message": fmt.Sprintf("价格查询失败: %v", err),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"instance_type":  instanceType,
		"region":         account.Region,
		"spot_strategy":  spotStrategy,
		"instance_price": priceInfo.InstancePrice,
		"spot_price":     priceInfo.SpotPrice,
		"spot_discount":  priceInfo.SpotDiscount,
		"total_hourly":   priceInfo.TotalHourly,
		"currency":       priceInfo.Currency,
		"price_unit":     priceInfo.PriceUnit,
	})
}

// ==================== 可用实例规格查询 ====================

func listAvailableInstanceTypes(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var account db.CloudAccount
	if err := db.DB.Where("id = ? AND tenant_id = ?", id, tenantID).First(&account).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "凭证不存在"})
		return
	}

	if account.Region == "" && c.Query("region") == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "凭证未配置地域，请通过 region 参数指定"})
		return
	}

	akID, err := cloud.DecryptSecret(account.AccessKeyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "凭证解密失败"})
		return
	}
	akSecret, err := cloud.DecryptSecret(account.AccessKeySecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "凭证解密失败"})
		return
	}

	// 获取竞价策略
	spotStrategy := "SpotAsPriceGo"
	var policy db.CloudScalingPolicy
	if err := db.DB.Where("cloud_account_id = ? AND tenant_id = ?", id, tenantID).First(&policy).Error; err == nil {
		if policy.SpotStrategy != "" {
			spotStrategy = policy.SpotStrategy
		}
	}
	if qs := c.Query("spot_strategy"); qs != "" {
		spotStrategy = qs
	}

	region := account.Region
	if qr := c.Query("region"); qr != "" {
		region = qr
	}

	provider, err := aliyun.NewECSProvider(akID, akSecret, region)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("创建 Provider 失败: %v", err)})
		return
	}

	types, err := provider.QueryAvailableInstanceTypes(spotStrategy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("规格查询失败: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"instance_types": types,
		"region":         region,
		"default_type":   account.DefaultInstanceType,
	})
}
