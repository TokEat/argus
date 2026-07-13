package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/cloud"
	"github.com/user/dddd-server/internal/cloud/aliyun"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

func listCloudAccounts(c *gin.Context) {
	tenantID := currentTenantID(c)
	var accounts []db.CloudAccount
	cloudAccountQuery(c).Order("created_at DESC").Find(&accounts)

	type AccountResp struct {
		ID                   string   `json:"id"`
		TenantID             string   `json:"tenant_id"`
		OwnerUserID          string   `json:"owner_user_id"`
		OwnerUsername        string   `json:"owner_username"`
		AccessLevel          string   `json:"access_level"`
		Name                 string   `json:"name"`
		Provider             string   `json:"provider"`
		AccessKeyID          string   `json:"access_key_id"`
		Region               string   `json:"region"`
		DefaultImageID       string   `json:"default_image_id"`
		DefaultInstanceType  string   `json:"default_instance_type"`
		DefaultSecurityGroup string   `json:"default_security_group"`
		DefaultVSwitch       string   `json:"default_v_switch"`
		OSSBucket            string   `json:"oss_bucket"`
		OSSEndpoint          string   `json:"oss_endpoint"`
		Status               string   `json:"status"`
		CreatedAt            string   `json:"created_at"`
		UpdatedAt            string   `json:"updated_at"`
		BoundUserIDs         []string `json:"bound_user_ids,omitempty"`
	}

	ownerIDs := make([]string, 0, len(accounts))
	for _, account := range accounts {
		if account.OwnerUserID != "" {
			ownerIDs = append(ownerIDs, account.OwnerUserID)
		}
	}
	ownerNames := map[string]string{}
	if len(ownerIDs) > 0 {
		var users []db.User
		db.DB.Where("tenant_id = ? AND id IN ?", tenantID, ownerIDs).Find(&users)
		for _, user := range users {
			ownerNames[fmt.Sprintf("%d", user.ID)] = user.Username
		}
	}

	boundUserIDsByAccount := map[string][]string{}
	if currentUserIsAdmin(c) && len(accounts) > 0 {
		accountIDs := make([]string, 0, len(accounts))
		for _, account := range accounts {
			accountIDs = append(accountIDs, account.ID)
		}
		var bindings []db.CloudAccountBinding
		db.DB.Where("tenant_id = ? AND cloud_account_id IN ?", tenantID, accountIDs).Find(&bindings)
		for _, binding := range bindings {
			boundUserIDsByAccount[binding.CloudAccountID] = append(boundUserIDsByAccount[binding.CloudAccountID], binding.UserID)
		}
	}

	resp := make([]AccountResp, 0, len(accounts))
	for _, a := range accounts {
		// 解密 AK ID 后脱敏
		akID, _ := cloud.DecryptSecret(a.AccessKeyID)
		resp = append(resp, AccountResp{
			ID:                   a.ID,
			TenantID:             a.TenantID,
			OwnerUserID:          a.OwnerUserID,
			OwnerUsername:        ownerNames[a.OwnerUserID],
			AccessLevel:          accountAccessLevel(c, a),
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
			UpdatedAt:            a.UpdatedAt.Format(time.RFC3339),
			BoundUserIDs:         boundUserIDsByAccount[a.ID],
		})
	}

	c.JSON(http.StatusOK, resp)
}

func createCloudAccount(c *gin.Context) {
	var req struct {
		Name                 string   `json:"name" binding:"required"`
		Provider             string   `json:"provider" binding:"required"`
		AccessKeyID          string   `json:"access_key_id" binding:"required"`
		AccessKeySecret      string   `json:"access_key_secret" binding:"required"`
		Region               string   `json:"region"`
		DefaultImageID       string   `json:"default_image_id"`
		DefaultInstanceType  string   `json:"default_instance_type"`
		DefaultSecurityGroup string   `json:"default_security_group"`
		DefaultVSwitch       string   `json:"default_v_switch"`
		OSSBucket            string   `json:"oss_bucket"`
		OSSEndpoint          string   `json:"oss_endpoint"`
		BoundUserIDs         []string `json:"bound_user_ids"`
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
		OwnerUserID:          currentUserID(c),
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

	if account.OwnerUserID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing user identity"})
		return
	}

	if currentUserIsAdmin(c) && len(req.BoundUserIDs) > 0 {
		if _, err := validateCloudAccountBindingUsers(account.TenantID, req.BoundUserIDs); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&account).Error; err != nil {
			return err
		}
		if err := ensureCloudAccountBinding(tx, account.TenantID, account.ID, account.OwnerUserID, "owner"); err != nil {
			return err
		}
		if currentUserIsAdmin(c) {
			for _, userID := range req.BoundUserIDs {
				if userID == account.OwnerUserID {
					continue
				}
				if err := ensureCloudAccountBinding(tx, account.TenantID, account.ID, userID, "bound"); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "id": account.ID})
}

func updateCloudAccount(c *gin.Context) {
	id := c.Param("id")

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

	if _, ok := loadCloudAccountForManage(c, id); !ok {
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

	if err := db.DB.Model(&db.CloudAccount{}).Where("id = ? AND tenant_id = ?", id, currentTenantID(c)).Updates(updates).Error; err != nil {
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
	var ok bool
	if account, ok = loadCloudAccountForManage(c, id); !ok {
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

	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("tenant_id = ? AND cloud_account_id = ?", tenantID, id).Delete(&db.CloudAccountBinding{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ? AND tenant_id = ?", id, tenantID).Delete(&db.CloudAccount{}).Error
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if cloudAutoScaler != nil {
		cloudAutoScaler.InvalidateManager(account.ID)
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func getCloudAccountBindings(c *gin.Context) {
	if !currentUserIsAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only tenant admin can manage cloud account bindings"})
		return
	}
	account, ok := loadCloudAccountForUse(c, c.Param("id"), false)
	if !ok {
		return
	}

	var bindings []db.CloudAccountBinding
	db.DB.Where("tenant_id = ? AND cloud_account_id = ?", account.TenantID, account.ID).
		Order("created_at ASC").
		Find(&bindings)

	userIDs := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		userIDs = append(userIDs, binding.UserID)
	}

	c.JSON(http.StatusOK, gin.H{
		"cloud_account_id": account.ID,
		"owner_user_id":    account.OwnerUserID,
		"user_ids":         userIDs,
		"bindings":         bindings,
	})
}

func updateCloudAccountBindings(c *gin.Context) {
	if !currentUserIsAdmin(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only tenant admin can manage cloud account bindings"})
		return
	}
	account, ok := loadCloudAccountForUse(c, c.Param("id"), false)
	if !ok {
		return
	}

	var req struct {
		UserIDs []string `json:"user_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := replaceCloudAccountBindings(account, req.UserIDs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func testCloudAccount(c *gin.Context) {
	id := c.Param("id")

	var account db.CloudAccount
	var ok bool
	if account, ok = loadCloudAccountForUse(c, id, false); !ok {
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
