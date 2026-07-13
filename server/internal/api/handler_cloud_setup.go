package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/cloud/aliyun"
	"github.com/user/dddd-server/internal/db"
)

// listCloudRegions 通过 AK/SK 自动获取所有可用地域列表
func (h *CloudHandler) listCloudRegions(c *gin.Context) {
	accountID := c.Param("id")

	var account db.CloudAccount
	var ok bool
	if account, ok = h.loadCloudAccountForUse(c, accountID, false); !ok {
		return
	}

	provider, err := h.ProviderFactory(&account)
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
func (h *CloudHandler) discoverCloudResources(c *gin.Context) {
	account, ok := h.loadCloudAccountForUse(c, c.Param("id"), false)
	if !ok {
		return
	}

	result, serviceErr := h.setupService().DiscoverResources(&account)
	if serviceErr != nil {
		c.JSON(serviceErr.Status, gin.H{"error": serviceErr.Message})
		return
	}
	c.JSON(http.StatusOK, result)
}

// autoConfigureCloudAccount 将用户选择的发现结果写入 CloudAccount 配置
func (h *CloudHandler) autoConfigureCloudAccount(c *gin.Context) {
	accountID := c.Param("id")

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
	if _, ok := h.loadCloudAccountForManage(c, accountID); !ok {
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

	if err := h.DB.Model(&db.CloudAccount{}).Where("id = ? AND tenant_id = ?", accountID, currentTenantID(c)).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "配置已更新"})
}

// oneClickSetup 一键配置：自动发现资源 → 选择最优默认值 → 写入凭证 → 创建策略
func (h *CloudHandler) oneClickSetup(c *gin.Context) {
	actor := requestActor(c)
	account, ok := h.loadCloudAccountForManage(c, c.Param("id"))
	if !ok {
		return
	}

	result, serviceErr := h.setupService().OneClickSetup(actor, account, h.ossService())
	if serviceErr != nil {
		c.JSON(serviceErr.Status, gin.H{"error": serviceErr.Message})
		return
	}
	c.JSON(http.StatusOK, result)
}

func chooseOneClickInstanceType(instanceTypes []string) string {
	if len(instanceTypes) == 0 {
		return ""
	}
	for _, preferred := range []string{"ecs.e-c1m1.large", "ecs.u1-c1m1.large", "ecs.c6.large"} {
		for _, instanceType := range instanceTypes {
			if instanceType == preferred {
				return instanceType
			}
		}
	}
	return instanceTypes[0]
}

func containsIgnoreCase(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
