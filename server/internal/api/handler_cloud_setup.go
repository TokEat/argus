package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/cloud"
	"github.com/user/dddd-server/internal/cloud/aliyun"
	"github.com/user/dddd-server/internal/db"
)

// listCloudRegions 通过 AK/SK 自动获取所有可用地域列表
func listCloudRegions(c *gin.Context) {
	accountID := c.Param("id")

	var account db.CloudAccount
	var ok bool
	if account, ok = loadCloudAccountForUse(c, accountID, false); !ok {
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

	var account db.CloudAccount
	var ok bool
	if account, ok = loadCloudAccountForUse(c, accountID, false); !ok {
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
	if _, ok := loadCloudAccountForManage(c, accountID); !ok {
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

	if err := db.DB.Model(&db.CloudAccount{}).Where("id = ? AND tenant_id = ?", accountID, currentTenantID(c)).Updates(updates).Error; err != nil {
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
	var ok bool
	if account, ok = loadCloudAccountForManage(c, accountID); !ok {
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

	// 实例规格：总是覆盖，优先 2c2g 经济型
	if len(result.InstanceTypes) > 0 {
		instanceTypeIDs := make([]string, 0, len(result.InstanceTypes))
		for _, instanceType := range result.InstanceTypes {
			instanceTypeIDs = append(instanceTypeIDs, instanceType.ID)
		}
		pick := chooseOneClickInstanceType(instanceTypeIDs)
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
	db.DB.Where("id = ? AND tenant_id = ?", accountID, tenantID).First(&account)

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
