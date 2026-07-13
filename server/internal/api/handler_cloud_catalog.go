package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/cloud"
	"github.com/user/dddd-server/internal/cloud/aliyun"
	"github.com/user/dddd-server/internal/db"
)

// checkCloudPermissions 检查指定凭证的 AK/SK 拥有的所有权限
func checkCloudPermissions(c *gin.Context) {
	accountID := c.Param("id")

	var account db.CloudAccount
	var ok bool
	if account, ok = loadCloudAccountForUse(c, accountID, false); !ok {
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

func queryCloudPrice(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var account db.CloudAccount
	var ok bool
	if account, ok = loadCloudAccountForUse(c, id, false); !ok {
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
		"region":         region,
		"spot_strategy":  spotStrategy,
		"instance_price": priceInfo.InstancePrice,
		"spot_price":     priceInfo.SpotPrice,
		"spot_discount":  priceInfo.SpotDiscount,
		"total_hourly":   priceInfo.TotalHourly,
		"currency":       priceInfo.Currency,
		"price_unit":     priceInfo.PriceUnit,
	})
}

func listAvailableInstanceTypes(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)

	var account db.CloudAccount
	var ok bool
	if account, ok = loadCloudAccountForUse(c, id, false); !ok {
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
