package cloud

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

// ============================================================================
// ResourceManager — 实例生命周期管理
//
// 负责实例的创建、等待就绪、销毁，以及 DB 状态追踪。
// 从原有的简单 manager.go 重构而来，增加了 DB 持久化。
// ============================================================================

// ResourceManager 负责动态实例的生老病死
type ResourceManager struct {
	provider CloudProvider
	database *gorm.DB
}

func NewResourceManager(provider CloudProvider) *ResourceManager {
	return &ResourceManager{
		provider: provider,
	}
}

// SetDB 设置数据库引用
func (rm *ResourceManager) SetDB(database *gorm.DB) {
	rm.database = database
}

// ProvisionInstance 创建一台云实例并追踪其生命周期
func (rm *ResourceManager) ProvisionInstance(
	ctx context.Context,
	account *db.CloudAccount,
	policy *db.CloudScalingPolicy,
	grpcAddr, apiURL, psk string,
) (*db.CloudInstance, error) {
	// 生成 Agent ID
	agentID := fmt.Sprintf("cloud-%s-%d", account.Provider, time.Now().UnixNano())

	// 渲染 Cloud-Init 脚本
	tmpl := policy.UserDataTemplate
	userData, err := RenderCloudInitBase64(tmpl, CloudInitVars{
		ServerAddr: grpcAddr,
		APIURL:     apiURL,
		AgentID:    agentID,
		TenantID:   account.TenantID,
		Tags:       "cloud,auto-scaled",
		PSK:        psk,
	})
	if err != nil {
		return nil, fmt.Errorf("render cloud-init: %w", err)
	}

	// 构建实例配置
	cfg := InstanceConfig{
		Region:        account.Region,
		InstanceType:  account.DefaultInstanceType,
		ImageID:       account.DefaultImageID,
		SecurityGroup: account.DefaultSecurityGroup,
		VSwitch:       account.DefaultVSwitch,
		UserData:      userData,
		Tags: map[string]string{
			"argus:managed":  "true",
			"argus:agent-id": agentID,
			"argus:policy":   policy.ID,
			"argus:tenant":   account.TenantID,
		},
		SpotStrategy: policy.SpotStrategy,
		MaxPrice:     policy.MaxSpotPrice,
		AgentID:      agentID,
		TenantID:     account.TenantID,
	}

	// 创建 DB 记录（状态: Provisioning）
	now := time.Now()
	cloudInst := &db.CloudInstance{
		ID:             fmt.Sprintf("ci-%d", now.UnixNano()),
		TenantID:       account.TenantID,
		CloudAccountID: account.ID,
		PolicyID:       policy.ID,
		AgentID:        agentID,
		Region:         account.Region,
		Status:         db.CloudStatusProvisioning,
		Spot:           policy.SpotStrategy != "" && policy.SpotStrategy != "NoSpot",
		LaunchedAt:     &now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if rm.database != nil {
		if err := rm.database.Create(cloudInst).Error; err != nil {
			return nil, fmt.Errorf("create cloud instance record: %w", err)
		}
	}

	// 调用云 API 创建实例
	inst, err := rm.provider.CreateInstance(cfg)
	if err != nil {
		if rm.database != nil {
			rm.database.Model(cloudInst).Updates(map[string]interface{}{
				"status":        db.CloudStatusError,
				"error_message": err.Error(),
			})
		}
		return nil, fmt.Errorf("create cloud instance: %w", err)
	}

	// 更新 provider 侧实例 ID
	if rm.database != nil {
		rm.database.Model(cloudInst).Updates(map[string]interface{}{
			"provider_instance_id": inst.ID,
			"status":               db.CloudStatusWaitingReady,
		})
	}
	cloudInst.ProviderInstanceID = inst.ID
	cloudInst.Status = db.CloudStatusWaitingReady

	log.Printf("[Provision] Instance %s created (provider_id=%s), waiting for ready...", cloudInst.ID, inst.ID)

	// 异步等待实例就绪
	go rm.waitAndActivate(ctx, cloudInst)

	return cloudInst, nil
}

// waitAndActivate 等待实例就绪并更新 DB 状态
func (rm *ResourceManager) waitAndActivate(ctx context.Context, cloudInst *db.CloudInstance) {
	err := rm.provider.WaitReady(cloudInst.ProviderInstanceID, 5*time.Minute)
	if err != nil {
		log.Printf("[Provision] WaitReady failed for %s: %v, tearing down", cloudInst.ID, err)
		if rm.database != nil {
			rm.database.Model(cloudInst).Updates(map[string]interface{}{
				"status":        db.CloudStatusError,
				"error_message": fmt.Sprintf("WaitReady timeout: %v", err),
			})
		}
		_ = rm.provider.TerminateInstance(cloudInst.ProviderInstanceID)
		return
	}

	// 获取 IP
	ip, _ := rm.provider.GetInstanceIP(cloudInst.ProviderInstanceID)

	now := time.Now()
	if rm.database != nil {
		rm.database.Model(cloudInst).Updates(map[string]interface{}{
			"ip":       ip,
			"status":   db.CloudStatusRunning,
			"ready_at": &now,
		})
	}

	log.Printf("[Provision] Instance %s is ready at IP: %s", cloudInst.ID, ip)
}

// TerminateInstance 销毁实例并更新 DB
func (rm *ResourceManager) TerminateInstance(ctx context.Context, cloudInst *db.CloudInstance) error {
	log.Printf("[Recycle] Tearing down instance %s (provider_id=%s)", cloudInst.ID, cloudInst.ProviderInstanceID)

	// 更新状态为 Terminating
	if rm.database != nil {
		rm.database.Model(cloudInst).Update("status", db.CloudStatusTerminating)
	}

	// 调用云 API 销毁
	if cloudInst.ProviderInstanceID != "" {
		if err := rm.provider.TerminateInstance(cloudInst.ProviderInstanceID); err != nil {
			log.Printf("[Recycle] Failed to terminate provider instance %s: %v", cloudInst.ProviderInstanceID, err)
			return err
		}
	}

	// 更新状态为 Terminated
	now := time.Now()
	if rm.database != nil {
		rm.database.Model(cloudInst).Updates(map[string]interface{}{
			"status":        db.CloudStatusTerminated,
			"terminated_at": &now,
		})
	}

	// 同时将关联的 Node 标记为 Offline
	if rm.database != nil && cloudInst.AgentID != "" {
		rm.database.Model(&db.Node{}).Where("agent_id = ?", cloudInst.AgentID).
			Update("status", "Offline")
	}

	log.Printf("[Recycle] Instance %s terminated", cloudInst.ID)
	return nil
}

// Recycle 简单回收接口（兼容旧调用）
func (rm *ResourceManager) Recycle(instanceID string) error {
	log.Printf("[Recycle] Tearing down instance %s", instanceID)
	return rm.provider.TerminateInstance(instanceID)
}
