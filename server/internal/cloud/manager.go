package cloud

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
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

func nonNilContext(ctx context.Context) context.Context {
	if ctx != nil {
		return ctx
	}
	return context.Background()
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
	ctx = nonNilContext(ctx)

	// 弹性扩缩创建实例必须指定 Region
	if account.Region == "" {
		return nil, fmt.Errorf("该云凭证尚未配置地域 (Region)，请先在凭证管理中选择地域后再执行弹性扩缩")
	}

	// 生成 Agent ID
	agentID := fmt.Sprintf("cloud-%s-%d", account.Provider, time.Now().UnixNano())

	// 生成 Agent 二进制下载 URL（OSS 为唯一分发通道）
	if account.OSSBucket == "" || account.OSSEndpoint == "" {
		return nil, fmt.Errorf("该云凭证未配置 OSS (Bucket/Endpoint)，无法分发 Agent 二进制。请先在凭证管理中配置 OSS 或执行一键配置")
	}
	downloadURL, err := GenerateAgentDownloadURL(account, "linux", "amd64")
	if err != nil {
		return nil, fmt.Errorf("生成 OSS 预签名 URL 失败: %w（请确认 OSS 中已上传 Agent 制品）", err)
	}

	// 渲染 Cloud-Init 脚本
	tmpl := policy.UserDataTemplate
	userData, err := RenderCloudInitBase64(tmpl, CloudInitVars{
		ServerAddr:  grpcAddr,
		APIURL:      apiURL,
		AgentID:     agentID,
		TenantID:    account.TenantID,
		Tags:        "cloud=true,auto_scaled=true,target_type=all",
		PSK:         psk,
		DownloadURL: downloadURL,
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
		SpotDuration: int32(policy.SpotDurationHours),
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
	ctx = nonNilContext(ctx)
	err := rm.provider.WaitReady(ctx, cloudInst.ProviderInstanceID, 5*time.Minute)
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

	if rm.database != nil {
		rm.database.Model(cloudInst).Update("ip", ip)
		rm.database.Model(cloudInst).
			Where("status IN ?", []string{db.CloudStatusProvisioning, db.CloudStatusWaitingReady}).
			Update("status", db.CloudStatusWaitingReady)
	}

	log.Printf("[Provision] Instance %s OS is ready at IP: %s, waiting for agent registration", cloudInst.ID, ip)
}

// RebootInstance 重启云实例（保留机器，OS 级重启以恢复 Agent）
func (rm *ResourceManager) RebootInstance(ctx context.Context, cloudInst *db.CloudInstance) error {
	ctx = nonNilContext(ctx)
	log.Printf("[Reboot] Rebooting instance %s (provider_id=%s, reboot_count=%d)",
		cloudInst.ID, cloudInst.ProviderInstanceID, cloudInst.RebootCount)

	// 更新状态为 Rebooting
	if rm.database != nil {
		rm.database.Model(cloudInst).Updates(map[string]interface{}{
			"status":       db.CloudStatusRebooting,
			"reboot_count": cloudInst.RebootCount + 1,
		})
	}

	// 调用云 API 重启
	if cloudInst.ProviderInstanceID != "" {
		if err := rm.provider.RebootInstance(cloudInst.ProviderInstanceID); err != nil {
			log.Printf("[Reboot] Failed to reboot instance %s: %v", cloudInst.ProviderInstanceID, err)
			if rm.database != nil {
				rm.database.Model(cloudInst).Updates(map[string]interface{}{
					"status":        db.CloudStatusError,
					"error_message": fmt.Sprintf("Reboot failed: %v", err),
				})
			}
			return err
		}
	}

	// 异步等待重启后恢复
	go rm.waitRebootRecovery(ctx, cloudInst)

	log.Printf("[Reboot] Instance %s reboot initiated, waiting for agent re-registration...", cloudInst.ID)
	return nil
}

// waitRebootRecovery 等待重启后 Agent 重新上线
func (rm *ResourceManager) waitRebootRecovery(ctx context.Context, cloudInst *db.CloudInstance) {
	ctx = nonNilContext(ctx)
	// 等待实例重新进入 Running 状态（OS 层面）
	err := rm.provider.WaitReady(ctx, cloudInst.ProviderInstanceID, 5*time.Minute)
	if err != nil {
		log.Printf("[Reboot] WaitReady after reboot failed for %s: %v", cloudInst.ID, err)
		if rm.database != nil {
			rm.database.Model(cloudInst).Updates(map[string]interface{}{
				"status":        db.CloudStatusError,
				"error_message": fmt.Sprintf("Post-reboot WaitReady failed: %v", err),
			})
		}
		return
	}

	// OS 已就绪，将状态改回 WaitingReady，等待 Agent 通过 gRPC 重新注册
	if rm.database != nil {
		rm.database.Model(cloudInst).
			Where("status = ?", db.CloudStatusRebooting).
			Update("status", db.CloudStatusWaitingReady)
	}
	log.Printf("[Reboot] Instance %s OS is ready, awaiting agent re-registration", cloudInst.ID)
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
			// 回滚状态为 Error，确保兆底协程能再次捕获
			if rm.database != nil {
				rm.database.Model(cloudInst).Updates(map[string]interface{}{
					"status":        db.CloudStatusError,
					"error_message": fmt.Sprintf("Terminate failed: %v", err),
				})
			}
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
