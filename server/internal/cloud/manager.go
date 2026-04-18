package cloud

import (
	"context"
	"fmt"
	"log"
	"time"
)

// ResourceManager 负责动态实例的生老病死
type ResourceManager struct {
	provider CloudProvider
}

func NewResourceManager(provider CloudProvider) *ResourceManager {
	return &ResourceManager{
		provider: provider,
	}
}

// ProvisionAndRunTask 申请一台实例，等待它上线，然后交接给后续逻辑
// (实际上 Agent 开机会自组网，Server 这里仅做申请与监控，如果超时则回滚销毁)
func (rm *ResourceManager) ProvisionAndRunTask(ctx context.Context, cfg InstanceConfig, taskID string) (*Instance, error) {
	log.Printf("[Provision] Requesting instance for Task %s...", taskID)
	inst, err := rm.provider.CreateInstance(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance: %w", err)
	}

	log.Printf("[Provision] Instance %s created (Status: %s). Waiting for ready...", inst.ID, inst.Status)

	// 等待最多 5 分钟
	err = rm.provider.WaitReady(inst.ID, 5*time.Minute)
	if err != nil {
		log.Printf("[Provision Error] WaitReady timeout for %s, tearing down.", inst.ID)
		_ = rm.provider.TerminateInstance(inst.ID)
		return nil, err
	}

	ip, _ := rm.provider.GetInstanceIP(inst.ID)
	inst.IP = ip
	inst.Status = "Running"

	log.Printf("[Provision] Instance %s is ready at IP: %s", inst.ID, ip)
	return inst, nil
}

// Recycle 回收实例
func (rm *ResourceManager) Recycle(instanceID string) error {
	log.Printf("[Recycle] Tearing down instance %s", instanceID)
	return rm.provider.TerminateInstance(instanceID)
}

// SweepOrphans 扫除因为异常留下的孤儿实例 (配合 crontab 调用)
func (rm *ResourceManager) SweepOrphans(tags map[string]string) {
	instances, err := rm.provider.ListInstances(tags)
	if err != nil {
		log.Printf("[Sweep] Failed to list instances: %v", err)
		return
	}
	for _, inst := range instances {
		// 简单的过期逻辑判断：如果一个扫描实例存活超过 2 小时，强制回收
		if time.Since(inst.CreatedAt) > 2*time.Hour {
			log.Printf("[Sweep] Instance %s lived too long, terminating...", inst.ID)
			_ = rm.provider.TerminateInstance(inst.ID)
		}
	}
}
