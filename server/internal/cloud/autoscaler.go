package cloud

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/user/dddd-server/internal/db"
	"github.com/user/dddd-server/internal/scheduler"
	"gorm.io/gorm"
)

// ============================================================================
// AutoScaler — 自动伸缩引擎
//
// 核心决策循环:
//   1. 每 30 秒读取所有启用的 CloudScalingPolicy
//   2. 对每个策略：查询队列深度 + 在线节点数 + 运行中云实例数
//   3. Scale Up:  队列积压 > threshold 且 实例数 < max → 创建实例
//   4. Scale Down: 队列空闲 且 存在闲置实例 且 实例数 > min → 回收实例
//   5. 所有操作写入 cloud_instances 表追踪状态
// ============================================================================

// AutoScaler 自动伸缩控制器
type AutoScaler struct {
	db       *gorm.DB
	queue    *scheduler.TaskQueue
	managers map[string]*ResourceManager // accountID → manager
	mu       sync.RWMutex
	psk      string // Agent PSK，传入 Cloud-Init
	apiURL   string // Server HTTP API 地址
	grpcAddr string // Server gRPC 地址
}

// NewAutoScaler 创建自动伸缩控制器
func NewAutoScaler(database *gorm.DB, queue *scheduler.TaskQueue) *AutoScaler {
	return &AutoScaler{
		db:       database,
		queue:    queue,
		managers: make(map[string]*ResourceManager),
	}
}

// SetServerAddrs 设置 Server 地址信息（用于 Cloud-Init 模板渲染）
func (as *AutoScaler) SetServerAddrs(grpcAddr, apiURL, psk string) {
	as.grpcAddr = grpcAddr
	as.apiURL = apiURL
	as.psk = psk
}

// Start 启动自动伸缩守护协程（阻塞，应在 goroutine 中调用）
func (as *AutoScaler) Start(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Println("[AutoScaler] Started, evaluation interval: 30s")

	for {
		select {
		case <-ctx.Done():
			log.Println("[AutoScaler] Stopped")
			return
		case <-ticker.C:
			as.evaluate(ctx)
		}
	}
}

// evaluate 执行一次完整的伸缩决策循环
func (as *AutoScaler) evaluate(ctx context.Context) {
	var policies []db.CloudScalingPolicy
	if err := as.db.Where("enabled = ?", true).Find(&policies).Error; err != nil {
		log.Printf("[AutoScaler] Failed to load policies: %v", err)
		return
	}

	if len(policies) == 0 {
		return // 没有启用的策略，跳过
	}

	// 查询队列深度
	depths := as.queue.QueueDepth(ctx)
	var totalQueueDepth int64
	for _, d := range depths {
		totalQueueDepth += d
	}

	for _, policy := range policies {
		as.evaluatePolicy(ctx, &policy, totalQueueDepth)
	}
}

// evaluatePolicy 对单个策略执行伸缩判定
func (as *AutoScaler) evaluatePolicy(ctx context.Context, policy *db.CloudScalingPolicy, queueDepth int64) {
	// 检查冷却期
	if policy.LastScaleAction != nil {
		cooldown := time.Duration(policy.CooldownSeconds) * time.Second
		if time.Since(*policy.LastScaleAction) < cooldown {
			return // 仍在冷却期
		}
	}

	// 查询当前该策略下运行中的云实例数
	var runningInstances int64
	as.db.Model(&db.CloudInstance{}).
		Where("policy_id = ? AND status IN ?", policy.ID, []string{
			db.CloudStatusProvisioning,
			db.CloudStatusWaitingReady,
			db.CloudStatusRunning,
		}).Count(&runningInstances)

	// Scale Up 判定
	if queueDepth > int64(policy.ScaleUpThreshold) && runningInstances < int64(policy.MaxInstances) {
		needed := as.calculateScaleUpCount(queueDepth, int64(policy.ScaleUpThreshold), runningInstances, int64(policy.MaxInstances))
		if needed > 0 {
			log.Printf("[AutoScaler] Scale UP: policy=%s queue=%d threshold=%d running=%d max=%d → launching %d instances",
				policy.Name, queueDepth, policy.ScaleUpThreshold, runningInstances, policy.MaxInstances, needed)
			as.scaleUp(ctx, policy, int(needed))
		}
		return
	}

	// Scale Down 判定
	if queueDepth <= int64(policy.ScaleDownThreshold) && runningInstances > int64(policy.MinInstances) {
		as.scaleDown(ctx, policy, runningInstances)
	}
}

// calculateScaleUpCount 计算需要扩容的实例数
func (as *AutoScaler) calculateScaleUpCount(queueDepth, threshold, running, maxInst int64) int64 {
	// 每台实例预期消化 256 个目标（与 SubTask 切分粒度一致）
	const targetsPerInstance = 256
	excess := queueDepth - threshold
	needed := (excess + targetsPerInstance - 1) / targetsPerInstance // 向上取整
	if needed < 1 {
		needed = 1
	}

	available := maxInst - running
	if needed > available {
		needed = available
	}
	return needed
}

// scaleUp 执行扩容操作
func (as *AutoScaler) scaleUp(ctx context.Context, policy *db.CloudScalingPolicy, count int) {
	// 加载云账号凭证
	var account db.CloudAccount
	if err := as.db.First(&account, "id = ? AND status = ?", policy.CloudAccountID, "active").Error; err != nil {
		log.Printf("[AutoScaler] Failed to load cloud account %s: %v", policy.CloudAccountID, err)
		return
	}

	manager, err := as.getOrCreateManager(&account)
	if err != nil {
		log.Printf("[AutoScaler] Failed to create manager for account %s: %v", account.ID, err)
		return
	}

	for i := 0; i < count; i++ {
		go func(idx int) {
			instance, err := manager.ProvisionInstance(ctx, &account, policy, as.grpcAddr, as.apiURL, as.psk)
			if err != nil {
				log.Printf("[AutoScaler] Failed to provision instance %d/%d: %v", idx+1, count, err)
				return
			}
			log.Printf("[AutoScaler] Instance provisioned: id=%s provider_id=%s agent_id=%s",
				instance.ID, instance.ProviderInstanceID, instance.AgentID)
		}(i)
	}

	// 更新冷却时间戳
	now := time.Now()
	as.db.Model(policy).Update("last_scale_action", &now)
}

// scaleDown 执行缩容操作
func (as *AutoScaler) scaleDown(ctx context.Context, policy *db.CloudScalingPolicy, running int64) {
	// 查找空闲且运行时间 > 10 分钟的云实例
	var idleInstances []db.CloudInstance
	cutoff := time.Now().Add(-10 * time.Minute)
	as.db.Where(
		"policy_id = ? AND status = ? AND created_at < ?",
		policy.ID, db.CloudStatusRunning, cutoff,
	).Find(&idleInstances)

	// 过滤出真正空闲的（Agent running_tasks == 0）
	var toTerminate []db.CloudInstance
	for _, inst := range idleInstances {
		if running-int64(len(toTerminate)) <= int64(policy.MinInstances) {
			break // 保留最小实例数
		}
		var node db.Node
		if err := as.db.Where("agent_id = ?", inst.AgentID).First(&node).Error; err != nil {
			continue // 找不到 Agent 节点记录，跳过
		}
		if node.RunningTasks == 0 {
			toTerminate = append(toTerminate, inst)
		}
	}

	if len(toTerminate) == 0 {
		return
	}

	log.Printf("[AutoScaler] Scale DOWN: policy=%s terminating %d idle instances", policy.Name, len(toTerminate))

	var account db.CloudAccount
	if err := as.db.First(&account, "id = ?", policy.CloudAccountID).Error; err != nil {
		log.Printf("[AutoScaler] Failed to load cloud account: %v", err)
		return
	}

	manager, err := as.getOrCreateManager(&account)
	if err != nil {
		log.Printf("[AutoScaler] Failed to get manager: %v", err)
		return
	}

	for _, inst := range toTerminate {
		go func(instance db.CloudInstance) {
			if err := manager.TerminateInstance(ctx, &instance); err != nil {
				log.Printf("[AutoScaler] Failed to terminate instance %s: %v", instance.ID, err)
			}
		}(inst)
	}

	// 更新冷却时间戳
	now := time.Now()
	as.db.Model(policy).Update("last_scale_action", &now)
}

// getOrCreateManager 获取或创建某个云账号对应的 ResourceManager
func (as *AutoScaler) getOrCreateManager(account *db.CloudAccount) (*ResourceManager, error) {
	as.mu.RLock()
	if m, ok := as.managers[account.ID]; ok {
		as.mu.RUnlock()
		return m, nil
	}
	as.mu.RUnlock()

	as.mu.Lock()
	defer as.mu.Unlock()

	// 双检
	if m, ok := as.managers[account.ID]; ok {
		return m, nil
	}

	provider, err := NewProviderFromAccount(account)
	if err != nil {
		return nil, err
	}

	manager := NewResourceManager(provider)
	manager.SetDB(as.db)
	as.managers[account.ID] = manager
	return manager, nil
}

// StartReconciler 启动实例对账协程（定期检查 DB 中 Running 实例在云端是否存活）
func (as *AutoScaler) StartReconciler(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("[Reconciler] Started, interval: %v", interval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			as.reconcile(ctx)
		}
	}
}

// reconcile 对账：检查 DB 中 Running/WaitingReady 状态的实例是否在云端仍然存在
func (as *AutoScaler) reconcile(ctx context.Context) {
	var instances []db.CloudInstance
	as.db.Where("status IN ?", []string{db.CloudStatusRunning, db.CloudStatusWaitingReady}).Find(&instances)

	if len(instances) == 0 {
		return
	}

	// 按 account 分组
	byAccount := make(map[string][]db.CloudInstance)
	for _, inst := range instances {
		byAccount[inst.CloudAccountID] = append(byAccount[inst.CloudAccountID], inst)
	}

	for accountID, insts := range byAccount {
		var account db.CloudAccount
		if err := as.db.First(&account, "id = ?", accountID).Error; err != nil {
			continue
		}

		manager, err := as.getOrCreateManager(&account)
		if err != nil {
			continue
		}

		// 查询云端实例列表
		cloudInstances, err := manager.provider.ListInstances(map[string]string{"argus:managed": "true"})
		if err != nil {
			log.Printf("[Reconciler] Failed to list instances for account %s: %v", accountID, err)
			continue
		}

		// 建立云端 ID 集合
		cloudIDs := make(map[string]bool, len(cloudInstances))
		for _, ci := range cloudInstances {
			cloudIDs[ci.ID] = true
		}

		// 对比：DB 中有但云端没有的 → 标记为 Terminated
		for _, inst := range insts {
			if inst.ProviderInstanceID != "" && !cloudIDs[inst.ProviderInstanceID] {
				log.Printf("[Reconciler] Instance %s (provider=%s) not found in cloud, marking as Terminated",
					inst.ID, inst.ProviderInstanceID)
				now := time.Now()
				as.db.Model(&inst).Updates(map[string]interface{}{
					"status":        db.CloudStatusTerminated,
					"terminated_at": &now,
				})
			}
		}
	}
}

// StartOrphanSweeper 启动孤儿实例回收协程（清理超过 TTL 的实例）
func (as *AutoScaler) StartOrphanSweeper(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("[OrphanSweeper] Started, interval: %v", interval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			as.sweepOrphans(ctx)
		}
	}
}

// sweepOrphans 回收超过策略 TTL 的实例
func (as *AutoScaler) sweepOrphans(ctx context.Context) {
	var policies []db.CloudScalingPolicy
	as.db.Where("enabled = ?", true).Find(&policies)

	for _, policy := range policies {
		ttl := time.Duration(policy.InstanceTTLMinutes) * time.Minute
		cutoff := time.Now().Add(-ttl)

		var expired []db.CloudInstance
		as.db.Where(
			"policy_id = ? AND status IN ? AND created_at < ?",
			policy.ID,
			[]string{db.CloudStatusRunning, db.CloudStatusWaitingReady},
			cutoff,
		).Find(&expired)

		if len(expired) == 0 {
			continue
		}

		var account db.CloudAccount
		if err := as.db.First(&account, "id = ?", policy.CloudAccountID).Error; err != nil {
			continue
		}

		manager, err := as.getOrCreateManager(&account)
		if err != nil {
			continue
		}

		for _, inst := range expired {
			log.Printf("[OrphanSweeper] Instance %s exceeded TTL (%v), terminating...", inst.ID, ttl)
			go func(instance db.CloudInstance) {
				if err := manager.TerminateInstance(ctx, &instance); err != nil {
					log.Printf("[OrphanSweeper] Failed to terminate instance %s: %v", instance.ID, err)
				}
			}(inst)
		}
	}
}
