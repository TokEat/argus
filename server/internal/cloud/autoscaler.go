package cloud

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/user/dddd-server/internal/db"
	"github.com/user/dddd-server/internal/scheduler"
	"gorm.io/gorm"
)

const ttlActiveTaskGracePeriod = 30 * time.Minute

type scaleUpReason string

const (
	scaleUpReasonNone        scaleUpReason = ""
	scaleUpReasonMinCapacity scaleUpReason = "min_capacity"
	scaleUpReasonColdStart   scaleUpReason = "cold_start"
	scaleUpReasonThreshold   scaleUpReason = "threshold"
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
	managers map[string]*ResourceManager // accountID:region → manager
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
	as.evaluate(ctx)

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

	// 按租户统计积压目标数，避免跨租户误扩容。
	queueDepthByTenant := as.queryPendingTargetsByTenant()

	for _, policy := range policies {
		as.evaluatePolicy(ctx, &policy, queueDepthByTenant[policy.TenantID])
	}
}

func (as *AutoScaler) queryPendingTargetsByTenant() map[string]int64 {
	// 与 API 层 getQueueDepth 口径一致：Pending/Dispatching/Recovered 视为可消费积压。
	type row struct {
		TenantID string
		Cnt      int64
	}
	var rows []row
	if err := as.db.Raw(`
		SELECT tenant_id, COALESCE(SUM(jsonb_array_length(chunk_targets::jsonb)), 0) AS cnt
		FROM sub_tasks
		WHERE status IN ('Pending', 'Dispatching', 'Recovered')
		GROUP BY tenant_id
	`).Scan(&rows).Error; err != nil {
		log.Printf("[AutoScaler] Failed to query pending targets: %v", err)
		return map[string]int64{}
	}

	result := make(map[string]int64, len(rows))
	for _, r := range rows {
		result[r.TenantID] = r.Cnt
	}
	return result
}

// evaluatePolicy 对单个策略执行伸缩判定
func (as *AutoScaler) evaluatePolicy(ctx context.Context, policy *db.CloudScalingPolicy, queueDepth int64) {
	// 查询当前该策略下运行中的云实例数
	var activeInstances int64
	as.db.Model(&db.CloudInstance{}).
		Where("policy_id = ? AND status IN ?", policy.ID, []string{
			db.CloudStatusProvisioning,
			db.CloudStatusWaitingReady,
			db.CloudStatusRunning,
		}).Count(&activeInstances)

	var inFlightInstances int64
	as.db.Model(&db.CloudInstance{}).
		Where("policy_id = ? AND status IN ?", policy.ID, []string{
			db.CloudStatusProvisioning,
			db.CloudStatusWaitingReady,
			db.CloudStatusRebooting,
		}).Count(&inFlightInstances)

	var aliveAgents int64
	as.db.Model(&db.Node{}).
		Where("tenant_id = ? AND status = ?", policy.TenantID, "Alive").
		Count(&aliveAgents)

	// Scale Up 判定
	if needed, reason := calculateScaleUpDecision(policy, queueDepth, activeInstances, inFlightInstances, aliveAgents); needed > 0 {
		if policyInCooldown(policy) {
			return
		}
		log.Printf("[AutoScaler] Scale UP: policy=%s reason=%s queue=%d threshold=%d active_instances=%d alive_agents=%d max=%d → launching %d instances",
			policy.Name, reason, queueDepth, policy.ScaleUpThreshold, activeInstances, aliveAgents, policy.MaxInstances, needed)
		as.scaleUp(ctx, policy, int(needed), "", "")
		return
	}

	if policyInCooldown(policy) {
		return
	}

	// Scale Down 判定
	if queueDepth <= int64(policy.ScaleDownThreshold) && activeInstances > int64(policy.MinInstances) {
		as.scaleDown(ctx, policy, activeInstances)
	}
}

func policyInCooldown(policy *db.CloudScalingPolicy) bool {
	if policy.LastScaleAction == nil || policy.CooldownSeconds <= 0 {
		return false
	}
	return time.Since(*policy.LastScaleAction) < time.Duration(policy.CooldownSeconds)*time.Second
}

func calculateScaleUpDecision(policy *db.CloudScalingPolicy, queueDepth, activeInstances, inFlightInstances, aliveAgents int64) (int64, scaleUpReason) {
	maxInstances := int64(policy.MaxInstances)
	if maxInstances <= 0 {
		return 0, scaleUpReasonNone
	}
	available := maxInstances - activeInstances
	if available <= 0 {
		return 0, scaleUpReasonNone
	}

	minInstances := int64(policy.MinInstances)
	if minInstances < 0 {
		minInstances = 0
	}
	if activeInstances < minInstances {
		needed := minInstances - activeInstances
		if needed > available {
			needed = available
		}
		return needed, scaleUpReasonMinCapacity
	}

	// Cold start: with zero live agents, even a small queue cannot drain. This
	// bypasses ScaleUpThreshold, while evaluatePolicy still enforces cooldown.
	if queueDepth > 0 && aliveAgents == 0 && inFlightInstances == 0 {
		return 1, scaleUpReasonColdStart
	}

	threshold := int64(policy.ScaleUpThreshold)
	if threshold < 0 {
		threshold = 0
	}
	if queueDepth > threshold {
		needed := calculateScaleUpCount(queueDepth, threshold, activeInstances, maxInstances)
		if needed > 0 {
			return needed, scaleUpReasonThreshold
		}
	}

	return 0, scaleUpReasonNone
}

// calculateScaleUpCount 计算需要扩容的实例数
func calculateScaleUpCount(queueDepth, threshold, running, maxInst int64) int64 {
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

// ScaleUpManual 手动触发扩容，绕过队列判定和冷却期限制
func (as *AutoScaler) ScaleUpManual(ctx context.Context, policy *db.CloudScalingPolicy, count int, instanceTypeOverride, regionOverride string) {
	log.Printf("[AutoScaler] Manual Scale UP: policy=%s launching %d instances (type=%s, region=%s)", policy.Name, count, instanceTypeOverride, regionOverride)
	as.scaleUp(ctx, policy, count, instanceTypeOverride, regionOverride)
}

func (as *AutoScaler) capScaleUpCountByActiveInstances(policy *db.CloudScalingPolicy, count int) int {
	if count <= 0 {
		return 0
	}
	if policy.MaxInstances <= 0 {
		return count
	}

	var currentActive int64
	err := as.db.Model(&db.CloudInstance{}).
		Where("policy_id = ? AND status IN ?", policy.ID, []string{
			db.CloudStatusProvisioning,
			db.CloudStatusWaitingReady,
			db.CloudStatusRunning,
		}).
		Count(&currentActive).Error
	if err != nil {
		log.Printf("[AutoScaler] Scale UP aborted: failed to refresh active instances for policy=%s: %v", policy.Name, err)
		return 0
	}

	allowed := int64(policy.MaxInstances) - currentActive
	if allowed <= 0 {
		return 0
	}
	if int64(count) > allowed {
		return int(allowed)
	}
	return count
}

// scaleUp 执行扩容操作
func (as *AutoScaler) scaleUp(ctx context.Context, policy *db.CloudScalingPolicy, count int, instanceTypeOverride, regionOverride string) {
	originalCount := count
	count = as.capScaleUpCountByActiveInstances(policy, count)
	if count <= 0 {
		log.Printf("[AutoScaler] Scale UP aborted: policy=%s requested=%d max=%d active instances already at limit", policy.Name, originalCount, policy.MaxInstances)
		return
	}
	if count != originalCount {
		log.Printf("[AutoScaler] Scale UP capped: policy=%s requested=%d allowed=%d max=%d", policy.Name, originalCount, count, policy.MaxInstances)
	}

	// 加载云账号凭证
	var account db.CloudAccount
	if err := as.db.First(&account, "id = ? AND status = ?", policy.CloudAccountID, "active").Error; err != nil {
		log.Printf("[AutoScaler] Failed to load cloud account %s: %v", policy.CloudAccountID, err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			as.markScaleUpCooldown(policy, "cloud account is missing or inactive")
		}
		return
	}

	// 如果指定了规格覆盖，临时替换（不修改数据库）
	if instanceTypeOverride != "" {
		log.Printf("[AutoScaler] Instance type override: %s -> %s", account.DefaultInstanceType, instanceTypeOverride)
		account.DefaultInstanceType = instanceTypeOverride
	}
	if regionOverride != "" {
		log.Printf("[AutoScaler] Region override: %s -> %s", account.Region, regionOverride)
		account.Region = regionOverride
	}

	manager, err := as.getOrCreateManager(&account)
	if err != nil {
		log.Printf("[AutoScaler] Failed to create manager for account %s: %v", account.ID, err)
		// Manager creation only performs deterministic local credential/provider
		// setup. Retrying it every reconcile cycle cannot recover without config changes.
		as.markScaleUpCooldown(policy, "cloud manager initialization failed")
		return
	}

	// 使用信号量限制并发创建数，防止触发云厂商 API 限流
	const maxConcurrentProvisions = 5
	sem := make(chan struct{}, maxConcurrentProvisions)
	var wg sync.WaitGroup
	var successCount int64
	var fatalErrCount int64

	for i := 0; i < count; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			instance, err := manager.ProvisionInstance(ctx, &account, policy, as.grpcAddr, as.apiURL, as.psk)
			if err != nil {
				log.Printf("[AutoScaler] Failed to provision instance %d/%d: %v", idx+1, count, err)
				if isFatalProvisionError(err.Error()) {
					atomic.AddInt64(&fatalErrCount, 1)
				}
				return
			}
			atomic.AddInt64(&successCount, 1)
			log.Printf("[AutoScaler] Instance provisioned: id=%s provider_id=%s agent_id=%s",
				instance.ID, instance.ProviderInstanceID, instance.AgentID)
		}(i)
	}

	wg.Wait()
	succeeded := atomic.LoadInt64(&successCount)
	fatalFailures := atomic.LoadInt64(&fatalErrCount)
	if scaleUpOutcomeRequiresCooldown(succeeded, fatalFailures) {
		as.markScaleUpCooldown(policy, "provision attempt completed or failed fatally")
		if succeeded > 0 {
			log.Printf("[AutoScaler] Scale UP complete: %d/%d instances created successfully", succeeded, count)
		} else {
			log.Printf("[AutoScaler] Scale UP failed with %d fatal errors; cooldown updated to prevent retry spam", fatalFailures)
		}
	} else {
		log.Printf("[AutoScaler] Scale UP failed: all %d instance creation attempts failed with transient errors; cooldown not updated", count)
	}
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

	for _, inst := range toTerminate {
		go func(instance db.CloudInstance) {
			manager, err := as.getOrCreateManagerForRegion(&account, instance.Region)
			if err != nil {
				log.Printf("[AutoScaler] Failed to get manager for instance %s region %s: %v", instance.ID, instance.Region, err)
				return
			}
			if err := manager.TerminateInstance(ctx, &instance); err != nil {
				log.Printf("[AutoScaler] Failed to terminate instance %s: %v", instance.ID, err)
			}
		}(inst)
	}

	// 更新冷却时间戳
	now := time.Now()
	as.db.Model(policy).Update("last_scale_action", &now)
}

func managerCacheKey(account *db.CloudAccount) string {
	return account.ID + ":" + account.Region
}

func managerCachePrefix(accountID string) string {
	return accountID + ":"
}

func accountWithRegion(account *db.CloudAccount, region string) db.CloudAccount {
	copy := *account
	if region = strings.TrimSpace(region); region != "" {
		copy.Region = region
	}
	return copy
}

func (as *AutoScaler) getOrCreateManagerForRegion(account *db.CloudAccount, region string) (*ResourceManager, error) {
	scopedAccount := accountWithRegion(account, region)
	return as.getOrCreateManager(&scopedAccount)
}

// getOrCreateManager 获取或创建某个云账号与地域对应的 ResourceManager
func (as *AutoScaler) getOrCreateManager(account *db.CloudAccount) (*ResourceManager, error) {
	cacheKey := managerCacheKey(account)

	as.mu.RLock()
	if m, ok := as.managers[cacheKey]; ok {
		as.mu.RUnlock()
		return m, nil
	}
	as.mu.RUnlock()

	as.mu.Lock()
	defer as.mu.Unlock()

	// 双检
	if m, ok := as.managers[cacheKey]; ok {
		return m, nil
	}

	provider, err := NewProviderFromAccount(account)
	if err != nil {
		return nil, err
	}

	manager := NewResourceManager(provider)
	manager.SetDB(as.db)
	as.managers[cacheKey] = manager
	return manager, nil
}

// InvalidateManager 清除指定云账号的所有地域缓存 Manager。
// 当用户更新了 AK/SK 凭证时，必须调用此方法以确保后续操作使用新凭证。
func (as *AutoScaler) InvalidateManager(accountID string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	prefix := managerCachePrefix(accountID)
	for key := range as.managers {
		if strings.HasPrefix(key, prefix) {
			delete(as.managers, key)
		}
	}
	log.Printf("[AutoScaler] Manager cache invalidated for account %s", accountID)
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
	as.db.Where("status IN ?", []string{
		db.CloudStatusProvisioning,
		db.CloudStatusRunning,
		db.CloudStatusWaitingReady,
		db.CloudStatusRebooting,
		db.CloudStatusTerminating,
	}).Find(&instances)

	if len(instances) == 0 {
		return
	}

	type accountRegionKey struct {
		accountID string
		region    string
	}

	// 按 account + region 分组，避免跨地域实例用账号默认地域对账。
	byAccountRegion := make(map[accountRegionKey][]db.CloudInstance)
	for _, inst := range instances {
		key := accountRegionKey{
			accountID: inst.CloudAccountID,
			region:    strings.TrimSpace(inst.Region),
		}
		byAccountRegion[key] = append(byAccountRegion[key], inst)
	}

	for key, insts := range byAccountRegion {
		var account db.CloudAccount
		if err := as.db.First(&account, "id = ?", key.accountID).Error; err != nil {
			continue
		}

		manager, err := as.getOrCreateManagerForRegion(&account, key.region)
		if err != nil {
			continue
		}

		// 查询云端实例列表
		cloudInstances, err := manager.provider.ListInstances(map[string]string{"argus:managed": "true"})
		if err != nil {
			log.Printf("[Reconciler] Failed to list instances for account %s region %s: %v", key.accountID, accountWithRegion(&account, key.region).Region, err)
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
	as.db.Find(&policies)

	now := time.Now()
	for _, policy := range policies {
		ttl := time.Duration(policy.InstanceTTLMinutes) * time.Minute
		cutoff := now.Add(-ttl)
		hardCutoff := now.Add(-(ttl + ttlActiveTaskGracePeriod))

		var expired []db.CloudInstance
		as.db.Where(
			"policy_id = ? AND status IN ? AND created_at < ?",
			policy.ID,
			[]string{
				db.CloudStatusProvisioning,
				db.CloudStatusWaitingReady,
				db.CloudStatusRunning,
				db.CloudStatusRebooting,
				db.CloudStatusTerminating,
				db.CloudStatusError,
			},
			cutoff,
		).Find(&expired)

		if len(expired) == 0 {
			continue
		}

		var account db.CloudAccount
		if err := as.db.First(&account, "id = ?", policy.CloudAccountID).Error; err != nil {
			continue
		}

		for _, inst := range expired {
			if as.shouldDeferTTLTermination(&inst, hardCutoff) {
				log.Printf("[OrphanSweeper] Instance %s exceeded TTL (%v) but agent %s still has running tasks; deferring up to %v grace",
					inst.ID, ttl, inst.AgentID, ttlActiveTaskGracePeriod)
				continue
			}

			log.Printf("[OrphanSweeper] Instance %s exceeded TTL (%v), terminating...", inst.ID, ttl)
			go func(instance db.CloudInstance) {
				manager, err := as.getOrCreateManagerForRegion(&account, instance.Region)
				if err != nil {
					log.Printf("[OrphanSweeper] Failed to get manager for instance %s region %s: %v", instance.ID, instance.Region, err)
					return
				}
				if err := manager.TerminateInstance(ctx, &instance); err != nil {
					log.Printf("[OrphanSweeper] Failed to terminate instance %s: %v", instance.ID, err)
				}
			}(inst)
		}
	}
}

func (as *AutoScaler) shouldDeferTTLTermination(inst *db.CloudInstance, hardCutoff time.Time) bool {
	if inst.Status != db.CloudStatusRunning || inst.AgentID == "" {
		return false
	}
	if !inst.CreatedAt.After(hardCutoff) {
		return false
	}

	var node db.Node
	if err := as.db.Select("running_tasks").
		Where("agent_id = ? AND status = ?", inst.AgentID, "Alive").
		First(&node).Error; err != nil {
		return false
	}
	return node.RunningTasks > 0
}

func scaleUpOutcomeRequiresCooldown(successCount, fatalFailureCount int64) bool {
	return successCount > 0 || fatalFailureCount > 0
}

func (as *AutoScaler) markScaleUpCooldown(policy *db.CloudScalingPolicy, reason string) {
	if as == nil || as.db == nil || policy == nil {
		return
	}
	now := time.Now()
	if err := as.db.Model(policy).Update("last_scale_action", &now).Error; err != nil {
		log.Printf("[AutoScaler] Failed to update scale-up cooldown for policy=%s: %v", policy.Name, err)
		return
	}
	policy.LastScaleAction = &now
	log.Printf("[AutoScaler] Scale-up cooldown updated: policy=%s reason=%s", policy.Name, reason)
}

// isFatalProvisionError identifies account/configuration/quota and throttling
// failures that should not trigger another scale-up attempt every 30 seconds.
func isFatalProvisionError(errMsg string) bool {
	normalized := strings.ToLower(errMsg)
	for _, kw := range []string{
		"notenoughbalance",
		"realnameauthenticationerror",
		"forbidden",
		"quotaexceeded",
		"maxspotinstancecountexceeded",
		"operationdenied.riskcontrol",
		"invalidparameter",
		"throttling",
		"invalidaccesskeyid",
		"signaturedoesnotmatch",
		"authfailure",
		"unauthorized",
		"invalidcredentials",
		"decrypt access_key",
		"unsupported cloud provider",
		"尚未配置地域",
		"未配置 oss",
	} {
		if strings.Contains(normalized, kw) {
			return true
		}
	}
	return false
}
