package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

func getTasks(c *gin.Context) {
	var tasks []db.RootTask
	tenantID := c.GetString("tenant")
	page, pageSize := parsePagination(c, 20, 100)
	query := db.DB.Where("tenant_id = ?", tenantID)
	query, _ = applyProjectScope(c, query, "project_id")

	var total int64
	if err := query.Model(&db.RootTask{}).Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := query.Order("created_at desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&tasks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 增强返回：包含目标维度进度
	type TaskResponse struct {
		db.RootTask
	}
	resp := make([]TaskResponse, 0, len(tasks))
	for _, t := range tasks {
		resp = append(resp, TaskResponse{RootTask: t})
	}
	c.JSON(http.StatusOK, pagedResponse(resp, total, page, pageSize, ""))
}

type taskReasonStat struct {
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Count       int    `json:"count"`
	TargetCount int    `json:"target_count"`
}

func subTaskTargetCount(st db.SubTask) int {
	var targets []string
	if json.Unmarshal([]byte(st.ChunkTargets), &targets) == nil {
		return len(targets)
	}
	return 0
}

func buildTaskReasonStats(subTasks []db.SubTask) []taskReasonStat {
	type acc struct {
		status      string
		reason      string
		count       int
		targetCount int
	}
	statsByKey := make(map[string]*acc)
	order := make([]string, 0)
	add := func(status, reason string, targetCount int) {
		if reason == "" {
			return
		}
		key := status + "\x00" + reason
		if _, ok := statsByKey[key]; !ok {
			statsByKey[key] = &acc{status: status, reason: reason}
			order = append(order, key)
		}
		statsByKey[key].count++
		statsByKey[key].targetCount += targetCount
	}

	for _, st := range subTasks {
		targetCount := subTaskTargetCount(st)
		switch db.NormalizeSubTaskStatus(st.Status) {
		case "FAILED":
			add(st.Status, "批次失败或重试耗尽", targetCount)
		case "TIMEOUT":
			if st.TimeoutSec > 0 {
				add(st.Status, fmt.Sprintf("超过 %d 秒未完成或重试耗尽", st.TimeoutSec), targetCount)
			} else {
				add(st.Status, "批次超时或重试耗尽", targetCount)
			}
		case "CANCELLED":
			add(st.Status, "用户取消后已终止", targetCount)
		case "CANCELPENDING":
			add(st.Status, "取消请求已下发，等待 Agent 确认", targetCount)
		case "PENDING", "DISPATCHING", "RECOVERED":
			if strings.TrimSpace(st.AgentID) == "" {
				add(st.Status, "等待可匹配节点认领", targetCount)
			}
		}
	}

	stats := make([]taskReasonStat, 0, len(order))
	for _, key := range order {
		item := statsByKey[key]
		stats = append(stats, taskReasonStat{
			Status:      item.status,
			Reason:      item.reason,
			Count:       item.count,
			TargetCount: item.targetCount,
		})
	}
	return stats
}

// getTaskDetail 返回单个任务的详细信息，包括子任务列表和结果统计
func getTaskDetail(c *gin.Context) {
	taskID := c.Param("id")
	tenantID := currentTenantID(c)

	// 查询 RootTask
	var rootTask db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", taskID, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}

	// 查询关联的所有 SubTask
	var subTasks []db.SubTask
	db.DB.Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).
		Order("created_at asc").Find(&subTasks)

	// 子任务状态分布统计
	statusDistribution := make(map[string]int)
	for _, st := range subTasks {
		statusDistribution[st.Status]++
	}

	// 构建子任务摘要（不暴露完整 Config 和 ChunkTargets 原文）
	type SubTaskSummary struct {
		ID          string    `json:"id"`
		Status      string    `json:"status"`
		AgentID     string    `json:"agent_id"`
		TargetCount int       `json:"target_count"`
		RetryCount  int       `json:"retry_count"`
		MaxRetry    int       `json:"max_retry"`
		Priority    int       `json:"priority"`
		TimeoutSec  int       `json:"timeout_sec"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
	}
	subSummaries := make([]SubTaskSummary, 0, len(subTasks))
	for _, st := range subTasks {
		targetCount := subTaskTargetCount(st)
		subSummaries = append(subSummaries, SubTaskSummary{
			ID:          st.ID,
			Status:      st.Status,
			AgentID:     st.AgentID,
			TargetCount: targetCount,
			RetryCount:  st.RetryCount,
			MaxRetry:    st.MaxRetry,
			Priority:    st.Priority,
			TimeoutSec:  st.TimeoutSec,
			CreatedAt:   st.CreatedAt,
			UpdatedAt:   st.UpdatedAt,
		})
	}

	// 结果统计（通过 root_task_id 直接关联到 RootTask，不受 upsert 改写 task_id 影响）
	var assetCount, fpCount, vulnCount int64
	db.DB.Model(&db.Asset{}).Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).Count(&assetCount)
	db.DB.Model(&db.FingerprintHit{}).Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).Count(&fpCount)
	db.DB.Model(&db.Vulnerability{}).Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).Count(&vulnCount)

	// Fallback: 如果 root_task_id 为空（旧数据），用 task_id IN subTaskIDs 兜底
	if assetCount == 0 && fpCount == 0 && vulnCount == 0 && len(subTasks) > 0 {
		subTaskIDs := make([]string, len(subTasks))
		for i, st := range subTasks {
			subTaskIDs[i] = st.ID
		}
		db.DB.Model(&db.Asset{}).Where("task_id IN ? AND tenant_id = ?", subTaskIDs, tenantID).Count(&assetCount)
		db.DB.Model(&db.FingerprintHit{}).Where("task_id IN ? AND tenant_id = ?", subTaskIDs, tenantID).Count(&fpCount)
		db.DB.Model(&db.Vulnerability{}).Where("task_id IN ? AND tenant_id = ?", subTaskIDs, tenantID).Count(&vulnCount)
	}

	// 漏洞严重度分布
	type sevCount struct {
		Severity string
		Cnt      int64
	}
	var sevDist []sevCount
	db.DB.Model(&db.Vulnerability{}).
		Select("severity, count(*) as cnt").
		Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).
		Group("severity").Scan(&sevDist)
	severityMap := make(map[string]int64)
	for _, s := range sevDist {
		severityMap[s.Severity] = s.Cnt
	}

	// 解析原始配置为 JSON 对象返回
	var configObj interface{}
	if json.Unmarshal([]byte(rootTask.Config), &configObj) != nil {
		configObj = rootTask.Config
	}

	c.JSON(http.StatusOK, gin.H{
		"task": gin.H{
			"id":                rootTask.ID,
			"name":              rootTask.Name,
			"status":            rootTask.Status,
			"priority":          rootTask.Priority,
			"total_chunks":      rootTask.TotalChunks,
			"completed_chunks":  rootTask.CompletedChunks,
			"total_targets":     rootTask.TotalTargets,
			"completed_targets": rootTask.CompletedTargets,
			"timeout_sec":       rootTask.TimeoutSec,
			"original_targets":  rootTask.OriginalTargets,
			"config":            configObj,
			"rule_version":      rootTask.RuleVersion,
			"created_at":        rootTask.CreatedAt,
			"updated_at":        rootTask.UpdatedAt,
		},
		"sub_tasks":           subSummaries,
		"status_distribution": statusDistribution,
		"reason_stats":        buildTaskReasonStats(subTasks),
		"result_stats": gin.H{
			"assets":       assetCount,
			"fingerprints": fpCount,
			"vulns":        vulnCount,
			"severity":     severityMap,
		},
	})
}

func createTask(c *gin.Context) {
	var req struct {
		ProjectID          string          `json:"project_id"`
		Name               string          `json:"name"`
		Targets            json.RawMessage `json:"targets"`
		Config             json.RawMessage `json:"config"`
		Priority           int             `json:"priority"`
		TimeoutSec         int             `json:"timeout_sec"`
		AgentSelector      json.RawMessage `json:"agent_selector"`
		AgentSelectorRules json.RawMessage `json:"agent_selector_rules"`
		SkipUnsupported    bool            `json:"skip_unsupported"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.ProjectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project_id is required"})
		return
	}
	project, ok := requireProjectAccess(c, req.ProjectID)
	if !ok {
		return
	}
	if project.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project is not active"})
		return
	}

	if req.Priority < 0 || req.Priority > 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "priority must be 0 (urgent), 1 (normal), or 2 (low)"})
		return
	}
	if req.TimeoutSec < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "timeout_sec must be greater than or equal to 0"})
		return
	}
	userSelector, err := parseAgentSelector(req.AgentSelector)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	userRules, err := parseAgentSelectorRules(req.AgentSelectorRules)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	configJSON, targetMode, err := normalizeTaskConfigPayload(req.Config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var skippedTargets []invalidTarget
	var targets []string
	var targetSummary taskTargetSummary
	if req.SkipUnsupported {
		rawTargets, parseErr := parseTargets(req.Targets)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": parseErr.Error()})
			return
		}
		targets, skippedTargets, _ = classifyTargets(rawTargets, targetMode)
		if len(targets) > 0 {
			targets, targetSummary, err = validateTargetsByMode(targets, targetMode)
		}
	} else {
		targets, targetSummary, err = parseAndValidateTargetsForMode(req.Targets, targetMode)
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(targets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "targets is empty"})
		return
	}

	targetsJSON, err := json.Marshal(targets)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if taskQueue == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "task queue not initialized"})
		return
	}

	rootTaskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = targets[0]
	}

	// 多租户隔离下钻
	tenantID := c.GetString("tenant")

	// ================================================================
	// 批次聚合入队（激进档）
	//
	// 替代原有"每目标一个SubTask"的原子拆分：
	//   1. 按 target_type 分组
	//   2. 每组按激进档批大小切片生成聚合 SubTask
	//   3. 聚合后 TotalChunks = 批次数（不再等于目标数）
	//   4. TotalTargets 记录原始目标总数用于进度展示
	// ================================================================

	batches := groupAndBatchTargets(targets, targetMode)

	var subTasks []db.SubTask
	profile := batchProfile{
		TotalTargets:  len(targets),
		TotalBatches:  len(batches),
		BatchesByType: make(map[string]int),
		BatchSize:     make(map[string]int),
	}

	for idx, batch := range batches {
		chunkJSON, _ := json.Marshal(batch.Targets)

		_, _, rulesJSON := effectiveSelectorRules(batch.SelectorJSON, userSelector, userRules)
		subTasks = append(subTasks, db.SubTask{
			ID:                 fmt.Sprintf("%s-batch-%d-%s", rootTaskID, idx, batch.TargetType),
			TenantID:           tenantID,
			ProjectID:          req.ProjectID,
			RootTaskID:         rootTaskID,
			ChunkTargets:       string(chunkJSON),
			Status:             subTaskStatusDispatching,
			Config:             configJSON,
			Priority:           req.Priority,
			TimeoutSec:         req.TimeoutSec,
			MaxRetry:           3,
			AgentSelector:      mergeAgentSelector(batch.SelectorJSON, userSelector),
			AgentSelectorRules: rulesJSON,
		})

		profile.BatchesByType[batch.TargetType]++
		if _, ok := profile.BatchSize[batch.TargetType]; !ok {
			profile.BatchSize[batch.TargetType] = batchSizeForTargetType(batch.TargetType)
		}
	}

	rootTask := db.RootTask{
		ID:               rootTaskID,
		TenantID:         tenantID,
		ProjectID:        req.ProjectID,
		UserID:           currentUserID(c),
		Name:             name,
		Status:           "Queued",
		OriginalTargets:  string(targetsJSON),
		Config:           configJSON,
		TotalChunks:      len(subTasks),
		CompletedChunks:  0,
		TotalTargets:     len(targets),
		CompletedTargets: 0,
		Priority:         req.Priority,
		TimeoutSec:       req.TimeoutSec,
	}

	// 2. Transaction for Root and SubTasks
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		if err := db.CheckTenantTaskCreationQuota(tx, tenantID, time.Now()); err != nil {
			return err
		}
		if err := tx.Create(&rootTask).Error; err != nil {
			return err
		}
		if len(subTasks) > 0 {
			if err := tx.CreateInBatches(subTasks, 100).Error; err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		if writeTenantQuotaError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 3. Dispatch to Queue（闭环保证：失败任务保留 Dispatching，守护协程会继续补投）
	pushedByPriority, dispatchPending := dispatchSubTasks(context.Background(), taskQueue, subTasks)
	pushedCount := totalDispatchedTasks(pushedByPriority)
	broadcastDispatchedTasks(pushedByPriority)
	if dispatchPending > 0 {
		log.Printf("[CreateTask] RootTask %s has %d batches pending dispatch recovery", rootTask.ID, dispatchPending)
	}

	log.Printf("[CreateTask] RootTask %s: %d targets → %d batches (profile: %v)",
		rootTask.ID, len(targets), len(subTasks), profile.BatchesByType)

	resp := gin.H{
		"status":           "task_created",
		"task_id":          rootTask.ID,
		"target_summary":   targetSummary,
		"dispatched":       pushedCount,
		"dispatch_pending": dispatchPending,
		"batch_profile":    profile,
		"batch_summary": gin.H{
			"total_targets": len(targets),
			"total_batches": len(subTasks),
		},
	}
	if len(skippedTargets) > 0 {
		resp["skipped_targets"] = skippedTargets
	}
	c.JSON(http.StatusOK, resp)
}
