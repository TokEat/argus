package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

func deleteTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var rootTask db.RootTask
	if err := db.DB.Select("id", "project_id").Where("id = ? AND tenant_id = ?", id, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	db.DB.Delete(&db.RootTask{}, "id = ? AND tenant_id = ?", id, tenantID)
	db.DB.Delete(&db.SubTask{}, "root_task_id = ? AND tenant_id = ?", id, tenantID)

	// 删除任务关联的扫描结果
	db.DB.Where("root_task_id = ? AND tenant_id = ?", id, tenantID).Delete(&db.Asset{})
	db.DB.Where("root_task_id = ? AND tenant_id = ?", id, tenantID).Delete(&db.FingerprintHit{})
	db.DB.Where("root_task_id = ? AND tenant_id = ?", id, tenantID).Delete(&db.Vulnerability{})

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func cancelTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var rootTask db.RootTask
	if err := db.DB.Select("id", "project_id").Where("id = ? AND tenant_id = ?", id, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	cancelledWithoutClaim := int64(0)
	cancelPendingRunning := int64(0)

	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&db.SubTask{}).
			Where("root_task_id = ? AND tenant_id = ? AND status IN ?", id, tenantID, []string{"Pending", "Recovered", subTaskStatusDispatching}).
			Updates(map[string]interface{}{
				"status":        "Cancelled",
				"agent_id":      "",
				"stream_msg_id": "",
			})
		if res.Error != nil {
			return res.Error
		}
		cancelledWithoutClaim = res.RowsAffected

		res = tx.Model(&db.SubTask{}).
			Where("root_task_id = ? AND tenant_id = ? AND status IN ?", id, tenantID, []string{"Running", "CancelPending"}).
			Update("status", "CancelPending")
		if res.Error != nil {
			return res.Error
		}
		cancelPendingRunning = res.RowsAffected
		return nil
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	db.RefreshRootTaskStatus(id)

	c.JSON(http.StatusOK, gin.H{
		"status":                   "cancellation dispatched",
		"cancelled_without_claim":  cancelledWithoutClaim,
		"cancel_pending_on_agents": cancelPendingRunning,
	})
}

func pauseTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var rootTask db.RootTask
	if err := db.DB.Select("id", "project_id", "status").Where("id = ? AND tenant_id = ?", id, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	switch db.NormalizeSubTaskStatus(rootTask.Status) {
	case "QUEUED", "RUNNING", "PARTIALDONE":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "task is not in a pausable state"})
		return
	}

	var pausedWithoutClaim int64
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&db.SubTask{}).
			Where("root_task_id = ? AND tenant_id = ? AND status IN ?", id, tenantID, []string{"Pending", "Recovered", subTaskStatusDispatching}).
			Updates(map[string]interface{}{
				"status":        "Paused",
				"agent_id":      "",
				"stream_msg_id": "",
			})
		if res.Error != nil {
			return res.Error
		}
		pausedWithoutClaim = res.RowsAffected
		return tx.Model(&db.RootTask{}).
			Where("id = ? AND tenant_id = ?", id, tenantID).
			Update("status", "Paused").Error
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":                 "paused",
		"paused_without_claim":   pausedWithoutClaim,
		"running_tasks_continue": true,
	})
}

func resumeTask(c *gin.Context) {
	id := c.Param("id")
	tenantID := currentTenantID(c)
	var rootTask db.RootTask
	if err := db.DB.Select("id", "project_id", "status").Where("id = ? AND tenant_id = ?", id, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	if db.NormalizeSubTaskStatus(rootTask.Status) != "PAUSED" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "task is not paused"})
		return
	}

	var pausedSubs []db.SubTask
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("root_task_id = ? AND tenant_id = ? AND status = ?", id, tenantID, "Paused").
			Find(&pausedSubs).Error; err != nil {
			return err
		}
		for i := range pausedSubs {
			pausedSubs[i].Status = subTaskStatusDispatching
		}
		if len(pausedSubs) > 0 {
			ids := make([]string, 0, len(pausedSubs))
			for _, sub := range pausedSubs {
				ids = append(ids, sub.ID)
			}
			if err := tx.Model(&db.SubTask{}).
				Where("id IN ? AND root_task_id = ? AND tenant_id = ? AND status = ?", ids, id, tenantID, "Paused").
				Updates(map[string]interface{}{
					"status":        subTaskStatusDispatching,
					"agent_id":      "",
					"stream_msg_id": "",
				}).Error; err != nil {
				return err
			}
		}
		return tx.Model(&db.RootTask{}).
			Where("id = ? AND tenant_id = ?", id, tenantID).
			Update("status", "Queued").Error
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	pushedByPriority, dispatchPending := dispatchSubTasks(context.Background(), routerRuntime().TaskQueue, pausedSubs)
	if totalDispatchedTasks(pushedByPriority) > 0 {
		broadcastDispatchedTasks(pushedByPriority)
	}
	db.RefreshRootTaskStatus(id)

	c.JSON(http.StatusOK, gin.H{
		"status":           "resumed",
		"reactivated":      len(pausedSubs),
		"dispatch_pending": dispatchPending,
	})
}

// appendTargets 向运行中的任务动态追加目标
// POST /tasks/:id/append  body: { "targets": "1.1.1.1\n2.2.2.2" }
func appendTargets(c *gin.Context) {
	rootTaskID := c.Param("id")

	var req struct {
		Targets json.RawMessage `json:"targets"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 校验 RootTask 存在（含租户隔离）
	var rootTask db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", rootTaskID, currentTenantID(c)).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}

	// 解析新目标
	targetMode := detectTargetModeFromStoredConfig(rootTask.Config)
	newTargets, targetSummary, err := parseAndValidateTargetsForMode(req.Targets, targetMode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(newTargets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No targets to append"})
		return
	}
	if routerRuntime().TaskQueue == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "task queue not initialized"})
		return
	}

	tenantID := c.GetString("tenant")

	// 获取当前已有子任务数量作为新批次的起始编号
	var existingCount int64
	db.DB.Model(&db.SubTask{}).Where("root_task_id = ? AND tenant_id = ?", rootTaskID, tenantID).Count(&existingCount)
	baseIndex := int(existingCount)

	// 聚合切批生成 SubTasks
	batches := groupAndBatchTargets(newTargets, targetMode)
	configJSON := rootTask.Config

	var newSubTasks []db.SubTask
	profile := batchProfile{
		TotalTargets:  len(newTargets),
		TotalBatches:  len(batches),
		BatchesByType: make(map[string]int),
		BatchSize:     make(map[string]int),
	}

	for idx, batch := range batches {
		chunkJSON, _ := json.Marshal(batch.Targets)
		newSubTasks = append(newSubTasks, db.SubTask{
			ID:            fmt.Sprintf("%s-batch-%d-%s", rootTaskID, baseIndex+idx, batch.TargetType),
			TenantID:      tenantID,
			ProjectID:     rootTask.ProjectID,
			RootTaskID:    rootTaskID,
			ChunkTargets:  string(chunkJSON),
			Status:        subTaskStatusDispatching,
			Config:        configJSON,
			Priority:      rootTask.Priority,
			TimeoutSec:    rootTask.TimeoutSec,
			MaxRetry:      3,
			AgentSelector: batch.SelectorJSON,
		})
		profile.BatchesByType[batch.TargetType]++
		if _, ok := profile.BatchSize[batch.TargetType]; !ok {
			profile.BatchSize[batch.TargetType] = batchSizeForTargetType(batch.TargetType)
		}
	}

	// 事务写入新 SubTasks
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.CreateInBatches(newSubTasks, 100).Error; err != nil {
			return err
		}
		// 更新 RootTask 的 TotalChunks/TotalTargets 和状态
		return tx.Model(&rootTask).Updates(map[string]interface{}{
			"total_chunks":  gorm.Expr("total_chunks + ?", len(newSubTasks)),
			"total_targets": gorm.Expr("total_targets + ?", len(newTargets)),
			"status":        "Running", // 如果之前是 FINISHED/PartialDone，重新激活
		}).Error
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 推入调度队列（失败保留 Dispatching，守护协程继续补投）
	pushedByPriority, dispatchPending := dispatchSubTasks(context.Background(), routerRuntime().TaskQueue, newSubTasks)
	pushedCount := totalDispatchedTasks(pushedByPriority)
	broadcastDispatchedTasks(pushedByPriority)
	if dispatchPending > 0 {
		log.Printf("[AppendTargets] RootTask %s has %d batches pending dispatch recovery", rootTaskID, dispatchPending)
	}

	log.Printf("[AppendTargets] RootTask %s: appended %d targets → %d batches", rootTaskID, len(newTargets), len(newSubTasks))

	c.JSON(http.StatusOK, gin.H{
		"status":           "appended",
		"new_subtasks":     len(newSubTasks),
		"new_targets":      len(newTargets),
		"total_chunks":     rootTask.TotalChunks + len(newSubTasks),
		"target_summary":   targetSummary,
		"dispatched":       pushedCount,
		"dispatch_pending": dispatchPending,
		"batch_profile":    profile,
		"batch_summary": gin.H{
			"total_targets": len(newTargets),
			"total_batches": len(newSubTasks),
		},
	})
}

func getQueueDepth(c *gin.Context) {
	if routerRuntime().TaskQueue == nil {
		c.JSON(http.StatusOK, gin.H{"error": "queue not initialized"})
		return
	}

	tenantID := currentTenantID(c)
	ctx := context.Background()
	depth := routerRuntime().TaskQueue.QueueDepth(ctx)
	pending := routerRuntime().TaskQueue.PendingCount(ctx)

	// 计算批次维度总量
	readyBatches := int64(0)
	pendingBatches := int64(0)
	for _, v := range depth {
		readyBatches += v
	}
	for _, v := range pending {
		pendingBatches += v
	}

	// 从 DB 统计目标维度（按 SubTask 状态聚合 ChunkTargets 中的目标数量）
	var readyTargets, pendingTargets int64
	type targetCountResult struct {
		Status string
		Cnt    int64
	}
	var results []targetCountResult
	db.DB.Raw(`
			SELECT status, SUM(jsonb_array_length(chunk_targets::jsonb)) as cnt
			FROM sub_tasks
			WHERE tenant_id = ? AND status IN ('Pending', 'Dispatching', 'Running', 'Recovered')
			GROUP BY status
		`, tenantID).Scan(&results)
	for _, r := range results {
		switch db.NormalizeSubTaskStatus(r.Status) {
		case "PENDING", "DISPATCHING", "RECOVERED":
			readyTargets += r.Cnt
		case "RUNNING":
			pendingTargets += r.Cnt
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"depth":           depth,
		"pending":         pending,
		"mode":            routerRuntime().TaskQueue.Mode(),
		"ready_batches":   readyBatches,
		"pending_batches": pendingBatches,
		"ready_targets":   readyTargets,
		"pending_targets": pendingTargets,
	})
}
