package db

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type subTaskStatusCounter struct {
	Status string
	Cnt    int64
}

func NormalizeSubTaskStatus(status string) string {
	return strings.ToUpper(strings.TrimSpace(status))
}

// RefreshRootTaskStatus 聚合子任务状态并刷新 RootTask 状态、completed_chunks 与 completed_targets。
func RefreshRootTaskStatus(rootTaskID string) {
	refreshRootTaskStatus(rootTaskID, 0)
}

func refreshRootTaskStatus(rootTaskID string, attempt int) {
	if DB == nil || strings.TrimSpace(rootTaskID) == "" {
		return
	}
	const maxCASAttempts = 5
	if attempt >= maxCASAttempts {
		log.Printf("[TaskLifecycle] Root task %s status refresh did not converge after %d CAS attempts", rootTaskID, maxCASAttempts)
		return
	}

	var root RootTask
	if err := DB.Select("id", "tenant_id", "status").Where("id = ?", rootTaskID).First(&root).Error; err != nil {
		return
	}
	currentPaused := NormalizeSubTaskStatus(root.Status) == "PAUSED"
	currentCancelled := NormalizeSubTaskStatus(root.Status) == "CANCELLED"
	if currentCancelled {
		return
	}

	var counters []subTaskStatusCounter
	DB.Model(&SubTask{}).
		Select("status, count(*) as cnt").
		Where("root_task_id = ? AND tenant_id = ?", rootTaskID, root.TenantID).
		Group("status").
		Scan(&counters)

	total := int64(0)
	done := int64(0)
	active := int64(0)
	timeout := int64(0)
	failed := int64(0)
	cancelled := int64(0)
	paused := int64(0)

	for _, c := range counters {
		total += c.Cnt
		switch NormalizeSubTaskStatus(c.Status) {
		case "DONE":
			done += c.Cnt
		case "PENDING", "RUNNING", "CANCELPENDING", "RECOVERED", "DISPATCHING":
			active += c.Cnt
		case "PAUSED":
			paused += c.Cnt
			active += c.Cnt
		case "TIMEOUT":
			timeout += c.Cnt
		case "FAILED":
			failed += c.Cnt
		case "CANCELLED":
			cancelled += c.Cnt
		}
	}

	if total == 0 {
		return
	}
	if currentPaused && (active > 0 || paused > 0) {
		return
	}

	nextStatus := "Running"
	switch {
	case active > 0:
		if done > 0 {
			nextStatus = "PartialDone"
		} else {
			nextStatus = "Running"
		}
	case timeout > 0:
		nextStatus = "Timeout"
	case failed > 0:
		nextStatus = "Failed"
	case cancelled > 0:
		nextStatus = "Cancelled"
	case done == total:
		nextStatus = "FINISHED"
	default:
		nextStatus = "Queued"
	}

	// 计算已完成目标数（从已完成批次的 ChunkTargets 聚合）
	var completedTargets int64
	var doneChunks []SubTask
	DB.Select("chunk_targets").
		Where("root_task_id = ? AND tenant_id = ? AND UPPER(status) = ?", rootTaskID, root.TenantID, "DONE").
		Find(&doneChunks)
	for _, chunk := range doneChunks {
		var targets []string
		if err := json.Unmarshal([]byte(chunk.ChunkTargets), &targets); err != nil {
			continue
		}
		completedTargets += int64(len(targets))
	}

	result := DB.Model(&RootTask{}).
		Where("id = ? AND tenant_id = ? AND status = ?", rootTaskID, root.TenantID, root.Status).
		Updates(map[string]interface{}{
			"status":            nextStatus,
			"completed_chunks":  done,
			"completed_targets": completedTargets,
		})
	if result.Error != nil {
		log.Printf("[TaskLifecycle] Failed to refresh root task %s: %v", rootTaskID, result.Error)
		return
	}
	if result.RowsAffected == 0 {
		refreshRootTaskStatus(rootTaskID, attempt+1)
	}
}

// ============================================================================
// 失败批次二分拆分重试
//
// 对 FAILED/TIMEOUT 且 len(chunk_targets)>1 且仍有重试预算的 SubTask：
//   - 原 SubTask 改写为第一半目标并回到 Dispatching
//   - 新建兄弟 SubTask 承载第二半目标
//   - RootTask.total_chunks += 1
//   - 返回两个需要重新入队的 SubTask
//
// 单目标失败仍走现有重试/终态逻辑，避免无限拆分。
// ============================================================================

func lockRetryableSubTask(tx *gorm.DB, expected *SubTask) (SubTask, bool, error) {
	var current SubTask
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ? AND tenant_id = ?", expected.ID, expected.TenantID).
		First(&current).Error; err != nil {
		return current, false, err
	}
	if NormalizeSubTaskStatus(current.Status) != NormalizeSubTaskStatus(expected.Status) {
		return current, false, nil
	}
	if current.RootTaskID == "" {
		return current, true, nil
	}

	var root RootTask
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Select("id", "status").
		Where("id = ? AND tenant_id = ?", current.RootTaskID, current.TenantID).
		First(&root).Error; err != nil {
		return current, false, err
	}
	switch NormalizeSubTaskStatus(root.Status) {
	case "QUEUED", "RUNNING", "PARTIALDONE":
		return current, true, nil
	default:
		return current, false, nil
	}
}

// PrepareSubTaskRetry atomically checks the current lease and root lifecycle,
// then advances one failed/running subtask to Dispatching for a regular retry.
func PrepareSubTaskRetry(sub *SubTask) (prepared SubTask, ok bool) {
	if DB == nil || sub == nil || strings.TrimSpace(sub.ID) == "" {
		return SubTask{}, false
	}
	err := DB.Transaction(func(tx *gorm.DB) error {
		current, allowed, err := lockRetryableSubTask(tx, sub)
		if err != nil {
			return err
		}
		if !allowed || current.RetryCount >= current.MaxRetry {
			return nil
		}
		update := tx.Model(&SubTask{}).
			Where("id = ? AND tenant_id = ? AND status = ?", current.ID, current.TenantID, current.Status).
			Updates(map[string]interface{}{
				"status":        "Dispatching",
				"retry_count":   current.RetryCount + 1,
				"agent_id":      "",
				"stream_msg_id": "",
			})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			return nil
		}
		current.Status = "Dispatching"
		current.RetryCount++
		current.AgentID = ""
		current.StreamMsgID = ""
		prepared = current
		ok = true
		return nil
	})
	if err != nil {
		log.Printf("[Retry] Failed to prepare subtask %s: %v", sub.ID, err)
		return SubTask{}, false
	}
	if ok {
		*sub = prepared
	}
	return prepared, ok
}

// SplitFailedSubTask atomically checks the subtask lease and root lifecycle,
// then splits a retryable multi-target batch. resetRetryBudget is reserved for
// the timeout daemon's last-resort split after the ordinary budget is exhausted.
func SplitFailedSubTask(sub *SubTask, resetRetryBudget bool) (split []SubTask, didSplit, retryAllowed bool) {
	if DB == nil || sub == nil || strings.TrimSpace(sub.ID) == "" {
		return nil, false, false
	}

	var current SubTask
	var sibling SubTask
	err := DB.Transaction(func(tx *gorm.DB) error {
		var allowed bool
		var err error
		current, allowed, err = lockRetryableSubTask(tx, sub)
		if err != nil {
			return err
		}
		if !allowed {
			return nil
		}
		retryAllowed = true

		var targets []string
		if err := json.Unmarshal([]byte(current.ChunkTargets), &targets); err != nil {
			log.Printf("[SplitRetry] Failed to parse ChunkTargets for subtask %s: %v", current.ID, err)
			return nil
		}
		retryCount := current.RetryCount
		if resetRetryBudget {
			retryCount = 0
		}
		if len(targets) <= 1 || retryCount >= current.MaxRetry {
			return nil
		}

		mid := len(targets) / 2
		firstJSON, _ := json.Marshal(targets[:mid])
		secondJSON, _ := json.Marshal(targets[mid:])
		update := tx.Model(&SubTask{}).
			Where("id = ? AND tenant_id = ? AND status = ?", current.ID, current.TenantID, current.Status).
			Updates(map[string]interface{}{
				"chunk_targets": string(firstJSON),
				"status":        "Dispatching",
				"retry_count":   retryCount + 1,
				"agent_id":      "",
				"stream_msg_id": "",
			})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			retryAllowed = false
			return nil
		}

		sibling = SubTask{
			ID:                 fmt.Sprintf("%s-split-%d", current.ID, time.Now().UnixNano()),
			TenantID:           current.TenantID,
			ProjectID:          current.ProjectID,
			RootTaskID:         current.RootTaskID,
			ChunkTargets:       string(secondJSON),
			Status:             "Dispatching",
			Config:             current.Config,
			Priority:           current.Priority,
			AgentSelector:      current.AgentSelector,
			AgentSelectorRules: current.AgentSelectorRules,
			TimeoutSec:         current.TimeoutSec,
			RetryCount:         retryCount + 1,
			MaxRetry:           current.MaxRetry,
		}
		if err := tx.Create(&sibling).Error; err != nil {
			return err
		}
		if current.RootTaskID != "" {
			rootUpdate := tx.Model(&RootTask{}).
				Where("id = ? AND tenant_id = ?", current.RootTaskID, current.TenantID).
				UpdateColumn("total_chunks", gorm.Expr("total_chunks + 1"))
			if rootUpdate.Error != nil {
				return rootUpdate.Error
			}
			if rootUpdate.RowsAffected != 1 {
				return fmt.Errorf("root task %s not found for tenant %s", current.RootTaskID, current.TenantID)
			}
		}

		current.ChunkTargets = string(firstJSON)
		current.Status = "Dispatching"
		current.RetryCount = retryCount + 1
		current.AgentID = ""
		current.StreamMsgID = ""
		didSplit = true
		return nil
	})
	if err != nil {
		log.Printf("[SplitRetry] Failed to split subtask %s: %v", sub.ID, err)
		return nil, false, false
	}
	if !didSplit {
		return nil, false, retryAllowed
	}

	*sub = current
	log.Printf("[SplitRetry] SubTask %s split into 2 batches (retry %d/%d)", sub.ID, sub.RetryCount, sub.MaxRetry)
	return []SubTask{current, sibling}, true, true
}
