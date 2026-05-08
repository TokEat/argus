package db

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
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
	if DB == nil || strings.TrimSpace(rootTaskID) == "" {
		return
	}

	var counters []subTaskStatusCounter
	DB.Model(&SubTask{}).
		Select("status, count(*) as cnt").
		Where("root_task_id = ?", rootTaskID).
		Group("status").
		Scan(&counters)

	total := int64(0)
	done := int64(0)
	active := int64(0)
	timeout := int64(0)
	failed := int64(0)
	cancelled := int64(0)

	for _, c := range counters {
		total += c.Cnt
		switch NormalizeSubTaskStatus(c.Status) {
		case "DONE":
			done += c.Cnt
		case "PENDING", "RUNNING", "CANCELPENDING", "RECOVERED", "DISPATCHING":
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
		Where("root_task_id = ? AND UPPER(status) = ?", rootTaskID, "DONE").
		Find(&doneChunks)
	for _, chunk := range doneChunks {
		var targets []string
		if err := json.Unmarshal([]byte(chunk.ChunkTargets), &targets); err != nil {
			continue
		}
		completedTargets += int64(len(targets))
	}

	DB.Model(&RootTask{}).Where("id = ?", rootTaskID).Updates(map[string]interface{}{
		"status":            nextStatus,
		"completed_chunks":  done,
		"completed_targets": completedTargets,
	})
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

// SplitFailedSubTask 对失败的多目标批次执行二分拆分重试。
// 返回需要重新入队调度的 SubTask 列表（0~2个），以及是否执行了拆分。
func SplitFailedSubTask(sub *SubTask) ([]SubTask, bool) {
	// 解析 ChunkTargets
	var targets []string
	if err := json.Unmarshal([]byte(sub.ChunkTargets), &targets); err != nil {
		log.Printf("[SplitRetry] Failed to parse ChunkTargets for subtask %s: %v", sub.ID, err)
		return nil, false
	}

	// 单目标不拆分
	if len(targets) <= 1 {
		return nil, false
	}

	// 检查重试预算
	if sub.RetryCount >= sub.MaxRetry {
		return nil, false
	}

	mid := len(targets) / 2
	firstHalf := targets[:mid]
	secondHalf := targets[mid:]

	firstJSON, _ := json.Marshal(firstHalf)
	secondJSON, _ := json.Marshal(secondHalf)

	// 原 SubTask 改写为第一半目标，回到 Dispatching
	if err := DB.Model(sub).Updates(map[string]interface{}{
		"chunk_targets": string(firstJSON),
		"status":        "Dispatching",
		"retry_count":   sub.RetryCount + 1,
		"agent_id":      "",
		"stream_msg_id": "",
	}).Error; err != nil {
		log.Printf("[SplitRetry] Failed to update first-half subtask %s: %v", sub.ID, err)
		return nil, false
	}

	// 新建兄弟 SubTask 承载第二半目标
	siblingID := fmt.Sprintf("%s-split-%d", sub.ID, time.Now().UnixMilli()%10000)
	sibling := SubTask{
		ID:                 siblingID,
		TenantID:           sub.TenantID,
		ProjectID:          sub.ProjectID,
		RootTaskID:         sub.RootTaskID,
		ChunkTargets:       string(secondJSON),
		Status:             "Dispatching",
		Config:             sub.Config,
		Priority:           sub.Priority,
		AgentSelector:      sub.AgentSelector,
		AgentSelectorRules: sub.AgentSelectorRules,
		TimeoutSec:         sub.TimeoutSec,
		RetryCount:         sub.RetryCount + 1,
		MaxRetry:           sub.MaxRetry,
	}

	if err := DB.Create(&sibling).Error; err != nil {
		log.Printf("[SplitRetry] Failed to create sibling subtask %s: %v", siblingID, err)
		return nil, false
	}

	// RootTask.total_chunks += 1（拆分产生了一个新批次）
	DB.Exec("UPDATE root_tasks SET total_chunks = total_chunks + 1 WHERE id = ?", sub.RootTaskID)

	log.Printf("[SplitRetry] SubTask %s split: [%d targets] → [%d] + [%d] (retry %d/%d)",
		sub.ID, len(targets), len(firstHalf), len(secondHalf), sub.RetryCount+1, sub.MaxRetry)

	// 返回两个需要入队的 SubTask
	// 更新 sub 内存状态以便调用方使用
	sub.ChunkTargets = string(firstJSON)
	sub.Status = "Dispatching"
	sub.RetryCount++
	sub.AgentID = ""
	sub.StreamMsgID = ""

	return []SubTask{*sub, sibling}, true
}
