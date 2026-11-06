package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/credentialbundle"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/scheduler"
)

type TaskRecoveryService struct {
	queue    *scheduler.TaskQueue
	interval time.Duration
}

func NewTaskRecoveryService(queue *scheduler.TaskQueue) *TaskRecoveryService {
	return &TaskRecoveryService{queue: queue, interval: 30 * time.Second}
}

func (s *TaskRecoveryService) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	pendingRecovery := &pendingRecoveryState{}
	recoverScanWorkClaimWaiters(s.queue)
	_, err := recoverPendingTasksForQueueGeneration(ctx, s.queue, pendingRecovery, time.Now())
	if err != nil {
		log.Printf("[DispatchRecover] initial pending reconciliation failed: %v", err)
	}
	// 启动对账：回收已 Offline 节点持有的 Running 任务（不等 30s 守护首次 tick）。
	recoverOrphanedRunningAttempts(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			recoverQueueIfDead(s.queue)
			recoverScanWorkClaimWaiters(s.queue)
			recoverDispatchingTasks(s.queue)
			recovered, err := recoverPendingTasksForQueueGeneration(ctx, s.queue, pendingRecovery, time.Now())
			if err != nil {
				log.Printf("[DispatchRecover] pending reconciliation failed: %v", err)
			} else if recovered > 0 {
				log.Printf("[DispatchRecover] reconciled %d stranded pending subtasks", recovered)
			}
			handleTimeoutTasks(s.queue)
			recoverScanWorkClaimWaiters(s.queue)
		}
	}
}

// recoverOrphanedRunningAttempts 启动对账：把「DB 已判 Offline 节点」仍持有的 Running/CancelPending
// 子任务立即回收（复用心跳守护同一入口 RecycleNodeRunningTasks），不等 30s 守护首次 tick。
// 仅处理 Offline 节点——它们确死、名下任务必为孤儿；Alive 节点可能正在慢重连，仍交由守护按 60s
// 阈值处理，避免误回收正在恢复的连接。回收不消耗重试预算（ConsumeRetryBudget=false），误回收代价为零。
func recoverOrphanedRunningAttempts(ctx context.Context) {
	var agentIDs []string
	if err := db.DB.Model(&db.SubTask{}).
		Where("status IN ? AND agent_id <> ''", []string{"Running", "CancelPending"}).
		Distinct().Pluck("agent_id", &agentIDs).Error; err != nil {
		log.Printf("[StartupReconcile] list agents holding running tasks failed: %v", err)
		return
	}
	recycled := 0
	for _, agentID := range agentIDs {
		var node db.Node
		if err := db.DB.First(&node, "agent_id = ?", agentID).Error; err != nil {
			continue // 节点行已删，交给超时守护兜底
		}
		if !strings.EqualFold(strings.TrimSpace(node.Status), "Offline") {
			continue
		}
		recycled += RecycleNodeRunningTasks(ctx, node)
	}
	if recycled > 0 {
		log.Printf("[StartupReconcile] recycled %d orphaned running tasks held by offline agents", recycled)
	}
}

func recoverScanWorkClaimWaiters(q *scheduler.TaskQueue) {	ready, err := db.ResolveTerminalScanWorkClaimWaiters(db.DB, 200)
	if err != nil {
		log.Printf("[WorkClaimRecover] terminal owner reconciliation failed: %v", err)
		return
	}
	if len(ready) == 0 {
		return
	}
	pushedByPriority, dispatchPending := dispatchSubTasks(context.Background(), q, ready)
	pushedCount := totalDispatchedTasks(pushedByPriority)
	if pushedCount > 0 {
		broadcastDispatchedTasks(pushedByPriority)
	}
	log.Printf("[WorkClaimRecover] replanned=%d dispatched=%d pending=%d", len(ready), pushedCount, dispatchPending)
}

// StartTaskTimeoutDaemon 保留旧内部入口，委托给显式 service。
func StartTaskTimeoutDaemon(ctx context.Context, q *scheduler.TaskQueue) {
	NewTaskRecoveryService(q).Run(ctx)
}

func recoverQueueIfDead(q *scheduler.TaskQueue) {
	if q == nil {
		return
	}
	recovered, err := q.ForceRecover()
	if err != nil {
		log.Printf("[QueueRecover] RabbitMQ reconnect failed: %v", err)
		return
	}
	if recovered {
		log.Printf("[QueueRecover] RabbitMQ connection was dead -- rebuilt; stranded tasks will recover in next dispatch cycle")
	}
}

func recoverDispatchingTasks(q *scheduler.TaskQueue) {
	if q == nil {
		return
	}

	var subs []db.SubTask
	if err := db.DB.Where("status = ?", subTaskStatusDispatching).
		Order("updated_at asc").
		Limit(200).
		Find(&subs).Error; err != nil || len(subs) == 0 {
		return
	}

	pushedByPriority, dispatchPending := dispatchSubTasks(context.Background(), q, subs)
	pushedCount := totalDispatchedTasks(pushedByPriority)
	if pushedCount > 0 {
		broadcastDispatchedTasks(pushedByPriority)
	}
	if pushedCount > 0 || dispatchPending > 0 {
		log.Printf("[DispatchRecover] scanned=%d dispatched=%d pending=%d", len(subs), pushedCount, dispatchPending)
	}
}

type pendingRecoveryState struct {
	token              string
	queuedRecoveryDone bool
}

func queuedMarkerForQueue(q *scheduler.TaskQueue) string {
	if q == nil {
		return subTaskQueuedMarker
	}
	token := q.RecoveryToken()
	if token == "" {
		return subTaskQueuedMarker
	}
	return subTaskQueuedMarker + ":" + token
}

func recoverPendingTasksForQueueGeneration(
	ctx context.Context,
	q *scheduler.TaskQueue,
	state *pendingRecoveryState,
	now time.Time,
) (int, error) {
	if q == nil {
		return 0, nil
	}
	token := q.RecoveryToken()
	if token == "" {
		return 0, nil
	}
	if state.token != token {
		state.token = token
		state.queuedRecoveryDone = q.Mode() != "memory"
	}

	totalPushed := 0
	dispatchClaimed := func(subs []db.SubTask) {
		if len(subs) == 0 {
			return
		}
		pushedByPriority, dispatchPending := dispatchSubTasks(ctx, q, subs)
		pushedCount := totalDispatchedTasks(pushedByPriority)
		totalPushed += pushedCount
		if pushedCount > 0 {
			broadcastDispatchedTasks(pushedByPriority)
		}
		log.Printf("[DispatchRecover] stranded-pending claimed=%d dispatched=%d pending=%d", len(subs), pushedCount, dispatchPending)
	}

	// The in-memory queue is intentionally ephemeral. For each new lifecycle,
	// drain queued markers that predate the lifecycle boundary. Keep this phase
	// retryable until a complete empty batch confirms that all rows were handled.
	for !state.queuedRecoveryDone {
		if err := ctx.Err(); err != nil {
			return totalPushed, err
		}
		subs, claimErr := claimStrandedPendingSubTasks(ctx, time.Time{}, 200, true, queuedMarkerForQueue(q))
		dispatchClaimed(subs)
		if claimErr != nil {
			return totalPushed, claimErr
		}
		if len(subs) == 0 {
			state.queuedRecoveryDone = true
		}
	}

	// Empty markers are scanned every cycle. This covers rows that become stale
	// after the queue generation was first observed without duplicating queued rows.
	for {
		if err := ctx.Err(); err != nil {
			return totalPushed, err
		}
		subs, claimErr := claimStrandedPendingSubTasks(ctx, now.Add(-strandedPendingGrace), 200, false, "")
		dispatchClaimed(subs)
		if claimErr != nil {
			return totalPushed, claimErr
		}
		if len(subs) == 0 {
			break
		}
	}
	return totalPushed, nil
}

func claimStrandedPendingSubTasks(
	ctx context.Context,
	cutoff time.Time,
	limit int,
	queuedOnly bool,
	currentQueuedMarker string,
) ([]db.SubTask, error) {
	var candidates []db.SubTask
	store := db.DB.WithContext(ctx)
	query := store.Where(
		"status = ? AND updated_at < ? AND agent_id = '' AND stream_msg_id = ''",
		"Pending", cutoff,
	)
	if queuedOnly {
		query = store.Where(
			"status = ? AND agent_id = '' AND (stream_msg_id = ? OR (stream_msg_id LIKE ? AND stream_msg_id <> ?))",
			"Pending", subTaskQueuedMarker, subTaskQueuedMarker+":%", currentQueuedMarker,
		)
	}
	query = query.Order("updated_at asc")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if err := query.Find(&candidates).Error; err != nil {
		return nil, err
	}

	claimed := make([]db.SubTask, 0, len(candidates))
	for _, sub := range candidates {
		claimQuery := store.Model(&db.SubTask{}).
			Where("id = ? AND status = ? AND agent_id = '' AND stream_msg_id = ?", sub.ID, "Pending", sub.StreamMsgID)
		if !queuedOnly {
			claimQuery = claimQuery.Where("updated_at < ?", cutoff)
		}
		result := claimQuery.Update("status", subTaskStatusDispatching)
		if result.Error != nil {
			return claimed, result.Error
		}
		if result.RowsAffected == 0 {
			continue
		}
		sub.Status = subTaskStatusDispatching
		claimed = append(claimed, sub)
	}
	return claimed, nil
}

func handleTimeoutTasks(q *scheduler.TaskQueue) {
	// 查找超时运行任务 + 长时间未收敛的取消任务
	var subs []db.SubTask
	db.DB.Where("(status = ? AND timeout_sec > 0) OR status = ?", "Running", "CancelPending").Find(&subs)

	now := time.Now()
	for _, sub := range subs {
		if db.IsStoppingAttemptStatus(sub.Status) {
			cancelDeadline := sub.UpdatedAt.Add(cancelPendingSettleGrace)
			if now.Before(cancelDeadline) {
				continue
			}

			if q != nil && sub.StreamMsgID != "" {
				_ = q.AckTask(context.Background(), sub.StreamMsgID)
			}

			updateRes := db.DB.Model(&db.SubTask{}).
				Where("id = ? AND status = ?", sub.ID, "CancelPending").
				Updates(map[string]interface{}{
					"status":         "Cancelled",
					"stream_msg_id":  "",
					"failure_reason": "cancel request exceeded Agent grace period",
					"finished_at":    now,
				})
			if updateRes.Error != nil {
				log.Printf("[TimeoutDaemon] Failed to settle CancelPending subtask %s: %v", sub.ID, updateRes.Error)
				continue
			}
			if updateRes.RowsAffected == 0 {
				continue
			}

			log.Printf("[TimeoutDaemon] SubTask %s force-settled to Cancelled after %s grace", sub.ID, cancelPendingSettleGrace)
			if sub.AgentID != "" {
				db.DB.Exec("UPDATE nodes SET running_tasks = GREATEST(running_tasks - 1, 0) WHERE agent_id = ?", sub.AgentID)
			}
			if sub.RootTaskID != "" {
				if sub.BatchID != "" {
					_ = db.SettleStoppedTaskBatch(db.DB, sub.TenantID, sub.BatchID, sub.ID)
				}
				_ = db.SyncTaskBatchStatuses(db.DB, sub.TenantID, sub.RootTaskID)
				db.RefreshRootTaskStatus(sub.RootTaskID)
			}
			continue
		}

		deadline := sub.UpdatedAt.Add(time.Duration(sub.TimeoutSec) * time.Second)
		if now.Before(deadline) {
			continue
		}

		leaseAgentID := sub.AgentID
		leaseStreamMsgID := sub.StreamMsgID
		log.Printf("[TimeoutDaemon] SubTask %s timed out (timeout=%ds)", sub.ID, sub.TimeoutSec)
		if sub.RetryCount < sub.MaxRetry {
			prepared, retryPrepared, retryErr := credentialbundle.AppendRetry(db.DB, &sub, db.AttemptRetryOptions{
				Trigger:              db.AttemptTriggerTimeoutRetry,
				TerminalStatus:       "Timeout",
				FailureReason:        fmt.Sprintf("attempt exceeded %d second timeout", sub.TimeoutSec),
				ConsumeRetryBudget:   true,
				UseCurrentTaskConfig: true,
			})
			if retryErr != nil {
				log.Printf("[TimeoutDaemon] SubTask %s retry preparation failed: %v", sub.ID, retryErr)
				continue
			}
			if !retryPrepared {
				var batch db.TaskBatch
				batchPaused := sub.BatchID != "" && db.DB.Select("id", "control_state").
					Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", sub.BatchID, sub.TenantID, sub.ID).
					First(&batch).Error == nil && db.CanonicalBatchControlState(batch.ControlState) == db.BatchControlPaused
				if batchPaused {
					settled := db.DB.Model(&db.SubTask{}).
						Where("id = ? AND tenant_id = ? AND status = ?", sub.ID, sub.TenantID, "Running").
						Updates(map[string]interface{}{
							"status": "Timeout", "stream_msg_id": "",
							"failure_reason": fmt.Sprintf("attempt exceeded %d second timeout while batch was paused", sub.TimeoutSec),
							"finished_at":    now,
						})
					if settled.Error == nil && settled.RowsAffected == 1 {
						if q != nil && leaseStreamMsgID != "" {
							_ = q.AckTask(context.Background(), leaseStreamMsgID)
						}
						_ = db.DB.Model(&db.TaskBatch{}).
							Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", sub.BatchID, sub.TenantID, sub.ID).
							Update("status", "Timeout").Error
						if leaseAgentID != "" {
							db.DB.Exec("UPDATE nodes SET running_tasks = GREATEST(running_tasks - 1, 0) WHERE agent_id = ?", leaseAgentID)
						}
						if sub.RootTaskID != "" {
							db.RefreshRootTaskStatus(sub.RootTaskID)
						}
					}
					continue
				}
				log.Printf("[TimeoutDaemon] SubTask %s retry blocked by state, budget, or root lifecycle", sub.ID)
				continue
			}

			oldMessageReleased := leaseStreamMsgID == ""
			if q != nil && leaseStreamMsgID != "" {
				if err := q.AckTask(context.Background(), leaseStreamMsgID); err != nil {
					log.Printf("[TimeoutDaemon] ACK failed for timed-out subtask %s: %v", sub.ID, err)
				} else {
					oldMessageReleased = true
				}
			}
			if q != nil && oldMessageReleased {
				_, dispatchPending := dispatchSubTasks(context.Background(), q, []db.SubTask{prepared})
				if dispatchPending == 0 {
					broadcastDispatchedTasks(map[int]int{prepared.Priority: 1})
				}
			}

			log.Printf("[TimeoutDaemon] SubTask %s recovered (retry %d/%d)", sub.ID, prepared.RetryCount, prepared.MaxRetry)
		} else if db.IsImmutableDerivedExecutionConfig(sub.Config) {
			// 验证快照不可二分拆分：RiskValidationTargets 是全集，拆半后
			// 另一半的目标会被覆盖校验拒绝（"outside the dispatched batch"）。
			// 改为不消耗重试预算的全量重派，按尝试次数封顶防死循环。
			const maxAutomaticStageTimeoutRedeliveries = 5
			if sub.AttemptNo > maxAutomaticStageTimeoutRedeliveries {
				log.Printf("[TimeoutDaemon] Validation attempt %s exceeded redelivery cap (%d); settling as Timeout", sub.ID, maxAutomaticStageTimeoutRedeliveries)
				settleRes := db.DB.Model(&sub).Where("status = ?", "Running").Updates(map[string]interface{}{
					"status":         "Timeout",
					"stream_msg_id":  "",
					"failure_reason": fmt.Sprintf("attempt exceeded %d second timeout beyond validation redelivery cap", sub.TimeoutSec),
					"finished_at":    time.Now(),
				})
				if settleRes.Error == nil && settleRes.RowsAffected == 1 {
					if q != nil && leaseStreamMsgID != "" {
						_ = q.AckTask(context.Background(), leaseStreamMsgID)
					}
					if sub.RootTaskID != "" {
						db.RefreshRootTaskStatus(sub.RootTaskID)
					}
				}
				continue
			}
			prepared, retryPrepared, retryErr := credentialbundle.AppendRetry(db.DB, &sub, db.AttemptRetryOptions{
				Trigger:              db.AttemptTriggerTimeoutRetry,
				TerminalStatus:       "Timeout",
				FailureReason:        fmt.Sprintf("attempt exceeded %d second timeout", sub.TimeoutSec),
				ConsumeRetryBudget:   false,
				UseCurrentTaskConfig: true,
			})
			if retryErr != nil || !retryPrepared {
				log.Printf("[TimeoutDaemon] Validation attempt %s full redelivery failed: err=%v prepared=%v", sub.ID, retryErr, retryPrepared)
				continue
			}
			oldMessageReleased := leaseStreamMsgID == ""
			if q != nil && leaseStreamMsgID != "" {
				if err := q.AckTask(context.Background(), leaseStreamMsgID); err != nil {
					log.Printf("[TimeoutDaemon] ACK failed for validation redelivery %s: %v", sub.ID, err)
				} else {
					oldMessageReleased = true
				}
			}
			if q != nil && oldMessageReleased {
				_, dispatchPending := dispatchSubTasks(context.Background(), q, []db.SubTask{prepared})
				if dispatchPending == 0 {
					broadcastDispatchedTasks(map[int]int{prepared.Priority: 1})
				}
			}
			log.Printf("[TimeoutDaemon] Validation attempt %s timed out; requeued in full with preserved stage config (attempt %d)", prepared.ID, sub.AttemptNo+1)
			continue
		} else {
			// 尝试二分拆分重试（绕过 retry_count 上限检查，直接看目标数）
			var targets []string
			_ = json.Unmarshal([]byte(sub.ChunkTargets), &targets)
			if len(targets) > 1 {
				splitSubs, didSplit, retryAllowed := db.SplitFailedSubTask(&sub, true)
				if !retryAllowed {
					log.Printf("[TimeoutDaemon] SubTask %s last-resort split blocked by state or root lifecycle", sub.ID)
					continue
				}
				if didSplit {
					oldMessageReleased := leaseStreamMsgID == ""
					if q != nil && leaseStreamMsgID != "" {
						if err := q.AckTask(context.Background(), leaseStreamMsgID); err != nil {
							log.Printf("[TimeoutDaemon] ACK failed before split dispatch for %s: %v", sub.ID, err)
						} else {
							oldMessageReleased = true
						}
					}
					if q != nil && oldMessageReleased {
						_, dispatchPending := dispatchSubTasks(context.Background(), q, splitSubs)
						if dispatchPending == 0 {
							broadcastDispatchedTasks(map[int]int{sub.Priority: 1})
						}
					}
					log.Printf("[TimeoutDaemon] SubTask %s split into %d sub-batches (last-resort)", sub.ID, len(splitSubs))
					if leaseAgentID != "" {
						db.DB.Exec("UPDATE nodes SET running_tasks = GREATEST(running_tasks - 1, 0) WHERE agent_id = ?", leaseAgentID)
					}
					continue
				}
			}

			updateRes := db.DB.Model(&sub).Where("status = ?", "Running").Updates(map[string]interface{}{
				"status":         "Timeout",
				"stream_msg_id":  "",
				"failure_reason": fmt.Sprintf("attempt exceeded %d second timeout and retry budget", sub.TimeoutSec),
				"finished_at":    now,
			})
			if updateRes.Error != nil {
				log.Printf("[TimeoutDaemon] Failed to mark subtask %s as Timeout: %v", sub.ID, updateRes.Error)
				continue
			}
			if updateRes.RowsAffected == 0 {
				continue
			}
			if q != nil && leaseStreamMsgID != "" {
				if err := q.AckTask(context.Background(), leaseStreamMsgID); err != nil {
					log.Printf("[TimeoutDaemon] ACK failed for terminal subtask %s: %v", sub.ID, err)
				}
			}

			log.Printf("[TimeoutDaemon] SubTask %s marked as Timeout (max retries exceeded)", sub.ID)
			if sub.RootTaskID != "" {
				_ = db.SyncTaskBatchStatuses(db.DB, sub.TenantID, sub.RootTaskID)
				db.RefreshRootTaskStatus(sub.RootTaskID)
			}
		}

		// 递减关联节点 running_tasks
		if leaseAgentID != "" {
			db.DB.Exec("UPDATE nodes SET running_tasks = GREATEST(running_tasks - 1, 0) WHERE agent_id = ?", leaseAgentID)
		}
	}
}
