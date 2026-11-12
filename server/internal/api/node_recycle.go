package api

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/shared/proto/go/scanpolicy"
)

// RecycleNodeRunningTasks 将节点持有的 Running/CancelPending 子任务退回队列重新调度，
// 并结算处于停止中的尝试。返回成功重新入队的任务数（>0 时广播通知在线 Agent）。
// 心跳守护（节点掉线）调用此逻辑；手动 drain/节点摘除端点可复用同一入口。
func RecycleNodeRunningTasks(ctx context.Context, n db.Node) int {
	rt := routerRuntime()
	tenantID := strings.TrimSpace(n.TenantID)
	if tenantID == "" {
		tenantID = "default"
	}
	var orphanTasks []db.SubTask
	db.DB.Where("tenant_id = ? AND agent_id = ? AND status IN ?", tenantID, n.AgentID, []string{"Running", "CancelPending"}).Find(&orphanTasks)
	requeued := 0
	for _, sub := range orphanTasks {
		// ACK 掉旧的 MQ 消息（如果还在）
		if sub.StreamMsgID != "" {
			_ = rt.TaskQueue.AckTask(ctx, sub.StreamMsgID)
		}

		if db.IsStoppingAttemptStatus(sub.Status) {
			finishedAt := time.Now()
			db.DB.Model(&db.SubTask{}).
				Where("id = ? AND tenant_id = ? AND status = ?", sub.ID, sub.TenantID, sub.Status).
				Updates(map[string]interface{}{
					"status":         "Cancelled",
					"stream_msg_id":  "",
					"failure_reason": "cancelled while Agent went offline",
					"finished_at":    finishedAt,
				})
			_ = db.SettleStoppedTaskBatch(db.DB, sub.TenantID, sub.BatchID, sub.ID)
			_ = db.SyncTaskBatchStatuses(db.DB, sub.TenantID, sub.RootTaskID)
			log.Printf("[NodeRecycle] Settled cancelled attempt %s from agent %s", sub.ID, n.AgentID)
		} else if prepared, appended := db.AppendSubTaskAttempt(&sub, db.AttemptRetryOptions{
			Trigger:              db.AttemptTriggerAgentOfflineRecovery,
			TerminalStatus:       "Failed",
			FailureReason:        "Agent heartbeat expired during execution",
			ConsumeRetryBudget:   false,
			UseCurrentTaskConfig: true,
		}); appended {
			if scanpolicy.NormalizeDispatchStrategy(scanpolicy.DispatchStrategy(prepared.DispatchStrategy), scanpolicy.DefaultDispatchStrategy()) == scanpolicy.DispatchStrategyControllerPush {
				// Controller-push：留在 Dispatching，由 DispatchController 立即重新路由到其他存活 Agent。
				if rt.DispatchController != nil {
					rt.DispatchController.Notify()
				}
				requeued++
			} else if pbTask, err := db.SubTaskToProto(&prepared); err == nil && pbTask != nil {
				if pushErr := rt.TaskQueue.PushTaskToFront(ctx, pbTask); pushErr == nil {
					db.DB.Model(&db.SubTask{}).Where("id = ? AND tenant_id = ? AND status = ?", prepared.ID, prepared.TenantID, "Dispatching").
						Updates(map[string]interface{}{"status": "Pending", "stream_msg_id": "queued"})
					db.DB.Model(&db.TaskBatch{}).
						Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", prepared.BatchID, prepared.TenantID, prepared.ID).
						Update("status", "Pending")
					requeued++
				}
			}
		} else if db.SettlePausedTaskBatchAttempt(&sub, "Failed", "Agent heartbeat expired while batch was paused") {
			log.Printf("[NodeRecycle] Settled paused attempt %s from agent %s without automatic recovery", sub.ID, n.AgentID)
		}

		if sub.RootTaskID != "" {
			db.RefreshRootTaskStatus(sub.RootTaskID)
		}
	}

	// 回收后通知在线 Agent
	if requeued > 0 && rt.NotifyHub != nil {
		rt.NotifyHub.BroadcastNewTask(int32(requeued), 0)
	}
	return requeued
}
