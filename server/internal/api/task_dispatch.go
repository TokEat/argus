package api

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/scheduler"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
)

// effectiveDispatchStrategy resolves a sub-task's stored dispatch strategy,
// where empty means "inherit the process-wide default at read time".
func effectiveDispatchStrategy(sub *db.SubTask) scanpolicy.DispatchStrategy {
	return scanpolicy.NormalizeDispatchStrategy(scanpolicy.DispatchStrategy(sub.DispatchStrategy), scanpolicy.DefaultDispatchStrategy())
}

// notifyDispatchController nudges the controller-push reconciler that new
// dispatchable work may exist. It is a no-op when no controller is wired
// (e.g. in tests that exercise only the legacy pull path).
func notifyDispatchController() {
	if rt := routerRuntime(); rt != nil && rt.DispatchController != nil {
		rt.DispatchController.Notify()
	}
}

func dispatchSubTasks(ctx context.Context, q *scheduler.TaskQueue, subTasks []db.SubTask) (map[int]int, int) {
	pushedByPriority := make(map[int]int)
	if len(subTasks) == 0 {
		return pushedByPriority, 0
	}
	if q == nil {
		return pushedByPriority, len(subTasks)
	}

	dispatchPending := 0
	for _, st := range subTasks {
		if legacyProviderConfigJSON(st.Config) {
			finishedAt := time.Now()
			if err := db.DB.Model(&db.SubTask{}).Where("id = ? AND status = ?", st.ID, subTaskStatusDispatching).
				Updates(map[string]interface{}{"status": "Failed", "failure_reason": "Provider discovery configuration is Server-only", "finished_at": finishedAt, "stream_msg_id": ""}).Error; err != nil {
				log.Printf("[Dispatch] Failed to reject legacy Provider task %s: %v", st.ID, err)
				dispatchPending++
				continue
			}
			if st.RootTaskID != "" {
				_ = db.SyncTaskBatchStatuses(db.DB, st.TenantID, st.RootTaskID)
				db.RefreshRootTaskStatus(st.RootTaskID)
			}
			log.Printf("[Dispatch] Rejected legacy Provider task %s", st.ID)
			continue
		}
		if st.NextEligibleAt != nil && st.NextEligibleAt.After(time.Now()) {
			// Exponential backoff not yet elapsed: leave Dispatching and let a
			// later reconcile pass dispatch it once eligible. Not counted as
			// pending-recovery; it is intentionally waiting.
			continue
		}
		if effectiveDispatchStrategy(&st) == scanpolicy.DispatchStrategyControllerPush {
			// Controller-push: never touch a shared queue. Leave the sub-task in
			// Dispatching and let the DispatchController route it to a specific
			// agent's queue. The periodic recoverDispatchingTasks pass funnels back
			// here, so a missed Notify is harmless.
			notifyDispatchController()
			continue
		}
		pbSub, err := db.SubTaskToProto(&st)
		if err != nil || pbSub == nil {
			log.Printf("[Dispatch] Failed to encode subtask %s: %v", st.ID, err)
			dispatchPending++
			continue
		}

		if err := q.PushTask(ctx, pbSub); err != nil {
			log.Printf("[Dispatch] Failed to push subtask %s: %v", st.ID, err)
			dispatchPending++
			continue
		}

		// 入队成功后再将状态推进为 Pending，避免“先改状态后崩溃”导致任务既不在队列也不可恢复。
		updateRes := db.DB.Model(&db.SubTask{}).
			Where("id = ? AND status = ?", st.ID, subTaskStatusDispatching).
			Updates(map[string]interface{}{
				"status":        "Pending",
				"stream_msg_id": queuedMarkerForQueue(q),
			})
		if updateRes.Error != nil {
			log.Printf("[Dispatch] Subtask %s queued but status transition to Pending failed: %v", st.ID, updateRes.Error)
		} else if updateRes.RowsAffected == 1 && st.BatchID != "" {
			if err := db.DB.Model(&db.TaskBatch{}).
				Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", st.BatchID, st.TenantID, st.ID).
				Update("status", "Pending").Error; err != nil {
				log.Printf("[Dispatch] Batch %s status transition to Pending failed: %v", st.BatchID, err)
			}
		}

		pushedByPriority[st.Priority]++
	}

	return pushedByPriority, dispatchPending
}

func totalDispatchedTasks(pushedByPriority map[int]int) int {
	total := 0
	for _, n := range pushedByPriority {
		total += n
	}
	return total
}

// DispatchReleasedSubTask pushes one already-Dispatching attempt into the
// queue and flips it to Pending. It is the release path for passive-collection
// holds; enqueue failures deliberately leave the attempt in Dispatching so
// the dispatch recovery daemon re-pushes it.
func DispatchReleasedSubTask(ctx context.Context, q *scheduler.TaskQueue, sub db.SubTask) error {
	if q == nil {
		return fmt.Errorf("task queue unavailable")
	}
	_, pending := dispatchSubTasks(ctx, q, []db.SubTask{sub})
	if pending > 0 {
		return fmt.Errorf("push subtask %s into queue failed", sub.ID)
	}
	return nil
}

func broadcastDispatchedTasks(pushedByPriority map[int]int) {
	if routerRuntime().NotifyHub == nil {
		return
	}
	for priority, count := range pushedByPriority {
		if count <= 0 {
			continue
		}
		routerRuntime().NotifyHub.BroadcastNewTask(int32(count), int32(priority))
	}
}
