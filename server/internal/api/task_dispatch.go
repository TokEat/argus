package api

import (
	"context"
	"log"

	"github.com/user/dddd-server/internal/db"
	"github.com/user/dddd-server/internal/scheduler"
)

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

func broadcastDispatchedTasks(pushedByPriority map[int]int) {
	if notifyHub == nil {
		return
	}
	for priority, count := range pushedByPriority {
		if count <= 0 {
			continue
		}
		notifyHub.BroadcastNewTask(int32(count), int32(priority))
	}
}
