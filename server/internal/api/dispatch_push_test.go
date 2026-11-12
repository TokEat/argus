package api

import (
	"context"
	"fmt"
	"testing"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/server/internal/scheduler"
	"github.com/TokEat/argus/shared/proto/go/scanpolicy"
)

// withDispatchStrategy overrides the process-wide default for the duration of
// a test. The package init pins agent_claim; push tests flip it locally and
// restore the pinned value on cleanup.
func withDispatchStrategy(t *testing.T, s scanpolicy.DispatchStrategy) {
	t.Helper()
	scanpolicy.SetDefaultDispatchStrategy(s)
	t.Cleanup(func() { scanpolicy.SetDefaultDispatchStrategy(scanpolicy.DispatchStrategyAgentClaim) })
}

func TestGroupAndBatchTargetsForDispatchFansOutAcrossFreeSlots(t *testing.T) {
	targets := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		targets = append(targets, fmt.Sprintf("10.0.0.%d", i+1))
	}

	// Pull model (or no free slots) keeps the pure grouping: 100 ip targets at
	// batch size 50 -> 2 batches.
	pull := groupAndBatchTargetsForDispatch(targets, taskTargetModeDirect, scanpolicy.DispatchStrategyAgentClaim, 15)
	if len(pull) != 2 {
		t.Fatalf("pull grouping should stay 2 batches, got %d", len(pull))
	}

	// Push with 15 free slots fans out to ~ceil(100/15)=7 per batch.
	push := groupAndBatchTargetsForDispatch(targets, taskTargetModeDirect, scanpolicy.DispatchStrategyControllerPush, 15)
	if len(push) < 13 || len(push) > 16 {
		t.Fatalf("push fan-out with 15 free slots should produce ~15 batches, got %d", len(push))
	}
	for _, g := range push {
		if g.TargetType != "ip" {
			t.Fatalf("fan-out must preserve target type, got %q", g.TargetType)
		}
		if len(g.Targets) > 7 {
			t.Fatalf("fan-out chunk exceeded computed size 7, got %d", len(g.Targets))
		}
	}

	// No free slots falls back to the pure grouping.
	none := groupAndBatchTargetsForDispatch(targets, taskTargetModeDirect, scanpolicy.DispatchStrategyControllerPush, 0)
	if len(none) != 2 {
		t.Fatalf("push with no free slots should fall back to 2 batches, got %d", len(none))
	}
}

func TestDispatchSubTasksLeavesPushSubTasksDispatching(t *testing.T) {
	store := setupAITestDB(t)
	withDispatchStrategy(t, scanpolicy.DispatchStrategyControllerPush)
	queue := scheduler.NewTaskQueue("")
	t.Cleanup(queue.Close)

	pushSub := db.SubTask{
		ID:               "push-sub",
		TenantID:         "default",
		Status:           subTaskStatusDispatching,
		ChunkTargets:     `["10.0.0.1"]`,
		Config:           `{}`,
		Priority:         scheduler.PriorityNormal,
		DispatchStrategy: string(scanpolicy.DispatchStrategyControllerPush),
	}
	if err := store.Create(&pushSub).Error; err != nil {
		t.Fatalf("seed push subtask: %v", err)
	}

	pushed, pending := dispatchSubTasks(context.Background(), queue, []db.SubTask{pushSub})
	if len(pushed) != 0 || pending != 0 {
		t.Fatalf("push sub-task must not be counted as pushed/pending, got pushed=%v pending=%d", pushed, pending)
	}

	var reloaded db.SubTask
	if err := store.First(&reloaded, "id = ?", pushSub.ID).Error; err != nil {
		t.Fatalf("reload push subtask: %v", err)
	}
	if reloaded.Status != subTaskStatusDispatching {
		t.Fatalf("push sub-task must stay Dispatching, got %q", reloaded.Status)
	}
	// Nothing may reach the shared queue for a push sub-task.
	if task, _, err := queue.TryPopTask(context.Background(), "agent-x"); err != nil || task != nil {
		t.Fatalf("push sub-task must never enter the shared queue, task=%+v err=%v", task, err)
	}
}

func TestDispatchSubTasksPullSubTasksUnchanged(t *testing.T) {
	store := setupAITestDB(t)
	// Package init pins agent_claim; this test relies on that default.
	queue := scheduler.NewTaskQueue("")
	t.Cleanup(queue.Close)

	pullSub := db.SubTask{
		ID:               "pull-sub",
		TenantID:         "default",
		Status:           subTaskStatusDispatching,
		ChunkTargets:     `["10.0.0.1"]`,
		Config:           `{}`,
		Priority:         scheduler.PriorityNormal,
		DispatchStrategy: string(scanpolicy.DispatchStrategyAgentClaim),
	}
	if err := store.Create(&pullSub).Error; err != nil {
		t.Fatalf("seed pull subtask: %v", err)
	}

	pushed, pending := dispatchSubTasks(context.Background(), queue, []db.SubTask{pullSub})
	if pending != 0 {
		t.Fatalf("pull sub-task should dispatch cleanly, pending=%d", pending)
	}
	if pushed[scheduler.PriorityNormal] != 1 {
		t.Fatalf("pull sub-task should be pushed once, got %v", pushed)
	}
	var reloaded db.SubTask
	if err := store.First(&reloaded, "id = ?", pullSub.ID).Error; err != nil {
		t.Fatalf("reload pull subtask: %v", err)
	}
	if reloaded.Status != "Pending" {
		t.Fatalf("pull sub-task should advance to Pending, got %q", reloaded.Status)
	}
	if task, _, err := queue.TryPopTask(context.Background(), "agent-x"); err != nil || task == nil || task.TaskId != "pull-sub" {
		t.Fatalf("pull sub-task should be on the shared queue, task=%+v err=%v", task, err)
	}
}
