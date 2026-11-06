package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/scheduler"
	"gorm.io/gorm"
)

func TestClaimStrandedPendingSubTasksUsesCompareAndSwap(t *testing.T) {
	store := setupAITestDB(t)
	cutoff := time.Now().Add(-time.Minute)
	staleAt := cutoff.Add(-time.Minute)

	for _, sub := range []db.SubTask{
		{ID: "stale", TenantID: "default", Status: "Pending", ChunkTargets: `[]`},
		{ID: "recent", TenantID: "default", Status: "Pending", ChunkTargets: `[]`},
		{ID: "assigned", TenantID: "default", Status: "Pending", AgentID: "agent-1", ChunkTargets: `[]`},
		{ID: "delivered", TenantID: "default", Status: "Pending", StreamMsgID: "msg-1", ChunkTargets: `[]`},
	} {
		if err := store.Create(&sub).Error; err != nil {
			t.Fatalf("seed %s: %v", sub.ID, err)
		}
	}
	if err := store.Model(&db.SubTask{}).
		Where("id IN ?", []string{"stale", "assigned", "delivered"}).
		UpdateColumn("updated_at", staleAt).Error; err != nil {
		t.Fatalf("age stale subtasks: %v", err)
	}

	first, err := claimStrandedPendingSubTasks(context.Background(), cutoff, 200, false, "")
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	second, err := claimStrandedPendingSubTasks(context.Background(), cutoff, 200, false, "")
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if len(first) != 1 || first[0].ID != "stale" || first[0].Status != subTaskStatusDispatching {
		t.Fatalf("expected first claim to own only stale subtask, got %+v", first)
	}
	if len(second) != 0 {
		t.Fatalf("expected compare-and-swap to reject duplicate claim, got %+v", second)
	}
	var stale db.SubTask
	if err := store.First(&stale, "id = ?", "stale").Error; err != nil {
		t.Fatalf("reload stale subtask: %v", err)
	}
	if stale.Status != subTaskStatusDispatching {
		t.Fatalf("claimed task must remain Dispatching until queue push succeeds, got %s", stale.Status)
	}
}

func TestRecoverPendingTasksCoversGenerationGraceWindow(t *testing.T) {
	store := setupAITestDB(t)
	observedAt := time.Now()
	createdAt := observedAt.Add(-30 * time.Second)
	sub := db.SubTask{
		ID:           "stranded-pending",
		TenantID:     "default",
		RootTaskID:   "root-1",
		Status:       "Pending",
		ChunkTargets: `["https://example.com"]`,
		Config:       `{}`,
		Priority:     scheduler.PriorityNormal,
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}
	if err := store.Model(&db.SubTask{}).Where("id = ?", sub.ID).UpdateColumn("updated_at", createdAt).Error; err != nil {
		t.Fatalf("age subtask: %v", err)
	}

	queue := scheduler.NewTaskQueue("")
	defer queue.Close()
	state := pendingRecoveryState{}
	recovered, err := recoverPendingTasksForQueueGeneration(context.Background(), queue, &state, observedAt)
	if err != nil {
		t.Fatalf("initial recovery: %v", err)
	}
	if state.token == "" || recovered != 0 {
		t.Fatalf("recent pending should wait for grace window, state=%+v recovered=%d", state, recovered)
	}

	recovered, err = recoverPendingTasksForQueueGeneration(context.Background(), queue, &state, observedAt.Add(31*time.Second))
	if err != nil {
		t.Fatalf("recovery after pending becomes stale: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("expected one recovery after grace period, state=%+v recovered=%d", state, recovered)
	}
	task, _, err := queue.TryPopTask(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("pop recovered task: %v", err)
	}
	if task == nil || task.TaskId != sub.ID {
		t.Fatalf("unexpected recovered task: %+v", task)
	}
	var queued db.SubTask
	if err := store.First(&queued, "id = ?", sub.ID).Error; err != nil {
		t.Fatalf("reload queued subtask: %v", err)
	}
	if queued.Status != "Pending" || queued.StreamMsgID != queuedMarkerForQueue(queue) {
		t.Fatalf("queued subtask must be marked without a delivery id, got %+v", queued)
	}

	recovered, err = recoverPendingTasksForQueueGeneration(context.Background(), queue, &state, observedAt.Add(61*time.Second))
	if err != nil {
		t.Fatalf("final generation recovery: %v", err)
	}
	if recovered != 0 {
		t.Fatalf("queued marker should prevent duplicate recovery, state=%+v recovered=%d", state, recovered)
	}
	duplicate, _, err := queue.TryPopTask(context.Background(), "agent-1")
	if err != nil {
		t.Fatalf("pop duplicate task: %v", err)
	}
	if duplicate != nil {
		t.Fatalf("same generation enqueued duplicate task: %+v", duplicate)
	}
}

func TestRecoverScanWorkClaimWaitersDispatchesTerminalSourceDependents(t *testing.T) {
	store := setupAITestDB(t)
	if err := store.AutoMigrate(&db.ScanWorkClaim{}, &db.TaskCoverageLink{}); err != nil {
		t.Fatalf("migrate work claim recovery tables: %v", err)
	}
	tenantID := "tenant-work-claim-recovery"
	projectID := "project-work-claim-recovery"
	source := db.SubTask{
		ID: "source-work-claim-recovery", TenantID: tenantID, ProjectID: projectID,
		RootTaskID: "root-source-work-claim-recovery", BatchID: "batch-source-work-claim-recovery",
		Status: "Done", ChunkTargets: `[` + `"https://recovery.example.test"` + `]`,
	}
	waiter := db.SubTask{
		ID: "waiter-work-claim-recovery", TenantID: tenantID, ProjectID: projectID,
		RootTaskID: "root-waiter-work-claim-recovery", BatchID: "batch-waiter-work-claim-recovery",
		Status: "Pending", StreamMsgID: "workclaim:digest", Priority: scheduler.PriorityNormal,
		ChunkTargets: `[` + `"https://recovery.example.test"` + `]`, Config: `{}`,
	}
	claim := db.ScanWorkClaim{
		SchemaVersion: "argus.scanplan/v1", TenantID: tenantID, ProjectID: projectID,
		NetworkZone: "agent:agent-recovery", NormalizedTarget: "https://recovery.example.test",
		Stage: "fingerprint", WorkKeyHash: "recovery-work-key", Status: "active",
		OwnerTaskID: source.RootTaskID, OwnerBatchID: source.BatchID, OwnerAttemptID: source.ID,
		OwnerAgentID: "agent-recovery", ClaimedAt: time.Now().Add(-time.Minute), Revision: 1,
	}
	for _, record := range []interface{}{
		&source,
		&db.RootTask{ID: waiter.RootTaskID, TenantID: tenantID, ProjectID: projectID, Status: "Queued", TotalChunks: 1, TotalTargets: 1},
		&db.TaskBatch{ID: waiter.BatchID, TenantID: tenantID, ProjectID: projectID, RootTaskID: waiter.RootTaskID, Sequence: 0, Status: "Pending", LatestAttemptID: waiter.ID},
		&waiter,
		&claim,
	} {
		if err := store.Create(record).Error; err != nil {
			t.Fatalf("seed work claim recovery: %v", err)
		}
	}
	link := db.TaskCoverageLink{
		SchemaVersion: "argus.scanplan/v1", TenantID: tenantID, ProjectID: projectID,
		RootTaskID: waiter.RootTaskID, BatchID: waiter.BatchID, AttemptID: waiter.ID,
		WorkKeyHash: claim.WorkKeyHash, LinkType: "in_flight", Status: "waiting", ClaimID: claim.ID,
		SourceTaskID: source.RootTaskID, SourceBatchID: source.BatchID, SourceAttemptID: source.ID,
	}
	if err := store.Create(&link).Error; err != nil {
		t.Fatal(err)
	}

	queue := scheduler.NewTaskQueue("")
	defer queue.Close()
	recoverScanWorkClaimWaiters(queue)
	task, _, err := queue.TryPopTask(context.Background(), "agent-recovery")
	if err != nil || task == nil || task.TaskId != waiter.ID {
		t.Fatalf("recovered task=%+v err=%v", task, err)
	}
	if err := store.First(&waiter, "id = ?", waiter.ID).Error; err != nil {
		t.Fatal(err)
	}
	if waiter.Status != "Pending" || waiter.StreamMsgID != queuedMarkerForQueue(queue) {
		t.Fatalf("recovered waiter was not durably queued: %+v", waiter)
	}
	if err := store.First(&claim, claim.ID).Error; err != nil {
		t.Fatal(err)
	}
	if claim.Status != "completed" || claim.ReleasedAt == nil {
		t.Fatalf("terminal source claim was not released: %+v", claim)
	}
	if err := store.First(&link, link.ID).Error; err != nil {
		t.Fatal(err)
	}
	if link.Status != "resolved" {
		t.Fatalf("waiter provenance was not resolved: %+v", link)
	}
}

func TestRecoverPendingTasksFindsRowsThatBecomeStaleAfterInitialScan(t *testing.T) {
	store := setupAITestDB(t)
	observedAt := time.Now()
	sub := db.SubTask{ID: "late-pending", TenantID: "default", Status: "Pending", ChunkTargets: `[]`}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed late pending: %v", err)
	}
	if err := store.Model(&db.SubTask{}).Where("id = ?", sub.ID).
		UpdateColumn("updated_at", observedAt.Add(time.Second)).Error; err != nil {
		t.Fatalf("set late pending timestamp: %v", err)
	}

	queue := scheduler.NewTaskQueue("")
	defer queue.Close()
	state := pendingRecoveryState{}
	if recovered, err := recoverPendingTasksForQueueGeneration(context.Background(), queue, &state, observedAt); err != nil || recovered != 0 {
		t.Fatalf("initial scan: recovered=%d err=%v", recovered, err)
	}
	if recovered, err := recoverPendingTasksForQueueGeneration(context.Background(), queue, &state, observedAt.Add(62*time.Second)); err != nil || recovered != 1 {
		t.Fatalf("late stale scan: recovered=%d err=%v", recovered, err)
	}
}

func TestRecoverPendingTasksRestoresQueuedMarkerForNewMemoryLifecycle(t *testing.T) {
	store := setupAITestDB(t)
	now := time.Now()
	oldQueue := scheduler.NewTaskQueue("")
	oldMarker := queuedMarkerForQueue(oldQueue)
	oldQueue.Close()
	sub := db.SubTask{
		ID:           "memory-restart",
		TenantID:     "default",
		Status:       "Pending",
		StreamMsgID:  oldMarker,
		ChunkTargets: `[]`,
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed queued memory task: %v", err)
	}
	if err := store.Model(&db.SubTask{}).Where("id = ?", sub.ID).
		UpdateColumn("updated_at", now.Add(-30*time.Second)).Error; err != nil {
		t.Fatalf("age queued memory task: %v", err)
	}

	queue := scheduler.NewTaskQueue("")
	defer queue.Close()
	state := pendingRecoveryState{}
	recovered, err := recoverPendingTasksForQueueGeneration(context.Background(), queue, &state, now)
	if err != nil || recovered != 1 || !state.queuedRecoveryDone {
		t.Fatalf("recover new memory lifecycle: recovered=%d err=%v", recovered, err)
	}
	depth := queue.QueueDepth(context.Background())["memory"]
	if depth != 1 {
		t.Fatalf("expected one restored memory task, depth=%d", depth)
	}
}

func TestRecoverQueuedMarkersDrainsBatchesAndIgnoresCurrentLifecycle(t *testing.T) {
	store := setupAITestDB(t)
	now := time.Now()
	oldQueue := scheduler.NewTaskQueue("")
	oldMarker := queuedMarkerForQueue(oldQueue)
	oldQueue.Close()
	queue := scheduler.NewTaskQueue("")
	defer queue.Close()
	currentMarker := queuedMarkerForQueue(queue)
	subs := make([]db.SubTask, 206)
	oldIDs := make([]string, 205)
	for i := range oldIDs {
		oldIDs[i] = fmt.Sprintf("queued-old-%03d", i)
		subs[i] = db.SubTask{ID: oldIDs[i], TenantID: "default", Status: "Pending", StreamMsgID: oldMarker, ChunkTargets: `[]`}
	}
	subs[205] = db.SubTask{ID: "queued-current", TenantID: "default", Status: "Pending", StreamMsgID: currentMarker, ChunkTargets: `[]`}
	if err := store.Create(&subs).Error; err != nil {
		t.Fatalf("seed queued markers: %v", err)
	}
	if err := store.Model(&db.SubTask{}).Where("id IN ?", oldIDs).
		UpdateColumn("updated_at", now.Add(-30*time.Second)).Error; err != nil {
		t.Fatalf("age old queued markers: %v", err)
	}
	state := pendingRecoveryState{}
	recovered, err := recoverPendingTasksForQueueGeneration(context.Background(), queue, &state, time.Now())
	if err != nil {
		t.Fatalf("recover queued marker batches: %v", err)
	}
	if recovered != len(oldIDs) || !state.queuedRecoveryDone {
		t.Fatalf("expected %d old queued markers and completed state, recovered=%d state=%+v", len(oldIDs), recovered, state)
	}
	if depth := queue.QueueDepth(context.Background())["memory"]; depth != int64(len(oldIDs)) {
		t.Fatalf("expected memory depth %d, got %d", len(oldIDs), depth)
	}
	var current db.SubTask
	if err := store.First(&current, "id = ?", "queued-current").Error; err != nil {
		t.Fatalf("reload current lifecycle marker: %v", err)
	}
	if current.Status != "Pending" || current.StreamMsgID != currentMarker {
		t.Fatalf("current lifecycle marker should remain untouched: %+v", current)
	}
}

func TestRecoverQueuedMarkersRetriesAfterQueryFailure(t *testing.T) {
	store := setupAITestDB(t)
	now := time.Now()
	oldQueue := scheduler.NewTaskQueue("")
	oldMarker := queuedMarkerForQueue(oldQueue)
	oldQueue.Close()
	sub := db.SubTask{ID: "queued-retry", TenantID: "default", Status: "Pending", StreamMsgID: oldMarker, ChunkTargets: `[]`}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed queued marker: %v", err)
	}
	if err := store.Model(&db.SubTask{}).Where("id = ?", sub.ID).
		UpdateColumn("updated_at", now.Add(-time.Second)).Error; err != nil {
		t.Fatalf("age queued marker: %v", err)
	}

	const callbackName = "test:fail_queued_recovery_once"
	failOnce := true
	if err := store.Callback().Query().Before("gorm:query").Register(callbackName, func(tx *gorm.DB) {
		if failOnce {
			failOnce = false
			tx.AddError(errors.New("injected queued recovery query failure"))
		}
	}); err != nil {
		t.Fatalf("register failure callback: %v", err)
	}
	t.Cleanup(func() { _ = store.Callback().Query().Remove(callbackName) })

	queue := scheduler.NewTaskQueue("")
	defer queue.Close()
	state := pendingRecoveryState{}
	if recovered, err := recoverPendingTasksForQueueGeneration(context.Background(), queue, &state, now); err == nil || recovered != 0 {
		t.Fatalf("expected injected query failure, recovered=%d err=%v", recovered, err)
	}
	if state.queuedRecoveryDone {
		t.Fatal("failed queued recovery must remain retryable")
	}
	if recovered, err := recoverPendingTasksForQueueGeneration(context.Background(), queue, &state, now.Add(time.Second)); err != nil || recovered != 1 {
		t.Fatalf("retry queued recovery: recovered=%d err=%v", recovered, err)
	}
	if !state.queuedRecoveryDone {
		t.Fatal("successful queued recovery should mark lifecycle complete")
	}
}

func TestRecoverPendingTasksDrainsMoreThanOneBatch(t *testing.T) {
	store := setupAITestDB(t)
	now := time.Now()
	subs := make([]db.SubTask, 205)
	ids := make([]string, len(subs))
	for i := range subs {
		ids[i] = fmt.Sprintf("stranded-%03d", i)
		subs[i] = db.SubTask{ID: ids[i], TenantID: "default", Status: "Pending", ChunkTargets: `[]`}
	}
	if err := store.Create(&subs).Error; err != nil {
		t.Fatalf("seed pending batch: %v", err)
	}
	if err := store.Model(&db.SubTask{}).Where("id IN ?", ids).
		UpdateColumn("updated_at", now.Add(-2*time.Minute)).Error; err != nil {
		t.Fatalf("age pending batch: %v", err)
	}

	queue := scheduler.NewTaskQueue("")
	defer queue.Close()
	state := pendingRecoveryState{}
	recovered, err := recoverPendingTasksForQueueGeneration(context.Background(), queue, &state, now)
	if err != nil {
		t.Fatalf("recover pending batches: %v", err)
	}
	if recovered != len(subs) {
		t.Fatalf("expected all %d pending tasks to recover, got %d", len(subs), recovered)
	}
	if depth := queue.QueueDepth(context.Background())["memory"]; depth != int64(len(subs)) {
		t.Fatalf("expected memory queue depth %d, got %d", len(subs), depth)
	}
}

func TestRecoverPendingTasksRabbitMQSmoke(t *testing.T) {
	amqpURL := os.Getenv("ARGUS_RABBITMQ_TEST_URL")
	if amqpURL == "" {
		t.Skip("ARGUS_RABBITMQ_TEST_URL is not set")
	}
	store := setupAITestDB(t)
	sub := db.SubTask{
		ID:           "rabbit-stranded-pending",
		TenantID:     "default",
		Status:       "Pending",
		ChunkTargets: `["https://example.com"]`,
		Config:       `{}`,
		Priority:     scheduler.PriorityNormal,
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}
	if err := store.Model(&db.SubTask{}).Where("id = ?", sub.ID).
		UpdateColumn("updated_at", time.Now().Add(-2*time.Minute)).Error; err != nil {
		t.Fatalf("age subtask: %v", err)
	}

	queue := scheduler.NewTaskQueue(amqpURL)
	if queue.Mode() != "rabbitmq" {
		queue.Close()
		t.Fatalf("expected RabbitMQ mode, got %q", queue.Mode())
	}
	state := pendingRecoveryState{}
	recovered, err := recoverPendingTasksForQueueGeneration(context.Background(), queue, &state, time.Now())
	if err != nil {
		queue.Close()
		t.Fatalf("recover pending task through RabbitMQ: %v", err)
	}
	if recovered != 1 {
		queue.Close()
		t.Fatalf("expected one RabbitMQ recovery, got %d", recovered)
	}
	firstToken := state.token
	queue.Close()

	// A new queue lifecycle changes the token, but the queued marker must prevent a duplicate publish.
	queue = scheduler.NewTaskQueue(amqpURL)
	defer queue.Close()
	recovered, err = recoverPendingTasksForQueueGeneration(context.Background(), queue, &state, time.Now())
	if err != nil {
		t.Fatalf("recover after queue lifecycle change: %v", err)
	}
	if state.token == firstToken || recovered != 0 {
		t.Fatalf("new lifecycle should change token without duplicate recovery, state=%+v recovered=%d", state, recovered)
	}
	task, deliveryID, err := queue.TryPopTask(context.Background(), "agent-rabbit")
	if err != nil {
		t.Fatalf("pop RabbitMQ task: %v", err)
	}
	if task == nil || task.TaskId != sub.ID || deliveryID == "" {
		t.Fatalf("unexpected RabbitMQ delivery: task=%+v id=%q", task, deliveryID)
	}
	if err := queue.AckTask(context.Background(), deliveryID); err != nil {
		t.Fatalf("ack RabbitMQ task: %v", err)
	}
	duplicate, _, err := queue.TryPopTask(context.Background(), "agent-rabbit")
	if err != nil {
		t.Fatalf("check duplicate RabbitMQ delivery: %v", err)
	}
	if duplicate != nil {
		t.Fatalf("queue lifecycle change published duplicate task: %+v", duplicate)
	}
}

func TestRecoverOrphanedRunningAttemptsRecyclesOfflineAgentTasksOnly(t *testing.T) {
	store := setupAITestDB(t)
	queue := scheduler.NewTaskQueue("")
	defer queue.Close()
	previous := *routerRuntime()
	t.Cleanup(func() { ConfigureRouterDependencies(previous) })
	ConfigureRouterDependencies(RouterDependencies{TaskQueue: queue})

	// Offline agent：确死，其 Running 子任务启动时必须被回收。
	offlineNode := db.Node{TenantID: "default", AgentID: "agent-offline", Status: "Offline", LastBeat: time.Now().Add(-time.Hour).UnixMilli()}
	if err := store.Create(&offlineNode).Error; err != nil {
		t.Fatalf("seed offline node: %v", err)
	}
	// Alive agent：可能正在慢重连，其 Running 子任务必须保持不动。
	aliveNode := db.Node{TenantID: "default", AgentID: "agent-alive", Status: "Alive", LastBeat: time.Now().UnixMilli()}
	if err := store.Create(&aliveNode).Error; err != nil {
		t.Fatalf("seed alive node: %v", err)
	}

	root := db.RootTask{ID: "root-orphan", TenantID: "default", Status: "Running", TotalChunks: 2, TotalTargets: 2}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	batch := db.TaskBatch{ID: "batch-orphan", TenantID: "default", RootTaskID: root.ID, Sequence: 0, Status: "Running", LatestAttemptID: "sub-offline"}
	if err := store.Create(&batch).Error; err != nil {
		t.Fatalf("seed batch: %v", err)
	}
	offlineSub := db.SubTask{
		ID: "sub-offline", TenantID: "default", RootTaskID: root.ID, BatchID: batch.ID,
		Status: "Running", AgentID: "agent-offline", ChunkTargets: `["https://one.test"]`, MaxRetry: 3,
	}
	if err := store.Create(&offlineSub).Error; err != nil {
		t.Fatalf("seed offline subtask: %v", err)
	}
	aliveSub := db.SubTask{
		ID: "sub-alive", TenantID: "default", RootTaskID: root.ID, BatchID: batch.ID,
		Status: "Running", AgentID: "agent-alive", ChunkTargets: `["https://two.test"]`, MaxRetry: 3,
	}
	if err := store.Create(&aliveSub).Error; err != nil {
		t.Fatalf("seed alive subtask: %v", err)
	}

	recoverOrphanedRunningAttempts(context.Background())

	// Offline 节点的 Running 任务必须被回收：原尝试进入终态，并产生一个可回收的新尝试。
	var settled db.SubTask
	if err := store.First(&settled, "id = ?", offlineSub.ID).Error; err != nil {
		t.Fatalf("reload offline subtask: %v", err)
	}
	if settled.Status == "Running" || settled.Status == "CancelPending" {
		t.Fatalf("offline-agent running task must be recycled out of Running, got %+v", settled)
	}
	var attempts []db.SubTask
	if err := store.Where("parent_attempt_id = ?", offlineSub.ID).Find(&attempts).Error; err != nil {
		t.Fatalf("load recovery attempts: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatalf("expected a recovery attempt for the offline task")
	}

	// Alive 节点的 Running 任务必须原样保留。
	var alive db.SubTask
	if err := store.First(&alive, "id = ?", aliveSub.ID).Error; err != nil {
		t.Fatalf("reload alive subtask: %v", err)
	}
	if alive.Status != "Running" || alive.AgentID != "agent-alive" {
		t.Fatalf("alive-agent running task must be untouched, got %+v", alive)
	}
}

func TestHandleTimeoutTasksDoesNotRetryPausedRoot(t *testing.T) {
	store := setupAITestDB(t)
	root := db.RootTask{ID: "root-paused-timeout", TenantID: "default", Status: "Paused", TotalChunks: 1}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	sub := db.SubTask{
		ID:           "sub-paused-timeout",
		TenantID:     root.TenantID,
		RootTaskID:   root.ID,
		Status:       "Running",
		ChunkTargets: `["https://one.test"]`,
		TimeoutSec:   1,
		MaxRetry:     3,
		UpdatedAt:    time.Now().Add(-time.Minute),
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}

	handleTimeoutTasks(nil)
	var got db.SubTask
	if err := store.First(&got, "id = ?", sub.ID).Error; err != nil {
		t.Fatalf("reload subtask: %v", err)
	}
	if got.Status != "Running" || got.RetryCount != 0 {
		t.Fatalf("paused root timeout was retried: %+v", got)
	}
}

func TestHandleTimeoutTasksPerformsLastResortSplit(t *testing.T) {
	store := setupAITestDB(t)
	root := db.RootTask{ID: "root-last-resort-timeout", TenantID: "default", Status: "Running", TotalChunks: 1}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	sub := db.SubTask{
		ID:           "sub-last-resort-timeout",
		TenantID:     root.TenantID,
		RootTaskID:   root.ID,
		Status:       "Running",
		ChunkTargets: `["https://one.test","https://two.test"]`,
		TimeoutSec:   1,
		RetryCount:   3,
		MaxRetry:     3,
		UpdatedAt:    time.Now().Add(-time.Minute),
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}

	handleTimeoutTasks(nil)
	var got []db.SubTask
	if err := store.Where("root_task_id = ?", root.ID).Order("id").Find(&got).Error; err != nil {
		t.Fatalf("load split subtasks: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("last-resort split attempts = %d, want original plus 2 retries", len(got))
	}
	dispatching := 0
	for _, item := range got {
		if item.Status == subTaskStatusDispatching {
			dispatching++
			if item.RetryCount != 1 || item.ParentAttemptID != sub.ID {
				t.Fatalf("last-resort retry state = %+v", item)
			}
		} else if item.ID != sub.ID || item.Status != "Timeout" || item.FinishedAt == nil {
			t.Fatalf("last-resort original evidence = %+v", item)
		}
	}
	if dispatching != 2 {
		t.Fatalf("last-resort dispatching retries = %d, want 2", dispatching)
	}
}
