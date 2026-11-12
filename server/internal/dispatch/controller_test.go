package dispatch

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/server/internal/scheduler"
	"github.com/TokEat/argus/shared/proto/go/scanpolicy"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type fakeNotifier struct {
	online map[string]bool
	nudged []string
}

func (f *fakeNotifier) NotifyAgent(agentID string, _ int32, _ string) {
	f.nudged = append(f.nudged, agentID)
}

func (f *fakeNotifier) IsAgentOnline(agentID string) bool { return f.online[agentID] }

func setupDispatchTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&db.SubTask{}, &db.Node{}, &db.RootTask{}, &db.TaskBatch{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return store
}

func newControllerForTest(t *testing.T, store *gorm.DB, notifier AgentNotifier) *Controller {
	t.Helper()
	queue := scheduler.NewTaskQueue("")
	t.Cleanup(queue.Close)
	c := NewController(store, queue, notifier)
	// Deterministic clock so reroute windows are stable.
	c.now = func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	return c
}

func seedAliveNode(t *testing.T, store *gorm.DB, agentID, tags string, capacity, running int) {
	t.Helper()
	node := db.Node{
		AgentID:      agentID,
		TenantID:     "default",
		Status:       "Alive",
		Tags:         tags,
		Capacity:     capacity,
		RunningTasks: running,
		LastBeat:     time.Date(2026, 9, 11, 11, 59, 30, 0, time.UTC).UnixMilli(),
	}
	if err := store.Create(&node).Error; err != nil {
		t.Fatalf("seed node %s: %v", agentID, err)
	}
}

func seedPushSubTask(t *testing.T, store *gorm.DB, id, strategy string) *db.SubTask {
	t.Helper()
	sub := db.SubTask{
		ID:               id,
		TenantID:         "default",
		Status:           "Dispatching",
		ChunkTargets:     `["10.0.0.1"]`,
		Config:           `{}`,
		DispatchStrategy: strategy,
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed subtask %s: %v", id, err)
	}
	return &sub
}

func reloadSubTask(t *testing.T, store *gorm.DB, id string) db.SubTask {
	t.Helper()
	var sub db.SubTask
	if err := store.First(&sub, "id = ?", id).Error; err != nil {
		t.Fatalf("reload subtask %s: %v", id, err)
	}
	return sub
}

func TestControllerRoutesPushSubTaskToLeastLoadedAgent(t *testing.T) {
	store := setupDispatchTestDB(t)
	notifier := &fakeNotifier{online: map[string]bool{"agent-busy": true, "agent-free": true}}
	c := newControllerForTest(t, store, notifier)

	seedAliveNode(t, store, "agent-busy", `{"target_type":"ip"}`, 1, 1)
	seedAliveNode(t, store, "agent-free", `{"target_type":"ip"}`, 1, 0)
	seedPushSubTask(t, store, "sub-1", string(scanpolicy.DispatchStrategyControllerPush))

	if err := c.dispatchNew(context.Background()); err != nil {
		t.Fatalf("dispatchNew: %v", err)
	}

	sub := reloadSubTask(t, store, "sub-1")
	if sub.RoutedAgentID != "agent-free" {
		t.Fatalf("expected routing to least-loaded agent-free, got %q", sub.RoutedAgentID)
	}
	if sub.RoutedAt == nil {
		t.Fatal("expected routed_at to be stamped")
	}
	if sub.Status != "Dispatching" {
		t.Fatalf("push routing must leave sub-task Dispatching, got %q", sub.Status)
	}
	// The routed task must be consumable from the winner's own queue. (Memory
	// mode returns an empty delivery ID, matching TryPopTask.)
	queue := c.queue.(*scheduler.TaskQueue)
	task, _, err := queue.TryPopAgentTask(context.Background(), "agent-free")
	if err != nil || task == nil || task.TaskId != "sub-1" {
		t.Fatalf("expected routed task on agent-free queue, task=%+v err=%v", task, err)
	}
	if len(notifier.nudged) != 1 || notifier.nudged[0] != "agent-free" {
		t.Fatalf("expected a single nudge to agent-free, got %v", notifier.nudged)
	}
}

func TestControllerSkipsPullStrategySubTasks(t *testing.T) {
	store := setupDispatchTestDB(t)
	notifier := &fakeNotifier{online: map[string]bool{"agent-free": true}}
	c := newControllerForTest(t, store, notifier)

	seedAliveNode(t, store, "agent-free", `{"target_type":"ip"}`, 1, 0)
	seedPushSubTask(t, store, "sub-pull", string(scanpolicy.DispatchStrategyAgentClaim))

	if err := c.dispatchNew(context.Background()); err != nil {
		t.Fatalf("dispatchNew: %v", err)
	}
	sub := reloadSubTask(t, store, "sub-pull")
	if sub.RoutedAgentID != "" {
		t.Fatalf("pull-mode sub-task must not be routed by the controller, got %q", sub.RoutedAgentID)
	}
}

func TestControllerRespectsAgentSelector(t *testing.T) {
	store := setupDispatchTestDB(t)
	notifier := &fakeNotifier{online: map[string]bool{"agent-ip": true, "agent-web": true}}
	c := newControllerForTest(t, store, notifier)

	seedAliveNode(t, store, "agent-ip", `{"target_type":"ip"}`, 2, 0)
	seedAliveNode(t, store, "agent-web", `{"target_type":"url"}`, 2, 0)
	sub := seedPushSubTask(t, store, "sub-sel", string(scanpolicy.DispatchStrategyControllerPush))
	sub.AgentSelector = `{"target_type":"ip"}`
	if err := store.Save(sub).Error; err != nil {
		t.Fatalf("set selector: %v", err)
	}

	if err := c.dispatchNew(context.Background()); err != nil {
		t.Fatalf("dispatchNew: %v", err)
	}
	if got := reloadSubTask(t, store, "sub-sel").RoutedAgentID; got != "agent-ip" {
		t.Fatalf("expected selector to route to agent-ip, got %q", got)
	}
}

func TestControllerSkipsBackoffNotYetEligible(t *testing.T) {
	store := setupDispatchTestDB(t)
	notifier := &fakeNotifier{online: map[string]bool{"agent-free": true}}
	c := newControllerForTest(t, store, notifier)

	seedAliveNode(t, store, "agent-free", `{"target_type":"ip"}`, 1, 0)
	sub := seedPushSubTask(t, store, "sub-backoff", string(scanpolicy.DispatchStrategyControllerPush))
	future := c.now().Add(5 * time.Minute)
	sub.NextEligibleAt = &future
	if err := store.Save(sub).Error; err != nil {
		t.Fatalf("set next_eligible_at: %v", err)
	}

	if err := c.dispatchNew(context.Background()); err != nil {
		t.Fatalf("dispatchNew: %v", err)
	}
	if got := reloadSubTask(t, store, "sub-backoff").RoutedAgentID; got != "" {
		t.Fatalf("backoff not-yet-eligible sub-task must not route, got %q", got)
	}
}

func TestControllerReroutesWhenOriginalAgentOffline(t *testing.T) {
	store := setupDispatchTestDB(t)
	notifier := &fakeNotifier{online: map[string]bool{"agent-new": true}}
	c := newControllerForTest(t, store, notifier)

	seedAliveNode(t, store, "agent-new", `{"target_type":"ip"}`, 1, 0)
	sub := seedPushSubTask(t, store, "sub-reroute", string(scanpolicy.DispatchStrategyControllerPush))
	oldRoute := c.now().Add(-10 * time.Minute)
	sub.RoutedAgentID = "agent-old"
	sub.RoutedAt = &oldRoute
	if err := store.Save(sub).Error; err != nil {
		t.Fatalf("seed routed subtask: %v", err)
	}

	if err := c.rerouteStale(context.Background()); err != nil {
		t.Fatalf("rerouteStale: %v", err)
	}
	got := reloadSubTask(t, store, "sub-reroute")
	if got.RoutedAgentID != "agent-new" {
		t.Fatalf("expected offline reroute to agent-new, got %q", got.RoutedAgentID)
	}
	if got.Status != "Dispatching" {
		t.Fatalf("reroute must leave sub-task Dispatching, got %q", got.Status)
	}
	queue := c.queue.(*scheduler.TaskQueue)
	if task, _, err := queue.TryPopAgentTask(context.Background(), "agent-new"); err != nil || task == nil || task.TaskId != "sub-reroute" {
		t.Fatalf("expected rerouted task on agent-new queue, task=%+v err=%v", task, err)
	}
}

func TestControllerLeavesRoutedTaskWhenAgentOnlineAndFresh(t *testing.T) {
	store := setupDispatchTestDB(t)
	notifier := &fakeNotifier{online: map[string]bool{"agent-a": true}}
	c := newControllerForTest(t, store, notifier)

	seedAliveNode(t, store, "agent-a", `{"target_type":"ip"}`, 4, 0)
	seedAliveNode(t, store, "agent-b", `{"target_type":"ip"}`, 4, 0)
	sub := seedPushSubTask(t, store, "sub-fresh", string(scanpolicy.DispatchStrategyControllerPush))
	recent := c.now().Add(-30 * time.Second)
	sub.RoutedAgentID = "agent-a"
	sub.RoutedAt = &recent
	if err := store.Save(sub).Error; err != nil {
		t.Fatalf("seed routed subtask: %v", err)
	}

	if err := c.rerouteStale(context.Background()); err != nil {
		t.Fatalf("rerouteStale: %v", err)
	}
	if got := reloadSubTask(t, store, "sub-fresh").RoutedAgentID; got != "agent-a" {
		t.Fatalf("online+fresh routing must be preserved, got %q", got)
	}
}
