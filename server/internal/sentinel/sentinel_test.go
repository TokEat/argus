package sentinel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/ai"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func sentinelTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(
		&db.SystemConfig{}, &db.RootTask{}, &db.SubTask{}, &db.TaskBatch{}, &db.TaskConfigRevision{},
		&db.Node{}, &db.Vulnerability{}, &db.EgressBanEvent{}, &db.NodeBan{}, &db.TaskAudit{},
	); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return store
}

func seedSentinelAIConfig(t *testing.T, store *gorm.DB) {
	t.Helper()
	now := time.Now()
	for _, row := range []db.SystemConfig{
		{Key: "ai_base_url", Value: "http://llm.local/v1", UpdatedAt: now},
		{Key: "ai_api_key", Value: "secret", UpdatedAt: now},
		{Key: "ai_model", Value: "test-model", UpdatedAt: now},
	} {
		if err := store.Save(&row).Error; err != nil {
			t.Fatalf("seed ai config: %v", err)
		}
	}
}

// fakeSentinelChat implements ai.ChatClient, returning a canned raw payload.
type fakeSentinelChat struct {
	calls int
	raw   string
	err   error
}

func (f *fakeSentinelChat) CompleteJSON(ctx context.Context, cfg ai.Config, messages []ai.ChatMessage) (string, error) {
	f.calls++
	return f.raw, f.err
}
func (f *fakeSentinelChat) CompleteWithTools(ctx context.Context, cfg ai.Config, messages []ai.ChatMessage, tools []ai.ToolDefinition) (string, []ai.ToolCall, error) {
	f.calls++
	return f.raw, nil, f.err
}
func (f *fakeSentinelChat) StreamWithTools(ctx context.Context, cfg ai.Config, messages []ai.ChatMessage, tools []ai.ToolDefinition, onToken func(string), onToolCall func(ai.ToolCall)) (string, []ai.ToolCall, error) {
	f.calls++
	return f.raw, nil, f.err
}

// fakePusher records PushSubTaskToAgent deliveries.
type fakePusher struct {
	pushes []pushRecord
	err    error
}

type pushRecord struct {
	agentID string
	subID   string
}

func (p *fakePusher) PushSubTaskToAgent(ctx context.Context, agentID string, sub db.SubTask) error {
	p.pushes = append(p.pushes, pushRecord{agentID: agentID, subID: sub.ID})
	return p.err
}

// seedActiveRoot seeds a Running root + batch + one Running subtask so the
// homogeneity detector treats root-1 as actively scanning.
func seedActiveRoot(t *testing.T, store *gorm.DB, rootID string) {
	t.Helper()
	root := db.RootTask{ID: rootID, TenantID: "default", ProjectID: "p1", Status: "Running"}
	sub := db.SubTask{ID: rootID + "-sub", TenantID: "default", ProjectID: "p1", RootTaskID: rootID, Status: "Running", ChunkTargets: `["10.0.0.1"]`}
	for _, row := range []interface{}{&root, &sub} {
		if err := store.Create(row).Error; err != nil {
			t.Fatalf("seed active root: %v", err)
		}
	}
}

func seedVulnAt(t *testing.T, store *gorm.DB, rootID, target, plugin, response string) {
	t.Helper()
	v := db.Vulnerability{
		TenantID: "default", ProjectID: "p1", RootTaskID: rootID,
		Target: target, Plugin: plugin, Severity: "high", Status: "open", Response: response,
	}
	if err := store.Create(&v).Error; err != nil {
		t.Fatalf("seed vuln %s: %v", target, err)
	}
}

func reloadEvent(t *testing.T, store *gorm.DB, id uint) db.EgressBanEvent {
	t.Helper()
	var ev db.EgressBanEvent
	if err := store.First(&ev, id).Error; err != nil {
		t.Fatalf("reload event %d: %v", id, err)
	}
	return ev
}

// --- detect: homogeneity ---

func TestDetectHomogeneityEmitsAndDedupes(t *testing.T) {
	store := sentinelTestDB(t)
	seedActiveRoot(t, store, "root-1")
	body := "HTTP/1.1 403 Forbidden\r\n\r\n<h1>WAF blocked</h1>"
	for _, port := range []string{"80", "81", "443", "8080", "9090"} {
		seedVulnAt(t, store, "root-1", "10.0.0.1:"+port, "nacos-version", body)
	}

	if err := RunDetectTick(context.Background(), store, DetectorOptions{}); err != nil {
		t.Fatalf("detect tick: %v", err)
	}
	var events []db.EgressBanEvent
	if err := store.Where("signal_type = ?", SignalHomogeneity).Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 homogeneity event, got %d", len(events))
	}
	ev := events[0]
	if ev.Target != "10.0.0.1" || ev.Host != "10.0.0.1" || ev.Classification != ClassPending {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if ev.Status != EventOpen {
		t.Fatalf("event status=%s want open", ev.Status)
	}

	// Second tick must dedupe — still exactly one open event for the host.
	if err := RunDetectTick(context.Background(), store, DetectorOptions{}); err != nil {
		t.Fatalf("second detect tick: %v", err)
	}
	var count int64
	store.Model(&db.EgressBanEvent{}).Where("signal_type = ? AND target = ?", SignalHomogeneity, "10.0.0.1").Count(&count)
	if count != 1 {
		t.Fatalf("dedupe failed, want 1 event, got %d", count)
	}
}

func TestDetectHomogeneityIgnoresDiverseBodies(t *testing.T) {
	store := sentinelTestDB(t)
	seedActiveRoot(t, store, "root-1")
	for i, port := range []string{"80", "81", "443", "8080", "9090"} {
		seedVulnAt(t, store, "root-1", "10.0.0.1:"+port, "p", fmt.Sprintf("unique body %d", i))
	}
	if err := RunDetectTick(context.Background(), store, DetectorOptions{}); err != nil {
		t.Fatalf("detect tick: %v", err)
	}
	var count int64
	store.Model(&db.EgressBanEvent{}).Where("signal_type = ?", SignalHomogeneity).Count(&count)
	if count != 0 {
		t.Fatalf("diverse bodies must not trigger homogeneity, got %d events", count)
	}
}

// --- detect: success drop ---

func TestDetectSuccessDropEmitsEvent(t *testing.T) {
	store := sentinelTestDB(t)
	root := db.RootTask{ID: "root-sd", TenantID: "default", ProjectID: "p1", Status: "Running"}
	if err := store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	// 5 finished attempts in the window, 4 failed → ratio 0.8 ≥ 0.6.
	statuses := []string{"Failed", "Failed", "Failed", "Timeout", "Succeeded"}
	for i, st := range statuses {
		sub := db.SubTask{
			ID: fmt.Sprintf("sd-sub-%d", i), TenantID: "default", ProjectID: "p1", RootTaskID: "root-sd",
			Status: st, AgentID: "agent-bad", ChunkTargets: `["10.0.0.9"]`, MaxRetry: 3, FinishedAt: &now,
		}
		if err := store.Create(&sub).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := detectSuccessDrop(context.Background(), store, DetectorOptions{}.withDefaults()); err != nil {
		t.Fatalf("detect success drop: %v", err)
	}
	var events []db.EgressBanEvent
	if err := store.Where("signal_type = ?", SignalSuccessDrop).Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 success_drop event, got %d", len(events))
	}
	ev := events[0]
	if ev.RootTaskID != "root-sd" || ev.AgentID != "agent-bad" || ev.Target != "" {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if ev.Classification != ClassPending || ev.Status != EventOpen {
		t.Fatalf("event should be pending/open: %+v", ev)
	}
}

// Regression: once an event is handled (executed/dismissed), the same evidence
// must not re-fire on every tick — dedup is time-windowed, not status=open-only.
func TestDetectDoesNotRefireAfterExecuted(t *testing.T) {
	store := sentinelTestDB(t)

	// success_drop scope
	root := db.RootTask{ID: "root-sd", TenantID: "default", ProjectID: "p1", Status: "Running"}
	if err := store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	statuses := []string{"Failed", "Failed", "Failed", "Timeout", "Succeeded"}
	for i, st := range statuses {
		sub := db.SubTask{
			ID: fmt.Sprintf("sd-sub-%d", i), TenantID: "default", ProjectID: "p1", RootTaskID: "root-sd",
			Status: st, AgentID: "agent-bad", ChunkTargets: `["10.0.0.9"]`, MaxRetry: 3, FinishedAt: &now,
		}
		if err := store.Create(&sub).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := detectSuccessDrop(context.Background(), store, DetectorOptions{}.withDefaults()); err != nil {
		t.Fatalf("detect success drop: %v", err)
	}

	// Simulate the executor handling the event: it is no longer open.
	res := store.Model(&db.EgressBanEvent{}).Where("signal_type = ?", SignalSuccessDrop).
		Updates(map[string]interface{}{"status": EventExecuted, "executed_by": "sentinel-auto"})
	if res.RowsAffected != 1 {
		t.Fatalf("mark executed rows=%d want 1", res.RowsAffected)
	}

	// Next tick sees the same still-failing subtasks but must NOT insert a dup.
	if err := detectSuccessDrop(context.Background(), store, DetectorOptions{}.withDefaults()); err != nil {
		t.Fatalf("second detect tick: %v", err)
	}
	var count int64
	store.Model(&db.EgressBanEvent{}).Where("signal_type = ?", SignalSuccessDrop).Count(&count)
	if count != 1 {
		t.Fatalf("executed event re-fired: want 1 success_drop event, got %d", count)
	}

	// homogeneity scope: same guarantee for host-scoped events.
	seedActiveRoot(t, store, "root-hom")
	body := "HTTP/1.1 403 Forbidden\r\n\r\n<h1>WAF blocked</h1>"
	for _, port := range []string{"80", "81", "443", "8080", "9090"} {
		seedVulnAt(t, store, "root-hom", "10.0.0.1:"+port, "nacos-version", body)
	}
	if err := detectHomogeneity(context.Background(), store, DetectorOptions{}.withDefaults()); err != nil {
		t.Fatalf("detect homogeneity: %v", err)
	}
	store.Model(&db.EgressBanEvent{}).Where("signal_type = ?", SignalHomogeneity).
		Updates(map[string]interface{}{"status": EventExecuted})
	if err := detectHomogeneity(context.Background(), store, DetectorOptions{}.withDefaults()); err != nil {
		t.Fatalf("second homogeneity tick: %v", err)
	}
	store.Model(&db.EgressBanEvent{}).Where("signal_type = ?", SignalHomogeneity).Count(&count)
	if count != 1 {
		t.Fatalf("executed homogeneity event re-fired: want 1, got %d", count)
	}
}

// --- decide ---

func TestDecideClassifiesAndPersists(t *testing.T) {
	store := sentinelTestDB(t)
	seedSentinelAIConfig(t, store)
	ev := db.EgressBanEvent{
		TenantID: "default", RootTaskID: "root-1", Target: "10.0.0.1", Host: "10.0.0.1",
		AgentID: "agent-bad", SignalType: SignalHomogeneity, Classification: ClassPending,
		Evidence: `{"sample":"x"}`, Status: EventOpen,
	}
	if err := store.Create(&ev).Error; err != nil {
		t.Fatal(err)
	}
	client := &fakeSentinelChat{raw: `{"classification":"waf_challenge","action":"flag_findings","confidence":0.88,"reason":"所有端口返回同一拦截页"}`}
	n, err := Decide(context.Background(), store, client, 10)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if n != 1 || client.calls != 1 {
		t.Fatalf("decided=%d calls=%d, want 1/1", n, client.calls)
	}
	updated := reloadEvent(t, store, ev.ID)
	if updated.Classification != ClassWAFChallenge || updated.RecommendedAction != ActionFlagFindings {
		t.Fatalf("decision not persisted: %+v", updated)
	}
	if updated.Confidence != 0.88 || updated.ActionReason == "" {
		t.Fatalf("confidence/reason not persisted: %+v", updated)
	}
}

func TestDecideSkipsWithoutAIConfig(t *testing.T) {
	store := sentinelTestDB(t) // no ai config
	ev := db.EgressBanEvent{
		TenantID: "default", RootTaskID: "root-1", Target: "10.0.0.1", SignalType: SignalHomogeneity,
		Classification: ClassPending, Status: EventOpen,
	}
	if err := store.Create(&ev).Error; err != nil {
		t.Fatal(err)
	}
	client := &fakeSentinelChat{raw: `{"classification":"banned","action":"backoff"}`}
	n, err := Decide(context.Background(), store, client, 10)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if n != 0 || client.calls != 0 {
		t.Fatalf("without config decide must be a no-op, n=%d calls=%d", n, client.calls)
	}
	if got := reloadEvent(t, store, ev.ID).Classification; got != ClassPending {
		t.Fatalf("event should stay pending, got %s", got)
	}
}

func TestDecideLeavesEventPendingOnLLMError(t *testing.T) {
	store := sentinelTestDB(t)
	seedSentinelAIConfig(t, store)
	ev := db.EgressBanEvent{
		TenantID: "default", RootTaskID: "root-1", Target: "10.0.0.1", SignalType: SignalSuccessDrop,
		Classification: ClassPending, Status: EventOpen,
	}
	if err := store.Create(&ev).Error; err != nil {
		t.Fatal(err)
	}
	client := &fakeSentinelChat{err: errors.New("llm down")}
	if _, err := Decide(context.Background(), store, client, 10); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if got := reloadEvent(t, store, ev.ID).Classification; got != ClassPending {
		t.Fatalf("LLM failure must leave event pending for retry, got %s", got)
	}
}

// --- execute ---

func seedRescanFixture(t *testing.T, store *gorm.DB) (db.SubTask, db.EgressBanEvent) {
	t.Helper()
	root := db.RootTask{ID: "root-1", TenantID: "default", ProjectID: "p1", Status: "Running", CurrentConfigVersion: 0}
	batch := db.TaskBatch{
		ID: "b1", TenantID: "default", ProjectID: "p1", RootTaskID: "root-1",
		LatestAttemptID: "b1-attempt-1", CurrentAttemptNo: 1, AttemptCount: 1, ControlState: string(db.BatchControlActive),
	}
	now := time.Now()
	sub := db.SubTask{
		ID: "b1-attempt-1", TenantID: "default", ProjectID: "p1", RootTaskID: "root-1", BatchID: "b1",
		AttemptNo: 1, Status: "Failed", AgentID: "agent-bad", ChunkTargets: `["10.0.0.1"]`, MaxRetry: 3, FinishedAt: &now,
	}
	for _, row := range []interface{}{&root, &batch, &sub} {
		if err := store.Create(row).Error; err != nil {
			t.Fatalf("seed rescan fixture: %v", err)
		}
	}
	ev := db.EgressBanEvent{
		TenantID: "default", RootTaskID: "root-1", SubTaskID: sub.ID, ProjectID: "p1",
		Target: "10.0.0.1", Host: "10.0.0.1", AgentID: "agent-bad",
		SignalType: SignalHomogeneity, Classification: ClassBanned,
		RecommendedAction: ActionRescanOtherNode, Status: EventOpen,
	}
	if err := store.Create(&ev).Error; err != nil {
		t.Fatalf("seed event: %v", err)
	}
	return sub, ev
}

func TestExecuteBackoffRecordsBanAndCloses(t *testing.T) {
	store := sentinelTestDB(t)
	ev := db.EgressBanEvent{
		TenantID: "default", RootTaskID: "root-1", Target: "10.0.0.1", Host: "10.0.0.1",
		AgentID: "agent-bad", SignalType: SignalSuccessDrop, Classification: ClassBanned,
		RecommendedAction: ActionBackoff, Status: EventOpen,
	}
	if err := store.Create(&ev).Error; err != nil {
		t.Fatal(err)
	}
	if err := RunExecuteTick(context.Background(), store, nil, false); err != nil {
		t.Fatalf("execute tick: %v", err)
	}
	var ban db.NodeBan
	err := store.Where("tenant_id = ? AND target = ? AND agent_id = ?", "default", "10.0.0.1", "agent-bad").First(&ban).Error
	if err != nil {
		t.Fatalf("backoff must record ban memory: %v", err)
	}
	if ban.CooldownUntil == nil || !ban.CooldownUntil.After(time.Now()) {
		t.Fatalf("ban cooldown_until should be in the future: %+v", ban)
	}
	if got := reloadEvent(t, store, ev.ID).Status; got != EventExecuted {
		t.Fatalf("backoff event should be executed, got %s", got)
	}
}

func TestExecuteRescanGatedWithoutAutoExecute(t *testing.T) {
	store := sentinelTestDB(t)
	seedRescanFixture(t, store)
	pusher := &fakePusher{}
	if err := RunExecuteTick(context.Background(), store, pusher, false); err != nil {
		t.Fatalf("execute tick: %v", err)
	}
	var open int64
	store.Model(&db.EgressBanEvent{}).Where("status = ?", EventOpen).Count(&open)
	if open != 1 {
		t.Fatalf("rescan must stay open when auto_execute is off, open=%d", open)
	}
	if len(pusher.pushes) != 0 {
		t.Fatalf("no push should happen while gated, got %d", len(pusher.pushes))
	}
	var newAttempts int64
	store.Model(&db.SubTask{}).Where("root_task_id = ? AND trigger = ?", "root-1", TriggerEgressBanRecovery).Count(&newAttempts)
	if newAttempts != 0 {
		t.Fatalf("no rescan attempt should be created while gated, got %d", newAttempts)
	}
}

func TestExecuteRescanOtherNodeRoutesToCleanAgent(t *testing.T) {
	store := sentinelTestDB(t)
	sub, ev := seedRescanFixture(t, store)
	// Two agents: the banned one and a clean one.
	for _, n := range []db.Node{
		{AgentID: "agent-bad", TenantID: "default", Status: "Alive", RunningTasks: 1},
		{AgentID: "agent-good", TenantID: "default", Status: "Alive", RunningTasks: 0},
	} {
		if err := store.Create(&n).Error; err != nil {
			t.Fatal(err)
		}
	}
	pusher := &fakePusher{}
	ex := &Executor{DB: store, Pusher: pusher, Opts: ExecutorOptions{AutoExecute: true}}
	updated, err := ex.ExecuteByID(context.Background(), ev.ID, "admin-1", "")
	if err != nil {
		t.Fatalf("execute by id: %v", err)
	}
	if updated.Status != EventExecuted {
		t.Fatalf("event should be executed, got %s", updated.Status)
	}
	// A fresh recovery attempt was appended and hard-routed to the clean agent.
	var attempts []db.SubTask
	if err := store.Where("root_task_id = ? AND trigger = ?", "root-1", TriggerEgressBanRecovery).Find(&attempts).Error; err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 {
		t.Fatalf("want 1 recovery attempt, got %d", len(attempts))
	}
	got := attempts[0]
	if got.RoutedAgentID != "agent-good" {
		t.Fatalf("rescan routed to %s, want agent-good", got.RoutedAgentID)
	}
	if got.AgentID != "" {
		t.Fatalf("fresh attempt must be unrouted-bound, agent_id=%q", got.AgentID)
	}
	if got.Status != "Pending" {
		t.Fatalf("prepared status=%s want Pending", got.Status)
	}
	if len(pusher.pushes) != 1 || pusher.pushes[0].agentID != "agent-good" {
		t.Fatalf("expected 1 push to agent-good, got %+v", pusher.pushes)
	}
	// The originating failed attempt is untouched and terminal.
	reloaded := db.SubTask{}
	if err := store.First(&reloaded, "id = ?", sub.ID).Error; err != nil {
		t.Fatal(err)
	}
	if reloaded.Status != "Failed" {
		t.Fatalf("original attempt status=%s want Failed", reloaded.Status)
	}
	// Ban memory recorded for the banned egress.
	var ban db.NodeBan
	if err := store.Where("tenant_id = ? AND target = ? AND agent_id = ?", "default", "10.0.0.1", "agent-bad").First(&ban).Error; err != nil {
		t.Fatalf("rescan must record ban memory: %v", err)
	}
}

func TestExecuteRescanNoCleanAgentFallsBackToBackoff(t *testing.T) {
	store := sentinelTestDB(t)
	_, ev := seedRescanFixture(t, store)
	// Only the banned agent exists.
	if err := store.Create(&db.Node{AgentID: "agent-bad", TenantID: "default", Status: "Alive"}).Error; err != nil {
		t.Fatal(err)
	}
	ex := &Executor{DB: store, Pusher: &fakePusher{}, Opts: ExecutorOptions{AutoExecute: true}}
	updated, err := ex.ExecuteByID(context.Background(), ev.ID, "admin-1", "")
	if err != nil {
		t.Fatalf("execute by id: %v", err)
	}
	if updated.Status != EventExecuted {
		t.Fatalf("fallback should still close the event, got %s", updated.Status)
	}
	if !strings.Contains(updated.ActionReason, "no clean egress") {
		t.Fatalf("fallback note missing, reason=%q", updated.ActionReason)
	}
	var ban db.NodeBan
	if err := store.Where("target = ? AND agent_id = ?", "10.0.0.1", "agent-bad").First(&ban).Error; err != nil {
		t.Fatalf("fallback must still record ban memory: %v", err)
	}
	var newAttempts int64
	store.Model(&db.SubTask{}).Where("trigger = ?", TriggerEgressBanRecovery).Count(&newAttempts)
	if newAttempts != 0 {
		t.Fatalf("no rescan attempt without a clean egress, got %d", newAttempts)
	}
}

func TestExecuteFlagFindingsTaintsVulns(t *testing.T) {
	store := sentinelTestDB(t)
	// Host-scoped + one unrelated vuln that must stay clean.
	seedVulnAt(t, store, "root-1", "10.0.0.1:80", "p1", "body")
	seedVulnAt(t, store, "root-1", "10.0.0.1:443", "p2", "body")
	seedVulnAt(t, store, "root-1", "10.0.0.2:80", "p3", "body")
	ev := db.EgressBanEvent{
		TenantID: "default", RootTaskID: "root-1", Target: "10.0.0.1", Host: "10.0.0.1",
		AgentID: "agent-bad", SignalType: SignalHomogeneity, Classification: ClassWAFChallenge,
		RecommendedAction: ActionFlagFindings, Status: EventOpen,
	}
	if err := store.Create(&ev).Error; err != nil {
		t.Fatal(err)
	}
	if err := RunExecuteTick(context.Background(), store, nil, false); err != nil {
		t.Fatalf("execute tick: %v", err)
	}
	var tainted, clean db.Vulnerability
	if err := store.Where("target = ?", "10.0.0.1:80").First(&tainted).Error; err != nil {
		t.Fatal(err)
	}
	if tainted.TaintStatus != TaintSuspectWAF || tainted.TaintReason == "" {
		t.Fatalf("vuln should be tainted suspect_waf: %+v", tainted)
	}
	if err := store.Where("target = ?", "10.0.0.2:80").First(&clean).Error; err != nil {
		t.Fatal(err)
	}
	if clean.TaintStatus != "" {
		t.Fatalf("unrelated host must stay clean, got %q", clean.TaintStatus)
	}
	if got := reloadEvent(t, store, ev.ID).Status; got != EventExecuted {
		t.Fatalf("flag_findings event should be executed, got %s", got)
	}
	var audits int64
	store.Model(&db.TaskAudit{}).Where("action = ? AND root_task_id = ?", "sentinel_flag_findings", "root-1").Count(&audits)
	if audits != 1 {
		t.Fatalf("expected 1 flag_findings audit, got %d", audits)
	}
}

func TestExecuteAutoDismissesScannerBugAndFalsePositive(t *testing.T) {
	for _, class := range []string{ClassScannerBug, ClassFalsePositive, ClassTargetDown} {
		store := sentinelTestDB(t)
		ev := db.EgressBanEvent{
			TenantID: "default", RootTaskID: "root-1", Target: "10.0.0.1", SignalType: SignalSuccessDrop,
			Classification: class, RecommendedAction: ActionBackoff, Status: EventOpen,
		}
		if err := store.Create(&ev).Error; err != nil {
			t.Fatal(err)
		}
		if err := RunExecuteTick(context.Background(), store, nil, false); err != nil {
			t.Fatalf("execute tick: %v", err)
		}
		if got := reloadEvent(t, store, ev.ID).Status; got != EventExecuted {
			t.Fatalf("class=%s should auto-dismiss to executed, got %s", class, got)
		}
		var bans int64
		store.Model(&db.NodeBan{}).Count(&bans)
		if bans != 0 {
			t.Fatalf("class=%s must not record a ban, got %d", class, bans)
		}
	}
}

func TestExecuteByIDRejectsAlreadyExecuted(t *testing.T) {
	store := sentinelTestDB(t)
	ev := db.EgressBanEvent{
		TenantID: "default", RootTaskID: "root-1", Target: "10.0.0.1", Host: "10.0.0.1",
		AgentID: "agent-bad", SignalType: SignalSuccessDrop, Classification: ClassBanned,
		RecommendedAction: ActionBackoff, Status: EventOpen,
	}
	if err := store.Create(&ev).Error; err != nil {
		t.Fatal(err)
	}
	ex := &Executor{DB: store}
	if _, err := ex.ExecuteByID(context.Background(), ev.ID, "admin-1", ""); err != nil {
		t.Fatalf("first execute: %v", err)
	}
	if _, err := ex.ExecuteByID(context.Background(), ev.ID, "admin-1", ""); !errors.Is(err, ErrEventNotActionable) {
		t.Fatalf("second execute should be ErrEventNotActionable, got %v", err)
	}
}

func TestLoadEnabledAndAutoExecuteDefaults(t *testing.T) {
	store := sentinelTestDB(t)
	if !LoadEnabled(store) {
		t.Fatal("sentinel enabled should default true")
	}
	if LoadAutoExecute(store) {
		t.Fatal("auto_execute should default false")
	}
	now := time.Now()
	if err := store.Save(&db.SystemConfig{Key: ConfigKeyEnabled, Value: "false", UpdatedAt: now}).Error; err != nil {
		t.Fatal(err)
	}
	if LoadEnabled(store) {
		t.Fatal("sentinel enabled should honor config=false")
	}
}
