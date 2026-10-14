package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/dispatch"
	"github.com/P0lar1ght/argus/server/internal/scheduler"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// simNotifier reports every seeded agent online and records nudges.
type simNotifier struct {
	online map[string]bool
	nudges []string
}

func (s *simNotifier) NotifyAgent(id string, _ int32, _ string) { s.nudges = append(s.nudges, id) }
func (s *simNotifier) IsAgentOnline(id string) bool             { return s.online[id] }

var simDBSeq int64

// setupSimDB builds an isolated in-memory DB for the simulation. Unlike the
// shared package helper it uses a unique DSN per call so the test is safe to
// re-run (-count>1) without leftover rows from a previous iteration.
func setupSimDB(t *testing.T) *gorm.DB {
	t.Helper()
	seq := atomic.AddInt64(&simDBSeq, 1)
	dsn := fmt.Sprintf("file:sim-%d-%d?mode=memory&cache=shared", time.Now().UnixNano(), seq)
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&db.RootTask{}, &db.SubTask{}, &db.TaskBatch{}, &db.Node{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	old := db.DB
	db.DB = store
	t.Cleanup(func() { db.DB = old })
	return store
}

// TestControllerPushSimulation100IPFullPort15Agents is a local end-to-end
// simulation of the controller-push dispatcher: 100 IP targets, a full-port
// (1-65535) scan with the low-and-slow pacing avoidance strategy, fanned out
// across 15 alive agents. It asserts the *real* dispatched strategy
// (controller_push with the avoidance config actually written on every
// sub-task), that the union of dispatched targets equals the original 100 IPs
// (no loss, no duplication), that load balancing uses all 15 agents, and dumps
// one agent's full received scan sequence.
func TestControllerPushSimulation100IPFullPort15Agents(t *testing.T) {
	store := setupSimDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// ---------- 1. 扫描配置：全端口 + 规避策略（low-and-slow pacing） ----------
	cfg := defaultTaskScanConfig()
	ports, err := scanpolicy.PortsForProfile(scanpolicy.PortProfileAll, "")
	if err != nil {
		t.Fatalf("resolve full-port profile: %v", err)
	}
	cfg.Ports = ports // "1-65535"（全端口，65535 个端口）
	cfg.PortScanType = "tcp"
	// 规避策略：对同一目标的探测散射在时间上、每目标最小间隔，降低被安全设备
	// 按单 IP 速率阈值自动封禁的概率。
	cfg.PortScanScatter = true
	cfg.PortScanProbeInterval = 200 // ms，位于 [MinimumPacingIntervalMillis, MaximumPacingIntervalMillis]
	cfg.NoPoc = true
	cfg.GolangPoc = false
	cfg.DisableGeneralPoc = true
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal scan config: %v", err)
	}

	// ---------- 2. 100 个 IP 目标 ----------
	const ipCount = 100
	targets := make([]string, 0, ipCount)
	for i := 0; i < ipCount; i++ {
		targets = append(targets, fmt.Sprintf("10.0.0.%d", i+1))
	}

	// ---------- 3. 15 个存活 agent（容量 1，标签匹配 ip 选择器） ----------
	const agentCount = 15
	agents := make([]string, 0, agentCount)
	online := make(map[string]bool, agentCount)
	for i := 0; i < agentCount; i++ {
		agent := fmt.Sprintf("agent-%02d", i)
		agents = append(agents, agent)
		online[agent] = true
		node := db.Node{
			AgentID:  agent,
			TenantID: "default",
			Status:   "Alive",
			Tags:     `{"target_type":"ip"}`,
			Capacity: 1,
			LastBeat: time.Now().UnixMilli(),
		}
		if err := store.Create(&node).Error; err != nil {
			t.Fatalf("seed node %s: %v", agent, err)
		}
	}

	// ---------- 4. 真实扇出（与 handler_tasks.go 同一入口） ----------
	userRules := db.ParseSelectorRulesJSON("{}")
	freeSlots := dispatchFreeSlots(userRules)
	batches := groupAndBatchTargetsForDispatch(targets, taskTargetModeDirect, scanpolicy.DispatchStrategyControllerPush, freeSlots)
	t.Logf("[plan] freeSlots=%d  batches=%d  batchSizes=%v", freeSlots, len(batches), batchSizes(batches))

	// ---------- 5. 物化 RootTask + TaskBatch + SubTask（镜像 handler_tasks.go） ----------
	rootID := "root-sim-100ip-fullport"
	root := db.RootTask{
		ID:                   rootID,
		TenantID:             "default",
		Status:               "Queued",
		TotalChunks:          len(batches),
		TotalTargets:         len(targets),
		Priority:             scheduler.PriorityNormal,
		TimeoutSec:           1800,
		CurrentConfigVersion: 1,
		DispatchStrategy:     string(scanpolicy.DispatchStrategyControllerPush),
	}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	for idx, batch := range batches {
		chunkJSON, _ := json.Marshal(batch.Targets)
		batchID := fmt.Sprintf("%s-batch-%d-%s", rootID, idx, batch.TargetType)
		attemptID := batchID + "-attempt-1"
		tb := db.TaskBatch{
			ID:                 batchID,
			TenantID:           "default",
			RootTaskID:         rootID,
			Sequence:           idx,
			Kind:               "asset_scan",
			TargetType:         batch.TargetType,
			Targets:            string(chunkJSON),
			TargetCount:        len(batch.Targets),
			Status:             subTaskStatusDispatching,
			ConfigVersion:      1,
			Priority:           scheduler.PriorityNormal,
			TimeoutSec:         1800,
			AgentSelector:      batch.SelectorJSON,
			AgentSelectorRules: "{}",
			DispatchStrategy:   string(scanpolicy.DispatchStrategyControllerPush),
			CurrentAttemptNo:   1,
			AttemptCount:       1,
			LatestAttemptID:    attemptID,
		}
		sub := db.SubTask{
			ID:                 attemptID,
			TenantID:           "default",
			RootTaskID:         rootID,
			BatchID:            batchID,
			AttemptNo:          1,
			Trigger:            db.AttemptTriggerInitial,
			ChunkTargets:       string(chunkJSON),
			Status:             subTaskStatusDispatching,
			Config:             string(configJSON),
			Priority:           scheduler.PriorityNormal,
			TimeoutSec:         1800,
			MaxRetry:           3,
			ConfigVersion:      1,
			AgentSelector:      batch.SelectorJSON,
			AgentSelectorRules: "{}",
			DispatchStrategy:   string(scanpolicy.DispatchStrategyControllerPush),
		}
		if err := store.Create(&tb).Error; err != nil {
			t.Fatalf("seed task batch %s: %v", batchID, err)
		}
		if err := store.Create(&sub).Error; err != nil {
			t.Fatalf("seed subtask %s: %v", attemptID, err)
		}
	}

	// ---------- 6. 启动控制器推送 ----------
	queue := scheduler.NewTaskQueue("")
	t.Cleanup(queue.Close)
	notifier := &simNotifier{online: online}
	controller := dispatch.NewController(store, queue, notifier)
	go controller.Run(ctx)

	// ---------- 7. 回合制 claim 循环：路由 → 各 agent 从自己的队列认领 → 完成释放 → 重复 ----------
	agentSeq := make(map[string][]pb.Task, agentCount) // agent -> 按接收顺序的扫描序列
	totalClaimed := func() int {
		n := 0
		for _, seq := range agentSeq {
			n += len(seq)
		}
		return n
	}
	claimAll := func() int {
		bound := 0
		for _, agent := range agents {
			var node db.Node
			if err := store.First(&node, "agent_id = ?", agent).Error; err != nil {
				continue
			}
			for int(node.RunningTasks) < node.Capacity {
				task, _, err := queue.TryPopAgentTask(ctx, agent)
				if err != nil || task == nil || task.TaskId == "" {
					break
				}
				res := store.Model(&db.SubTask{}).
					Where("id = ? AND status = ?", task.TaskId, subTaskStatusDispatching).
					Updates(map[string]interface{}{"status": "Running", "agent_id": agent, "stream_msg_id": "sim-lease"})
				if res.Error != nil || res.RowsAffected != 1 {
					break // 已被认领/状态变化
				}
				store.Model(&db.Node{}).Where("agent_id = ?", agent).
					UpdateColumn("running_tasks", gorm.Expr("running_tasks + 1"))
				node.RunningTasks++
				agentSeq[agent] = append(agentSeq[agent], *task)
				bound++
			}
		}
		return bound
	}
	// completeOneRunning finishes one running sub-task (FIFO) so its agent frees a
	// slot, modelling a real agent finishing work and becoming claimable again.
	completeOneRunning := func() bool {
		var done db.SubTask
		if err := store.Where("root_task_id = ? AND status = ?", rootID, "Running").
			Order("updated_at ASC").First(&done).Error; err != nil {
			return false
		}
		store.Model(&db.SubTask{}).Where("id = ?", done.ID).
			Updates(map[string]interface{}{"status": "Done", "stream_msg_id": "", "finished_at": time.Now()})
		store.Model(&db.Node{}).Where("agent_id = ?", done.AgentID).
			UpdateColumn("running_tasks", gorm.Expr("running_tasks - 1"))
		return true
	}
	for turn := 0; turn < 200; turn++ {
		controller.Notify()
		// 给控制器一小段时间处理本次可路由的子任务（不强制 unrouted==0：当所有
		// agent 满员时，多余的子任务本就无法路由，需等待完成释放容量）。
		time.Sleep(20 * time.Millisecond)
		bound := claimAll()
		if totalClaimed() == len(batches) {
			break
		}
		if bound == 0 {
			if !completeOneRunning() {
				break // 无在跑任务可完成且无法再认领：死锁，退出
			}
		}
	}
	if totalClaimed() != len(batches) {
		t.Fatalf("claimed %d/%d sub-tasks after the control loop", totalClaimed(), len(batches))
	}

	// ---------- 8. 真实下发的策略：每个子任务都盖了 controller_push + 规避/全端口配置 ----------
	var allSubs []db.SubTask
	if err := store.Where("root_task_id = ?", rootID).Find(&allSubs).Error; err != nil {
		t.Fatalf("reload subtasks: %v", err)
	}
	for _, sub := range allSubs {
		if sub.DispatchStrategy != string(scanpolicy.DispatchStrategyControllerPush) {
			t.Fatalf("subtask %s dispatched with non-push strategy %q", sub.ID, sub.DispatchStrategy)
		}
		var decoded map[string]interface{}
		if err := json.Unmarshal([]byte(sub.Config), &decoded); err != nil {
			t.Fatalf("subtask %s config not decodable: %v", sub.ID, err)
		}
		if decoded["Ports"] != "1-65535" {
			t.Fatalf("subtask %s missing full-port config, Ports=%v", sub.ID, decoded["Ports"])
		}
		if decoded["PortScanScatter"] != true || decoded["PortScanProbeInterval"] != float64(200) {
			t.Fatalf("subtask %s missing avoidance pacing config: %v", sub.ID, decoded)
		}
	}

	// ---------- 9. 无丢失/无重复：所有已认领目标并集 == 原始 100 IP ----------
	claimed := make(map[string]bool, ipCount)
	for _, seq := range agentSeq {
		for _, task := range seq {
			for _, tgt := range task.Targets {
				if claimed[tgt] {
					t.Fatalf("target %q dispatched to more than one agent", tgt)
				}
				claimed[tgt] = true
			}
		}
	}
	if len(claimed) != ipCount {
		t.Fatalf("dispatched target union=%d, want %d (lost or duplicated targets)", len(claimed), ipCount)
	}

	// ---------- 10. 负载均衡：用满 15 个 agent，且单 agent 不超过 ceil(batches/agents) ----------
	perAgent := make(map[string]int, agentCount)
	for _, agent := range agents {
		perAgent[agent] = len(agentSeq[agent])
	}
	used, maxPer := 0, 0
	for _, n := range perAgent {
		if n > 0 {
			used++
		}
		if n > maxPer {
			maxPer = n
		}
	}
	balanceCeil := (len(batches) + agentCount - 1) / agentCount
	t.Logf("[dispatch] agentsUsed=%d/%d  maxPerAgent=%d  balanceCeil=%d  perAgent=%v", used, agentCount, maxPer, balanceCeil, perAgent)
	if used != agentCount {
		t.Fatalf("controller-push must use all %d agents, used %d (perAgent=%v)", agentCount, used, perAgent)
	}
	if maxPer > balanceCeil {
		t.Fatalf("load imbalance: maxPerAgent=%d exceeds ceil(batches/agents)=%d (perAgent=%v)", maxPer, balanceCeil, perAgent)
	}

	// ---------- 11. 一个 agent 的扫描序列（真实下发顺序 + 目标 + 配置） ----------
	// 选最忙的 agent（任务数最多，并列取名字序最小）以展示尽可能完整的有序序列。
	busiest := agents[0]
	for _, agent := range agents {
		if len(agentSeq[agent]) > len(agentSeq[busiest]) ||
			(len(agentSeq[agent]) == len(agentSeq[busiest]) && agent < busiest) {
			busiest = agent
		}
	}
	dumpAgentScanSequence(t, store, busiest, agentSeq[busiest])
}

func batchSizes(batches []targetBatchGroup) []int {
	sizes := make([]int, 0, len(batches))
	for _, b := range batches {
		sizes = append(sizes, len(b.Targets))
	}
	return sizes
}

// dumpAgentScanSequence prints one agent's received scan sequence: the ordered
// list of sub-tasks it executes, each with its concrete IP targets and the real
// full-port + avoidance config that reached the agent's queue, plus per-target
// estimated pacing so the low-and-slow effect is visible.
func dumpAgentScanSequence(t *testing.T, store *gorm.DB, agent string, seq []pb.Task) {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "\n[agent %s] 扫描序列：%d 个任务\n", agent, len(seq))
	for i, task := range seq {
		var decoded map[string]interface{}
		_ = json.Unmarshal(task.Config, &decoded)
		fmt.Fprintf(&b, "  #%d  task=%s\n", i+1, task.TaskId)
		fmt.Fprintf(&b, "       全端口=%v  散射=%v  每目标间隔=%vms  超时=%ds  目标数=%d\n",
			decoded["Ports"], decoded["PortScanScatter"], decoded["PortScanProbeInterval"], task.TimeoutSec, len(task.Targets))
		fmt.Fprintf(&b, "       目标: %v\n", task.Targets)
		// 低慢规避的节奏估算：单目标全端口 65535 端口 × 每目标间隔
		interval, _ := decoded["PortScanProbeInterval"].(float64)
		if decoded["PortScanScatter"] == true && interval > 0 {
			perTarget := time.Duration(interval) * time.Millisecond
			fmt.Fprintf(&b, "       规避节奏: 每目标 %s（%d 端口散射扫描）\n", perTarget, scanpolicy.PortCount(fmt.Sprint(decoded["Ports"])))
		}
	}
	// 该 agent 的最终状态
	var node db.Node
	if err := store.First(&node, "agent_id = ?", agent).Error; err == nil {
		fmt.Fprintf(&b, "  => 最终 RunningTasks=%d/%d\n", node.RunningTasks, node.Capacity)
	}
	t.Log(b.String())
}
