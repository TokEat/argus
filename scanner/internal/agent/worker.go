package agent

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"

	"dddd/scanner/internal/engine"
	"dddd/scanner/structs"
	pb "github.com/user/dddd-proto/go/scan"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	newScanContext = engine.NewScanContext
	runScanTask    = engine.RunTask
)

// Worker 是扫描节点的核心
type Worker struct {
	agentID      string
	serverAddr   string
	apiURL       string
	client       pb.AgentServiceClient
	conn         *grpc.ClientConn
	wg           sync.WaitGroup
	mu           sync.Mutex
	runningTasks map[string]context.CancelFunc
	maxWorkers   int
	ruleVersion  string
	tags         map[string]string

	// sem 并发控制信号量
	sem chan struct{}
	// freeSlots 当前空闲 worker 数（原子操作）
	freeSlots atomic.Int32
}

func NewWorker(agentID, serverAddr, apiURL string, maxWorkers int, tags map[string]string) *Worker {
	if maxWorkers <= 0 {
		maxWorkers = 1
	}
	if tags == nil {
		tags = make(map[string]string)
	}
	return &Worker{
		agentID:      agentID,
		serverAddr:   serverAddr,
		apiURL:       apiURL,
		runningTasks: make(map[string]context.CancelFunc),
		maxWorkers:   maxWorkers,
		tags:         tags,
	}
}

func (w *Worker) Start() error {
	conn, err := grpc.NewClient(w.serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	w.conn = conn
	w.client = pb.NewAgentServiceClient(conn)

	// 1. 注册
	effectiveWorkers := w.effectiveWorkerCount()
	_, err = w.client.Register(context.Background(), &pb.RegisterReq{
		AgentId:  w.agentID,
		Version:  "v2.1.0",
		Tags:     w.tags,
		Os:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Capacity: int32(effectiveWorkers),
	})
	if err != nil {
		return err
	}
	log.Printf("Agent %s successfully registered to %s", w.agentID, w.serverAddr)

	// 开机同步热更新规则库 (Arsenal)
	w.syncRules()

	// 初始化并发控制
	w.sem = make(chan struct{}, effectiveWorkers)
	w.freeSlots.Store(int32(effectiveWorkers))

	// 后台心跳维持
	go w.heartbeatLoop()
	// 获取动态指令
	go w.commandLoop()

	log.Printf("Agent started with worker pool size: %d", effectiveWorkers)

	// 信号劫持
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	quit := make(chan struct{})

	go func() {
		<-sigCh
		log.Println("Received termination signal, waiting for running tasks to drain...")
		close(quit)
	}()

	// ★ 核心调度循环：Subscribe 通知 + ClaimTask 认领
	// 持续尝试建立 Subscribe 流，断开后自动重连
	for {
		select {
		case <-quit:
			w.wg.Wait()
			log.Println("All tasks finished. Shutting down agent.")
			return nil
		default:
		}

		w.subscribeAndClaim(quit)

		// Subscribe 断开后，等待 2 秒重连
		select {
		case <-quit:
			w.wg.Wait()
			return nil
		case <-time.After(2 * time.Second):
			log.Println("[Subscribe] Reconnecting to server...")
		}
	}
}

// subscribeAndClaim 建立 Subscribe 流并监听任务通知，收到通知后 ClaimTask 认领
func (w *Worker) subscribeAndClaim(quit chan struct{}) {
	stream, err := w.client.Subscribe(context.Background())
	if err != nil {
		log.Printf("[Subscribe] Failed to connect: %v", err)
		return
	}

	// 发送初始 AgentSignal（携带 agent_id 和初始空闲容量）
	if err := stream.Send(&pb.AgentSignal{
		AgentId:    w.agentID,
		FreeSlots:  w.freeSlots.Load(),
		SignalType: "ready",
	}); err != nil {
		log.Printf("[Subscribe] Failed to send initial signal: %v", err)
		return
	}

	log.Printf("[Subscribe] Stream established, listening for task notifications...")

	// 启动后台定期上报容量变化
	stopCapacity := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCapacity:
				return
			case <-ticker.C:
				_ = stream.Send(&pb.AgentSignal{
					AgentId:    w.agentID,
					FreeSlots:  w.freeSlots.Load(),
					SignalType: "capacity_update",
				})
			}
		}
	}()
	defer close(stopCapacity)

	for {
		select {
		case <-quit:
			return
		default:
		}

		// 接收 Server 推送的 TaskNotify
		notify, err := stream.Recv()
		if err == io.EOF {
			log.Println("[Subscribe] Server closed the stream (EOF)")
			return
		}
		if err != nil {
			log.Printf("[Subscribe] Stream error: %v", err)
			return
		}

		log.Printf("[Subscribe] Received notification: type=%s, available=%d, priority=%d",
			notify.NotifyType, notify.AvailableTasks, notify.Priority)

		// 有空闲 worker 就立即去认领任务
		w.claimAvailableTasks()
	}
}

// claimAvailableTasks 在收到通知后，尽可能多地认领任务（填满空闲 worker）
func (w *Worker) claimAvailableTasks() {
	for {
		// 检查是否有空闲 worker
		free := w.freeSlots.Load()
		if free <= 0 {
			return // 满载，等下次通知
		}

		// 尝试获取一个 worker 额度
		select {
		case w.sem <- struct{}{}:
		default:
			return // 信号量满
		}

		// 向 Server 认领任务
		task, err := w.client.ClaimTask(context.Background(), &pb.ClaimTaskReq{
			AgentId:   w.agentID,
			FreeSlots: w.freeSlots.Load(),
			Tags:      w.tags,
		})

		if err != nil {
			log.Printf("[ClaimTask] Error: %v", err)
			<-w.sem // 释放
			return
		}

		if task.TaskId == "" {
			// 队列已空
			<-w.sem // 释放
			return
		}

		// 认领成功，启动协程执行任务
		w.freeSlots.Add(-1)
		w.wg.Add(1)
		go func(t *pb.Task) {
			defer w.wg.Done()
			defer func() {
				<-w.sem
				w.freeSlots.Add(1)
				// 通知 Server 容量变化，让 Server 知道可以继续派发
				// （Server 在 TaskComplete 时也会检查队列并主动通知）
			}()
			w.executeTask(t)
		}(task)
	}
}

func (w *Worker) heartbeatLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if w.client != nil {
			w.mu.Lock()
			runningCount := int32(len(w.runningTasks))
			taskIDs := make([]string, 0, runningCount)
			for tid := range w.runningTasks {
				taskIDs = append(taskIDs, tid)
			}
			w.mu.Unlock()

			var cpuUsage float64
			var memUsage float64
			if p, err := cpu.Percent(0, false); err == nil && len(p) > 0 {
				cpuUsage = p[0]
			}
			if v, err := mem.VirtualMemory(); err == nil {
				memUsage = v.UsedPercent
			}

			resp, err := w.client.Heartbeat(context.Background(), &pb.HeartbeatReq{
				AgentId:        w.agentID,
				Status:         "Alive",
				RuleVersion:    w.ruleVersion,
				RunningTasks:   runningCount,
				RunningTaskIds: taskIDs,
				CpuUsage:       float32(cpuUsage),
				MemUsage:       float32(memUsage),
			})
			if err != nil {
				log.Printf("Heartbeat failure: %v", err)
				continue
			}
			if resp.ShouldSyncRules {
				log.Println("[Heartbeat] Server signaled rule sync needed via gRPC!")
				w.syncRules()
			}

			// 防饥饿兜底：心跳响应中如果 Server 告知有任务但我们有空闲，就主动认领
			if resp.TasksAvailable > 0 && w.freeSlots.Load() > 0 {
				log.Printf("[Heartbeat] Server reports %d tasks available, attempting claim...", resp.TasksAvailable)
				w.claimAvailableTasks()
			}
		}
	}
}

func (w *Worker) commandLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		resp, err := http.Get(w.apiURL + "/api/v1/agents/" + w.agentID + "/commands")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var result struct {
				CancelTasks []string `json:"cancel_tasks"`
				ReloadRules bool     `json:"reload_rules"`
			}
			if json.Unmarshal(body, &result) == nil {
				if result.ReloadRules {
					log.Println("[Command] Received dynamic rule hot-reload signal from Control Plane!")
					w.syncRules()
				}
				w.mu.Lock()
				for _, tid := range result.CancelTasks {
					if cancel, ok := w.runningTasks[tid]; ok {
						log.Printf("[Cancel] Received kill instruction for subtask %s from Control Plane!", tid)
						cancel()
					}
				}
				w.mu.Unlock()
			}
		}
	}
}

func (w *Worker) syncRules() {
	log.Println("[Sync] Checking Arsenal manifest for incremental update...")

	manifestURL := w.apiURL + "/api/v1/arsenals/manifest"
	resp, err := http.Get(manifestURL)
	if err != nil {
		log.Printf("[Sync] Failed to fetch manifest, falling back to full sync: %v", err)
		w.syncRulesFull()
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var manifest struct {
		RuleVersion string `json:"rule_version"`
		Items       []struct {
			Type     string `json:"type"`
			FileName string `json:"file_name"`
			Hash     string `json:"hash"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &manifest) != nil {
		log.Println("[Sync] Failed to parse manifest, falling back to full sync")
		w.syncRulesFull()
		return
	}

	localHashes := w.loadLocalManifest()

	updated := 0
	for _, item := range manifest.Items {
		localHash, exists := localHashes[item.Type+"/"+item.FileName]
		if exists && localHash == item.Hash {
			continue
		}

		dirPath := "config"
		if item.Type == "poc" {
			dirPath = "config/pocs"
		}
		_ = os.MkdirAll(dirPath, 0755)
		targetPath := filepath.Join(dirPath, item.FileName)

		backupDir := "config/.backup"
		_ = os.MkdirAll(backupDir, 0755)
		if _, err := os.Stat(targetPath); err == nil {
			backupPath := filepath.Join(backupDir, item.Type+"_"+item.FileName)
			data, _ := os.ReadFile(targetPath)
			_ = os.WriteFile(backupPath, data, 0644)
		}

		content := w.downloadRule(item.Type, item.FileName)
		if content != "" {
			_ = os.WriteFile(targetPath, []byte(content), 0644)
			log.Printf("[Sync] Updated %s -> %s (hash: %s)", item.Type, targetPath, item.Hash[:8])
			localHashes[item.Type+"/"+item.FileName] = item.Hash
			updated++
		}
	}

	w.saveLocalManifest(localHashes)
	w.ruleVersion = manifest.RuleVersion

	if updated > 0 {
		log.Printf("[Sync] Incremental sync complete: %d files updated, rule_version=%s", updated, manifest.RuleVersion)
	} else {
		log.Printf("[Sync] All rules up to date, rule_version=%s", manifest.RuleVersion)
	}
}

func (w *Worker) downloadRule(ruleType, fileName string) string {
	url := w.apiURL + "/api/v1/arsenals/" + ruleType
	resp, err := http.Get(url)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var rules []struct {
		FileName string `json:"FileName"`
		Content  string `json:"Content"`
	}
	if json.Unmarshal(body, &rules) == nil {
		for _, r := range rules {
			if r.FileName == fileName {
				return r.Content
			}
		}
	}
	return ""
}

func (w *Worker) loadLocalManifest() map[string]string {
	hashes := make(map[string]string)
	data, err := os.ReadFile("config/.manifest.json")
	if err != nil {
		return hashes
	}
	_ = json.Unmarshal(data, &hashes)
	return hashes
}

func (w *Worker) saveLocalManifest(hashes map[string]string) {
	data, _ := json.MarshalIndent(hashes, "", "  ")
	_ = os.MkdirAll("config", 0755)
	_ = os.WriteFile("config/.manifest.json", data, 0644)
}

func (w *Worker) syncRulesFull() {
	log.Println("[Sync] Full sync from Arsenal API...")

	ruleTypes := []string{"poc", "finger", "workflow", "dir"}
	localHashes := make(map[string]string)

	for _, rt := range ruleTypes {
		resp, err := http.Get(w.apiURL + "/api/v1/arsenals/" + rt)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var rules []struct {
				FileName string `json:"FileName"`
				Content  string `json:"Content"`
			}
			if json.Unmarshal(body, &rules) == nil && len(rules) > 0 {
				dirPath := "config"
				if rt == "poc" {
					dirPath = "config/pocs"
				}
				_ = os.MkdirAll(dirPath, 0755)
				for _, r := range rules {
					path := filepath.Join(dirPath, r.FileName)
					_ = os.WriteFile(path, []byte(r.Content), 0644)
					hash := fmt.Sprintf("%x", md5.Sum([]byte(r.Content)))
					localHashes[rt+"/"+r.FileName] = hash
					log.Printf("[Sync] Reloaded %s -> %s", rt, path)
				}
			}
		} else {
			log.Printf("[Sync] Failed to reach API for %s: %v", rt, err)
		}
	}

	w.saveLocalManifest(localHashes)
}

func (w *Worker) executeTask(task *pb.Task) {
	log.Printf("Received Task: %s with targets: %v", task.TaskId, task.Targets)

	cfg := engine.Config(structs.DefaultConfig())
	if len(task.Config) > 0 {
		_ = json.Unmarshal(task.Config, &cfg)
	}
	cfg.Targets = task.Targets
	cfg.OutputFile = ""
	cfg.ReportName = ""

	ctx, err := newScanContext(cfg)
	if err != nil {
		log.Printf("Failed to initialize scan context for task %s: %v", task.TaskId, err)
		w.reportTaskCompletion(task.TaskId, "FAILED", err.Error())
		return
	}
	defer ctx.Close()
	ctx.TaskID = task.TaskId

	var cancelRequested atomic.Bool
	cancelTask := func() {
		cancelRequested.Store(true)
		if ctx.Cancel != nil {
			ctx.Cancel()
		}
	}

	w.mu.Lock()
	w.runningTasks[task.TaskId] = cancelTask
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		delete(w.runningTasks, task.TaskId)
		w.mu.Unlock()
	}()

	// 挂载 OutputHook 进行 gRPC Stream 实时回传
	stream, err := w.client.StreamResult(context.Background())
	if err != nil {
		err = fmt.Errorf("open grpc result stream: %w", err)
		log.Printf("Failed to open grpc stream for task %s: %v", task.TaskId, err)
		w.reportTaskCompletion(task.TaskId, "FAILED", err.Error())
		return
	}

	var streamMu sync.Mutex
	var streamErr error
	ctx.OutputHook = func(msg engine.OutputMessage) {
		streamMu.Lock()
		defer streamMu.Unlock()

		if streamErr != nil {
			return
		}

		payload, err := json.Marshal(msg)
		if err != nil {
			streamErr = fmt.Errorf("marshal result payload: %w", err)
			if ctx.Cancel != nil {
				ctx.Cancel()
			}
			return
		}

		if err := stream.Send(&pb.ScanResult{
			TaskId:      task.TaskId,
			PayloadType: msg.Type,
			Payload:     payload,
			Timestamp:   time.Now().UnixMilli(),
		}); err != nil {
			streamErr = fmt.Errorf("send scan result: %w", err)
			if ctx.Cancel != nil {
				ctx.Cancel()
			}
		}
	}

	// 挂载阶段进度回调
	ctx.PhaseHook = func(phase engine.PhaseEvent) {
		streamMu.Lock()
		defer streamMu.Unlock()

		if streamErr != nil {
			return
		}

		payload, err := json.Marshal(phase)
		if err != nil {
			return
		}

		log.Printf("[Phase] Task %s: %s %s %s", task.TaskId, phase.Phase, phase.Status, phase.Message)
		_ = stream.Send(&pb.ScanResult{
			TaskId:      task.TaskId,
			PayloadType: "phase",
			Payload:     payload,
			Timestamp:   time.Now().UnixMilli(),
		})
	}

	// 启动引擎
	log.Printf("Starting Pipeline for Task %s...", task.TaskId)

	runErr := runScanTask(ctx)

	if streamErr != nil && (runErr == nil || (!cancelRequested.Load() && errors.Is(runErr, context.Canceled))) {
		runErr = streamErr
	}
	if closeErr := closeResultStream(stream); closeErr != nil && (runErr == nil || (!cancelRequested.Load() && errors.Is(runErr, context.Canceled))) {
		runErr = closeErr
	}

	if runErr != nil {
		if cancelRequested.Load() && errors.Is(runErr, context.Canceled) {
			log.Printf("[Cancel] Task %s aborted via control-plane cancellation", task.TaskId)
			w.reportTaskCompletion(task.TaskId, "CANCELLED", "task cancelled by control plane")
			return
		}

		log.Printf("Pipeline execution aborted or failed: %v", runErr)
		w.reportTaskCompletion(task.TaskId, "FAILED", runErr.Error())
		return
	}
	log.Printf("Finished Pipeline for Task %s.", task.TaskId)

	w.reportTaskCompletion(task.TaskId, "DONE", "")
}

func (w *Worker) effectiveWorkerCount() int {
	engineLimit := engine.MaxConcurrentTasks()
	if engineLimit <= 0 || w.maxWorkers <= engineLimit {
		return w.maxWorkers
	}
	return engineLimit
}

func (w *Worker) reportTaskCompletion(taskID, status, errMessage string) {
	_, _ = w.client.TaskComplete(context.Background(), &pb.TaskCompleteReq{
		AgentId:      w.agentID,
		TaskId:       taskID,
		Status:       status,
		ErrorMessage: errMessage,
	})
}

func closeResultStream(stream grpc.ClientStreamingClient[pb.ScanResult, pb.Ack]) error {
	if stream == nil {
		return nil
	}

	ack, err := stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("close grpc result stream: %w", err)
	}
	if ack != nil && !ack.Success {
		return fmt.Errorf("result stream rejected by server: %s", ack.Message)
	}
	return nil
}
