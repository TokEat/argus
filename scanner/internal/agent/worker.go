package agent

import (
	"context"
	"crypto/md5"
	"dddd/scanner/ddout"
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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"

	"dddd/scanner/internal/engine"
	"dddd/scanner/structs"
	pb "github.com/user/dddd-proto/go/scan"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	gologgerWriter "github.com/projectdiscovery/gologger/writer"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// grpcTeeWriter 实现 gologger Writer 接口，将日志同时写入本地终端和 gRPC StreamLogs。
type grpcTeeWriter struct {
	original gologgerWriter.Writer
	stream   pb.AgentService_StreamLogsClient
	agentID  string
	mu       sync.Mutex
	closed   bool
	queue    chan *pb.LogPayload
	stopCh   chan struct{}
	doneCh   chan struct{}
	dropped  atomic.Uint64
}

func (w *grpcTeeWriter) Write(data []byte, level levels.Level) {
	// 1. 始终写入本地终端
	if w.original != nil {
		w.original.Write(data, level)
	}

	// 2. 尝试通过 gRPC 回传（非阻塞，忽略发送失败）
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.stream == nil {
		return
	}

	levelStr := "INFO"
	switch level {
	case levels.LevelError, levels.LevelFatal:
		levelStr = "ERROR"
	case levels.LevelWarning:
		levelStr = "WARN"
	case levels.LevelDebug, levels.LevelVerbose:
		levelStr = "DEBUG"
	}

	msg := strings.TrimSpace(string(data))
	if msg == "" {
		return
	}

	payload := &pb.LogPayload{
		AgentId:   w.agentID,
		Level:     levelStr,
		Message:   msg,
		Timestamp: time.Now().UnixMilli(),
	}

	select {
	case w.queue <- payload:
	default:
		w.dropped.Add(1)
	}
}

func (w *grpcTeeWriter) runSender() {
	defer close(w.doneCh)
	for {
		select {
		case <-w.stopCh:
			for {
				select {
				case payload := <-w.queue:
					if payload == nil || w.stream == nil {
						continue
					}
					_ = w.stream.Send(payload)
				default:
					return
				}
			}
		case payload := <-w.queue:
			if payload == nil || w.stream == nil {
				continue
			}
			_ = w.stream.Send(payload)
		}
	}
}

func (w *grpcTeeWriter) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	close(w.stopCh)
	w.mu.Unlock()

	<-w.doneCh

	if w.stream != nil {
		_, _ = w.stream.CloseAndRecv()
	}
}

// perRPCPSK 实现 gRPC PerRPCCredentials，在每个 RPC 调用中自动附加 x-agent-psk metadata
type perRPCPSK struct {
	psk string
}

func (p *perRPCPSK) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{"x-agent-psk": p.psk}, nil
}

func (p *perRPCPSK) RequireTransportSecurity() bool {
	return false // 当前使用 insecure，生产环境应开启 TLS
}

var (
	newScanContext = engine.NewScanContext
	runScanTask    = engine.RunTask
)

const agentVersion = "v2.3.0"

// Worker 是扫描节点的核心
type Worker struct {
	agentID      string
	serverAddr   string
	apiURL       string
	psk          string // 预共享密钥，空则不发送鉴权信息
	sessionToken string
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

	logTee *grpcTeeWriter
	stopCh chan struct{}

	// reconnectCh 用于心跳连续失败时通知主循环重建 Subscribe 流
	reconnectCh chan struct{}

	debugMu      sync.Mutex
	debugCancel  context.CancelFunc
	debugSession string
	expMu        sync.Mutex
	expCancels   map[string]context.CancelFunc
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
		stopCh:       make(chan struct{}),
		reconnectCh:  make(chan struct{}, 1),
		expCancels:   make(map[string]context.CancelFunc),
	}
}

// SetPSK 设置 Agent 预共享密钥
func (w *Worker) SetPSK(psk string) {
	w.psk = psk
}

// apiGet 统一执行 Agent -> Server 的内部 HTTP GET，并附加注册会话头。
func (w *Worker) apiGet(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if w.sessionToken != "" {
		req.Header.Set("x-agent-id", w.agentID)
		req.Header.Set("x-agent-token", w.sessionToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s returned status %d: %s", url, resp.StatusCode, string(body))
	}
	return resp, nil
}

func (w *Worker) Start() error {
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// TCP Keepalive：防止空闲连接被 NAT/防火墙/LB 静默丢弃
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second, // 每 30 秒发送一次 keepalive ping
			Timeout:             10 * time.Second, // 10 秒无响应判定连接死亡
			PermitWithoutStream: true,             // 即使没有活跃 RPC 流也发送 ping
		}),
	}
	if w.psk != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(&perRPCPSK{psk: w.psk}))
		log.Printf("[Auth] PSK authentication enabled")
	}

	conn, err := grpc.NewClient(w.serverAddr, dialOpts...)
	if err != nil {
		return err
	}
	w.conn = conn
	w.client = pb.NewAgentServiceClient(conn)

	// 1. 注册
	effectiveWorkers := w.effectiveWorkerCount()
	resp, err := w.client.Register(context.Background(), &pb.RegisterReq{
		AgentId:  w.agentID,
		Version:  agentVersion,
		Tags:     w.tags,
		Os:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Capacity: int32(effectiveWorkers),
	})
	if err != nil {
		return err
	}
	w.sessionToken = strings.TrimSpace(resp.GetToken())
	if w.sessionToken == "" {
		return fmt.Errorf("server returned empty agent session token")
	}
	log.Printf("Agent %s successfully registered to %s", w.agentID, w.serverAddr)

	w.logTee = w.installGlobalLogTeeWriter()
	defer func() {
		if w.logTee != nil {
			w.logTee.Close()
		}
	}()

	// 开机同步热更新规则库 (Arsenal)
	w.syncRules()

	// 初始化并发控制
	w.sem = make(chan struct{}, effectiveWorkers)
	w.freeSlots.Store(int32(effectiveWorkers))

	// 后台心跳维持
	go w.heartbeatLoop()
	// 获取动态指令
	go w.commandLoop()

	// Spot 竞价实例回收监听：当 Agent 运行在云实例上时自动启用
	if os.Getenv("ARGUS_SPOT") == "1" || w.tags["cloud"] != "" {
		log.Println("[Spot] Spot termination listener enabled")
		w.StartSpotTerminationListener()
	}

	log.Printf("Agent started with worker pool size: %d", effectiveWorkers)

	// 信号劫持
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	quit := make(chan struct{})

	go func() {
		<-sigCh
		log.Println("Received termination signal, waiting for running tasks to drain...")
		close(w.stopCh)
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

		// 清空重连信号（防止残留信号导致立即退出）
		select {
		case <-w.reconnectCh:
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
		case <-w.reconnectCh:
			// 心跳连续失败触发 Subscribe 流重建
			log.Println("[Subscribe] Heartbeat detected connection failure, forcing stream reconnect...")
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

		if notify.DebugCommand != nil {
			w.handleDebugCommand(notify.DebugCommand)
			continue
		}

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

	consecutiveFailures := 0
	const maxConsecutiveFailures = 3

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

			// 给心跳 RPC 加超时，避免在死连接上无限阻塞
			hbCtx, hbCancel := context.WithTimeout(context.Background(), 10*time.Second)
			resp, err := w.client.Heartbeat(hbCtx, &pb.HeartbeatReq{
				AgentId:        w.agentID,
				Status:         "Alive",
				RuleVersion:    w.ruleVersion,
				RunningTasks:   runningCount,
				RunningTaskIds: taskIDs,
				CpuUsage:       float32(cpuUsage),
				MemUsage:       float32(memUsage),
			})
			hbCancel()

			if err != nil {
				consecutiveFailures++
				log.Printf("[Heartbeat] Failure (%d/%d): %v", consecutiveFailures, maxConsecutiveFailures, err)

				if consecutiveFailures >= maxConsecutiveFailures {
					log.Printf("[Heartbeat] %d consecutive failures detected, triggering Subscribe reconnect...", consecutiveFailures)
					consecutiveFailures = 0
					// 非阻塞发送重连信号
					select {
					case w.reconnectCh <- struct{}{}:
					default:
					}
				}
				continue
			}

			// 心跳成功，重置失败计数
			consecutiveFailures = 0

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
		resp, err := w.apiGet(w.apiURL + "/api/v1/agents/" + w.agentID + "/commands")
		if err != nil {
			log.Printf("[Command] Poll failed: %v", err)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var result struct {
			CancelTasks []string `json:"cancel_tasks"`
			ReloadRules bool     `json:"reload_rules"`
			RuleVersion string   `json:"rule_version"`
		}
		if json.Unmarshal(body, &result) == nil {
			if result.ReloadRules && result.RuleVersion != "" && result.RuleVersion != "unknown" && result.RuleVersion != w.ruleVersion {
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

func (w *Worker) syncRules() {
	log.Println("[Sync] Checking Arsenal DB for updates...")

	// 1. 探测 Server 端 DB hash（轻量级 JSON 请求）
	hashURL := w.apiURL + "/api/v1/arsenals/db/hash"
	resp, err := w.apiGet(hashURL)
	if err != nil {
		log.Printf("[Sync] Failed to fetch DB hash (server may not support DB sync): %v", err)
		return
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var hashResp struct {
		Hash         string `json:"hash"`
		RuleVersion  string `json:"rule_version"`
		ArsenalCount int    `json:"arsenal_count"`
	}
	if err := json.Unmarshal(body, &hashResp); err != nil {
		log.Printf("[Sync] Failed to parse DB hash response: %v", err)
		return
	}

	if hashResp.Hash == "" {
		log.Println("[Sync] Server returned empty hash (no approved rules), skipping")
		w.ruleVersion = hashResp.RuleVersion
		return
	}

	// 2. 与本地存储的 hash 对比
	localHash := w.loadLocalDBHash()
	if localHash == hashResp.Hash {
		log.Printf("[Sync] Arsenal DB up to date (hash=%s, version=%s, rules=%d)",
			hashResp.Hash[:8], hashResp.RuleVersion, hashResp.ArsenalCount)
		w.ruleVersion = hashResp.RuleVersion
		return
	}

	// 3. Hash 不同，下载完整 DB 文件
	log.Printf("[Sync] Arsenal DB outdated (local=%s, remote=%s), downloading...",
		truncHash(localHash), hashResp.Hash[:8])

	dbURL := w.apiURL + "/api/v1/arsenals/db"
	dbResp, err := w.apiGet(dbURL)
	if err != nil {
		log.Printf("[Sync] Failed to download arsenal.db: %v", err)
		return
	}
	dbData, err := io.ReadAll(dbResp.Body)
	dbResp.Body.Close()
	if err != nil {
		log.Printf("[Sync] Failed to read arsenal.db response: %v", err)
		return
	}

	if len(dbData) == 0 {
		log.Println("[Sync] Downloaded empty DB, skipping")
		return
	}

	// 4. 原子替换：先写临时文件，再 rename
	dbDir := "data"
	_ = os.MkdirAll(dbDir, 0755)
	dbPath := filepath.Join(dbDir, "arsenal.db")

	tmpFile, err := os.CreateTemp(dbDir, "arsenal-*.db.tmp")
	if err != nil {
		log.Printf("[Sync] Failed to create temp file: %v", err)
		return
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(dbData); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		log.Printf("[Sync] Failed to write temp DB file: %v", err)
		return
	}
	tmpFile.Close()

	// 备份旧 DB
	if _, err := os.Stat(dbPath); err == nil {
		backupDir := filepath.Join(dbDir, ".backup")
		_ = os.MkdirAll(backupDir, 0755)
		backupPath := filepath.Join(backupDir, "arsenal.db.bak")
		if oldData, err := os.ReadFile(dbPath); err == nil {
			_ = os.WriteFile(backupPath, oldData, 0644)
		}
	}

	// 原子 rename
	if err := os.Rename(tmpPath, dbPath); err != nil {
		os.Remove(tmpPath)
		log.Printf("[Sync] Failed to replace arsenal.db: %v", err)
		return
	}

	// 5. 保存 hash + 更新版本
	serverHash := dbResp.Header.Get("X-Arsenal-Hash")
	if serverHash == "" {
		serverHash = fmt.Sprintf("%x", md5.Sum(dbData))
	}
	w.saveLocalDBHash(serverHash)
	w.ruleVersion = hashResp.RuleVersion

	log.Printf("[Sync] ✅ Arsenal DB updated: size=%d bytes, hash=%s, version=%s",
		len(dbData), serverHash[:8], hashResp.RuleVersion)
}

// loadLocalDBHash 读取本地存储的 DB hash（用于增量对比）。
func (w *Worker) loadLocalDBHash() string {
	data, err := os.ReadFile("data/.arsenal_hash")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// saveLocalDBHash 保存 DB hash 到本地文件。
func (w *Worker) saveLocalDBHash(hash string) {
	_ = os.MkdirAll("data", 0755)
	_ = os.WriteFile("data/.arsenal_hash", []byte(hash), 0644)
}

// truncHash 截断 hash 用于日志显示。
func truncHash(h string) string {
	if len(h) >= 8 {
		return h[:8]
	}
	if h == "" {
		return "(none)"
	}
	return h
}

func (w *Worker) executeTask(task *pb.Task) {
	log.Printf("Received Task: %s with targets: %v", task.TaskId, task.Targets)

	cfg := engine.Config(structs.DefaultConfig())
	if len(task.Config) > 0 {
		if err := json.Unmarshal(task.Config, &cfg); err != nil {
			err = fmt.Errorf("decode task config: %w", err)
			log.Printf("Failed to decode config for task %s: %v", task.TaskId, err)
			w.reportTaskCompletion(task.TaskId, "FAILED", err.Error())
			return
		}
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
		mirrorAgentConsoleOutput(msg)

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
	req := &pb.TaskCompleteReq{
		AgentId:      w.agentID,
		TaskId:       taskID,
		Status:       status,
		ErrorMessage: errMessage,
	}
	if err := w.sendTaskCompletionWithRetry(req, 5); err != nil {
		log.Printf("[TaskComplete] Failed to persist completion for %s after retries: %v", taskID, err)
		go w.retryTaskCompletionAsync(req)
	}
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

func (w *Worker) sendTaskCompletionWithRetry(req *pb.TaskCompleteReq, attempts int) error {
	if attempts <= 0 {
		attempts = 1
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		lastErr = w.tryTaskComplete(req)
		if lastErr == nil {
			return nil
		}
		if attempt == attempts {
			break
		}
		select {
		case <-w.stopCh:
			return lastErr
		case <-time.After(taskCompleteBackoff(attempt)):
		}
	}
	return lastErr
}

func (w *Worker) retryTaskCompletionAsync(req *pb.TaskCompleteReq) {
	for attempt := 1; ; attempt++ {
		select {
		case <-w.stopCh:
			return
		default:
		}

		if err := w.tryTaskComplete(req); err == nil {
			log.Printf("[TaskComplete] Eventually persisted completion for %s", req.TaskId)
			return
		}

		select {
		case <-w.stopCh:
			return
		case <-time.After(taskCompleteBackoff(attempt + 5)):
		}
	}
}

func (w *Worker) tryTaskComplete(req *pb.TaskCompleteReq) error {
	if w.client == nil {
		return errors.New("agent client is not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ack, err := w.client.TaskComplete(ctx, req)
	if err != nil {
		return err
	}
	if ack != nil && !ack.Success {
		return fmt.Errorf("task completion rejected: %s", ack.Message)
	}
	return nil
}

func taskCompleteBackoff(attempt int) time.Duration {
	switch {
	case attempt <= 1:
		return 500 * time.Millisecond
	case attempt == 2:
		return time.Second
	case attempt == 3:
		return 2 * time.Second
	case attempt == 4:
		return 5 * time.Second
	default:
		return 10 * time.Second
	}
}

// installGlobalLogTeeWriter 将 gologger 的 Writer 替换为单个全局 TeeWriter，
// 避免多任务并发时互相抢占 DefaultLogger 的 Writer。
func (w *Worker) installGlobalLogTeeWriter() *grpcTeeWriter {
	logStream, err := w.client.StreamLogs(context.Background())
	if err != nil {
		log.Printf("[LogTee] Failed to open StreamLogs: %v (logs will only appear locally)", err)
		return nil
	}

	originalWriter := gologgerWriter.NewCLI()

	tee := &grpcTeeWriter{
		original: originalWriter,
		stream:   logStream,
		agentID:  w.agentID,
		queue:    make(chan *pb.LogPayload, 1024),
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
	go tee.runSender()

	gologger.DefaultLogger.SetWriter(tee)
	log.Printf("[LogTee] Streaming agent logs to Server")

	return tee
}

func mirrorAgentConsoleOutput(msg engine.OutputMessage) {
	if !shouldMirrorAgentOutput(msg.Type) {
		return
	}

	line := ddout.Render(toDDOutOutputMessage(msg))
	if line == "" {
		return
	}
	fmt.Println(line)
}

func shouldMirrorAgentOutput(messageType string) bool {
	switch messageType {
	case "Finger", "Active-Finger", "GoPoc", "Domain-Bind":
		return true
	default:
		return false
	}
}

func toDDOutOutputMessage(msg engine.OutputMessage) ddout.OutputMessage {
	return ddout.OutputMessage{
		Type:     msg.Type,
		IP:       msg.IP,
		IPs:      append([]string(nil), msg.IPs...),
		Port:     msg.Port,
		Protocol: msg.Protocol,
		Web: ddout.WebInfo{
			Status: msg.Web.Status,
			Title:  msg.Web.Title,
		},
		Finger: append([]string(nil), msg.Finger...),
		Domain: msg.Domain,
		GoPoc: ddout.GoPocsResultType{
			PocName:     msg.GoPoc.PocName,
			Security:    msg.GoPoc.Security,
			Description: msg.GoPoc.Description,
			Target:      msg.GoPoc.Target,
			InfoLeft:    msg.GoPoc.InfoLeft,
			InfoRight:   msg.GoPoc.InfoRight,
			ShowMsg:     msg.GoPoc.ShowMsg,
		},
		URI:           msg.URI,
		City:          msg.City,
		AdditionalMsg: msg.AdditionalMsg,
		Show:          msg.Show,
		Nuclei:        msg.Nuclei,
	}
}
