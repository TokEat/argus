package agent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
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

	"github.com/P0lar1ght/argus/scanner/internal/arsenal"
	"github.com/P0lar1ght/argus/scanner/internal/engine"
	"github.com/P0lar1ght/argus/scanner/internal/exploit"
	"github.com/P0lar1ght/argus/scanner/internal/timing"
	"github.com/P0lar1ght/argus/scanner/structs"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	gologgerWriter "github.com/projectdiscovery/gologger/writer"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

// grpcTeeWriter 实现 gologger Writer 接口，将日志同时写入本地终端和 gRPC StreamLogs。
type grpcTeeWriter struct {
	original  gologgerWriter.Writer
	stream    pb.AgentService_StreamLogsClient
	agentID   string
	mu        sync.Mutex
	closed    bool
	debugSink func(level, message string)
	queue     chan *pb.LogPayload
	stopCh    chan struct{}
	doneCh    chan struct{}
	dropped   atomic.Uint64
	stdLog    *standardLogTeeWriter
}

type standardLogTeeWriter struct {
	original io.Writer
	tee      *grpcTeeWriter
}

func (w *grpcTeeWriter) Write(data []byte, level levels.Level) {
	// 1. 始终写入本地终端
	if w.original != nil {
		w.original.Write(data, level)
	}

	// 2. 尝试通过 gRPC 回传（非阻塞，忽略发送失败）
	levelStr := "INFO"
	switch level {
	case levels.LevelError, levels.LevelFatal:
		levelStr = "ERROR"
	case levels.LevelWarning:
		levelStr = "WARN"
	case levels.LevelDebug, levels.LevelVerbose:
		levelStr = "DEBUG"
	}

	w.enqueue(levelStr, string(data))
}

func (w *grpcTeeWriter) enqueue(levelStr, message string) {
	msg := strings.TrimSpace(message)
	if msg == "" {
		return
	}

	w.mu.Lock()
	if w.closed || w.stream == nil {
		w.mu.Unlock()
		return
	}

	var debugSink func(level, message string)
	debugSink = w.debugSink

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
	w.mu.Unlock()

	if debugSink != nil {
		debugSink(levelStr, msg)
	}
}

func (w *standardLogTeeWriter) Write(data []byte) (int, error) {
	var err error
	if w.original != nil {
		_, err = w.original.Write(data)
	}
	if w.tee != nil {
		w.tee.enqueue("INFO", string(data))
	}
	return len(data), err
}

func (w *grpcTeeWriter) SetDebugSink(sink func(level, message string)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.debugSink = sink
}

func (w *grpcTeeWriter) ClearDebugSink() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.debugSink = nil
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

	if w.stdLog != nil {
		log.SetOutput(w.stdLog.original)
		w.stdLog = nil
	}
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
	// Asset-only legacy Agents still use the upgrade-window plaintext listener.
	// Credential validation is independently gated on a CA-verified transport.
	return false
}

var (
	newScanContext = engine.NewScanContext
	runScanTask    = engine.RunTask
)

const agentVersion = "v2.8.0"

type dispatchedTaskEnvelope struct {
	ResumePlan            *scanplan.ResumePlan
	ResumePlanHash        string
	ObservationConfigHash string
}

// Worker 是扫描节点的核心
type Worker struct {
	agentID                  string
	serverAddr               string
	apiURL                   string
	psk                      string // 预共享密钥，空则不发送鉴权信息
	sessionToken             string
	client                   pb.AgentServiceClient
	apiGetFn                 func(string) (*http.Response, error)
	conn                     *grpc.ClientConn
	transportCredentials     credentials.TransportCredentials
	transportTLS             bool
	credentialBundleProvider func(context.Context, string, string) ([]structs.UserPasswd, error)
	wg                       sync.WaitGroup
	mu                       sync.Mutex
	runningTasks             map[string]context.CancelFunc
	maxWorkers               int
	ruleVersion              string
	tags                     map[string]string
	rulesMu                  sync.Mutex
	pendingRules             *arsenal.PreparedRulePackage
	// activePackageSHA256 is the verified byte identity of the SQLite package
	// that produced the currently materialized config directory. It is guarded
	// by rulesMu and is never supplied by a dispatched task.
	activePackageSHA256 string
	// initializingRules covers the interval after a task has verified the
	// materialized rule package and before it is visible in runningTasks.
	// Keeping that interval counted prevents activation from replacing files
	// while NewScanContext is still reading them.
	initializingRules int

	// sem 并发控制信号量
	sem chan struct{}
	// freeSlots 当前空闲 worker 数（原子操作）
	freeSlots atomic.Int32
	// draining prevents new claims after a Spot termination notice.
	draining atomic.Bool

	logTee   *grpcTeeWriter
	stopCh   chan struct{}
	stopOnce sync.Once

	// reconnectCh 用于心跳连续失败时通知主循环重建 Subscribe 流
	reconnectCh chan struct{}

	debugMu      sync.Mutex
	debugCancel  context.CancelFunc
	debugSession string
	expMu        sync.Mutex
	expCancels   map[string]context.CancelFunc
}

func (w *Worker) requestStop() {
	w.stopOnce.Do(func() { close(w.stopCh) })
}

func NewWorker(agentID, serverAddr, apiURL string, maxWorkers int, tags map[string]string) *Worker {
	if maxWorkers <= 0 {
		maxWorkers = 1
	}
	cleanTags := make(map[string]string, len(tags)+6)
	for key, value := range tags {
		if key != "transport_tls" {
			cleanTags[key] = value
		}
	}
	tags = cleanTags
	pyenv := exploit.PythonRuntimeStatus()
	if pyenv.PythonPath != "" {
		tags["python_exp"] = "true"
		tags["pyexp_python"] = pyenv.PythonPath
		if pyenv.PythonVersion != "" {
			tags["pyexp_python_version"] = pyenv.PythonVersion
		}
		if pyenv.PipAvailable {
			tags["pyexp_pip"] = "true"
		} else {
			tags["pyexp_pip"] = "false"
		}
		if pyenv.InstallReady {
			tags["pyexp_install"] = "true"
		} else {
			tags["pyexp_install"] = "false"
		}
	} else if _, exists := tags["python_exp"]; !exists {
		tags["python_exp"] = "false"
		tags["pyexp_install"] = "false"
	}
	tags["native_egress"] = "v1"
	tags["scan_tcp"] = "v1"
	tags["risk_validation"] = "v1"
	tags["credential_validation"] = "v1"
	tags["subdomain_dictionary"] = "v1"
	tags["subdomain_depth"] = "v1"
	if _, err := exec.LookPath("masscan"); err == nil {
		tags["scan_syn"] = "v1"
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

// SetTLS configures a CA-pinned TLS 1.3 transport for Agent gRPC. Credential
// validation is rejected locally unless this transport is active.
func (w *Worker) SetTLS(caFile, serverName string) error {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("read Agent gRPC CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return errors.New("Agent gRPC CA file contains no valid certificates")
	}
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		host, _, splitErr := net.SplitHostPort(w.serverAddr)
		if splitErr != nil {
			return fmt.Errorf("derive Agent gRPC TLS server name from %q: %w", w.serverAddr, splitErr)
		}
		serverName = strings.Trim(host, "[]")
	}
	if serverName == "" {
		return errors.New("Agent gRPC TLS server name is required")
	}
	w.transportCredentials = credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: serverName,
	})
	w.transportTLS = true
	return nil
}

// apiGet 统一执行 Agent -> Server 的内部 HTTP GET，并附加注册会话头。
func (w *Worker) apiGet(url string) (*http.Response, error) {
	if w.apiGetFn != nil {
		return w.apiGetFn(url)
	}
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
	transport := w.transportCredentials
	if transport == nil {
		transport = insecure.NewCredentials()
	}
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(transport),
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
	w.credentialBundleProvider = w.fetchCredentialBundle
	log.Printf("Agent %s successfully registered to %s (tls=%t)", w.agentID, w.serverAddr, w.transportTLS)
	w.wg.Add(1)
	go w.runEgressTunnel()

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
		w.requestStop()
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
		if w.draining.Load() {
			w.wg.Wait()
			log.Println("Spot drain completed. Shutting down agent scheduler.")
			return nil
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

// claimAvailableTasks 在收到通知后，尽可能多地认领任务（填满空闲 worker）
func (w *Worker) claimAvailableTasks() {
	for {
		if w.draining.Load() {
			return
		}
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
		if w.draining.Load() {
			<-w.sem
			return
		}

		// 向 Server 认领任务
		claimCtx := context.Background()
		if w.sessionToken != "" {
			claimCtx = metadata.AppendToOutgoingContext(claimCtx, "x-agent-token", w.sessionToken)
		}
		task, err := w.client.ClaimTask(claimCtx, &pb.ClaimTaskReq{
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
		if w.draining.Load() {
			// EmergencyDump owns lease release once draining starts. Do not begin
			// executing a task returned by an in-flight ClaimTask call.
			<-w.sem
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
		if w.draining.Load() {
			return
		}
		if w.client != nil {
			w.mu.Lock()
			runningCount := int32(len(w.runningTasks) + w.initializingRules)
			taskIDs := make([]string, 0, len(w.runningTasks))
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
				RuleVersion:    w.currentRuleVersion(),
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
			if resp.ShouldTerminate {
				log.Printf("[Heartbeat] Server requested Agent termination")
				w.draining.Store(true)
				w.cancelActiveExecutions()
				w.requestStop()
				return
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
		if w.draining.Load() {
			return
		}
		cmdURL := fmt.Sprintf("%s/api/v1/agents/%s/commands", w.apiURL, w.agentID)
		resp, err := w.apiGet(cmdURL)
		if err != nil {
			log.Printf("[Command] Poll failed: %v", err)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		w.handleAgentCommandResponse(body)
	}
}

func (w *Worker) handleAgentCommandResponse(body []byte) {
	var result struct {
		CancelTasks []string `json:"cancel_tasks"`
		ReloadRules bool     `json:"reload_rules"`
		RuleVersion string   `json:"rule_version"`
	}
	if json.Unmarshal(body, &result) != nil {
		return
	}
	if result.ReloadRules && result.RuleVersion != "" && result.RuleVersion != "unknown" && result.RuleVersion != w.currentRuleVersion() {
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

func (w *Worker) syncRules() {
	w.rulesMu.Lock()
	defer w.rulesMu.Unlock()

	w.activatePendingRulesLocked()
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
		if !arsenal.IsRulePackageMaterialized("config", hashResp.Hash) {
			log.Printf("[Sync] Arsenal DB hash is current but config materialization is missing (hash=%s)", truncHash(hashResp.Hash))
			if err := w.prepareOrActivateRulesLocked(hashResp.Hash, hashResp.RuleVersion); err != nil {
				log.Printf("[Sync] Failed to materialize local arsenal.db: %v", err)
			}
			return
		}
		manifest, err := arsenal.ReadRulePackageManifest("config")
		if err != nil || w.bindActivePackageSHA256Locked(manifest) != nil {
			log.Printf("[Sync] Materialized Arsenal package failed SHA-256 verification; refusing to use it")
			return
		}
		log.Printf("[Sync] Arsenal DB up to date (hash=%s, version=%s, rules=%d)",
			truncHash(hashResp.Hash), hashResp.RuleVersion, hashResp.ArsenalCount)
		w.ruleVersion = hashResp.RuleVersion
		return
	}

	// 3. Hash 不同，下载完整 DB 文件
	log.Printf("[Sync] Arsenal DB outdated (local=%s, remote=%s), downloading...",
		truncHash(localHash), truncHash(hashResp.Hash))

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
	declaredPackageSHA256 := strings.TrimSpace(dbResp.Header.Get("X-Arsenal-SHA256"))
	actualPackageSHA256 := fmt.Sprintf("%x", sha256.Sum256(dbData))
	if len(declaredPackageSHA256) != sha256.Size*2 || declaredPackageSHA256 != strings.ToLower(declaredPackageSHA256) || declaredPackageSHA256 != actualPackageSHA256 {
		log.Printf("[Sync] Downloaded Arsenal DB failed package SHA-256 verification")
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

	// 5. 先物化为 CLI 形态 config/，成功激活后才保存 hash + 更新版本。
	fileHash := dbResp.Header.Get("X-Arsenal-Hash")
	if fileHash == "" {
		fileHash = actualPackageSHA256
	}
	if err := w.prepareOrActivateRulesLocked(hashResp.Hash, hashResp.RuleVersion); err != nil {
		log.Printf("[Sync] Failed to materialize downloaded arsenal.db: %v", err)
		return
	}

	log.Printf("[Sync] ✅ Arsenal DB cached: size=%d bytes, db_hash=%s, rule_hash=%s, version=%s",
		len(dbData), truncHash(fileHash), truncHash(hashResp.Hash), hashResp.RuleVersion)
}

func (w *Worker) prepareOrActivateRulesLocked(hash, ruleVersion string) error {
	prepared, err := arsenal.PrepareRulePackage(arsenal.MaterializeOptions{
		DBPath:      filepath.Join("data", "arsenal.db"),
		ConfigDir:   "config",
		BackupRoot:  filepath.Join("data", "arsenal", "backups"),
		Hash:        hash,
		RuleVersion: ruleVersion,
		BackupLimit: 3,
	})
	if err != nil {
		return err
	}
	if w.runningTaskCount() > 0 {
		w.replacePendingRulesLocked(prepared)
		log.Printf("[Sync] Prepared rule package hash=%s version=%s; activation deferred until running tasks finish",
			truncHash(hash), ruleVersion)
		return nil
	}
	if err := w.activatePreparedRulesLocked(prepared); err != nil {
		return err
	}
	return nil
}

func (w *Worker) replacePendingRulesLocked(prepared *arsenal.PreparedRulePackage) {
	if w.pendingRules != nil && w.pendingRules.StagingConfigDir != "" {
		_ = os.RemoveAll(filepath.Dir(w.pendingRules.StagingConfigDir))
	}
	w.pendingRules = prepared
}

func (w *Worker) activatePendingRulesIfIdle() {
	w.rulesMu.Lock()
	defer w.rulesMu.Unlock()
	w.activatePendingRulesLocked()
}

func (w *Worker) activatePendingRulesLocked() {
	if w.pendingRules == nil || w.runningTaskCount() > 0 {
		return
	}
	if err := w.activatePreparedRulesLocked(w.pendingRules); err != nil {
		log.Printf("[Sync] Failed to activate pending rule package: %v", err)
		return
	}
	w.pendingRules = nil
}

func (w *Worker) activatePreparedRulesLocked(prepared *arsenal.PreparedRulePackage) error {
	if err := arsenal.ActivatePreparedRulePackage(prepared); err != nil {
		return err
	}
	w.saveLocalDBHash(prepared.Manifest.Hash)
	w.ruleVersion = prepared.Manifest.RuleVersion
	w.activePackageSHA256 = prepared.Manifest.PackageSHA256
	log.Printf("[Sync] ✅ Arsenal rules materialized to config/: hash=%s version=%s pocs=%d",
		truncHash(prepared.Manifest.Hash), prepared.Manifest.RuleVersion, prepared.Manifest.Counts.Pocs)
	return nil
}

func (w *Worker) runningTaskCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.runningTasks) + w.initializingRules
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

func applyAgentRuleFileConfig(cfg *engine.Config) {
	cfg.RuleFilesOnly = true
	cfg.FingerConfigFilePath = filepath.Join("config", "finger.yaml")
	cfg.WorkflowYamlPath = filepath.Join("config", "workflow.yaml")
	cfg.DirSearchYaml = filepath.Join("config", "dir.yaml")
	cfg.NucleiTemplate = filepath.Join("config", "pocs")
}

func (w *Worker) executeTask(task *pb.Task) {
	log.Printf("Received Task: %s with targets: %v", task.TaskId, task.Targets)

	cfg := engine.Config(structs.DefaultConfig())
	// Server-dispatched asset discovery is always POC-off. Apply the safe
	// baseline before decoding so legacy `{}` configs cannot inherit the CLI's
	// explicit POC defaults.
	cfg.NoPoc = true
	cfg.GolangPoc = false
	cfg.DisableGeneralPoc = true
	cfg.PocNameForSearch = ""
	var envelope dispatchedTaskEnvelope
	if len(task.Config) > 0 {
		if err := json.Unmarshal(task.Config, &cfg); err != nil {
			err = fmt.Errorf("decode task config: %w", err)
			log.Printf("Failed to decode config for task %s: %v", task.TaskId, err)
			w.reportTaskCompletion(task.TaskId, "FAILED", err.Error())
			return
		}
		if err := json.Unmarshal(task.Config, &envelope); err != nil {
			err = fmt.Errorf("decode internal task envelope: %w", err)
			log.Printf("Failed to decode task envelope for task %s: %v", task.TaskId, err)
			w.reportTaskCompletion(task.TaskId, "FAILED", err.Error())
			return
		}
	}
	if err := engine.ValidateLegacyProviderConfig(cfg); err != nil {
		err = fmt.Errorf("reject legacy provider task: %w", err)
		log.Printf("Rejected legacy provider task %s: %v", task.TaskId, err)
		w.reportTaskCompletion(task.TaskId, "FAILED", err.Error())
		return
	}
	if strings.TrimSpace(cfg.ExecutionMode) == "" && (!cfg.NoPoc || cfg.GolangPoc || !cfg.DisableGeneralPoc || strings.TrimSpace(cfg.PocNameForSearch) != "") {
		err := errors.New("ordinary Agent tasks cannot execute POCs; use a confirmed risk-validation batch")
		log.Printf("Rejected unconfirmed POC task %s: %v", task.TaskId, err)
		w.reportTaskCompletion(task.TaskId, "FAILED", err.Error())
		return
	}
	if err := w.prepareCredentialValidationConfig(&cfg, task.TaskId); err != nil {
		err = fmt.Errorf("reject credential-validation task: %w", err)
		log.Printf("Rejected credential-validation task %s: %v", task.TaskId, err)
		w.reportTaskCompletion(task.TaskId, "FAILED", err.Error())
		return
	}
	cfg.Targets = task.Targets
	cfg.OutputFile = ""
	cfg.ReportName = ""
	applyAgentRuleFileConfig(&cfg)

	timingRecorder := timing.NewRecorder(nil)
	ruleSpan, timingErr := timingRecorder.Begin(scanplan.TimingRulePrepare, "")
	if timingErr != nil {
		log.Printf("Failed to begin rule preparation timing for task %s: %v", task.TaskId, timingErr)
	}
	taskRuleHash, taskRuleVersion, releaseRuleUse, err := w.acquireTaskRuleUse()
	if ruleSpan != nil {
		outcome := scanplan.ObservationSuccess
		if err != nil {
			outcome = scanplan.ObservationFailed
		}
		if finishErr := finishTimingSpan(ruleSpan, outcome); finishErr != nil {
			log.Printf("Failed to finish rule preparation timing for task %s: %v", task.TaskId, finishErr)
		}
	}
	if err != nil {
		err = fmt.Errorf("agent rules not ready: %w", err)
		log.Printf("Failed to prepare rules for task %s: %v", task.TaskId, err)
		w.reportTaskCompletion(task.TaskId, "FAILED", err.Error())
		return
	}
	// The Engine cache is keyed by the verified package identity. These fields
	// are deliberately not part of task JSON and cannot be controlled by the
	// dispatcher.
	cfg.KnowledgePackageHash = taskRuleHash
	cfg.KnowledgeRuleVersion = taskRuleVersion
	if strings.EqualFold(strings.TrimSpace(cfg.ExecutionMode), "risk_validation") {
		requiredRuleVersion := strings.TrimSpace(cfg.RequiredRuleVersion)
		if requiredRuleVersion == "" || taskRuleVersion != requiredRuleVersion {
			err := fmt.Errorf("risk validation requires Agent rules %q, current version is %q", requiredRuleVersion, taskRuleVersion)
			log.Printf("Rejected risk validation task %s: %v", task.TaskId, err)
			w.reportTaskCompletion(task.TaskId, "FAILED", err.Error())
			releaseRuleUse()
			return
		}
	}
	resumeRequested := envelope.ResumePlan != nil || strings.TrimSpace(envelope.ResumePlanHash) != "" || strings.TrimSpace(envelope.ObservationConfigHash) != ""
	if resumeRequested {
		decodedConfigHash, configHashErr := hex.DecodeString(envelope.ObservationConfigHash)
		if envelope.ResumePlan == nil || strings.TrimSpace(envelope.ResumePlanHash) == "" ||
			envelope.ObservationConfigHash != strings.ToLower(strings.TrimSpace(envelope.ObservationConfigHash)) ||
			configHashErr != nil || len(decodedConfigHash) != 32 {
			err := errors.New("incomplete or mismatched resume task envelope")
			log.Printf("Rejected resume task %s: %v", task.TaskId, err)
			w.reportTaskCompletion(task.TaskId, "FAILED", err.Error())
			releaseRuleUse()
			return
		}
		if err := engine.ValidateResumePlan(cfg, task.Targets, taskRuleVersion, envelope.ResumePlanHash, envelope.ResumePlan); err != nil {
			err = fmt.Errorf("reject resume task: %w", err)
			log.Printf("Rejected resume task %s: %v", task.TaskId, err)
			w.reportTaskCompletion(task.TaskId, "FAILED", err.Error())
			releaseRuleUse()
			return
		}
	}

	contextSpan, timingErr := timingRecorder.Begin(scanplan.TimingContextInit, "")
	if timingErr != nil {
		log.Printf("Failed to begin context initialization timing for task %s: %v", task.TaskId, timingErr)
	}
	ctx, err := newScanContext(cfg)
	if contextSpan != nil {
		outcome := scanplan.ObservationSuccess
		if err != nil {
			outcome = scanplan.ObservationFailed
		}
		if finishErr := finishTimingSpan(contextSpan, outcome); finishErr != nil {
			log.Printf("Failed to finish context initialization timing for task %s: %v", task.TaskId, finishErr)
		}
	}
	if err != nil {
		log.Printf("Failed to initialize scan context for task %s: %v", task.TaskId, err)
		w.reportTaskCompletion(task.TaskId, "FAILED", err.Error())
		releaseRuleUse()
		return
	}
	defer ctx.Close()
	ctx.TaskID = task.TaskId
	if resumeRequested {
		ctx.ResumePlan = envelope.ResumePlan
	}

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
	releaseRuleUse()

	defer func() {
		w.mu.Lock()
		delete(w.runningTasks, task.TaskId)
		w.mu.Unlock()
		w.activatePendingRulesIfIdle()
	}()

	// 挂载 OutputHook 进行 gRPC Stream 实时回传
	streamCtx := context.Background()
	if w.sessionToken != "" {
		streamCtx = metadata.AppendToOutgoingContext(streamCtx, "x-agent-token", w.sessionToken)
	}
	stream, err := w.client.StreamResult(streamCtx)
	if err != nil {
		err = fmt.Errorf("open grpc result stream: %w", err)
		log.Printf("Failed to open grpc stream for task %s: %v", task.TaskId, err)
		w.reportTaskCompletion(task.TaskId, "FAILED", err.Error())
		return
	}

	var streamMu sync.Mutex
	var streamErr error
	sendTimingEventLocked := func(event *scanplan.TimingEvent) {
		if streamErr != nil || event == nil {
			return
		}
		if err := event.Validate(); err != nil {
			streamErr = fmt.Errorf("validate timing event: %w", err)
			if ctx.Cancel != nil {
				ctx.Cancel()
			}
			return
		}
		payload, err := json.Marshal(event)
		if err != nil {
			streamErr = fmt.Errorf("marshal timing event: %w", err)
			if ctx.Cancel != nil {
				ctx.Cancel()
			}
			return
		}
		if err := stream.Send(&pb.ScanResult{TaskId: task.TaskId, PayloadType: scanplan.TimingEventPayloadType, Payload: payload, Timestamp: event.FinishedAt.UnixMilli()}); err != nil {
			streamErr = fmt.Errorf("send timing event: %w", err)
			if ctx.Cancel != nil {
				ctx.Cancel()
			}
		}
	}
	if err := timingRecorder.Bind(task.TaskId, w.agentID); err != nil {
		streamErr = fmt.Errorf("bind timing recorder: %w", err)
		if ctx.Cancel != nil {
			ctx.Cancel()
		}
	} else if events, err := timingRecorder.Snapshot(); err != nil {
		streamErr = fmt.Errorf("snapshot timing events: %w", err)
		if ctx.Cancel != nil {
			ctx.Cancel()
		}
	} else {
		for i := range events {
			sendTimingEventLocked(&events[i])
		}
	}
	reporterPlan := []stageObservationReporterPlan(nil)
	if resumeRequested {
		reporterPlan = append(reporterPlan, stageObservationReporterPlan{
			ConfigHash: envelope.ObservationConfigHash,
			Stages:     envelope.ResumePlan.ExecutionStages,
		})
	}
	coverageReporter := newStageObservationReporter(task.TaskId, w.agentID, task.Targets, task.Config, taskRuleVersion, cfg.ExecutionMode, reporterPlan...)
	stageTimings := newStageTimingTracker(nil)
	sendCoverageEventLocked := func(event *scanplan.StageObservationEvent) {
		if streamErr != nil || event == nil {
			return
		}
		if err := event.Validate(); err != nil {
			streamErr = fmt.Errorf("validate coverage event: %w", err)
			if ctx.Cancel != nil {
				ctx.Cancel()
			}
			return
		}
		payload, err := json.Marshal(event)
		if err != nil {
			streamErr = fmt.Errorf("marshal coverage event: %w", err)
			if ctx.Cancel != nil {
				ctx.Cancel()
			}
			return
		}
		if err := stream.Send(&pb.ScanResult{
			TaskId:      task.TaskId,
			PayloadType: scanplan.StageObservationPayloadType,
			Payload:     payload,
			Timestamp:   event.FinishedAt.UnixMilli(),
		}); err != nil {
			streamErr = fmt.Errorf("send coverage event: %w", err)
			if ctx.Cancel != nil {
				ctx.Cancel()
			}
		}
	}
	ctx.OutputHook = func(msg engine.OutputMessage) {
		mirrorAgentConsoleOutputForMode(msg, cfg.ExecutionMode)

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
		coverageReporter.recordOutput(msg.Type, payload)

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
		if err := stream.Send(&pb.ScanResult{
			TaskId:      task.TaskId,
			PayloadType: "phase",
			Payload:     payload,
			Timestamp:   time.Now().UnixMilli(),
		}); err != nil {
			streamErr = fmt.Errorf("send phase event: %w", err)
			if ctx.Cancel != nil {
				ctx.Cancel()
			}
			return
		}
		stageTimings.observePhase(phase)
		for _, event := range coverageReporter.observePhase(phase) {
			sendCoverageEventLocked(event)
			timingEvent, err := stageTimings.eventForObservation(event)
			if err != nil {
				streamErr = fmt.Errorf("build stage timing event: %w", err)
				if ctx.Cancel != nil {
					ctx.Cancel()
				}
				return
			}
			sendTimingEventLocked(timingEvent)
		}
	}

	// 启动引擎
	log.Printf("Starting Pipeline for Task %s...", task.TaskId)

	runErr := runScanTask(ctx)
	streamMu.Lock()
	if streamErr == nil {
		for _, event := range coverageReporter.finalize(runErr, cancelRequested.Load()) {
			sendCoverageEventLocked(event)
			timingEvent, err := stageTimings.eventForObservation(event)
			if err != nil {
				streamErr = fmt.Errorf("build terminal stage timing event: %w", err)
				if ctx.Cancel != nil {
					ctx.Cancel()
				}
				break
			}
			sendTimingEventLocked(timingEvent)
		}
	}
	streamMu.Unlock()

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
	tee.stdLog = &standardLogTeeWriter{original: log.Writer(), tee: tee}
	log.SetOutput(tee.stdLog)
	log.Printf("[LogTee] Streaming agent logs to Server")

	return tee
}
