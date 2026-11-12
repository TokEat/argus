package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/TokEat/argus/server/internal/ai"
	"github.com/TokEat/argus/server/internal/api"
	"github.com/TokEat/argus/server/internal/cloud"
	_ "github.com/TokEat/argus/server/internal/cloud/aliyun" // 注册阿里云 ECS Provider
	"github.com/TokEat/argus/server/internal/credentialvault"
	"github.com/TokEat/argus/server/internal/db"
	"github.com/TokEat/argus/server/internal/dispatch"
	egresspkg "github.com/TokEat/argus/server/internal/egress"
	"github.com/TokEat/argus/server/internal/grpc"
	"github.com/TokEat/argus/server/internal/scheduler"
	"github.com/TokEat/argus/server/internal/sentinel"
	"github.com/TokEat/argus/server/internal/subdomainpassive"
	pb "github.com/TokEat/argus/shared/proto/go/scan"
)

// sentinelPusher routes a rescan attempt onto a specific agent's dedicated
// queue, which ClaimTask drains before the shared queue — hard exclusion of
// the banned egress.
type sentinelPusher struct{ queue *scheduler.TaskQueue }

func (p sentinelPusher) PushSubTaskToAgent(ctx context.Context, agentID string, sub db.SubTask) error {
	pbSub, err := db.SubTaskToProto(&sub)
	if err != nil {
		return err
	}
	return p.queue.PushToAgentQueue(ctx, agentID, pbSub)
}

func resolveOutboundHost() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err == nil {
		defer conn.Close()
		if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP != nil && !udpAddr.IP.IsUnspecified() {
			return udpAddr.IP.String(), nil
		}
	}

	hostname, hostErr := os.Hostname()
	if hostErr == nil {
		hostname = strings.TrimSpace(hostname)
		if hostname != "" && hostname != "localhost" {
			return hostname, nil
		}
	}

	if err != nil {
		return "", err
	}
	return "", fmt.Errorf("unable to resolve advertise host from network interfaces")
}

func isRoutableAdvertiseHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" || host == "0.0.0.0" || host == "::" || strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsUnspecified() || ip.IsLoopback()) {
		return false
	}
	return true
}

func buildCloudAdvertiseAddrs(grpcPort int, apiAddr, publicIP, publicAPI string, detectHost func() (string, error)) (string, string, error) {
	publicIP = strings.TrimSpace(publicIP)
	publicAPI = strings.TrimSpace(publicAPI)
	if publicIP != "" {
		grpcAddr := fmt.Sprintf("%s:%d", publicIP, grpcPort)
		if publicAPI != "" {
			return grpcAddr, publicAPI, nil
		}
		return grpcAddr, fmt.Sprintf("http://%s%s", publicIP, apiAddr), nil
	}

	host, port, err := net.SplitHostPort(apiAddr)
	if err != nil {
		return "", "", fmt.Errorf("parse api bind address %q: %w", apiAddr, err)
	}
	if !isRoutableAdvertiseHost(host) {
		host, err = detectHost()
		if err != nil {
			return "", "", fmt.Errorf("resolve advertise host: %w", err)
		}
	}

	grpcAddr := fmt.Sprintf("%s:%d", host, grpcPort)
	apiURL := fmt.Sprintf("http://%s:%s", host, port)
	if publicAPI != "" {
		apiURL = publicAPI
	}
	return grpcAddr, apiURL, nil
}

func agentOfflineUpdates() map[string]interface{} {
	// Liveness loss is not an authentication decision. Keep the session token so
	// a still-running agent can recover after server restarts or transient stalls.
	return map[string]interface{}{
		"status":        "Offline",
		"running_tasks": 0,
	}
}

func shouldMarkAgentOffline(hub *grpc.NotifyHub, agentID string) bool {
	if hub == nil {
		return true
	}
	return !hub.IsAgentOnline(agentID)
}

func main() {
	var (
		dbDSN       string
		amqpURL     string
		grpcPort    int
		grpcTLSPort int
		grpcTLSCert string
		grpcTLSKey  string
		apiAddr     string
		configDir   string
		agentPSK    string
		deployMode  string
		devMode     bool
		seedFromDB  string
	)

	flag.StringVar(&dbDSN, "db", "", "PostgreSQL DSN. Empty uses the built-in local PostgreSQL default.")
	flag.StringVar(&amqpURL, "amqp", "amqp://guest:guest@localhost:5672/", "RabbitMQ AMQP URL. Empty falls back to in-memory queue")
	flag.IntVar(&grpcPort, "grpc", 50051, "gRPC listen port")
	flag.IntVar(&grpcTLSPort, "grpc-tls-port", 0, "TLS gRPC port for credential-capable Agents (0=disabled)")
	flag.StringVar(&grpcTLSCert, "grpc-tls-cert", "", "Server certificate for the TLS Agent listener")
	flag.StringVar(&grpcTLSKey, "grpc-tls-key", "", "Server private key for the TLS Agent listener")
	flag.StringVar(&apiAddr, "api", ":8085", "HTTP API listen address")
	flag.StringVar(&configDir, "config-dir", "", "Path to the directory containing finger.yaml, dir.yaml, workflow.yaml, and pocs/")
	flag.StringVar(&agentPSK, "agent-psk", "", "Pre-shared key for Agent authentication (env: ARGUS_AGENT_PSK)")
	flag.StringVar(&deployMode, "deploy-mode", "", "Deployment mode: cloud (default) or intranet. env: ARGUS_DEPLOY_MODE overrides")
	flag.BoolVar(&devMode, "dev", false, "Enable development mode (skip mandatory security checks)")
	flag.StringVar(&seedFromDB, "seed-from-db", "", "Path to SQLite db file containing precompiled rule assets to seed into PostgreSQL and exit")
	flag.Parse()

	// 环境变量优先级高于 flag
	if envPSK := os.Getenv("ARGUS_AGENT_PSK"); envPSK != "" {
		agentPSK = envPSK
	}
	deployMode = strings.ToLower(strings.TrimSpace(deployMode))
	if envMode := strings.ToLower(strings.TrimSpace(os.Getenv("ARGUS_DEPLOY_MODE"))); envMode != "" {
		deployMode = envMode
	}
	if deployMode == "" {
		deployMode = "cloud"
	}
	if deployMode != "cloud" && deployMode != "intranet" {
		log.Fatalf("Invalid deploy mode %q: must be %q or %q", deployMode, "cloud", "intranet")
	}
	intranetMode := deployMode == "intranet"
	if intranetMode {
		log.Println("[Deploy] mode=intranet: cloud autoscaler/egress disabled; agents register actively")
	}
	if value := strings.TrimSpace(os.Getenv("ARGUS_GRPC_TLS_PORT")); value != "" {
		parsed, parseErr := strconv.Atoi(value)
		if parseErr != nil {
			log.Fatalf("Invalid ARGUS_GRPC_TLS_PORT: %v", parseErr)
		}
		grpcTLSPort = parsed
	}
	if value := strings.TrimSpace(os.Getenv("ARGUS_GRPC_TLS_CERT")); value != "" {
		grpcTLSCert = value
	}
	if value := strings.TrimSpace(os.Getenv("ARGUS_GRPC_TLS_KEY")); value != "" {
		grpcTLSKey = value
	}
	tlsConfigured := grpcTLSPort != 0 || grpcTLSCert != "" || grpcTLSKey != ""
	if tlsConfigured && (grpcTLSPort < 1 || grpcTLSPort > 65535 || grpcTLSCert == "" || grpcTLSKey == "") {
		log.Fatal("ARGUS_GRPC_TLS_PORT, ARGUS_GRPC_TLS_CERT and ARGUS_GRPC_TLS_KEY must be configured together")
	}
	if grpcTLSPort == grpcPort && grpcTLSPort != 0 {
		log.Fatal("Agent plaintext and TLS gRPC listeners must use different ports")
	}

	// 生产模式安全强制检查。
	// 规则资产导入场景不启动 API/gRPC，也不依赖运行期鉴权密钥。
	if !devMode && seedFromDB == "" {
		if agentPSK == "" {
			log.Fatalf("[SECURITY] ARGUS_AGENT_PSK is required in production mode. Use --dev to skip.")
		}
		if os.Getenv("ARGUS_JWT_SECRET") == "" {
			log.Fatalf("[SECURITY] ARGUS_JWT_SECRET is required in production mode. Use --dev to skip.")
		}
		// 云 egress 加密密钥仅云模式需要；内网模式无云调度链路
		if !intranetMode {
			if err := cloud.ValidateEncryptKeyEnv(); err != nil {
				log.Fatalf("[SECURITY] %v. Use --dev to skip.", err)
			}
		}
		if err := credentialvault.ValidateEnvironment(); err != nil {
			log.Fatalf("[SECURITY] %v. Use --dev to skip.", err)
		}
	}

	if strings.TrimSpace(dbDSN) == "" {
		log.Printf("No DSN provided, using default PostgreSQL DSN: %s", db.DefaultPostgresDSN)
	}

	// 启动期只做数据库校验（连接重试 + schema 版本 + 结构契约），不执行任何迁移。
	// 数据库初始化/升级由 deploy/db-init.sh（纯 SQL 导入）在部署阶段完成。
	dbConnectTimeout := 30 * time.Second
	if v := strings.TrimSpace(os.Getenv("ARGUS_DB_CONNECT_TIMEOUT")); v != "" {
		if parsed, parseErr := time.ParseDuration(v); parseErr != nil {
			log.Fatalf("Invalid ARGUS_DB_CONNECT_TIMEOUT: %v", parseErr)
		} else if parsed > 0 {
			dbConnectTimeout = parsed
		}
	}
	log.Println("Opening PostgreSQL database connection...")
	conn, err := db.OpenDBWithRetry(dbDSN, dbConnectTimeout)
	if err != nil {
		log.Fatalf("Failed to open PostgreSQL database: %v", err)
	}
	db.SetDB(conn)

	log.Printf("Verifying database schema (required version >= %s)...", db.RequiredSchemaVersion)
	if err := db.VerifyDatabaseReady(conn); err != nil {
		log.Fatalf("Database not ready: %v", err)
	}

	// Run rule catalog sync in background to avoid blocking startup.
	// The sync rebuilds structured rule tables from raw arsenal data.
	go func() {
		log.Println("Synchronizing rule catalog indexes (background)...")
		if err := db.SyncRuleCatalogFromArsenal(); err != nil {
			log.Printf("[RuleCatalog] background sync error: %v", err)
			return
		}
		log.Println("[RuleCatalog] background sync completed")
	}()

	if err := egresspkg.ReconcileStaleAudits(context.Background()); err != nil {
		log.Fatalf("Failed to reconcile EXP egress audits: %v", err)
	}
	expWorkspace, err := initializeEXPWorkspace(context.Background(), conn, devMode)
	if err != nil {
		log.Fatalf("Failed to initialize MinIO-backed EXP workspace: %v", err)
	}
	seededEXP, err := seedDevelopmentEXPWorkspace(context.Background(), expWorkspace, devMode)
	if err != nil {
		log.Fatalf("Failed to seed development EXP lab: %v", err)
	}
	for _, seeded := range seededEXP {
		log.Printf("Development EXP lab ready: %s revision=%d sha256=%s reused=%t", seeded.Name, seeded.Revision, seeded.SourceSHA256, seeded.Reused)
	}
	go expWorkspace.StartMaintenance(context.Background())

	if configDir == "" {
		if _, err := os.Stat("scanner/common/config"); err == nil {
			configDir = "scanner/common/config" // Running from project root
		} else {
			configDir = "../scanner/common/config" // Running from release/ or server/
		}
	}

	if seedFromDB != "" {
		log.Printf("Seeding rule catalog from precompiled database: %s", seedFromDB)
		if err := db.SeedArsenalFromSQLite(seedFromDB); err != nil {
			log.Fatalf("Failed to seed from DB: %v", err)
		}
		log.Println("Database seed completed successfully.")
		return
	}

	// Set up the Hub Broadcast Hook for batching to prevent websocket surge
	db.OnResultBatchSaved = func(count int, rType string) {
		api.Hub.Broadcast(map[string]interface{}{
			"type":  "scan_result_batch",
			"count": count,
			"rtype": rType,
		})
	}
	db.StartBatchWriters()

	log.Println("Initializing task queue...")
	queue := scheduler.NewTaskQueue(amqpURL)
	log.Printf("Task queue mode: %s", queue.Mode())

	log.Printf("Initializing gRPC server on :%d...", grpcPort)
	srv := grpc.NewServer(grpcPort)
	srv.SetPSK(agentPSK)
	if devMode {
		srv.SetAllowOpenPSK(true)
	}
	if grpcTLSPort != 0 {
		go func() {
			log.Printf("Initializing TLS Agent gRPC server on :%d...", grpcTLSPort)
			if err := srv.ServeTLS(grpcTLSPort, grpcTLSCert, grpcTLSKey); err != nil {
				log.Fatalf("Failed to serve TLS Agent gRPC: %v", err)
			}
		}()
	}

	// ---- 挂载 RabbitMQ 队列 Hooks ----

	// ClaimTask 优先消费本 Agent 的控制器推送队列（controller-push），
	// 为空再回退到共享队列（agent_claim 拉取模型）。
	srv.SetClaimTaskHook(func(agentID string) (*pb.Task, string, error) {
		if task, msgID, err := queue.TryPopAgentTask(context.Background(), agentID); err != nil {
			log.Printf("Error claiming routed task for %s: %v", agentID, err)
			return nil, "", err
		} else if task != nil {
			log.Printf("Agent %s claimed routed Task %s (MsgID: %s)", agentID, task.TaskId, msgID)
			return task, msgID, nil
		}
		task, msgID, err := queue.TryPopTask(context.Background(), agentID)
		if err != nil {
			log.Printf("Error claiming task for %s: %v", agentID, err)
			return nil, "", err
		}
		if task == nil {
			return &pb.Task{}, "", nil
		}
		log.Printf("Agent %s claimed Task %s (MsgID: %s)", agentID, task.TaskId, msgID)
		return task, msgID, nil
	})

	srv.SetAckTaskHook(func(msgID string) error {
		return queue.AckTask(context.Background(), msgID)
	})

	// 标签不匹配时退回任务：Nack + requeue（RabbitMQ 原生重新入队）
	srv.SetReturnTaskHook(func(task *pb.Task, msgID string) error {
		return queue.NackTask(context.Background(), msgID)
	})

	// 用于重试/拆分产生的全新任务（没有老 msgID）入队
	srv.SetRequeueTaskHook(func(task *pb.Task) error {
		return queue.PushTaskToFront(context.Background(), task)
	})

	// 队列深度查询 Hook（用于心跳响应和防饥饿通知）
	srv.SetQueueDepthHook(func() int32 {
		depths := queue.QueueDepth(context.Background())
		var total int64
		for _, d := range depths {
			total += d
		}
		return int32(total)
	})

	// ★ 将 gRPC Server 的 NotifyHub 暴露给 API 层
	// 当 createTask 完成入队后，API 层通过此引用广播通知所有在线 Agent
	routerDeps := api.NewRouterDependencies(queue, srv.Hub, agentPSK)
	routerDeps.EgressBroker = srv.Egress
	routerDeps.EXPWorkspace = expWorkspace
	// k8s 风格控制器推送调度：为 controller_push 子任务选择存活 Agent 并
	// 路由到其专属队列；agent_claim 任务仍走共享队列，不受影响。
	dispatchController := dispatch.NewController(db.DB, queue, srv.Hub)
	routerDeps.DispatchController = dispatchController
	srv.SetDispatchNotifyHook(dispatchController.Notify)

	publicBase := strings.TrimRight(strings.TrimSpace(os.Getenv("ARGUS_PUBLIC_URL")), "/")
	if publicBase == "" {
		_, port, splitErr := net.SplitHostPort(apiAddr)
		if splitErr != nil || strings.TrimSpace(port) == "" {
			port = "8085"
		}
		publicBase = "http://127.0.0.1:" + port
	}
	routerDeps.PublicBaseURL = publicBase
	api.ConfigureRouterDependencies(routerDeps)

	// Server 端被动子域收集：派发前统一收集并按域缓存，结果密封进任务配置。
	// worker 必须常开：ARGUS_SERVER_PASSIVE_SUBDOMAIN=off 时进入排空模式，
	// 立即释放已持有的域名批次（回退 Agent 端被动收集），避免批次滞留 Queued。
	passiveWorker := subdomainpassive.NewWorker(db.DB, subdomainpassive.NewCollector(), func(ctx context.Context, sub db.SubTask) error {
		if err := api.DispatchReleasedSubTask(ctx, queue, sub); err != nil {
			return err
		}
		if srv.Hub != nil {
			srv.Hub.BroadcastNewTask(1, int32(sub.Priority))
		}
		return nil
	})
	go passiveWorker.Run(context.Background())
	if subdomainpassive.Enabled() {
		log.Println("[PassiveSubdomain] server-side passive collection enabled")
	} else {
		log.Println("[PassiveSubdomain] disabled; hold drain mode active")
	}

	scanOrchestrator := api.NewScanStageOrchestrator()
	srv.SetOnTaskTerminalHook(scanOrchestrator.HandleAttemptTerminal)
	go func() {
		if err := scanOrchestrator.Reconcile(context.Background()); err != nil {
			log.Printf("[ScanStageOrchestrator] startup reconciliation failed: %v", err)
		}
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := scanOrchestrator.Reconcile(context.Background()); err != nil {
				log.Printf("[ScanStageOrchestrator] reconciliation failed: %v", err)
			}
		}
	}()

	// AI 误报研判 worker：周期扫描未研判漏洞，异步调用已配置的 LLM 复核并回写
	// 判定；不侵入结果上报链路，LLM 不可用时静默跳过等待下次重试。
	go ai.StartTriageWorker(context.Background(), db.DB, ai.TriageWorkerOptions{})

	// 扫描安全设备对抗哨兵：规则检测封禁/拦截 → AI 分类建议 → 策略门控执行。
	// 换节点重扫需 sentinel_auto_execute 或人工确认；退避/污点只收敛、默认自动。
	api.SetSentinelTaskPusher(sentinelPusher{queue: queue})
	go sentinel.StartSentinelWorker(context.Background(), db.DB, sentinel.WorkerOptions{
		Pusher: sentinelPusher{queue: queue},
	})

	// AI 内容分析 worker：研判主动爬取的"同主机不同站点"关联资产候选、批量提取敏感信息，
	// 并把 confirmed 候选回流为资产（protocol='crawl'）。LLM 未配置/不可用时静默跳过。
	go ai.StartContentAnalysisWorker(context.Background(), db.DB, ai.ContentWorkerOptions{})

	gatewayAddress := strings.TrimSpace(os.Getenv("ARGUS_EGRESS_GATEWAY_LISTEN"))
	gatewayToken := strings.TrimSpace(os.Getenv("ARGUS_EGRESS_GATEWAY_TOKEN"))
	if (gatewayAddress == "") != (gatewayToken == "") {
		log.Fatal("[SECURITY] ARGUS_EGRESS_GATEWAY_LISTEN and ARGUS_EGRESS_GATEWAY_TOKEN must be configured together")
	}
	if gatewayAddress != "" {
		gateway := &egresspkg.Gateway{Broker: srv.Egress, Token: gatewayToken}
		go func() {
			log.Printf("Yaksha egress gateway listening on %s", gatewayAddress)
			if err := gateway.Serve(gatewayAddress); err != nil {
				log.Fatalf("Yaksha egress gateway failed: %v", err)
			}
		}()
	}

	// 注册 UI 动画广播 Hook
	srv.SetOnTaskClaimedHook(func(agentID, taskID string) {
		if api.Hub != nil {
			api.Hub.Broadcast(map[string]interface{}{
				"type":     "task_claimed",
				"task_id":  taskID,
				"agent_id": agentID,
				"time":     time.Now().UnixMilli(),
			})
		}
	})

	// ====== 云资源动态调度（仅 cloud 模式） ======
	// 内网模式下不启动任何云调度组件：Agent 主动注册 + 心跳守护 + 分布式扫描照常工作。
	if !intranetMode {
		autoScaler := cloud.NewAutoScaler(conn, queue)

		// Cloud-Init 中注入给 Agent 的 Server 地址
		// 优先使用环境变量，确保云实例上的 Agent 能通过公网地址连接 Server
		cloudGRPCAddr, cloudAPIURL, err := buildCloudAdvertiseAddrs(
			grpcPort,
			apiAddr,
			os.Getenv("ARGUS_PUBLIC_IP"),
			os.Getenv("ARGUS_PUBLIC_API"),
			resolveOutboundHost,
		)
		if err != nil {
			log.Fatalf("[Cloud] failed to determine routable advertise endpoints: %v. Set ARGUS_PUBLIC_IP or ARGUS_PUBLIC_API explicitly.", err)
		}
		log.Printf("[Cloud] Using advertise endpoints for Cloud-Init: gRPC=%s API=%s", cloudGRPCAddr, cloudAPIURL)
		autoScaler.SetServerAddrs(cloudGRPCAddr, cloudAPIURL, agentPSK)
		routerDeps.Cloud = api.NewCloudHandler(conn, autoScaler)

		// 启动自动伸缩决策循环
		scalerCtx, scalerCancel := context.WithCancel(context.Background())
		defer scalerCancel()
		go autoScaler.Start(scalerCtx)
		go autoScaler.StartReconciler(scalerCtx, 5*time.Minute)
		go autoScaler.StartOrphanSweeper(scalerCtx, 10*time.Minute)
		log.Println("[Cloud] AutoScaler and background reconcilers started")
	} else {
		log.Println("[Deploy] mode=intranet: skipping cloud autoscaler, reconcilers and cloud API handler")
	}
	api.ConfigureRouterDependencies(routerDeps)

	// 挂载一个后台协程启动 API HTTP Server
	go func() {
		api.InitRouter(apiAddr, routerDeps)
	}()

	// 挂载节点离线状态判定协程（含任务回收）
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			var deadNodes []db.Node
			cutoff := time.Now().UnixMilli() - 60000
			db.DB.Where("status = ? AND last_beat < ?", "Alive", cutoff).Find(&deadNodes)
			for _, n := range deadNodes {
				if !shouldMarkAgentOffline(srv.Hub, n.AgentID) {
					log.Printf("[Heartbeat] Agent %s heartbeat is stale but subscribe stream is active; keeping Alive.", n.AgentID)
					continue
				}
				log.Printf("[Heartbeat] Agent %s marked as offline.", n.AgentID)
				db.DB.Model(&n).Updates(agentOfflineUpdates())

				// 回收该节点持有的 Running 任务：退回队列重新调度（与手动 drain 端点共用逻辑）
				api.RecycleNodeRunningTasks(context.Background(), n)

				// 云实例梯度容错等后续逻辑仍依赖 tenantID
				tenantID := strings.TrimSpace(n.TenantID)
				if tenantID == "" {
					tenantID = "default"
				}

				// ★ 若断线 Agent 对应的是一台云实例，执行梯度容错策略：
				//   重启次数 < 2  → 尝试 OS 级重启（保留机器，等 Agent 自动恢复）
				//   重启次数 >= 2 → 放弃治疗，直接销毁底层机器
				var cloudInst db.CloudInstance
				if err := db.DB.Where("tenant_id = ? AND agent_id = ? AND status IN ?", tenantID, n.AgentID, []string{
					db.CloudStatusRunning, db.CloudStatusWaitingReady, db.CloudStatusProvisioning,
				}).First(&cloudInst).Error; err == nil {
					const maxRebootAttempts = 2
					go func(inst db.CloudInstance) {
						var account db.CloudAccount
						if err := db.DB.Where("id = ? AND tenant_id = ?", inst.CloudAccountID, inst.TenantID).First(&account).Error; err != nil {
							log.Printf("[Heartbeat] Cannot load cloud account for instance %s: %v", inst.ID, err)
							return
						}
						provider, err := cloud.NewProviderFromAccount(&account)
						if err != nil {
							log.Printf("[Heartbeat] Cannot create provider for instance %s: %v", inst.ID, err)
							return
						}
						mgr := cloud.NewResourceManager(provider)
						mgr.SetDB(db.DB)

						if inst.RebootCount < maxRebootAttempts {
							log.Printf("[Heartbeat] Dead agent %s → cloud instance %s: attempting reboot (%d/%d)",
								n.AgentID, inst.ProviderInstanceID, inst.RebootCount+1, maxRebootAttempts)
							if err := mgr.RebootInstance(context.Background(), &inst); err != nil {
								log.Printf("[Heartbeat] Reboot failed, falling back to terminate: %v", err)
								_ = mgr.TerminateInstance(context.Background(), &inst)
							}
						} else {
							log.Printf("[Heartbeat] Dead agent %s → cloud instance %s: max reboots exhausted (%d), terminating",
								n.AgentID, inst.ProviderInstanceID, inst.RebootCount)
							if err := mgr.TerminateInstance(context.Background(), &inst); err != nil {
								log.Printf("[Heartbeat] Failed to terminate cloud instance %s: %v", inst.ID, err)
							} else {
								log.Printf("[Heartbeat] Cloud instance %s terminated successfully", inst.ID)
							}
						}
					}(cloudInst)
				}
			}

			// 自动清理长时间离线的节点（10分钟无心跳直接从数据库删除，避免大屏和数据库堆积）
			cleanCutoff := time.Now().UnixMilli() - 600000 // 10分钟
			res := db.DB.Where("status = ? AND last_beat < ?", "Offline", cleanCutoff).Delete(&db.Node{})
			if res.RowsAffected > 0 {
				log.Printf("[Heartbeat] Auto-cleaned %d long-offline agents.", res.RowsAffected)
			}
		}
	}()

	// 超时 + 重试守护协程
	go routerDeps.TaskRecovery.Run(context.Background())
	go routerDeps.AgentLogRetention.Run(context.Background())
	// 控制器推送调度协程：周期对账 + 入队信号触发
	go dispatchController.Run(context.Background())

	// 初始化规则版本号（如果尚未设置）
	if api.GetCurrentRuleVersion() == "" {
		ver := api.BumpRuleVersion()
		log.Printf("[Init] Initial rule version set to %s", ver)
	}

	if err := srv.Serve(); err != nil {
		log.Fatalf("Failed to serve gRPC: %v", err)
	}
}
