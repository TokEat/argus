package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-server/internal/api"
	"github.com/user/dddd-server/internal/cloud"
	_ "github.com/user/dddd-server/internal/cloud/aliyun" // 注册阿里云 ECS Provider
	"github.com/user/dddd-server/internal/db"
	"github.com/user/dddd-server/internal/grpc"
	"github.com/user/dddd-server/internal/scheduler"
)

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

func main() {
	var (
		dbDSN           string
		amqpURL         string
		grpcPort        int
		apiAddr         string
		configDir       string
		agentPSK        string
		devMode         bool
		migrateOnly     bool
		dbMigrationMode string
	)

	flag.StringVar(&dbDSN, "db", "", "PostgreSQL DSN. Empty uses the built-in local PostgreSQL default.")
	flag.StringVar(&amqpURL, "amqp", "amqp://guest:guest@localhost:5672/", "RabbitMQ AMQP URL. Empty falls back to in-memory queue")
	flag.IntVar(&grpcPort, "grpc", 50051, "gRPC listen port")
	flag.StringVar(&apiAddr, "api", ":8085", "HTTP API listen address")
	flag.StringVar(&configDir, "config-dir", "", "Path to the directory containing finger.yaml, dir.yaml, workflow.yaml, and pocs/")
	flag.StringVar(&agentPSK, "agent-psk", "", "Pre-shared key for Agent authentication (env: ARGUS_AGENT_PSK)")
	flag.BoolVar(&devMode, "dev", false, "Enable development mode (skip mandatory security checks)")
	flag.BoolVar(&migrateOnly, "migrate-only", false, "Apply/verify PostgreSQL schema and exit without starting services")
	flag.StringVar(&dbMigrationMode, "db-migration-mode", string(db.MigrationModeApply), "Database migration mode: apply|verify|dev-auto")
	flag.Parse()

	// 环境变量优先级高于 flag
	if envPSK := os.Getenv("ARGUS_AGENT_PSK"); envPSK != "" {
		agentPSK = envPSK
	}

	// 生产模式安全强制检查。
	// 数据库初始化/迁移场景不需要启动 API/gRPC，也不依赖运行期鉴权密钥。
	if !devMode && !migrateOnly {
		if agentPSK == "" {
			log.Fatalf("[SECURITY] ARGUS_AGENT_PSK is required in production mode. Use --dev to skip.")
		}
		if os.Getenv("ARGUS_JWT_SECRET") == "" {
			log.Fatalf("[SECURITY] ARGUS_JWT_SECRET is required in production mode. Use --dev to skip.")
		}
	}

	migrationMode, err := db.ParseMigrationMode(dbMigrationMode)
	if err != nil {
		log.Fatalf("Invalid db migration mode: %v", err)
	}
	if migrationMode == db.MigrationModeDevAuto && !devMode {
		log.Fatalf("db migration mode 'dev-auto' requires --dev")
	}

	if strings.TrimSpace(dbDSN) == "" {
		log.Printf("No DSN provided, using default PostgreSQL DSN: %s", db.DefaultPostgresDSN)
	}

	log.Println("Opening PostgreSQL database connection...")
	conn, err := db.OpenDB(dbDSN)
	if err != nil {
		log.Fatalf("Failed to open PostgreSQL database: %v", err)
	}
	db.SetDB(conn)

	log.Printf("Applying database migrations (mode=%s)...", migrationMode)
	if err := db.ApplyMigrations(conn, migrationMode); err != nil {
		log.Fatalf("Failed to apply database migrations: %v", err)
	}

	log.Println("Verifying database schema...")
	if err := db.VerifySchema(conn); err != nil {
		log.Fatalf("Failed to verify database schema: %v", err)
	}

	if migrateOnly {
		log.Println("Database migrations and schema verification completed successfully.")
		return
	}

	if configDir == "" {
		if _, err := os.Stat("scanner/common/config"); err == nil {
			configDir = "scanner/common/config" // Running from project root
		} else {
			configDir = "../scanner/common/config" // Running from release/ or server/
		}
	}

	// 启动时确保规则原始文件仓库与结构化规则目录都已初始化到 PostgreSQL。
	if err := db.BootstrapRuleCatalog(configDir); err != nil {
		log.Fatalf("Failed to bootstrap rule catalog from %s: %v", configDir, err)
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
	api.SetTaskQueue(queue)
	api.SetAgentPSK(agentPSK)
	api.SetDevelopmentMode(devMode)
	log.Printf("Task queue mode: %s", queue.Mode())

	log.Printf("Initializing gRPC server on :%d...", grpcPort)
	srv := grpc.NewServer(grpcPort)
	srv.SetPSK(agentPSK)

	// ---- 挂载 RabbitMQ 队列 Hooks ----

	// ClaimTask 使用 TryPopTask（完全非阻塞，即时返回）
	srv.SetClaimTaskHook(func(agentID string) (*pb.Task, string, error) {
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

	// FetchTask 兼容旧版 Agent：保留阻塞等待（最多 1 秒）
	srv.SetFetchTaskHook(func(agentID string) (*pb.Task, string, error) {
		task, msgID, err := queue.PopTask(context.Background(), agentID)
		if err != nil {
			log.Printf("Error popping task for %s: %v", agentID, err)
			return nil, "", err
		}
		if task == nil {
			return &pb.Task{}, "", nil
		}
		log.Printf("Assigned Task %s (MsgID: %s) to Agent %s", task.TaskId, msgID, agentID)
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
	api.SetNotifyHub(srv.Hub)

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

	// ====== 云资源动态调度 ======
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
	api.SetAutoScaler(autoScaler)

	// 启动自动伸缩决策循环
	scalerCtx, scalerCancel := context.WithCancel(context.Background())
	defer scalerCancel()
	go autoScaler.Start(scalerCtx)
	go autoScaler.StartReconciler(scalerCtx, 5*time.Minute)
	go autoScaler.StartOrphanSweeper(scalerCtx, 10*time.Minute)
	log.Println("[Cloud] AutoScaler and background reconcilers started")

	// 挂载一个后台协程启动 API HTTP Server
	go func() {
		api.InitRouter(apiAddr)
	}()

	// 挂载节点离线状态判定协程（含任务回收）
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			var deadNodes []db.Node
			cutoff := time.Now().UnixMilli() - 60000
			db.DB.Where("status = ? AND last_beat < ?", "Alive", cutoff).Find(&deadNodes)
			for _, n := range deadNodes {
				log.Printf("[Heartbeat] Agent %s marked as offline.", n.AgentID)
				db.DB.Model(&n).Updates(map[string]interface{}{
					"status":        "Offline",
					"running_tasks": 0,
				})

				// 回收该节点持有的 Running 任务：退回队列重新调度
				var orphanTasks []db.SubTask
				db.DB.Where("agent_id = ? AND status IN ?", n.AgentID, []string{"Running", "CancelPending"}).Find(&orphanTasks)
				for _, sub := range orphanTasks {
					// ACK 掉旧的 MQ 消息（如果还在）
					if sub.StreamMsgID != "" {
						_ = queue.AckTask(context.Background(), sub.StreamMsgID)
					}

					nextStatus := "Dispatching"
					if db.NormalizeSubTaskStatus(sub.Status) == "CANCELPENDING" {
						nextStatus = "Cancelled"
					}

					db.DB.Model(&db.SubTask{}).Where("id = ?", sub.ID).Updates(map[string]interface{}{
						"status":        nextStatus,
						"agent_id":      "",
						"stream_msg_id": "",
					})

					// Running 任务重新入队
					if nextStatus == "Dispatching" {
						pbTask, err := db.SubTaskToProto(&sub)
						if err == nil && pbTask != nil {
							if pushErr := queue.PushTaskToFront(context.Background(), pbTask); pushErr == nil {
								db.DB.Model(&db.SubTask{}).Where("id = ? AND status = ?", sub.ID, "Dispatching").
									Update("status", "Pending")
							}
						}
					}

					if sub.RootTaskID != "" {
						db.RefreshRootTaskStatus(sub.RootTaskID)
					}
					log.Printf("[DeadNode] Recovered subtask %s from dead agent %s → %s", sub.ID, n.AgentID, nextStatus)
				}

				// 回收后通知在线 Agent
				if len(orphanTasks) > 0 {
					srv.Hub.BroadcastNewTask(int32(len(orphanTasks)), 0)
				}

				// ★ 若断线 Agent 对应的是一台云实例，执行梯度容错策略：
				//   重启次数 < 2  → 尝试 OS 级重启（保留机器，等 Agent 自动恢复）
				//   重启次数 >= 2 → 放弃治疗，直接销毁底层机器
				var cloudInst db.CloudInstance
				if err := db.DB.Where("agent_id = ? AND status IN ?", n.AgentID, []string{
					db.CloudStatusRunning, db.CloudStatusWaitingReady, db.CloudStatusProvisioning,
				}).First(&cloudInst).Error; err == nil {
					const maxRebootAttempts = 2
					go func(inst db.CloudInstance) {
						var account db.CloudAccount
						if err := db.DB.First(&account, "id = ?", inst.CloudAccountID).Error; err != nil {
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
	go api.StartTaskTimeoutDaemon(context.Background(), queue)

	// 初始化规则版本号（如果尚未设置）
	if api.GetCurrentRuleVersion() == "" {
		ver := api.BumpRuleVersion()
		log.Printf("[Init] Initial rule version set to %s", ver)
	}

	if err := srv.Serve(); err != nil {
		log.Fatalf("Failed to serve gRPC: %v", err)
	}
}
