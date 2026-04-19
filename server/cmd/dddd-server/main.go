package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-server/internal/api"
	"github.com/user/dddd-server/internal/db"
	"github.com/user/dddd-server/internal/grpc"
	"github.com/user/dddd-server/internal/scheduler"
)

func main() {
	var (
		dbDSN    string
		amqpURL  string
		grpcPort int
		apiAddr  string
		configDir string
	)

	flag.StringVar(&dbDSN, "db", "", "Database DSN. Empty uses local SQLite data/dddd.db")
	flag.StringVar(&amqpURL, "amqp", "amqp://guest:guest@localhost:5672/", "RabbitMQ AMQP URL. Empty falls back to in-memory queue")
	flag.IntVar(&grpcPort, "grpc", 50051, "gRPC listen port")
	flag.StringVar(&apiAddr, "api", ":8085", "HTTP API listen address")
	flag.StringVar(&configDir, "config-dir", "", "Path to the directory containing finger.yaml, dir.yaml, workflow.yaml, and pocs/")
	flag.Parse()

	log.Println("Initializing database...")
	db.InitDB(dbDSN)

	if configDir == "" {
		if _, err := os.Stat("scanner/common/config"); err == nil {
			configDir = "scanner/common/config" // Running from project root
		} else {
			configDir = "../scanner/common/config" // Running from release/ or server/
		}
	}

	// 启动时确保规则原始文件仓库与结构化规则目录都已初始化到 PostgreSQL。
	if err := db.BootstrapRuleCatalog(configDir); err != nil {
		log.Printf("Warning: Failed to bootstrap rule catalog from %s: %v", configDir, err)
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
	log.Printf("Task queue mode: %s", queue.Mode())

	log.Printf("Initializing gRPC server on :%d...", grpcPort)
	srv := grpc.NewServer(grpcPort)

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
		log.Printf("Assigned Task %s (StreamMsg: %s) to Agent %s", task.TaskId, msgID, agentID)
		return task, msgID, nil
	})

	srv.SetAckTaskHook(func(msgID string) error {
		return queue.AckTask(context.Background(), msgID)
	})

	// 标签不匹配时退回任务：Nack + requeue（RabbitMQ 原生重新入队）
	srv.SetReturnTaskHook(func(task *pb.Task, msgID string) error {
		return queue.NackTask(context.Background(), msgID)
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

	// 挂载一个后台协程启动 API HTTP Server
	go func() {
		api.InitRouter(apiAddr)
	}()

	// 挂载节点离线状态判定协程
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
