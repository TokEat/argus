package main

import (
	"context"
	"flag"
	"log"
	"time"

	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-server/internal/api"
	"github.com/user/dddd-server/internal/db"
	"github.com/user/dddd-server/internal/grpc"
	"github.com/user/dddd-server/internal/scheduler"
)

func main() {
	var (
		dbDSN         string
		redisAddr     string
		redisPassword string
		redisDB       int
		grpcPort      int
		apiAddr       string
	)

	flag.StringVar(&dbDSN, "db", "", "Database DSN. Empty uses local SQLite data/dddd.db")
	flag.StringVar(&redisAddr, "redis", "", "Redis address. Empty or unreachable falls back to in-memory queue")
	flag.StringVar(&redisPassword, "redis-password", "", "Redis password")
	flag.IntVar(&redisDB, "redis-db", 0, "Redis database index")
	flag.IntVar(&grpcPort, "grpc", 50051, "gRPC listen port")
	flag.StringVar(&apiAddr, "api", ":8085", "HTTP API listen address")
	flag.Parse()

	log.Println("Initializing database...")
	db.InitDB(dbDSN)

	// 首次启动时，从 scanner/common/config/ 导入 POC/指纹/Workflow 到 PostgreSQL
	db.SeedArsenalFromDisk("scanner/common/config")

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
	queue := scheduler.NewTaskQueue(redisAddr, redisPassword, redisDB)
	api.SetTaskQueue(queue)
	log.Printf("Task queue mode: %s", queue.Mode())

	log.Printf("Initializing gRPC server on :%d...", grpcPort)
	srv := grpc.NewServer(grpcPort)

	// 将 queue 的 pop 能力作为 hook 挂载给 gRPC Server
	srv.SetFetchTaskHook(func(agentID string) (*pb.Task, string, error) {
		task, msgID, err := queue.PopTask(context.Background(), agentID)
		if err != nil {
			log.Printf("Error popping task from stream for %s: %v", agentID, err)
			return nil, "", err
		}
		if task == nil {
			// 返回空的代表没任务
			return &pb.Task{}, "", nil
		}
		log.Printf("Assigned Task %s (StreamMsg: %s) to Agent %s", task.TaskId, msgID, agentID)
		return task, msgID, nil
	})

	srv.SetAckTaskHook(func(msgID string) error {
		return queue.AckTask(context.Background(), msgID)
	})

	// 挂载一个后台协程启动 API HTTP Server
	go func() {
		api.InitRouter(apiAddr)
	}()

	// 挂载一个死亡节点扫雷与任务抢救协程
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			var deadNodes []db.Node
			// 60秒收不到心跳即判定为掉线
			cutoff := time.Now().UnixMilli() - 60000
			db.DB.Where("status = ? AND last_beat < ?", "Alive", cutoff).Find(&deadNodes)
			for _, n := range deadNodes {
				log.Printf("[Sweep] Agent %s died.", n.AgentID)
				db.DB.Model(&n).Updates(map[string]interface{}{
					"status":        "Offline",
					"running_tasks": 0,
				})

				var zombieTasks []db.SubTask
				db.DB.Where("agent_id = ? AND status = ?", n.AgentID, "Running").Find(&zombieTasks)
				for _, z := range zombieTasks {
					log.Printf("[Recovery] Zombie SubTask %s recovered from dead agent %s! Pushing to queue front...", z.ID, n.AgentID)
					db.DB.Model(&z).Updates(map[string]interface{}{
						"status":   "Pending",
						"agent_id": "",
					})
					pbTask, err := db.SubTaskToProto(&z)
					if err != nil {
						log.Printf("[Recovery] Failed to rebuild subtask %s: %v", z.ID, err)
						continue
					}
					_ = queue.PushTaskToFront(context.Background(), pbTask)
				}
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

