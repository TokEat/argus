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

	log.Println("Initializing task queue...")
	queue := scheduler.NewTaskQueue(redisAddr, redisPassword, redisDB)
	api.SetTaskQueue(queue)
	log.Printf("Task queue mode: %s", queue.Mode())

	log.Printf("Initializing gRPC server on :%d...", grpcPort)
	srv := grpc.NewServer(grpcPort)

	// 将 queue 的 pop 能力作为 hook 挂载给 gRPC Server
	srv.SetFetchTaskHook(func(agentID string) (*pb.Task, error) {
		task, err := queue.PopTask(context.Background())
		if err != nil {
			log.Printf("Error popping task for %s: %v", agentID, err)
			return nil, err
		}
		if task == nil {
			// 返回空的代表没任务
			return &pb.Task{}, nil
		}
		log.Printf("Assigned Task %s to Agent %s", task.TaskId, agentID)
		return task, nil
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
				db.DB.Model(&n).Update("status", "Offline")

				var zombieTasks []db.Task
				db.DB.Where("agent_id = ? AND status = ?", n.AgentID, "Running").Find(&zombieTasks)
				for _, z := range zombieTasks {
					log.Printf("[Recovery] Zombie Task %s recovered from dead agent %s! Pushing to queue front...", z.ID, n.AgentID)
					db.DB.Model(&z).Updates(map[string]interface{}{
						"status":   "Pending",
						"agent_id": "",
					})
					pbTask, err := db.TaskToProto(&z)
					if err != nil {
						log.Printf("[Recovery] Failed to rebuild task %s: %v", z.ID, err)
						continue
					}
					_ = queue.PushTaskToFront(context.Background(), pbTask)
				}
			}
		}
	}()

	if err := srv.Serve(); err != nil {
		log.Fatalf("Failed to serve gRPC: %v", err)
	}
}
