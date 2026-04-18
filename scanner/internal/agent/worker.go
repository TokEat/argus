package agent

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"dddd/scanner/internal/engine"
	pb "github.com/user/dddd-proto/go/scan"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Worker 是扫描节点的核心
type Worker struct {
	agentID    string
	serverAddr string
	apiURL     string
	client     pb.AgentServiceClient
	conn       *grpc.ClientConn
	wg         sync.WaitGroup // 跟踪并发任务
}

func NewWorker(agentID, serverAddr, apiURL string) *Worker {
	return &Worker{
		agentID:    agentID,
		serverAddr: serverAddr,
		apiURL:     apiURL,
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
	_, err = w.client.Register(context.Background(), &pb.RegisterReq{
		AgentId: w.agentID,
		Version: "v2.0.1",
	})
	if err != nil {
		return err
	}
	log.Printf("Agent %s successfully registered to %s", w.agentID, w.serverAddr)

	// 开机同步热更新规则库 (Arsenal)
	w.syncRules()

	// 后台心跳维持
	go w.heartbeatLoop()

	// Phase 1: 每个 agent 同一时刻只执行一个任务，进程内不做多任务并发。
	maxWorkers := 1
	sem := make(chan struct{}, maxWorkers)

	// 信号劫持
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	quit := make(chan struct{})

	go func() {
		<-sigCh
		log.Println("Received termination signal, waiting for running tasks to drain...")
		close(quit)
	}()

	log.Printf("Agent started with worker pool size: %d", maxWorkers)

	// 2. 轮询领取任务
	for {
		select {
		case <-quit:
			w.wg.Wait()
			log.Println("All tasks finished. Shutting down agent.")
			return nil
		default:
		}

		// 阻塞等待资源额度
		sem <- struct{}{}

		task, err := w.client.FetchTask(context.Background(), &pb.FetchTaskReq{
			AgentId: w.agentID,
		})

		if err != nil {
			log.Printf("FetchTask error (will retry): %v", err)
			<-sem // 释放
			time.Sleep(5 * time.Second)
			continue
		}

		if task.TaskId == "" {
			// 没有任务，闲置等待
			<-sem // 释放
			time.Sleep(3 * time.Second)
			continue
		}

		// 协程派发任务
		w.wg.Add(1)
		go func(t *pb.Task) {
			defer w.wg.Done()
			defer func() { <-sem }() // 执行完毕释放 quota
			w.executeTask(t)
		}(task)
	}
}

func (w *Worker) heartbeatLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if w.client != nil {
			_, err := w.client.Heartbeat(context.Background(), &pb.HeartbeatReq{
				AgentId: w.agentID,
				Status:  "Alive",
			})
			if err != nil {
				log.Printf("Heartbeat failure: %v", err)
			}
		}
	}
}

func (w *Worker) syncRules() {
	log.Println("[Sync] Requesting Arsenal rules from API...")

	// 拉取 POC
	resp, err := http.Get(w.apiURL + "/api/v1/arsenals/poc")
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var rules []struct {
			FileName string `json:"FileName"`
			Content  string `json:"Content"`
		}
		if json.Unmarshal(body, &rules) == nil {
			if len(rules) > 0 {
				_ = os.MkdirAll("config/pocs", 0755)
				for _, r := range rules {
					path := filepath.Join("config/pocs", r.FileName)
					_ = os.WriteFile(path, []byte(r.Content), 0644)
					log.Printf("[Sync] Reloaded POC -> %s", path)
				}
			}
		}
	} else {
		log.Printf("[Sync] Failed to reach API for POCs: %v", err)
	}

	// （可视情况扩展对 finger.yaml 的同步覆盖逻辑...）
}

func (w *Worker) executeTask(task *pb.Task) {
	log.Printf("Received Task: %s with targets: %v", task.TaskId, task.Targets)

	// 解析配置
	var cfg engine.Config
	if len(task.Config) > 0 {
		_ = json.Unmarshal(task.Config, &cfg)
	}
	// 强制覆盖 target 为下发的 target
	cfg.Targets = task.Targets
	cfg.OutputFile = ""
	cfg.ReportName = ""

	// 初始化上下文
	ctx, err := engine.NewScanContext(cfg)
	if err != nil {
		log.Printf("Failed to initialize scan context for task %s: %v", task.TaskId, err)
		_, _ = w.client.TaskComplete(context.Background(), &pb.TaskCompleteReq{
			AgentId:      w.agentID,
			TaskId:       task.TaskId,
			Status:       "FAILED",
			ErrorMessage: err.Error(),
		})
		return
	}
	defer ctx.Reset()
	defer ctx.Close()
	ctx.TaskID = task.TaskId

	// 挂载 OutputHook 进行 gRPC Stream 实时回传 (Task 1.7)
	stream, err := w.client.StreamResult(context.Background())
	if err == nil {
		ctx.OutputHook = func(msg engine.OutputMessage) {
			payload, _ := json.Marshal(msg)
			_ = stream.Send(&pb.ScanResult{
				TaskId:      task.TaskId,
				PayloadType: msg.Type,
				Payload:     payload,
				Timestamp:   time.Now().UnixMilli(),
			})
		}
	} else {
		log.Printf("Failed to open grpc stream: %v", err)
	}

	// 启动引擎
	log.Printf("Starting Pipeline for Task %s...", task.TaskId)
	runErr := engine.RunTask(ctx)

	if stream != nil {
		_, _ = stream.CloseAndRecv()
	}
	if runErr != nil {
		log.Printf("Pipeline failed for Task %s: %v", task.TaskId, runErr)
		_, _ = w.client.TaskComplete(context.Background(), &pb.TaskCompleteReq{
			AgentId:      w.agentID,
			TaskId:       task.TaskId,
			Status:       "FAILED",
			ErrorMessage: runErr.Error(),
		})
		return
	}
	log.Printf("Finished Pipeline for Task %s.", task.TaskId)

	// 回传任务完成
	_, _ = w.client.TaskComplete(context.Background(), &pb.TaskCompleteReq{
		AgentId: w.agentID,
		TaskId:  task.TaskId,
		Status:  "DONE",
	})
}
