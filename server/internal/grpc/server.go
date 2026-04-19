package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-server/internal/db"
	"google.golang.org/grpc"
)

// Server 封装了对 Agent 通信的 gRPC 服务端
type Server struct {
	pb.UnimplementedAgentServiceServer
	port int
	// queue 负责从 redis 等调度队列获取任务，当前暂用回调解耦
	fetchTaskHook func(agentID string) (*pb.Task, string, error)
	ackTaskHook   func(msgID string) error
}

// NewServer 初始化 gRPC Server
func NewServer(port int) *Server {
	return &Server{
		port: port,
	}
}

// SetFetchTaskHook 注入从队列拉取任务的钩子
func (s *Server) SetFetchTaskHook(fn func(agentID string) (*pb.Task, string, error)) {
	s.fetchTaskHook = fn
}

// SetAckTaskHook 注入完成任务后确认的钩子
func (s *Server) SetAckTaskHook(fn func(msgID string) error) {
	s.ackTaskHook = fn
}

// Serve 启动 gRPC 监听
func (s *Server) Serve() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAgentServiceServer(grpcServer, s)

	log.Printf("gRPC server listening at %v", lis.Addr())
	return grpcServer.Serve(lis)
}

// Register 节点上线注册
func (s *Server) Register(ctx context.Context, req *pb.RegisterReq) (*pb.RegisterResp, error) {
	log.Printf("[Register] Agent %s connected, version: %s", req.AgentId, req.Version)

	// 序列化 tags
	tagsJSON := "{}"
	if len(req.Tags) > 0 {
		if data, err := json.Marshal(req.Tags); err == nil {
			tagsJSON = string(data)
		}
	}

	// 持久化落地 — 保存完整节点信息
	db.DB.Save(&db.Node{
		AgentID:      req.AgentId,
		Status:       "Alive",
		Version:      req.Version,
		Tags:         tagsJSON,
		Capacity:     1, // 默认容量，Agent 可通过心跳上报真实值
		RunningTasks: 0,
		LastBeat:     time.Now().UnixMilli(),
	})

	return &pb.RegisterResp{
		Success: true,
		Token:   "dummy_token_" + req.AgentId,
	}, nil
}

func (s *Server) Heartbeat(ctx context.Context, req *pb.HeartbeatReq) (*pb.HeartbeatResp, error) {
	// 从 DB 直接计算节点当前运行中的任务数
	var running int64
	db.DB.Model(&db.SubTask{}).Where("agent_id = ? AND status = ?", req.AgentId, "Running").Count(&running)

	// 更新节点状态（包含规则版本）
	updates := map[string]interface{}{
		"status":        "Alive",
		"last_beat":     time.Now().UnixMilli(),
		"running_tasks": int(running),
	}
	// 如果 Agent 上报了规则版本，保存到 Node
	if req.RuleVersion != "" {
		updates["rule_version"] = req.RuleVersion
	}
	_ = db.DB.Model(&db.Node{}).Where("agent_id = ?", req.AgentId).Updates(updates).Error

	// 检查是否需要同步规则（通过版本号对比，替代 HTTP 轮询）
	shouldSync := false
	var cfg db.SystemConfig
	if db.DB.Where("key = ?", "rule_version").First(&cfg).Error == nil {
		if req.RuleVersion != "" && req.RuleVersion != cfg.Value {
			shouldSync = true
		}
	}

	return &pb.HeartbeatResp{
		Ack:             true,
		ShouldTerminate: false,
		ShouldSyncRules: shouldSync,
	}, nil
}

func (s *Server) FetchTask(ctx context.Context, req *pb.FetchTaskReq) (*pb.Task, error) {
	// P0: 容量检查 — 节点超载时不分配任务
	var node db.Node
	if db.DB.Where("agent_id = ?", req.AgentId).First(&node).Error == nil {
		if node.Capacity > 0 && node.RunningTasks >= node.Capacity {
			log.Printf("[FetchTask] Agent %s at capacity (%d/%d), skipping", req.AgentId, node.RunningTasks, node.Capacity)
			return &pb.Task{}, nil
		}
	}

	var task *pb.Task
	var msgID string
	var err error
	if s.fetchTaskHook != nil {
		task, msgID, err = s.fetchTaskHook(req.AgentId)
	}
	if task != nil && task.TaskId != "" {
		// 记录流转：状态变为执行中，挂载关联代理人和流的消息位点
		db.DB.Model(&db.SubTask{}).Where("id = ?", task.TaskId).
			Updates(map[string]interface{}{
				"status":        "Running",
				"agent_id":      req.AgentId,
				"stream_msg_id": msgID,
			})
		// 更新节点 running_tasks 计数
		db.DB.Exec("UPDATE nodes SET running_tasks = running_tasks + 1 WHERE agent_id = ?", req.AgentId)

		// 如果 RootTask 还在 Queued，更新为 Running
		var sub db.SubTask
		if db.DB.First(&sub, "id = ?", task.TaskId).Error == nil {
			db.DB.Model(&db.RootTask{}).Where("id = ? AND status = ?", sub.RootTaskID, "Queued").
				Update("status", "Running")
		}
	} else if task == nil {
		task = &pb.Task{}
	}
	return task, err
}

// StreamResult 流式接收客户端回传的结果
func (s *Server) StreamResult(stream pb.AgentService_StreamResultServer) error {
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.Ack{Success: true, Message: "EOF"})
		}
		if err != nil {
			return err
		}
		// 异步推入分层缓冲池 (Data Surge Protection & Structured Storage)
		db.AddResultAsync(res.TaskId, res.PayloadType, string(res.Payload))
	}
}

// TaskComplete 任务完成通知
func (s *Server) TaskComplete(ctx context.Context, req *pb.TaskCompleteReq) (*pb.Ack, error) {
	log.Printf("[TaskComplete] SubTask %s by Agent %s => Status: %s", req.TaskId, req.AgentId, req.Status)
	db.DB.Model(&db.SubTask{}).Where("id = ?", req.TaskId).Update("status", req.Status)

	// 递减节点 running_tasks
	db.DB.Exec("UPDATE nodes SET running_tasks = GREATEST(running_tasks - 1, 0) WHERE agent_id = ?", req.AgentId)

	if req.Status == "DONE" {
		var sub db.SubTask
		if err := db.DB.First(&sub, "id = ?", req.TaskId).Error; err == nil {
			// 一旦数据库判定找得到，立刻上报 Redis Stream 消费组进行 ACK
			if s.ackTaskHook != nil && sub.StreamMsgID != "" {
				_ = s.ackTaskHook(sub.StreamMsgID)
			}
			if sub.RootTaskID != "" {
				// 利用 PG 的原子更新
				db.DB.Exec("UPDATE root_tasks SET completed_chunks = completed_chunks + 1 WHERE id = ?", sub.RootTaskID)

				var root db.RootTask
				if err := db.DB.First(&root, "id = ?", sub.RootTaskID).Error; err == nil {
					if root.CompletedChunks >= root.TotalChunks {
						db.DB.Model(&root).Update("status", "FINISHED")
						log.Printf("[Aggregation] RootTask %s is fully completed! (%d/%d chunks)", root.ID, root.CompletedChunks, root.TotalChunks)
					} else if root.CompletedChunks > 0 && root.CompletedChunks < root.TotalChunks {
						// 部分完成状态
						if root.Status == "Running" {
							db.DB.Model(&root).Update("status", "PartialDone")
						}
					}
				}
			}
		}
	}

	return &pb.Ack{Success: true}, nil
}

// EmergencyDump 紧急数据下刷（处理 Spot 回收）
func (s *Server) EmergencyDump(ctx context.Context, req *pb.EmergencyReq) (*pb.Ack, error) {
	log.Printf("[EmergencyDump] Agent %s is flushing all local states due to Spot termination signal!", req.AgentId)
	return &pb.Ack{Success: true, Message: "Safe drop signal received"}, nil
}

// StreamLogs 遥测日志黑匣子上传通道
func (s *Server) StreamLogs(stream pb.AgentService_StreamLogsServer) error {
	for {
		payload, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.Ack{Success: true})
		}
		if err != nil {
			return err
		}

		// 异步写入数据库
		db.DB.Create(&db.AgentLog{
			AgentID:   payload.AgentId,
			Level:     payload.Level,
			Message:   payload.Message,
			Timestamp: payload.Timestamp,
		})

		log.Printf("[Telemetry][Agent %s][%s] %s", payload.AgentId, payload.Level, payload.Message)
	}
}

