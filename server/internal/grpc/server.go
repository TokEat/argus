package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-server/internal/db"
	"google.golang.org/grpc"
)

// Server 封装了对 Agent 通信的 gRPC 服务端
type Server struct {
	pb.UnimplementedAgentServiceServer
	port int

	// NotifyHub 管理所有在线 Agent 的 Subscribe 流连接
	Hub *NotifyHub

	// queue hooks — 通过回调与 Redis 队列解耦
	claimTaskHook  func(agentID string) (*pb.Task, string, error)   // 原子认领
	fetchTaskHook  func(agentID string) (*pb.Task, string, error)   // 兼容旧版
	ackTaskHook    func(msgID string) error                         // ACK 确认
	returnTaskHook func(task *pb.Task, msgID string) error          // 退回队列
	queueDepthHook func() int32                                     // 获取队列深度
	onTaskClaimedHook func(agentID, taskID string)                  // UI 广播 Hook
}

// NewServer 初始化 gRPC Server
func NewServer(port int) *Server {
	return &Server{
		port: port,
		Hub:  NewNotifyHub(),
	}
}

// ---- Hook 注入接口 ----

func (s *Server) SetClaimTaskHook(fn func(agentID string) (*pb.Task, string, error)) {
	s.claimTaskHook = fn
}

func (s *Server) SetFetchTaskHook(fn func(agentID string) (*pb.Task, string, error)) {
	s.fetchTaskHook = fn
}

func (s *Server) SetAckTaskHook(fn func(msgID string) error) {
	s.ackTaskHook = fn
}

func (s *Server) SetReturnTaskHook(fn func(task *pb.Task, msgID string) error) {
	s.returnTaskHook = fn
}

func (s *Server) SetQueueDepthHook(fn func() int32) {
	s.queueDepthHook = fn
}

func (s *Server) SetOnTaskClaimedHook(fn func(agentID, taskID string)) {
	s.onTaskClaimedHook = fn
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

// ============================================================================
// Register 节点上线注册
// ============================================================================

func (s *Server) Register(ctx context.Context, req *pb.RegisterReq) (*pb.RegisterResp, error) {
	log.Printf("[Register] Agent %s connected, version: %s", req.AgentId, req.Version)

	tagsJSON := "{}"
	if len(req.Tags) > 0 {
		if data, err := json.Marshal(req.Tags); err == nil {
			tagsJSON = string(data)
		}
	}

	db.DB.Save(&db.Node{
		AgentID:      req.AgentId,
		Status:       "Alive",
		Version:      req.Version,
		Tags:         tagsJSON,
		Capacity:     int(req.Capacity),
		RunningTasks: 0,
		LastBeat:     time.Now().UnixMilli(),
		OS:           req.Os,
		Arch:         req.Arch,
	})

	return &pb.RegisterResp{
		Success: true,
		Token:   "dummy_token_" + req.AgentId,
	}, nil
}

// ============================================================================
// Subscribe — Server→Agent 的任务通知双向流
//
// Agent 连接后持续监听 TaskNotify；
// Server 有新任务时通过 NotifyHub 广播到所有在线 Agent。
// ============================================================================

func (s *Server) Subscribe(stream pb.AgentService_SubscribeServer) error {
	// 第一条消息必须携带 agent_id 用于注册
	firstMsg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("subscribe: failed to receive initial signal: %w", err)
	}

	agentID := firstMsg.AgentId
	if agentID == "" {
		return fmt.Errorf("subscribe: agent_id is required in first AgentSignal")
	}

	// 注册到 NotifyHub
	s.Hub.Register(agentID, stream, firstMsg.FreeSlots, nil)
	defer s.Hub.Unregister(agentID)

	log.Printf("[Subscribe] Agent %s stream established (free_slots=%d)", agentID, firstMsg.FreeSlots)

	// 注册成功后，立即检查队列是否有积压任务并通知
	if depth := s.getQueueDepth(); depth > 0 {
		s.Hub.NotifyAgent(agentID, depth, "backlog")
	}

	// 持续监听 Agent 上行信号（容量变化、ping 等）
	for {
		signal, err := stream.Recv()
		if err == io.EOF {
			log.Printf("[Subscribe] Agent %s stream closed (EOF)", agentID)
			return nil
		}
		if err != nil {
			log.Printf("[Subscribe] Agent %s stream error: %v", agentID, err)
			return err
		}

		switch signal.SignalType {
		case "capacity_update":
			s.Hub.UpdateFreeSlots(agentID, signal.FreeSlots)
			// 如果有空闲且队列有任务，立即通知
			if signal.FreeSlots > 0 {
				if depth := s.getQueueDepth(); depth > 0 {
					s.Hub.NotifyAgent(agentID, depth, "capacity_available")
				}
			}
		case "ping":
			// keep-alive，无需处理
		}
	}
}

// ============================================================================
// ClaimTask — Agent 主动认领任务（原子操作）
//
// 流程：
//   1. Agent 收到 TaskNotify → 调用 ClaimTask
//   2. Server 从 Redis XREADGROUP 原子消费一条消息
//   3. 标签路由检查：不匹配则退回重试
//   4. 更新 DB 状态，返回任务给 Agent
// ============================================================================

func (s *Server) ClaimTask(ctx context.Context, req *pb.ClaimTaskReq) (*pb.Task, error) {
	hook := s.claimTaskHook
	if hook == nil {
		hook = s.fetchTaskHook // fallback
	}
	if hook == nil {
		return &pb.Task{}, nil
	}

	// 获取节点标签用于路由匹配
	var node db.Node
	db.DB.Where("agent_id = ?", req.AgentId).First(&node)

	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		task, msgID, err := hook(req.AgentId)
		if err != nil || task == nil || task.TaskId == "" {
			return &pb.Task{}, err
		}

		// 标签路由检查
		if !s.matchAgentSelector(task.TaskId, node.Tags) {
			log.Printf("[ClaimTask] Task %s selector mismatch for Agent %s, returning to queue (attempt %d)",
				task.TaskId, req.AgentId, attempt+1)
			if s.returnTaskHook != nil {
				_ = s.returnTaskHook(task, msgID)
			}
			continue
		}

		// 认领成功：更新 DB 状态
		db.DB.Model(&db.SubTask{}).Where("id = ?", task.TaskId).
			Updates(map[string]interface{}{
				"status":        "Running",
				"agent_id":      req.AgentId,
				"stream_msg_id": msgID,
			})
		db.DB.Exec("UPDATE nodes SET running_tasks = running_tasks + 1 WHERE agent_id = ?", req.AgentId)

		// 更新 RootTask 状态
		var sub db.SubTask
		if db.DB.First(&sub, "id = ?", task.TaskId).Error == nil {
			db.DB.Model(&db.RootTask{}).Where("id = ? AND status = ?", sub.RootTaskID, "Queued").
				Update("status", "Running")
		}

		log.Printf("[ClaimTask] Agent %s claimed task %s", req.AgentId, task.TaskId)

		// 广播认领动作给前端 UI（通过 Hook 交给 main.go 处理，避免循环依赖）
		if s.onTaskClaimedHook != nil {
			s.onTaskClaimedHook(req.AgentId, task.TaskId)
		}

		// 更新 NotifyHub 中的空闲容量
		s.Hub.UpdateFreeSlots(req.AgentId, req.FreeSlots-1)

		return task, nil
	}

	return &pb.Task{}, nil // 重试耗尽
}

// ============================================================================
// FetchTask — 兼容旧版 Agent 的轮询接口
// ============================================================================

func (s *Server) FetchTask(ctx context.Context, req *pb.FetchTaskReq) (*pb.Task, error) {
	// 委托给 ClaimTask 逻辑
	return s.ClaimTask(ctx, &pb.ClaimTaskReq{
		AgentId:   req.AgentId,
		FreeSlots: 1,
	})
}

// ============================================================================
// Heartbeat — 节点心跳保活
// ============================================================================

func (s *Server) Heartbeat(ctx context.Context, req *pb.HeartbeatReq) (*pb.HeartbeatResp, error) {
	taskIDsJSON := "[]"
	if len(req.RunningTaskIds) > 0 {
		b, _ := json.Marshal(req.RunningTaskIds)
		taskIDsJSON = string(b)
	}

	updates := map[string]interface{}{
		"status":           "Alive",
		"last_beat":        time.Now().UnixMilli(),
		"running_tasks":    int(req.RunningTasks),
		"running_task_ids": taskIDsJSON,
		"cpu_usage":        req.CpuUsage,
		"mem_usage":        req.MemUsage,
	}
	if req.RuleVersion != "" {
		updates["rule_version"] = req.RuleVersion
	}
	_ = db.DB.Model(&db.Node{}).Where("agent_id = ?", req.AgentId).Updates(updates).Error

	// 检查是否需要同步规则
	shouldSync := false
	var cfg db.SystemConfig
	if db.DB.Where("key = ?", "rule_version").First(&cfg).Error == nil {
		if req.RuleVersion != "" && req.RuleVersion != cfg.Value {
			shouldSync = true
		}
	}

	// 返回队列深度，让 Agent 知道是否需要认领任务（防饥饿兜底）
	tasksAvailable := s.getQueueDepth()

	return &pb.HeartbeatResp{
		Ack:             true,
		ShouldTerminate: false,
		ShouldSyncRules: shouldSync,
		TasksAvailable:  tasksAvailable,
	}, nil
}

// ============================================================================
// TaskComplete — 任务完成通知
// ============================================================================

func (s *Server) TaskComplete(ctx context.Context, req *pb.TaskCompleteReq) (*pb.Ack, error) {
	log.Printf("[TaskComplete] SubTask %s by Agent %s => Status: %s", req.TaskId, req.AgentId, req.Status)
	db.DB.Model(&db.SubTask{}).Where("id = ?", req.TaskId).Update("status", req.Status)

	// 递减节点 running_tasks
	db.DB.Exec("UPDATE nodes SET running_tasks = GREATEST(running_tasks - 1, 0) WHERE agent_id = ?", req.AgentId)

	if req.Status == "DONE" {
		var sub db.SubTask
		if err := db.DB.First(&sub, "id = ?", req.TaskId).Error; err == nil {
			// ACK Redis Stream
			if s.ackTaskHook != nil && sub.StreamMsgID != "" {
				_ = s.ackTaskHook(sub.StreamMsgID)
			}
			if sub.RootTaskID != "" {
				db.DB.Exec("UPDATE root_tasks SET completed_chunks = completed_chunks + 1 WHERE id = ?", sub.RootTaskID)

				var root db.RootTask
				if err := db.DB.First(&root, "id = ?", sub.RootTaskID).Error; err == nil {
					if root.CompletedChunks >= root.TotalChunks {
						db.DB.Model(&root).Update("status", "FINISHED")
						log.Printf("[Aggregation] RootTask %s is fully completed! (%d/%d chunks)", root.ID, root.CompletedChunks, root.TotalChunks)
					} else if root.CompletedChunks > 0 && root.CompletedChunks < root.TotalChunks {
						if root.Status == "Running" {
							db.DB.Model(&root).Update("status", "PartialDone")
						}
					}
				}
			}
		}
	}

	// ★ 核心：任务完成后，检查队列是否还有任务，主动通知该 Agent 继续认领
	// 这保证了 Agent 完成一个任务后立即知道还有任务可做，杜绝空闲浪费
	if depth := s.getQueueDepth(); depth > 0 {
		s.Hub.NotifyAgent(req.AgentId, depth, "task_completed")
	}

	return &pb.Ack{Success: true}, nil
}

// ============================================================================
// StreamResult — 流式接收扫描结果
// ============================================================================

func (s *Server) StreamResult(stream pb.AgentService_StreamResultServer) error {
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.Ack{Success: true, Message: "EOF"})
		}
		if err != nil {
			return err
		}
		db.AddResultAsync(res.TaskId, res.PayloadType, string(res.Payload))
	}
}

// ============================================================================
// EmergencyDump — 紧急数据下刷
// ============================================================================

func (s *Server) EmergencyDump(ctx context.Context, req *pb.EmergencyReq) (*pb.Ack, error) {
	log.Printf("[EmergencyDump] Agent %s is flushing all local states due to Spot termination signal!", req.AgentId)
	return &pb.Ack{Success: true, Message: "Safe drop signal received"}, nil
}

// ============================================================================
// StreamLogs — 遥测日志上传
// ============================================================================

func (s *Server) StreamLogs(stream pb.AgentService_StreamLogsServer) error {
	for {
		payload, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.Ack{Success: true})
		}
		if err != nil {
			return err
		}

		db.DB.Create(&db.AgentLog{
			AgentID:   payload.AgentId,
			Level:     payload.Level,
			Message:   payload.Message,
			Timestamp: payload.Timestamp,
		})

		log.Printf("[Telemetry][Agent %s][%s] %s", payload.AgentId, payload.Level, payload.Message)
	}
}

// ============================================================================
// 内部辅助方法
// ============================================================================

func (s *Server) matchAgentSelector(taskID string, nodeTags string) bool {
	var sub db.SubTask
	if db.DB.Select("agent_selector").Where("id = ?", taskID).First(&sub).Error != nil {
		return true
	}

	selector := strings.TrimSpace(sub.AgentSelector)
	if selector == "" || selector == "{}" {
		return true
	}

	var selectorMap map[string]string
	if err := json.Unmarshal([]byte(selector), &selectorMap); err != nil {
		return true
	}

	var tagMap map[string]string
	if err := json.Unmarshal([]byte(nodeTags), &tagMap); err != nil {
		return len(selectorMap) == 0
	}

	for key, val := range selectorMap {
		if nodeVal, ok := tagMap[key]; !ok || nodeVal != val {
			return false
		}
	}
	return true
}

func (s *Server) getQueueDepth() int32 {
	if s.queueDepthHook != nil {
		return s.queueDepthHook()
	}
	return 0
}
