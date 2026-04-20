package grpc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Server 封装了对 Agent 通信的 gRPC 服务端
type Server struct {
	pb.UnimplementedAgentServiceServer
	port int
	psk  string // Agent 预共享密钥，为空则跳过鉴权（开发模式）

	// NotifyHub 管理所有在线 Agent 的 Subscribe 流连接
	Hub *NotifyHub

	// queue hooks — 通过回调与任务队列解耦（RabbitMQ / Memory）
	claimTaskHook     func(agentID string) (*pb.Task, string, error) // 原子认领
	fetchTaskHook     func(agentID string) (*pb.Task, string, error) // 兼容旧版
	ackTaskHook       func(msgID string) error                       // ACK 确认
	returnTaskHook    func(task *pb.Task, msgID string) error        // 退回队列
	queueDepthHook    func() int32                                   // 获取队列深度
	onTaskClaimedHook func(agentID, taskID string)                   // UI 广播 Hook
}

var (
	claimableSubTaskStatuses = []string{"Pending", "Recovered", "Dispatching"}
	activeSubTaskStatuses    = []string{"Running", "CancelPending"}
)

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

// SetPSK 设置 Agent 预共享密钥（为空则跳过鉴权，适用于开发环境）
func (s *Server) SetPSK(psk string) {
	s.psk = psk
}

// Serve 启动 gRPC 监听
func (s *Server) Serve() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	opts := []grpc.ServerOption{}
	if s.psk != "" {
		opts = append(opts,
			grpc.UnaryInterceptor(s.unaryPSKInterceptor),
			grpc.StreamInterceptor(s.streamPSKInterceptor),
		)
		log.Printf("[Auth] Agent PSK authentication enabled")
	} else {
		log.Printf("[Auth] WARNING: Agent PSK not set, running in open mode (dev only)")
	}

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterAgentServiceServer(grpcServer, s)

	log.Printf("gRPC server listening at %v", lis.Addr())
	return grpcServer.Serve(lis)
}

// unaryPSKInterceptor 校验 Agent 的预共享密钥（Unary RPC）
func (s *Server) unaryPSKInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if err := s.validatePSK(ctx); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

// streamPSKInterceptor 校验 Agent 的预共享密钥（Stream RPC）
func (s *Server) streamPSKInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := s.validatePSK(ss.Context()); err != nil {
		return err
	}
	return handler(srv, ss)
}

// validatePSK 从 gRPC metadata 中提取并校验 x-agent-psk
func (s *Server) validatePSK(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	tokens := md.Get("x-agent-psk")
	if len(tokens) == 0 || tokens[0] != s.psk {
		return status.Error(codes.Unauthenticated, "invalid agent pre-shared key")
	}
	return nil
}

// generateSessionToken 生成随机 session token
func generateSessionToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
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

	token := generateSessionToken()
	db.DB.Model(&db.Node{}).Where("agent_id = ?", req.AgentId).Update("token", token)

	return &pb.RegisterResp{
		Success: true,
		Token:   token,
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
//   2. Server 通过 RabbitMQ basic.get 原子消费一条消息
//   3. 标签路由检查：不匹配则 Nack 退回重试
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

	// 优先使用请求中携带的标签（避免重复查库），回退到 DB 查询
	var nodeTagsJSON string
	if len(req.Tags) > 0 {
		if data, err := json.Marshal(req.Tags); err == nil {
			nodeTagsJSON = string(data)
		}
	}
	if nodeTagsJSON == "" {
		var node db.Node
		db.DB.Select("tags").Where("agent_id = ?", req.AgentId).First(&node)
		nodeTagsJSON = node.Tags
	}

	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		task, msgID, err := hook(req.AgentId)
		if err != nil || task == nil || task.TaskId == "" {
			return &pb.Task{}, err
		}

		// DB 状态机校验：只允许 Pending / Recovered 任务进入执行态。
		var sub db.SubTask
		if err := db.DB.Select("id", "status", "root_task_id").Where("id = ?", task.TaskId).First(&sub).Error; err != nil {
			// 队列里有脏消息（DB 不存在），直接 ACK 丢弃避免死循环。
			if s.ackTaskHook != nil && msgID != "" {
				_ = s.ackTaskHook(msgID)
			}
			log.Printf("[ClaimTask] Dropped orphan queue message for task %s: %v", task.TaskId, err)
			continue
		}

		switch normalizeSubTaskStatus(sub.Status) {
		case "CANCELPENDING":
			// 用户已取消但消息仍在队列里：消费掉并落库为 Cancelled。
			if s.ackTaskHook != nil && msgID != "" {
				_ = s.ackTaskHook(msgID)
			}
			_ = db.DB.Model(&db.SubTask{}).Where("id = ?", sub.ID).
				Updates(map[string]interface{}{
					"status":        "Cancelled",
					"agent_id":      "",
					"stream_msg_id": "",
				}).Error
			if sub.RootTaskID != "" {
				db.RefreshRootTaskStatus(sub.RootTaskID)
			}
			log.Printf("[ClaimTask] Dropped cancelled task %s before assignment", task.TaskId)
			continue
		case "DONE", "FAILED", "CANCELLED", "TIMEOUT":
			// 终态任务残留消息，直接消费掉。
			if s.ackTaskHook != nil && msgID != "" {
				_ = s.ackTaskHook(msgID)
			}
			_ = db.DB.Model(&db.SubTask{}).Where("id = ?", sub.ID).
				Updates(map[string]interface{}{
					"agent_id":      "",
					"stream_msg_id": "",
				}).Error
			log.Printf("[ClaimTask] Dropped terminal task message %s (status=%s)", task.TaskId, sub.Status)
			continue
		}

		// 标签路由检查
		if !s.matchAgentSelector(task.TaskId, nodeTagsJSON) {
			log.Printf("[ClaimTask] Task %s selector mismatch for Agent %s, returning to queue (attempt %d)",
				task.TaskId, req.AgentId, attempt+1)
			if s.returnTaskHook != nil {
				_ = s.returnTaskHook(task, msgID)
			}
			continue
		}

		// 认领成功：CAS 更新 DB 状态，避免并发状态漂移（例如被取消/超时回收）
		updateRes := db.DB.Model(&db.SubTask{}).
			Where("id = ? AND status IN ?", task.TaskId, claimableSubTaskStatuses).
			Updates(map[string]interface{}{
				"status":        "Running",
				"agent_id":      req.AgentId,
				"stream_msg_id": msgID,
			})
		if updateRes.Error != nil {
			if s.returnTaskHook != nil {
				_ = s.returnTaskHook(task, msgID)
			}
			log.Printf("[ClaimTask] Failed to set running state for %s: %v", task.TaskId, updateRes.Error)
			continue
		}
		if updateRes.RowsAffected == 0 {
			// 任务状态已变化（例如 CancelPending/Timeout），退回队列给下一轮处理。
			if s.returnTaskHook != nil {
				_ = s.returnTaskHook(task, msgID)
			}
			log.Printf("[ClaimTask] Task %s state changed before claim commit, returned to queue", task.TaskId)
			continue
		}
		db.DB.Exec("UPDATE nodes SET running_tasks = running_tasks + 1 WHERE agent_id = ?", req.AgentId)

		// 更新 RootTask 状态
		if db.DB.First(&sub, "id = ?", task.TaskId).Error == nil {
			db.DB.Model(&db.RootTask{}).Where("id = ? AND status = ?", sub.RootTaskID, "Queued").
				Update("status", "Running")
		}

		targetCount := len(task.Targets)
		log.Printf("[ClaimTask] Agent %s claimed task %s (target_count=%d)", req.AgentId, task.TaskId, targetCount)

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
	status := canonicalTaskCompleteStatus(req.Status)
	if status == "" {
		return &pb.Ack{Success: false, Message: "invalid status"}, nil
	}

	var sub db.SubTask
	if err := db.DB.Where("id = ?", req.TaskId).First(&sub).Error; err != nil {
		return &pb.Ack{Success: false, Message: "subtask not found"}, nil
	}

	// lease 校验：只接受当前持有者的完成回调，拒绝迟到/过期上报。
	if sub.AgentID != "" && req.AgentId != sub.AgentID {
		log.Printf("[TaskComplete] Ignored stale completion for %s from %s (owner=%s)", req.TaskId, req.AgentId, sub.AgentID)
		return &pb.Ack{Success: true, Message: "stale completion ignored"}, nil
	}

	currentStatus := normalizeSubTaskStatus(sub.Status)
	if !containsStatus(activeSubTaskStatuses, sub.Status) {
		log.Printf("[TaskComplete] Ignored duplicate completion for %s (status=%s)", req.TaskId, sub.Status)
		return &pb.Ack{Success: true, Message: "duplicate completion ignored"}, nil
	}

	log.Printf("[TaskComplete] SubTask %s by Agent %s => Status: %s", req.TaskId, req.AgentId, status)

	updates := map[string]interface{}{
		"status":        status,
		"agent_id":      "",
		"stream_msg_id": "",
	}
	if err := db.DB.Model(&db.SubTask{}).Where("id = ?", req.TaskId).Updates(updates).Error; err != nil {
		return &pb.Ack{Success: false, Message: "failed to persist completion"}, nil
	}

	// 仅在任务处于活跃态时扣减节点并发计数。
	if currentStatus == "RUNNING" || currentStatus == "CANCELPENDING" {
		db.DB.Exec("UPDATE nodes SET running_tasks = GREATEST(running_tasks - 1, 0) WHERE agent_id = ?", req.AgentId)
	}

	// 终态统一 ACK，防止 FAILED/CANCELLED 任务在 MQ 中“复活”。
	if s.ackTaskHook != nil && sub.StreamMsgID != "" {
		_ = s.ackTaskHook(sub.StreamMsgID)
	}

	// 失败批次拆分重试：对多目标失败批次执行二分拆分
	if (status == "FAILED" || status == "TIMEOUT") && sub.RootTaskID != "" {
		splitSubs, didSplit := db.SplitFailedSubTask(&sub)
		if didSplit && len(splitSubs) > 0 {
			// 拆分成功，将两个子批次推入 urgent 队列优先调度
			for _, splitSub := range splitSubs {
				pbSub, err := db.SubTaskToProto(&splitSub)
				if err != nil || pbSub == nil {
					log.Printf("[SplitRetry] Failed to encode split subtask %s: %v", splitSub.ID, err)
					continue
				}
				pbSub.Priority = 0 // urgent 优先级
				if s.returnTaskHook != nil {
					if err := s.returnTaskHook(pbSub, ""); err != nil {
						log.Printf("[SplitRetry] Failed to enqueue split subtask %s: %v", splitSub.ID, err)
					}
				}
			}
			log.Printf("[SplitRetry] Task %s split into %d sub-batches and re-enqueued", req.TaskId, len(splitSubs))
		}
	}

	if status == "DONE" && sub.RootTaskID != "" {
		db.DB.Exec("UPDATE root_tasks SET completed_chunks = completed_chunks + 1 WHERE id = ?", sub.RootTaskID)
	}
	if sub.RootTaskID != "" {
		db.RefreshRootTaskStatus(sub.RootTaskID)
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
	// 兼容单机/开发模式：Agent 无标签时视为“通用节点”，允许领取全部任务。
	if len(tagMap) == 0 {
		return true
	}

	for key, val := range selectorMap {
		nodeVal, ok := tagMap[key]
		if !ok {
			// 支持通配能力标签，例如 target_type=all|any|*
			if key == "target_type" {
				if wildcard, okw := tagMap["target_type"]; okw {
					w := strings.ToLower(strings.TrimSpace(wildcard))
					if w == "all" || w == "any" || w == "*" {
						continue
					}
				}
			}
			return false
		}
		if nodeVal != val {
			n := strings.ToLower(strings.TrimSpace(nodeVal))
			if n == "all" || n == "any" || n == "*" {
				continue
			}
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

func normalizeSubTaskStatus(status string) string {
	return db.NormalizeSubTaskStatus(status)
}

func canonicalTaskCompleteStatus(status string) string {
	switch normalizeSubTaskStatus(status) {
	case "DONE", "FINISHED", "SUCCESS":
		return "DONE"
	case "FAILED", "FAIL", "ERROR":
		return "FAILED"
	case "CANCELLED", "CANCELED", "CANCEL":
		return "CANCELLED"
	case "TIMEOUT", "TIMEDOUT":
		return "TIMEOUT"
	default:
		return ""
	}
}

func containsStatus(statuses []string, status string) bool {
	for _, s := range statuses {
		if strings.EqualFold(strings.TrimSpace(s), strings.TrimSpace(status)) {
			return true
		}
	}
	return false
}
