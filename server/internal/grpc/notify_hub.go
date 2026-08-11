package grpc

import (
	"errors"
	"log"
	"strings"
	"sync"

	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
)

// ============================================================================
// NotifyHub — Agent 连接管理器 + 公平任务通知广播
//
// 核心职责：
//   1. 管理所有在线 Agent 的 Subscribe 双向流连接
//   2. 新任务入队后，向有空闲容量的 Agent 广播 TaskNotify
//   3. 保证公平性：优先通知空闲容量最大的 Agent
//   4. 防饥饿：Agent 完成任务后触发补发通知
// ============================================================================

// NotifyHub 管理所有在线 Agent 的 Subscribe 流连接
type NotifyHub struct {
	mu     sync.RWMutex
	agents map[string]*agentConn // agentID → connection
}

var ErrAgentOffline = errors.New("agent is offline")

// agentConn 单个 Agent 的连接状态
type agentConn struct {
	agentID   string
	tenantID  string
	stream    pb.AgentService_SubscribeServer
	freeSlots int32 // Agent 上报的空闲 worker 数
	tags      map[string]string
	sendMu    sync.Mutex // 保护 stream.Send 的并发安全
}

// NewNotifyHub 创建通知广播器
func NewNotifyHub() *NotifyHub {
	return &NotifyHub{
		agents: make(map[string]*agentConn),
	}
}

// Register 注册一个 Agent 的 Subscribe 流连接
func (h *NotifyHub) Register(agentID string, stream pb.AgentService_SubscribeServer, freeSlots int32, tags map[string]string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	tenantID := normalizeNotifyTenantID("")
	if tags != nil {
		tenantID = normalizeNotifyTenantID(tags["tenant_id"])
	}
	h.agents[agentID] = &agentConn{
		agentID:   agentID,
		tenantID:  tenantID,
		stream:    stream,
		freeSlots: freeSlots,
		tags:      tags,
	}
	log.Printf("[NotifyHub] Agent %s subscribed (tenant=%s free_slots=%d)", agentID, tenantID, freeSlots)
}

// Unregister 移除 Agent 连接（断开时调用）。如果 Agent 已经建立了更新的
// Subscribe 流，旧流退出时不能删除新连接。
func (h *NotifyHub) Unregister(agentID string, stream pb.AgentService_SubscribeServer) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if conn, ok := h.agents[agentID]; !ok || conn.stream != stream {
		log.Printf("[NotifyHub] Ignored stale unsubscribe for Agent %s", agentID)
		return
	}
	delete(h.agents, agentID)
	log.Printf("[NotifyHub] Agent %s unsubscribed", agentID)
}

// UpdateFreeSlots 更新 Agent 的空闲容量
func (h *NotifyHub) UpdateFreeSlots(agentID string, freeSlots int32) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if conn, ok := h.agents[agentID]; ok {
		conn.freeSlots = freeSlots
	}
}

// OnlineAgentCount 返回在线 Agent 数量
func (h *NotifyHub) OnlineAgentCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.agents)
}

// IsAgentOnline 返回指定 Agent 是否存在活跃 Subscribe 流连接。
func (h *NotifyHub) IsAgentOnline(agentID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.agents[agentID]
	return ok
}

// SendDebugCommand 通过现有 Subscribe 流向指定 Agent 下发 POC 调试命令。
func (h *NotifyHub) SendDebugCommand(agentID string, cmd *pb.DebugCommand) error {
	h.mu.RLock()
	conn, ok := h.agents[agentID]
	h.mu.RUnlock()

	if !ok {
		return ErrAgentOffline
	}

	notify := &pb.TaskNotify{
		NotifyType:     "debug_command",
		DebugCommand:   cmd,
		AvailableTasks: 0,
	}

	conn.sendMu.Lock()
	err := conn.stream.Send(notify)
	conn.sendMu.Unlock()
	if err != nil {
		log.Printf("[NotifyHub] Failed to send debug command to Agent %s: %v", agentID, err)
		return err
	}

	return nil
}

func normalizeNotifyTenantID(tenantID string) string {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return "default"
	}
	return tenantID
}

// BroadcastNewTask 新任务入队后广播通知所有有空闲容量的 Agent。
//
// 调度算法：
//   - 遍历所有在线 Agent，向 freeSlots > 0 的 Agent 发送 TaskNotify
//   - 如果所有 Agent 都满载，则全部通知（等待它们完成当前任务后认领）
//   - 保证不会有在线 Agent 不知道有新任务
func (h *NotifyHub) BroadcastNewTask(availableTasks int32, priority int32) {
	h.mu.RLock()
	agents := make([]*agentConn, 0, len(h.agents))
	for _, conn := range h.agents {
		agents = append(agents, conn)
	}
	h.mu.RUnlock()

	if len(agents) == 0 {
		log.Printf("[NotifyHub] No agents online to notify, %d tasks waiting in queue", availableTasks)
		return
	}

	notify := &pb.TaskNotify{
		AvailableTasks: availableTasks,
		Priority:       priority,
		NotifyType:     "new_task",
	}

	notified := 0
	for _, conn := range agents {
		conn.sendMu.Lock()
		err := conn.stream.Send(notify)
		conn.sendMu.Unlock()

		if err != nil {
			log.Printf("[NotifyHub] Failed to notify Agent %s: %v (will be cleaned on next heartbeat)", conn.agentID, err)
			continue
		}
		notified++
	}

	log.Printf("[NotifyHub] Broadcast: %d agents notified, %d tasks available (priority=%d)",
		notified, availableTasks, priority)
}

// NotifyAgent 向特定 Agent 发送通知（用于任务完成后的补发）
func (h *NotifyHub) NotifyAgent(agentID string, availableTasks int32, notifyType string) {
	h.mu.RLock()
	conn, ok := h.agents[agentID]
	h.mu.RUnlock()

	if !ok {
		return
	}

	notify := &pb.TaskNotify{
		AvailableTasks: availableTasks,
		NotifyType:     notifyType,
	}

	conn.sendMu.Lock()
	err := conn.stream.Send(notify)
	conn.sendMu.Unlock()

	if err != nil {
		log.Printf("[NotifyHub] Failed to notify Agent %s: %v", agentID, err)
	}
}

// NotifyIdleAgents 通知所有有空闲容量的 Agent（用于心跳检查时的防饥饿补发）
func (h *NotifyHub) NotifyIdleAgents(availableTasks int32) {
	if availableTasks <= 0 {
		return
	}

	h.mu.RLock()
	agents := make([]*agentConn, 0)
	for _, conn := range h.agents {
		if conn.freeSlots > 0 {
			agents = append(agents, conn)
		}
	}
	h.mu.RUnlock()

	notify := &pb.TaskNotify{
		AvailableTasks: availableTasks,
		NotifyType:     "heartbeat_check",
	}

	for _, conn := range agents {
		conn.sendMu.Lock()
		_ = conn.stream.Send(notify)
		conn.sendMu.Unlock()
	}
}
