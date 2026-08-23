package grpc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/credentialbundle"
	"github.com/P0lar1ght/argus/server/internal/db"
	egressbroker "github.com/P0lar1ght/argus/server/internal/egress"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const agentSessionTTL = 7 * 24 * time.Hour
const retryQueuedMarker = "queued"

func agentHasCapabilities(nodeTagsJSON string, capabilities ...string) bool {
	var tags map[string]string
	if json.Unmarshal([]byte(nodeTagsJSON), &tags) != nil {
		return false
	}
	for _, capability := range capabilities {
		expected := "v1"
		if capability == "transport_tls" {
			expected = "verified"
		}
		if tags[capability] != expected {
			return false
		}
	}
	return true
}

func taskRequestsSYN(task *pb.Task) bool {
	if task == nil || len(task.Config) == 0 {
		return false
	}
	var config struct {
		PortScanType string
	}
	return json.Unmarshal(task.Config, &config) == nil && strings.EqualFold(strings.TrimSpace(config.PortScanType), "syn")
}

func taskRequestsUnconfirmedPOC(task *pb.Task) bool {
	if task == nil || len(task.Config) == 0 || isRiskValidationTask(task) {
		return false
	}
	var config struct {
		NoPoc             *bool
		GolangPoc         bool
		DisableGeneralPoc *bool
		PocNameForSearch  string
	}
	if json.Unmarshal(task.Config, &config) != nil {
		return false
	}
	return (config.NoPoc != nil && !*config.NoPoc) || config.GolangPoc ||
		(config.DisableGeneralPoc != nil && !*config.DisableGeneralPoc) || strings.TrimSpace(config.PocNameForSearch) != ""
}

// Server 封装了对 Agent 通信的 gRPC 服务端
type Server struct {
	pb.UnimplementedAgentServiceServer
	pb.UnimplementedAgentEgressServiceServer
	port int
	psk  string // Agent 预共享密钥，为空则跳过鉴权（开发模式）
	// NotifyHub 管理所有在线 Agent 的 Subscribe 流连接
	Hub    *NotifyHub
	Egress *egressbroker.Broker

	// queue hooks — 通过回调与任务队列解耦（RabbitMQ / Memory）
	claimTaskHook      func(agentID string) (*pb.Task, string, error) // 原子认领
	fetchTaskHook      func(agentID string) (*pb.Task, string, error) // 兼容旧版
	ackTaskHook        func(msgID string) error                       // ACK 确认
	returnTaskHook     func(task *pb.Task, msgID string) error        // 退回队列
	requeueTaskHook    func(task *pb.Task) error                      // 重新入队（用于重试/拆分）
	queueDepthHook     func() int32                                   // 获取队列深度
	onTaskClaimedHook  func(agentID, taskID string)                   // UI 广播 Hook
	onTaskTerminalHook func(context.Context, db.SubTask) error
}

func heartbeatRunningTasksExpr(reported int) interface{} {
	if db.DB != nil && db.DB.Dialector != nil && db.DB.Dialector.Name() == "sqlite" {
		return gorm.Expr("MAX(running_tasks, ?)", reported)
	}
	return gorm.Expr("GREATEST(running_tasks, ?)", reported)
}

func decrementRunningTasksExpr() interface{} {
	if db.DB != nil && db.DB.Dialector != nil && db.DB.Dialector.Name() == "sqlite" {
		return gorm.Expr("MAX(running_tasks - 1, 0)")
	}
	return gorm.Expr("GREATEST(running_tasks - 1, 0)")
}

var (
	claimableSubTaskStatuses = []string{"Pending", "Recovered", "Dispatching"}
	activeSubTaskStatuses    = []string{"Running", "CancelPending"}
)

// NewServer 初始化 gRPC Server
func NewServer(port int) *Server {
	return &Server{port: port, Hub: NewNotifyHub(), Egress: egressbroker.NewBroker()}
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

func (s *Server) SetRequeueTaskHook(fn func(task *pb.Task) error) {
	s.requeueTaskHook = fn
}

func (s *Server) SetQueueDepthHook(fn func() int32) {
	s.queueDepthHook = fn
}

func (s *Server) SetOnTaskClaimedHook(fn func(agentID, taskID string)) {
	s.onTaskClaimedHook = fn
}

func (s *Server) SetOnTaskTerminalHook(fn func(context.Context, db.SubTask) error) {
	s.onTaskTerminalHook = fn
}

// SetPSK 设置 Agent 预共享密钥（为空则跳过鉴权，适用于开发环境）
func (s *Server) SetPSK(psk string) {
	s.psk = psk
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

	tags := attestedAgentTags(ctx, req.Tags)
	tagsJSON := "{}"
	if len(tags) > 0 {
		if data, err := json.Marshal(tags); err == nil {
			tagsJSON = string(data)
		}
	}

	// 多租户：从 Agent 标签中提取 tenant_id（Cloud-Init 会注入），
	// 回退到关联 CloudInstance 的 tenant_id，最终兜底 "default"。
	tenantID := "default"
	if tid, ok := tags["tenant_id"]; ok && strings.TrimSpace(tid) != "" {
		tenantID = strings.TrimSpace(tid)
	} else {
		// 尝试从已有的 CloudInstance 记录中继承 tenant_id
		var cloudInst db.CloudInstance
		if err := db.DB.Select("tenant_id").Where("agent_id = ?", req.AgentId).First(&cloudInst).Error; err == nil && cloudInst.TenantID != "" {
			tenantID = cloudInst.TenantID
		}
	}

	token := generateSessionToken()
	now := time.Now()
	expiresAt := now.Add(agentSessionTTL)
	db.DB.Save(&db.Node{
		TenantID:           tenantID,
		AgentID:            req.AgentId,
		Status:             "Alive",
		Token:              token,
		TokenExpiresAt:     &expiresAt,
		TokenRevokedAt:     nil,
		LastTokenRotatedAt: &now,
		Version:            req.Version,
		Tags:               tagsJSON,
		Capacity:           int(req.Capacity),
		RunningTasks:       0,
		LastBeat:           now.UnixMilli(),
		OS:                 req.Os,
		Arch:               req.Arch,
	})
	_ = db.DB.Create(&db.AgentSessionAudit{
		TenantID:  tenantID,
		AgentID:   req.AgentId,
		Action:    "register_rotate",
		Reason:    "agent register issued new session token",
		CreatedAt: now,
	}).Error

	db.DB.Model(&db.CloudInstance{}).
		Where("agent_id = ? AND status IN ?", req.AgentId, []string{
			db.CloudStatusProvisioning,
			db.CloudStatusWaitingReady,
			db.CloudStatusRebooting,
			db.CloudStatusRunning,
		}).
		Updates(map[string]interface{}{
			"status":   db.CloudStatusRunning,
			"ready_at": &now,
		})

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

	tenantID := tenantIDForAgent(agentID)
	// 注册到 NotifyHub
	s.Hub.Register(agentID, stream, firstMsg.FreeSlots, map[string]string{"tenant_id": tenantID})
	defer s.Hub.Unregister(agentID, stream)
	s.markSubscribedAgentAlive(agentID, firstMsg.FreeSlots)

	log.Printf("[Subscribe] Agent %s stream established (tenant=%s free_slots=%d)", agentID, tenantID, firstMsg.FreeSlots)

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

func (s *Server) markSubscribedAgentAlive(agentID string, freeSlots int32) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return
	}
	var existing db.Node
	if err := db.DB.Select("agent_id", "tenant_id").Where("agent_id = ?", agentID).First(&existing).Error; err == nil && isTerminatingSpotAgent(agentID, existing.TenantID) {
		s.Hub.UpdateFreeSlots(agentID, 0)
		log.Printf("[Subscribe] Agent %s belongs to a terminating Spot instance; preserving drain state", agentID)
		return
	}
	now := time.Now().UnixMilli()
	updates := map[string]interface{}{
		"status":    "Alive",
		"last_beat": now,
	}
	res := db.DB.Model(&db.Node{}).Where("agent_id = ?", agentID).Updates(updates)
	if res.Error != nil {
		log.Printf("[Subscribe] Failed to mark Agent %s alive: %v", agentID, res.Error)
		return
	}
	if res.RowsAffected == 0 {
		db.DB.Save(&db.Node{
			TenantID: "default",
			AgentID:  agentID,
			Status:   "Alive",
			Capacity: int(freeSlots),
			LastBeat: now,
		})
		log.Printf("[Subscribe] Re-created node record for Agent %s from subscribe stream", agentID)
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
	var claimCandidate db.Node
	if err := db.DB.Select("status", "version", "rule_version", "tags").Where("agent_id = ?", req.AgentId).First(&claimCandidate).Error; err == nil && claimCandidate.Status != "" && !strings.EqualFold(claimCandidate.Status, "Alive") {
		log.Printf("[ClaimTask] Agent %s is %s; skipping task claim", req.AgentId, claimCandidate.Status)
		return &pb.Task{}, nil
	}

	hook := s.claimTaskHook
	if hook == nil {
		hook = s.fetchTaskHook // fallback
	}
	if hook == nil {
		return &pb.Task{}, nil
	}

	// Agent capabilities are read only from the Server-attested registration
	// record. ClaimTask request tags are untrusted routing hints and cannot grant
	// TLS or credential-validation authority.
	nodeTagsJSON := claimCandidate.Tags

	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		task, msgID, err := hook(req.AgentId)
		if err != nil || task == nil || task.TaskId == "" {
			return &pb.Task{}, err
		}

		// DB 状态机校验：只允许 Pending / Recovered 任务进入执行态。
		var sub db.SubTask
		if err := db.DB.Where("id = ?", task.TaskId).First(&sub).Error; err != nil {
			// 队列里有脏消息（DB 不存在），直接 ACK 丢弃避免死循环。
			if s.ackTaskHook != nil && msgID != "" {
				_ = s.ackTaskHook(msgID)
			}
			log.Printf("[ClaimTask] Dropped orphan queue message for task %s: %v", task.TaskId, err)
			continue
		}

		if sub.RootTaskID != "" {
			var rootStatus string
			_ = db.DB.Model(&db.RootTask{}).Select("status").Where("id = ? AND tenant_id = ?", sub.RootTaskID, sub.TenantID).Scan(&rootStatus).Error
			if normalizeSubTaskStatus(rootStatus) == "PAUSED" {
				if s.ackTaskHook != nil && msgID != "" {
					_ = s.ackTaskHook(msgID)
				}
				_ = db.DB.Model(&db.SubTask{}).
					Where("id = ? AND status IN ?", sub.ID, claimableSubTaskStatuses).
					Updates(map[string]interface{}{
						"status":        "Paused",
						"agent_id":      "",
						"stream_msg_id": "",
					}).Error
				_ = db.SyncTaskBatchStatuses(db.DB, sub.TenantID, sub.RootTaskID)
				log.Printf("[ClaimTask] Dropped paused task message %s under root %s", task.TaskId, sub.RootTaskID)
				continue
			}
		}

		switch normalizeSubTaskStatus(sub.Status) {
		case "PENDING", "RECOVERED", "DISPATCHING":
			// Claimable states continue through selector, quota and CAS checks below.
		case "PAUSED":
			// 任务暂停后队列中可能残留旧消息：消费掉，等待 resume 重新投递。
			if s.ackTaskHook != nil && msgID != "" {
				_ = s.ackTaskHook(msgID)
			}
			_ = db.DB.Model(&db.SubTask{}).Where("id = ?", sub.ID).
				Updates(map[string]interface{}{
					"agent_id":      "",
					"stream_msg_id": "",
				}).Error
			log.Printf("[ClaimTask] Dropped paused task message %s", task.TaskId)
			continue
		case "CANCELPENDING":
			// 用户已取消但消息仍在队列里：消费掉并落库为 Cancelled。
			if s.ackTaskHook != nil && msgID != "" {
				_ = s.ackTaskHook(msgID)
			}
			_ = db.DB.Model(&db.SubTask{}).Where("id = ?", sub.ID).
				Updates(map[string]interface{}{
					"status":         "Cancelled",
					"stream_msg_id":  "",
					"failure_reason": "cancelled before Agent assignment",
					"finished_at":    time.Now(),
				}).Error
			if sub.RootTaskID != "" {
				_ = db.SyncTaskBatchStatuses(db.DB, sub.TenantID, sub.RootTaskID)
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
					"stream_msg_id": "",
				}).Error
			log.Printf("[ClaimTask] Dropped terminal task message %s (status=%s)", task.TaskId, sub.Status)
			continue
		case "RUNNING":
			// A Running task already has an active assignment, so this queue message is a duplicate.
			if s.ackTaskHook == nil {
				return &pb.Task{}, fmt.Errorf("ack duplicate running task %s: queue ACK hook is unavailable", task.TaskId)
			}
			if err := s.ackTaskHook(msgID); err != nil {
				log.Printf("[ClaimTask] Failed to ACK duplicate running task %s: %v", task.TaskId, err)
				return &pb.Task{}, fmt.Errorf("ack duplicate running task %s: %w", task.TaskId, err)
			}
			log.Printf("[ClaimTask] Dropped duplicate running task %s", task.TaskId)
			continue
		default:
			// Unknown states may become claimable in a future state machine revision.
			// Return them conservatively instead of permanently acknowledging the message.
			if s.returnTaskHook == nil {
				return &pb.Task{}, fmt.Errorf("cannot return task %s with unknown status %s: queue return hook is unavailable", task.TaskId, sub.Status)
			}
			if err := s.returnTaskHook(task, msgID); err != nil {
				log.Printf("[ClaimTask] Failed to return task %s with unknown status %s: %v", task.TaskId, sub.Status, err)
				return &pb.Task{}, fmt.Errorf("return task %s with unknown status %s: %w", task.TaskId, sub.Status, err)
			}
			log.Printf("[ClaimTask] Returned task %s with unknown status %s", task.TaskId, sub.Status)
			return &pb.Task{}, nil
		}

		if taskRequestsUnconfirmedPOC(task) {
			if s.ackTaskHook == nil {
				return &pb.Task{}, fmt.Errorf("reject unconfirmed POC task %s: queue ACK hook is unavailable", task.TaskId)
			}
			if err := s.ackTaskHook(msgID); err != nil {
				return &pb.Task{}, fmt.Errorf("reject unconfirmed POC task %s: %w", task.TaskId, err)
			}
			finishedAt := time.Now()
			if err := db.DB.Model(&db.SubTask{}).
				Where("id = ? AND tenant_id = ? AND status IN ?", sub.ID, sub.TenantID, claimableSubTaskStatuses).
				Updates(map[string]interface{}{
					"status": "Failed", "failure_reason": "POC execution requires a confirmed risk-validation batch",
					"finished_at": finishedAt, "agent_id": "", "stream_msg_id": "",
				}).Error; err != nil {
				return &pb.Task{}, fmt.Errorf("record unconfirmed POC rejection for task %s: %w", task.TaskId, err)
			}
			if sub.RootTaskID != "" {
				_ = db.SyncTaskBatchStatuses(db.DB, sub.TenantID, sub.RootTaskID)
				db.RefreshRootTaskStatus(sub.RootTaskID)
			}
			log.Printf("[ClaimTask] Rejected unconfirmed POC execution in ordinary task %s", task.TaskId)
			continue
		}

		if taskRequestsLegacyProviderDiscovery(task) {
			if err := s.rejectLegacyProviderTask(task, msgID, sub); err != nil {
				return &pb.Task{}, err
			}
			continue
		}

		if isRiskValidationTask(task) && (!agentSupportsRiskValidation(claimCandidate.Version) || !agentHasCapabilities(nodeTagsJSON, "risk_validation") || strings.TrimSpace(claimCandidate.RuleVersion) != strings.TrimSpace(sub.RuleVersion)) {
			if s.returnTaskHook == nil {
				return &pb.Task{}, fmt.Errorf("return risk validation task %s for incompatible Agent: queue return hook is unavailable", task.TaskId)
			}
			if err := s.returnTaskHook(task, msgID); err != nil {
				return &pb.Task{}, fmt.Errorf("return risk validation task %s for incompatible Agent: %w", task.TaskId, err)
			}
			log.Printf("[ClaimTask] Returned risk validation task %s: Agent %s version=%q rules=%q requires version>=v2.4.0 rules=%q",
				task.TaskId, req.AgentId, claimCandidate.Version, claimCandidate.RuleVersion, sub.RuleVersion)
			return &pb.Task{}, nil
		}
		if taskRequestsSYN(task) && !agentHasCapabilities(nodeTagsJSON, "scan_syn") {
			if s.returnTaskHook == nil {
				return &pb.Task{}, fmt.Errorf("return SYN task %s for incompatible Agent: queue return hook is unavailable", task.TaskId)
			}
			if err := s.returnTaskHook(task, msgID); err != nil {
				return &pb.Task{}, fmt.Errorf("return SYN task %s for incompatible Agent: %w", task.TaskId, err)
			}
			log.Printf("[ClaimTask] Returned SYN task %s: Agent %s lacks scan_syn=v1", task.TaskId, req.AgentId)
			return &pb.Task{}, nil
		}
		if isCredentialValidationTask(task) {
			credentialErr := error(nil)
			if !agentTransportTLS(ctx) || !agentSupportsCredentialValidation(nodeTagsJSON) {
				credentialErr = status.Error(codes.FailedPrecondition, "credential validation requires a Server-attested TLS Agent session")
			} else if _, sessionErr := validateEmergencyAgentSession(ctx, req.AgentId); sessionErr != nil {
				credentialErr = sessionErr
			}
			if credentialErr != nil {
				if s.returnTaskHook == nil {
					return &pb.Task{}, fmt.Errorf("return credential validation task %s for incompatible Agent: queue return hook is unavailable", task.TaskId)
				}
				if err := s.returnTaskHook(task, msgID); err != nil {
					return &pb.Task{}, fmt.Errorf("return credential validation task %s for incompatible Agent: %w", task.TaskId, err)
				}
				log.Printf("[ClaimTask] Returned credential validation task %s: Agent %s lacks Server-attested TLS credential capability on the current RPC", task.TaskId, req.AgentId)
				return &pb.Task{}, credentialErr
			}
		}
		if !validationAffinityAllows(sub.Config, req.AgentId, nodeTagsJSON, time.Now()) {
			if s.returnTaskHook == nil {
				return &pb.Task{}, fmt.Errorf("return validation task %s for preferred Agent: queue return hook is unavailable", task.TaskId)
			}
			if err := s.returnTaskHook(task, msgID); err != nil {
				return &pb.Task{}, fmt.Errorf("return validation task %s for preferred Agent: %w", task.TaskId, err)
			}
			return &pb.Task{}, nil
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

		// Historical reuse is planned only after the destination Agent is known,
		// because private network zones are derived from that Agent's registered
		// tags. A full reuse completes the Attempt before assignment; partial
		// target reuse sends only the remaining targets to the Agent.
		reuse := db.ScanReuseAtClaimResult{}
		if s.ackTaskHook != nil && msgID != "" {
			plannedReuse, reuseErr := db.ApplyReusableCoverageAtClaim(db.DB, sub.ID, sub.TenantID, req.AgentId)
			if reuseErr != nil {
				if s.returnTaskHook == nil {
					return &pb.Task{}, fmt.Errorf("return task %s after reuse planning failure: queue return hook is unavailable: %w", task.TaskId, reuseErr)
				}
				if err := s.returnTaskHook(task, msgID); err != nil {
					return &pb.Task{}, fmt.Errorf("return task %s after reuse planning failure: %w", task.TaskId, err)
				}
				log.Printf("[ClaimTask] Reuse planning deferred task %s: %v", task.TaskId, reuseErr)
				continue
			}
			reuse = plannedReuse
			if reuse.FullyReused {
				if sub.RootTaskID != "" {
					_ = db.SyncTaskBatchStatuses(db.DB, sub.TenantID, sub.RootTaskID)
					db.RefreshRootTaskStatus(sub.RootTaskID)
				}
				if err := s.ackTaskHook(msgID); err != nil {
					return &pb.Task{}, fmt.Errorf("ack fully reused task %s: %w", task.TaskId, err)
				}
				log.Printf("[ClaimTask] Completed task %s from project coverage (targets=%d stages=%d)", task.TaskId, reuse.ReusedTargets, reuse.ReusedStages)
				continue
			}
		}

		// The Scanner executes one target as a whole pipeline. A fingerprint
		// WorkKey therefore acts as the execution mutex for that target: if an
		// identical pipeline is already active, park this Attempt and ACK its
		// queue message without consuming Agent capacity. Terminal resolution
		// will enqueue it for a fresh coverage decision.
		workClaimPlan := db.ScanWorkClaimPlan{}
		if s.ackTaskHook != nil && msgID != "" {
			claimTargets := task.Targets
			if reuse.ReusedTargets > 0 {
				claimTargets = reuse.RemainingTargets
			}
			plannedClaims, claimErr := db.PlanScanWorkClaimsAtClaim(db.DB, sub.ID, sub.TenantID, req.AgentId, claimTargets)
			if claimErr != nil {
				if s.returnTaskHook == nil {
					return &pb.Task{}, fmt.Errorf("return task %s after work claim planning failure: queue return hook is unavailable: %w", task.TaskId, claimErr)
				}
				if err := s.returnTaskHook(task, msgID); err != nil {
					return &pb.Task{}, fmt.Errorf("return task %s after work claim planning failure: %w", task.TaskId, err)
				}
				log.Printf("[ClaimTask] Work claim planning deferred task %s: %v", task.TaskId, claimErr)
				continue
			}
			workClaimPlan = plannedClaims
			attached, claimCount, attachErr := db.AttachAttemptToActiveWorkClaims(db.DB, workClaimPlan)
			if attachErr != nil {
				if s.returnTaskHook == nil {
					return &pb.Task{}, fmt.Errorf("return task %s after work claim attachment failure: queue return hook is unavailable: %w", task.TaskId, attachErr)
				}
				if err := s.returnTaskHook(task, msgID); err != nil {
					return &pb.Task{}, fmt.Errorf("return task %s after work claim attachment failure: %w", task.TaskId, err)
				}
				log.Printf("[ClaimTask] Work claim attachment deferred task %s: %v", task.TaskId, attachErr)
				continue
			}
			if attached {
				if err := s.ackTaskHook(msgID); err != nil {
					return &pb.Task{}, fmt.Errorf("ack work claim waiter %s: %w", task.TaskId, err)
				}
				if sub.RootTaskID != "" {
					_ = db.SyncTaskBatchStatuses(db.DB, sub.TenantID, sub.RootTaskID)
					db.RefreshRootTaskStatus(sub.RootTaskID)
				}
				log.Printf("[ClaimTask] Attached task %s to %d active project work claim(s)", task.TaskId, claimCount)
				continue
			}
		}

		if err := db.CheckTenantSubTaskClaimQuota(db.DB, sub.TenantID); err != nil {
			var quotaErr *db.TenantQuotaError
			if errors.As(err, &quotaErr) {
				if s.returnTaskHook != nil {
					_ = s.returnTaskHook(task, msgID)
				}
				log.Printf("[ClaimTask] Tenant quota blocked task %s for Agent %s: %s", task.TaskId, req.AgentId, quotaErr.Message)
				return &pb.Task{}, nil
			}
			if s.returnTaskHook != nil {
				_ = s.returnTaskHook(task, msgID)
			}
			log.Printf("[ClaimTask] Tenant quota check failed for task %s: %v", task.TaskId, err)
			continue
		}

		// Lock the Agent row through the final lease CAS. EmergencyDump updates the
		// same row to Draining, so either this claim becomes visible to the dump or
		// the fetched MQ message is returned without creating a new lease.
		tx := db.DB.Begin()
		if tx.Error != nil {
			if s.returnTaskHook != nil {
				_ = s.returnTaskHook(task, msgID)
			}
			return &pb.Task{}, tx.Error
		}
		var claimNode db.Node
		claimNodeErr := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("agent_id", "tenant_id", "status", "version", "rule_version", "tags").
			Where("agent_id = ? AND tenant_id = ? AND UPPER(status) = ?", req.AgentId, sub.TenantID, "ALIVE").
			First(&claimNode).Error
		if claimNodeErr != nil {
			tx.Rollback()
			if s.returnTaskHook == nil {
				return &pb.Task{}, fmt.Errorf("return task %s after agent drain: queue return hook is unavailable", task.TaskId)
			}
			if err := s.returnTaskHook(task, msgID); err != nil {
				return &pb.Task{}, fmt.Errorf("return task %s after agent drain: %w", task.TaskId, err)
			}
			log.Printf("[ClaimTask] Agent %s stopped accepting work before lease commit; returned task %s", req.AgentId, task.TaskId)
			return &pb.Task{}, nil
		}
		if err := db.ValidateReusableCoverageLinksAtLease(tx, sub.ID, sub.TenantID, req.AgentId, reuse.Links); err != nil {
			tx.Rollback()
			if s.returnTaskHook == nil {
				return &pb.Task{}, fmt.Errorf("return task %s after reusable coverage changed: queue return hook is unavailable: %w", task.TaskId, err)
			}
			if returnErr := s.returnTaskHook(task, msgID); returnErr != nil {
				return &pb.Task{}, fmt.Errorf("return task %s after reusable coverage changed: %w", task.TaskId, returnErr)
			}
			log.Printf("[ClaimTask] Replanned task %s after reusable coverage changed: %v", task.TaskId, err)
			continue
		}
		var resumeLinks []db.TaskCoverageLink
		var resumeConfig []byte
		useResumePlan := reuse.ResumePlan != nil && len(reuse.ResumePlan.ReusedStages) > 0 &&
			agentSupportsCheckpointResume(claimNode.Version) && strings.TrimSpace(claimNode.RuleVersion) == strings.TrimSpace(sub.RuleVersion)
		if useResumePlan {
			resumeLinks, err = db.ValidateResumePlanAtLease(tx, sub.ID, sub.TenantID, req.AgentId, reuse.ResumePlan, reuse.ResumePlanHash)
			if err == nil {
				resumeConfig, err = configWithResumePlan(sub.Config, reuse.ResumePlan, reuse.ResumePlanHash)
			}
			if err != nil {
				tx.Rollback()
				if s.returnTaskHook == nil {
					return &pb.Task{}, fmt.Errorf("return task %s after resume plan changed: queue return hook is unavailable: %w", task.TaskId, err)
				}
				if returnErr := s.returnTaskHook(task, msgID); returnErr != nil {
					return &pb.Task{}, fmt.Errorf("return task %s after resume plan changed: %w", task.TaskId, returnErr)
				}
				log.Printf("[ClaimTask] Replanned task %s after resume evidence changed: %v", task.TaskId, err)
				continue
			}
		}
		claimConfig, deferred, err := s.resolveClaimSubdomainConfig(tx, task, sub, resumeConfig, msgID, claimNode.Tags)
		if err != nil {
			return &pb.Task{}, err
		}
		if deferred {
			continue
		}
		acquiredClaims, err := db.AcquireScanWorkClaimsAtLease(tx, workClaimPlan)
		if err != nil {
			tx.Rollback()
			if s.returnTaskHook == nil {
				return &pb.Task{}, fmt.Errorf("return task %s after work claim acquisition failure: queue return hook is unavailable: %w", task.TaskId, err)
			}
			if returnErr := s.returnTaskHook(task, msgID); returnErr != nil {
				return &pb.Task{}, fmt.Errorf("return task %s after work claim acquisition failure: %w", task.TaskId, returnErr)
			}
			log.Printf("[ClaimTask] Replanned task %s after work claim acquisition changed: %v", task.TaskId, err)
			continue
		}
		if acquiredClaims.Conflict {
			tx.Rollback()
			attached, claimCount, attachErr := db.AttachAttemptToActiveWorkClaims(db.DB, workClaimPlan)
			if attachErr != nil {
				if s.returnTaskHook == nil {
					return &pb.Task{}, fmt.Errorf("return raced work claim task %s: queue return hook is unavailable: %w", task.TaskId, attachErr)
				}
				if returnErr := s.returnTaskHook(task, msgID); returnErr != nil {
					return &pb.Task{}, fmt.Errorf("return raced work claim task %s: %w", task.TaskId, returnErr)
				}
				continue
			}
			if attached {
				if err := s.ackTaskHook(msgID); err != nil {
					return &pb.Task{}, fmt.Errorf("ack raced work claim waiter %s: %w", task.TaskId, err)
				}
				log.Printf("[ClaimTask] Attached raced task %s to %d active project work claim(s)", task.TaskId, claimCount)
				continue
			}
			if s.returnTaskHook == nil {
				return &pb.Task{}, fmt.Errorf("return task %s after work claim race: queue return hook is unavailable", task.TaskId)
			}
			if err := s.returnTaskHook(task, msgID); err != nil {
				return &pb.Task{}, fmt.Errorf("return task %s after work claim race: %w", task.TaskId, err)
			}
			continue
		}

		// 认领成功：CAS 更新 DB 状态，避免并发状态漂移（例如被取消/超时回收）
		attemptUpdates := map[string]interface{}{
			"status":        "Running",
			"agent_id":      req.AgentId,
			"stream_msg_id": msgID,
			"started_at":    time.Now(),
		}
		if reuse.ReusedTargets > 0 {
			remainingJSON, err := json.Marshal(reuse.RemainingTargets)
			if err != nil {
				tx.Rollback()
				if s.returnTaskHook != nil {
					_ = s.returnTaskHook(task, msgID)
				}
				return &pb.Task{}, fmt.Errorf("encode remaining targets for task %s: %w", task.TaskId, err)
			}
			attemptUpdates["chunk_targets"] = string(remainingJSON)
		}
		updateRes := tx.Model(&db.SubTask{}).
			Where("id = ? AND tenant_id = ? AND status IN ?", task.TaskId, sub.TenantID, claimableSubTaskStatuses).
			Updates(attemptUpdates)
		if updateRes.Error != nil {
			tx.Rollback()
			if s.returnTaskHook != nil {
				_ = s.returnTaskHook(task, msgID)
			}
			log.Printf("[ClaimTask] Failed to set running state for %s: %v", task.TaskId, updateRes.Error)
			continue
		}
		if updateRes.RowsAffected == 0 {
			tx.Rollback()
			// 任务状态已变化（例如 CancelPending/Timeout），退回队列给下一轮处理。
			if s.returnTaskHook != nil {
				_ = s.returnTaskHook(task, msgID)
			}
			log.Printf("[ClaimTask] Task %s state changed before claim commit, returned to queue", task.TaskId)
			continue
		}
		for index := range reuse.Links {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&reuse.Links[index]).Error; err != nil {
				tx.Rollback()
				if s.returnTaskHook != nil {
					_ = s.returnTaskHook(task, msgID)
				}
				return &pb.Task{}, fmt.Errorf("record reusable coverage for task %s: %w", task.TaskId, err)
			}
		}
		for index := range resumeLinks {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&resumeLinks[index]).Error; err != nil {
				tx.Rollback()
				if s.returnTaskHook != nil {
					_ = s.returnTaskHook(task, msgID)
				}
				return &pb.Task{}, fmt.Errorf("record resume coverage for task %s: %w", task.TaskId, err)
			}
		}
		for index := range acquiredClaims.Links {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&acquiredClaims.Links[index]).Error; err != nil {
				tx.Rollback()
				if s.returnTaskHook != nil {
					_ = s.returnTaskHook(task, msgID)
				}
				return &pb.Task{}, fmt.Errorf("record executed work claim for task %s: %w", task.TaskId, err)
			}
		}
		if sub.BatchID != "" {
			batchUpdate := tx.Model(&db.TaskBatch{}).
				Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", sub.BatchID, sub.TenantID, sub.ID).
				Update("status", "Running")
			if batchUpdate.Error != nil {
				tx.Rollback()
				if s.returnTaskHook != nil {
					_ = s.returnTaskHook(task, msgID)
				}
				return &pb.Task{}, fmt.Errorf("update batch %s for task claim: %w", sub.BatchID, batchUpdate.Error)
			}
		}
		if err := tx.Exec("UPDATE nodes SET running_tasks = running_tasks + 1 WHERE agent_id = ? AND tenant_id = ?", req.AgentId, sub.TenantID).Error; err != nil {
			tx.Rollback()
			if s.returnTaskHook != nil {
				_ = s.returnTaskHook(task, msgID)
			}
			return &pb.Task{}, fmt.Errorf("update agent running count for task %s: %w", task.TaskId, err)
		}
		if err := tx.Commit().Error; err != nil {
			if s.returnTaskHook != nil {
				_ = s.returnTaskHook(task, msgID)
			}
			return &pb.Task{}, fmt.Errorf("commit task claim %s: %w", task.TaskId, err)
		}
		if reuse.ReusedTargets > 0 {
			task.Targets = append([]string(nil), reuse.RemainingTargets...)
			log.Printf("[ClaimTask] Reused project coverage for task %s (targets=%d stages=%d remaining=%d)", task.TaskId, reuse.ReusedTargets, reuse.ReusedStages, len(task.Targets))
		}
		task.Config = claimConfig
		if len(resumeConfig) > 0 {
			log.Printf("[ClaimTask] Applied checkpoint resume for task %s (reused_stages=%d execute_stages=%d)", task.TaskId, len(reuse.ResumePlan.ReusedStages), len(reuse.ResumePlan.ExecutionStages))
		}

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
	var sessionNode db.Node
	if err := db.DB.Select("agent_id", "tenant_id", "status", "token_expires_at", "token_revoked_at").Where("agent_id = ?", req.AgentId).First(&sessionNode).Error; err == nil {
		if sessionNode.TokenRevokedAt != nil || (sessionNode.TokenExpiresAt != nil && time.Now().After(*sessionNode.TokenExpiresAt)) {
			return &pb.HeartbeatResp{
				Ack:             true,
				ShouldTerminate: true,
				ShouldSyncRules: false,
				TasksAvailable:  0,
			}, nil
		}
		if isTerminatingSpotAgent(req.AgentId, sessionNode.TenantID) {
			s.Hub.UpdateFreeSlots(req.AgentId, 0)
			return &pb.HeartbeatResp{
				Ack:             true,
				ShouldTerminate: true,
				ShouldSyncRules: false,
				TasksAvailable:  0,
			}, nil
		}
	}

	taskIDsJSON := "[]"
	if len(req.RunningTaskIds) > 0 {
		b, _ := json.Marshal(req.RunningTaskIds)
		taskIDsJSON = string(b)
	}

	updates := map[string]interface{}{
		"status":        "Alive",
		"last_beat":     time.Now().UnixMilli(),
		"running_tasks": heartbeatRunningTasksExpr(int(req.RunningTasks)),
		"cpu_usage":     req.CpuUsage,
		"mem_usage":     req.MemUsage,
	}
	if len(req.RunningTaskIds) > 0 {
		updates["running_task_ids"] = taskIDsJSON
	}
	if req.RuleVersion != "" {
		updates["rule_version"] = req.RuleVersion
	}

	// Upsert 语义：如果节点记录被自动清理协程删除了（10 分钟离线 → DELETE），
	// 心跳应该重新创建记录，避免 Agent 在运行但 UI 不可见的"幽灵节点"问题。
	res := db.DB.Model(&db.Node{}).Where("agent_id = ?", req.AgentId).Updates(updates)
	if res.Error == nil && res.RowsAffected == 0 {
		// 节点记录不存在（被清理或从未注册），重新创建
		db.DB.Save(&db.Node{
			TenantID:       "default",
			AgentID:        req.AgentId,
			Status:         "Alive",
			LastBeat:       time.Now().UnixMilli(),
			RunningTasks:   int(req.RunningTasks),
			RunningTaskIDs: taskIDsJSON,
			CPUUsage:       float32(req.CpuUsage),
			MemUsage:       float32(req.MemUsage),
			RuleVersion:    req.RuleVersion,
		})
		log.Printf("[Heartbeat] Re-created node record for Agent %s (was previously cleaned up)", req.AgentId)
	}

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

func isTerminatingSpotAgent(agentID, tenantID string) bool {
	var count int64
	err := db.DB.Model(&db.CloudInstance{}).
		Where("agent_id = ? AND tenant_id = ? AND spot = ? AND status = ?", agentID, tenantID, true, db.CloudStatusTerminating).
		Count(&count).Error
	return err == nil && count > 0
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

	// A cancellation already accepted by the server wins over a late FAILED/TIMEOUT
	// report from the Agent. This prevents the retry path from resurrecting it.
	if currentStatus == "CANCELPENDING" {
		status = "CANCELLED"
	}
	log.Printf("[TaskComplete] SubTask %s by Agent %s => Status: %s", req.TaskId, req.AgentId, status)

	finishedAt := time.Now()
	failureReason := db.NormalizeAttemptFailureReason(req.ErrorMessage)
	if failureReason == "" {
		switch status {
		case "FAILED":
			failureReason = "Agent reported scan failure"
		case "TIMEOUT":
			failureReason = "Agent reported scan timeout"
		case "CANCELLED":
			failureReason = "scan attempt cancelled"
		}
	}
	updates := map[string]interface{}{
		"status":         status,
		"stream_msg_id":  "",
		"failure_reason": failureReason,
		"finished_at":    finishedAt,
	}
	completion := db.DB.Model(&db.SubTask{}).
		Where("id = ? AND tenant_id = ? AND status = ?", req.TaskId, sub.TenantID, sub.Status)
	if sub.AgentID != "" {
		completion = completion.Where("agent_id = ?", req.AgentId)
	}
	completion = completion.Updates(updates)
	if completion.Error != nil {
		return &pb.Ack{Success: false, Message: "failed to persist completion"}, nil
	}
	if completion.RowsAffected != 1 {
		log.Printf("[TaskComplete] Ignored completion for %s because its lease or status changed", req.TaskId)
		return &pb.Ack{Success: true, Message: "stale completion ignored"}, nil
	}
	sub.Status = status
	sub.FailureReason = failureReason
	sub.FinishedAt = &finishedAt
	if sub.BatchID != "" {
		batchUpdates := map[string]interface{}{"status": status}
		if status == "DONE" {
			batchUpdates["control_state"] = db.BatchControlActive
		}
		if err := db.DB.Model(&db.TaskBatch{}).
			Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", sub.BatchID, sub.TenantID, sub.ID).
			Updates(batchUpdates).Error; err != nil {
			log.Printf("[TaskComplete] Failed to update batch %s status: %v", sub.BatchID, err)
		}
		if status == "CANCELLED" {
			_ = db.SettleStoppedTaskBatch(db.DB, sub.TenantID, sub.BatchID, sub.ID)
		}
	}

	// 仅在任务处于活跃态时扣减节点并发计数。
	if currentStatus == "RUNNING" || currentStatus == "CANCELPENDING" {
		db.DB.Model(&db.Node{}).Where("agent_id = ?", req.AgentId).Update("running_tasks", decrementRunningTasksExpr())
	}

	// 终态统一 ACK，防止 FAILED/CANCELLED 任务在 MQ 中“复活”。
	if s.ackTaskHook != nil && sub.StreamMsgID != "" {
		_ = s.ackTaskHook(sub.StreamMsgID)
	}

	// 失败批次拆分重试：对多目标失败批次执行二分拆分
	if (status == "FAILED" || status == "TIMEOUT") && sub.RootTaskID != "" && !isCredentialValidationConfig(sub.Config) {
		splitSubs, didSplit, _ := db.SplitFailedSubTask(&sub, false)
		if didSplit && len(splitSubs) > 0 {
			// 拆分成功，将两个子批次推入 urgent 队列优先调度。
			for _, splitSub := range splitSubs {
				s.enqueuePreparedRetry(splitSub)
			}
			log.Printf("[SplitRetry] Task %s split into %d sub-batches and re-enqueued", req.TaskId, len(splitSubs))
		} else if prepared, ok := db.PrepareSubTaskRetry(&sub); ok {
			// 普通重试：单目标批次失败或无法拆分时，走常规重试流程
			log.Printf("[Retry] Task %s failed, regular retry (%d/%d)", req.TaskId, prepared.RetryCount, prepared.MaxRetry)
			s.enqueuePreparedRetry(prepared)
		}
	}

	// Release the source's unique WorkClaims only after its terminal state is
	// durable. Waiters are moved to Dispatching in the same DB transaction and
	// then re-enqueued; a queue failure deliberately leaves them recoverable by
	// the periodic dispatch reconciler.
	readyWaiters, resolveErr := db.ResolveScanWorkClaimsForAttempt(db.DB, sub.ID)
	if resolveErr != nil {
		log.Printf("[WorkClaim] Failed to resolve terminal source %s: %v", sub.ID, resolveErr)
	} else {
		for _, waiter := range readyWaiters {
			s.enqueueWorkClaimReplan(waiter)
		}
		if len(readyWaiters) > 0 {
			log.Printf("[WorkClaim] Replanned %d waiter(s) after source %s became %s", len(readyWaiters), sub.ID, status)
		}
	}

	if status == "DONE" && sub.RootTaskID != "" {
		db.DB.Exec("UPDATE root_tasks SET completed_chunks = completed_chunks + 1 WHERE id = ?", sub.RootTaskID)
	}
	if sub.RootTaskID != "" {
		if s.onTaskTerminalHook != nil {
			if err := s.onTaskTerminalHook(ctx, sub); err != nil {
				log.Printf("[ScanStageOrchestrator] Failed to derive validation stages for %s: %v", sub.RootTaskID, err)
			}
		}
		db.RefreshRootTaskStatus(sub.RootTaskID)
	}

	// ★ 核心：任务完成后，检查队列是否还有任务，主动通知该 Agent 继续认领
	// 这保证了 Agent 完成一个任务后立即知道还有任务可做，杜绝空闲浪费
	if depth := s.getQueueDepth(); depth > 0 {
		s.Hub.NotifyAgent(req.AgentId, depth, "task_completed")
	}

	return &pb.Ack{Success: true}, nil
}

func (s *Server) enqueuePreparedRetry(sub db.SubTask) bool {
	pbSub, err := db.SubTaskToProto(&sub)
	if err != nil || pbSub == nil {
		log.Printf("[Retry] Failed to encode subtask %s: %v", sub.ID, err)
		return false
	}
	pbSub.Priority = 0
	if s.requeueTaskHook == nil {
		return false
	}
	if err := s.requeueTaskHook(pbSub); err != nil {
		log.Printf("[Retry] Failed to enqueue subtask %s: %v", sub.ID, err)
		return false
	}

	update := db.DB.Model(&db.SubTask{}).
		Where("id = ? AND tenant_id = ? AND status = ?", sub.ID, sub.TenantID, "Dispatching").
		Updates(map[string]interface{}{
			"status":        "Pending",
			"stream_msg_id": retryQueuedMarker,
		})
	if update.Error != nil {
		log.Printf("[Retry] Subtask %s queued but Pending transition failed: %v", sub.ID, update.Error)
		return false
	}
	if update.RowsAffected != 1 {
		return false
	}
	if sub.BatchID != "" {
		if err := db.DB.Model(&db.TaskBatch{}).
			Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", sub.BatchID, sub.TenantID, sub.ID).
			Update("status", "Pending").Error; err != nil {
			log.Printf("[Retry] Batch %s Pending transition failed: %v", sub.BatchID, err)
			return false
		}
	}
	return true
}

func (s *Server) enqueueWorkClaimReplan(sub db.SubTask) bool {
	pbSub, err := db.SubTaskToProto(&sub)
	if err != nil || pbSub == nil {
		log.Printf("[WorkClaim] Failed to encode replanned subtask %s: %v", sub.ID, err)
		return false
	}
	if s.requeueTaskHook == nil {
		return false
	}
	if err := s.requeueTaskHook(pbSub); err != nil {
		log.Printf("[WorkClaim] Failed to enqueue replanned subtask %s: %v", sub.ID, err)
		return false
	}

	update := db.DB.Model(&db.SubTask{}).
		Where("id = ? AND tenant_id = ? AND status = ?", sub.ID, sub.TenantID, "Dispatching").
		Updates(map[string]interface{}{
			"status":        "Pending",
			"stream_msg_id": retryQueuedMarker,
		})
	if update.Error != nil {
		log.Printf("[WorkClaim] Replanned subtask %s queued but Pending transition failed: %v", sub.ID, update.Error)
		return false
	}
	if update.RowsAffected != 1 {
		return false
	}
	if sub.BatchID != "" {
		if err := db.DB.Model(&db.TaskBatch{}).
			Where("id = ? AND tenant_id = ? AND latest_attempt_id = ?", sub.BatchID, sub.TenantID, sub.ID).
			Update("status", "Pending").Error; err != nil {
			log.Printf("[WorkClaim] Batch %s Pending transition failed: %v", sub.BatchID, err)
			return false
		}
	}
	return true
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
		if res.PayloadType == scanplan.StageObservationPayloadType {
			event, err := validateStageObservationResult(res)
			if err != nil {
				return status.Error(codes.InvalidArgument, err.Error())
			}
			attempt, err := validateStageObservationOwnership(event)
			if err != nil {
				return status.Error(codes.PermissionDenied, err.Error())
			}
			merged, err := db.MergeStageObservationEvent(db.DB, attempt, event)
			if err != nil {
				return status.Error(codes.Internal, "merge coverage event: "+err.Error())
			}
			if db.WSBroadcastHook != nil {
				db.WSBroadcastHook(attempt.TenantID, map[string]interface{}{
					"type":                  "coverage_event",
					"task_id":               attempt.RootTaskID,
					"attempt_id":            attempt.ID,
					"stage":                 event.Stage,
					"outcome":               event.Outcome,
					"observations_created":  merged.ObservationsCreated,
					"coverages_created":     merged.CoveragesCreated,
					"coverages_updated":     merged.CoveragesUpdated,
					"coverages_invalidated": merged.CoveragesInvalidated,
				})
			}
			continue
		}
		if res.PayloadType == scanplan.TimingEventPayloadType {
			if err := persistTimingEvent(stream.Context(), res); err != nil {
				return err
			}
			continue
		}
		if handled, err := persistCredentialValidationResult(stream.Context(), res); handled {
			if err != nil {
				return status.Error(codes.PermissionDenied, err.Error())
			}
			continue
		}
		db.AddResultAsync(res.TaskId, res.PayloadType, string(res.Payload))
	}
}

func validateStageObservationResult(result *pb.ScanResult) (scanplan.StageObservationEvent, error) {
	if result == nil || strings.TrimSpace(result.TaskId) == "" {
		return scanplan.StageObservationEvent{}, errors.New("coverage event requires task_id")
	}
	var event scanplan.StageObservationEvent
	if err := json.Unmarshal(result.Payload, &event); err != nil {
		return scanplan.StageObservationEvent{}, fmt.Errorf("decode coverage event: %w", err)
	}
	if err := event.Validate(); err != nil {
		return scanplan.StageObservationEvent{}, fmt.Errorf("validate coverage event: %w", err)
	}
	if event.AttemptID != strings.TrimSpace(result.TaskId) {
		return scanplan.StageObservationEvent{}, errors.New("coverage event attempt_id does not match stream task_id")
	}
	return event, nil
}

func validateStageObservationOwnership(event scanplan.StageObservationEvent) (db.SubTask, error) {
	var attempt db.SubTask
	if err := db.DB.Where("id = ? AND agent_id = ? AND status IN ?", event.AttemptID, event.AgentID, activeSubTaskStatuses).
		First(&attempt).Error; err != nil {
		return db.SubTask{}, errors.New("coverage event does not belong to an active attempt assigned to this agent")
	}
	var assignedTargets []string
	if err := json.Unmarshal([]byte(attempt.ChunkTargets), &assignedTargets); err != nil {
		return db.SubTask{}, errors.New("assigned attempt targets are invalid")
	}
	allowed := make(map[string]struct{}, len(assignedTargets))
	for _, target := range assignedTargets {
		target = strings.TrimSpace(target)
		if target != "" {
			allowed[target] = struct{}{}
		}
	}
	for _, target := range event.Targets {
		if _, ok := allowed[target]; !ok {
			return db.SubTask{}, fmt.Errorf("coverage target %q is outside the assigned attempt", target)
		}
	}
	return attempt, nil
}

// ============================================================================
// EmergencyDump — 紧急数据下刷
// ============================================================================

func (s *Server) EmergencyDump(ctx context.Context, req *pb.EmergencyReq) (*pb.Ack, error) {
	agentID := strings.TrimSpace(req.AgentId)
	node, err := validateEmergencyAgentSession(ctx, agentID)
	if err != nil {
		return nil, err
	}
	tenantID := strings.TrimSpace(node.TenantID)
	if tenantID == "" {
		tenantID = "default"
	}

	var instance db.CloudInstance
	if err := db.DB.Where(
		"agent_id = ? AND tenant_id = ? AND spot = ? AND status IN ?",
		agentID,
		tenantID,
		true,
		[]string{db.CloudStatusRunning, db.CloudStatusWaitingReady, db.CloudStatusTerminating},
	).First(&instance).Error; err != nil {
		return nil, status.Error(codes.FailedPrecondition, "agent is not attached to a reclaimable Spot instance")
	}
	if strings.EqualFold(node.Status, "Offline") && instance.Status != db.CloudStatusTerminating {
		return nil, status.Error(codes.FailedPrecondition, "offline agent has no in-progress Spot termination")
	}

	log.Printf("[EmergencyDump] Agent %s triggered Spot termination emergency dump!", agentID)

	// Stop new claims before releasing any existing lease. The session token is
	// preserved so a lost RPC response can be retried idempotently.
	db.DB.Model(&db.Node{}).
		Where("agent_id = ? AND tenant_id = ?", agentID, tenantID).
		Update("status", "Draining")
	s.Hub.UpdateFreeSlots(agentID, 0)
	db.DB.Model(&db.CloudInstance{}).
		Where("id = ? AND tenant_id = ? AND status IN ?", instance.ID, tenantID, []string{db.CloudStatusRunning, db.CloudStatusWaitingReady}).
		Updates(map[string]interface{}{
			"status":        db.CloudStatusTerminating,
			"error_message": "Spot instance preempted by cloud provider",
		})

	var orphanTasks []db.SubTask
	if err := db.DB.Where("tenant_id = ? AND agent_id = ? AND status IN ?", tenantID, agentID, []string{"Running", "CancelPending"}).Find(&orphanTasks).Error; err != nil {
		return &pb.Ack{Success: false, Message: "failed to load active Spot leases"}, nil
	}

	released := 0
	requeued := 0
	ackFailures := 0
	for _, sub := range orphanTasks {
		if sub.StreamMsgID != "" {
			if s.ackTaskHook == nil {
				ackFailures++
				log.Printf("[EmergencyDump] Cannot release subtask %s: queue ACK hook is unavailable", sub.ID)
				continue
			}
			if err := s.ackTaskHook(sub.StreamMsgID); err != nil {
				ackFailures++
				log.Printf("[EmergencyDump] Failed to ACK old lease for subtask %s: %v", sub.ID, err)
				continue
			}
		}

		if db.IsStoppingAttemptStatus(sub.Status) {
			finishedAt := time.Now()
			update := db.DB.Model(&db.SubTask{}).
				Where(
					"id = ? AND tenant_id = ? AND status = ? AND agent_id = ? AND stream_msg_id = ?",
					sub.ID, sub.TenantID, sub.Status, sub.AgentID, sub.StreamMsgID,
				).
				Updates(map[string]interface{}{
					"status":         "Cancelled",
					"stream_msg_id":  "",
					"failure_reason": "cancelled during Spot instance termination",
					"finished_at":    finishedAt,
				})
			if update.Error != nil || update.RowsAffected != 1 {
				log.Printf("[EmergencyDump] Failed to settle cancelled attempt %s: %v", sub.ID, update.Error)
				continue
			}
			released++
			_ = db.SettleStoppedTaskBatch(db.DB, sub.TenantID, sub.BatchID, sub.ID)
			_ = db.SyncTaskBatchStatuses(db.DB, sub.TenantID, sub.RootTaskID)
		} else {
			prepared, appended, appendErr := credentialbundle.AppendRetry(db.DB, &sub, db.AttemptRetryOptions{
				Trigger:              db.AttemptTriggerSpotRecovery,
				TerminalStatus:       "Failed",
				FailureReason:        "Agent lease interrupted by Spot instance termination",
				ConsumeRetryBudget:   false,
				UseCurrentTaskConfig: true,
			})
			if appendErr != nil {
				log.Printf("[EmergencyDump] Failed to prepare replacement attempt for %s: %v", sub.ID, appendErr)
				continue
			}
			if !appended {
				if db.SettlePausedTaskBatchAttempt(&sub, "Failed", "Agent lease interrupted while batch was paused") {
					released++
					if sub.RootTaskID != "" {
						db.RefreshRootTaskStatus(sub.RootTaskID)
					}
					continue
				}
				log.Printf("[EmergencyDump] Attempt %s lease already changed; skipping duplicate recovery", sub.ID)
				continue
			}
			released++
			if s.enqueuePreparedRetry(prepared) {
				requeued++
			}
		}

		if sub.RootTaskID != "" {
			db.RefreshRootTaskStatus(sub.RootTaskID)
		}
	}

	if requeued > 0 {
		s.Hub.BroadcastNewTask(int32(requeued), 0)
	}

	var remaining []string
	_ = db.DB.Model(&db.SubTask{}).
		Where("tenant_id = ? AND agent_id = ? AND status IN ?", tenantID, agentID, []string{"Running", "CancelPending"}).
		Pluck("id", &remaining).Error
	remainingJSON, _ := json.Marshal(remaining)
	db.DB.Model(&db.Node{}).
		Where("agent_id = ? AND tenant_id = ?", agentID, tenantID).
		Updates(map[string]interface{}{
			"status":           "Offline",
			"running_tasks":    len(remaining),
			"running_task_ids": string(remainingJSON),
		})

	log.Printf("[EmergencyDump] Agent %s: released=%d requeued=%d ack_failures=%d remaining=%d", agentID, released, requeued, ackFailures, len(remaining))
	if ackFailures > 0 {
		return &pb.Ack{Success: false, Message: fmt.Sprintf("emergency dump incomplete: %d queue acknowledgements failed", ackFailures)}, nil
	}
	return &pb.Ack{Success: true, Message: fmt.Sprintf("emergency dump processed: %d leases released, %d tasks requeued", released, requeued)}, nil
}

func validateEmergencyAgentSession(ctx context.Context, agentID string) (db.Node, error) {
	if agentID == "" {
		return db.Node{}, status.Error(codes.InvalidArgument, "agent_id is required")
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return db.Node{}, status.Error(codes.Unauthenticated, "missing agent session metadata")
	}
	tokens := md.Get("x-agent-token")
	if len(tokens) == 0 || strings.TrimSpace(tokens[0]) == "" {
		return db.Node{}, status.Error(codes.Unauthenticated, "missing agent session token")
	}

	var node db.Node
	if err := db.DB.Select("agent_id", "tenant_id", "status", "token", "token_expires_at", "token_revoked_at").Where("agent_id = ?", agentID).First(&node).Error; err != nil {
		return db.Node{}, status.Error(codes.Unauthenticated, "invalid agent session")
	}
	token := strings.TrimSpace(tokens[0])
	if node.TokenRevokedAt != nil || (node.TokenExpiresAt != nil && time.Now().After(*node.TokenExpiresAt)) || strings.TrimSpace(node.Token) == "" || subtle.ConstantTimeCompare([]byte(token), []byte(node.Token)) != 1 {
		return db.Node{}, status.Error(codes.Unauthenticated, "invalid agent session")
	}
	switch strings.ToUpper(strings.TrimSpace(node.Status)) {
	case "ALIVE", "DRAINING", "OFFLINE":
	default:
		return db.Node{}, status.Error(codes.FailedPrecondition, "agent session is not in a reclaimable state")
	}
	return node, nil
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

		logItem := db.AgentLog{
			TenantID:  tenantIDForAgentLog(payload.AgentId),
			AgentID:   payload.AgentId,
			Level:     payload.Level,
			Message:   payload.Message,
			Timestamp: payload.Timestamp,
		}
		db.DB.Create(&logItem)
		createAgentLogAlerts(logItem)

		log.Printf("[Telemetry][Agent %s][%s] %s", payload.AgentId, payload.Level, payload.Message)
	}
}

func tenantIDForAgent(agentID string) string {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return "default"
	}
	var node db.Node
	if err := db.DB.Select("tenant_id").Where("agent_id = ?", agentID).First(&node).Error; err == nil && strings.TrimSpace(node.TenantID) != "" {
		return node.TenantID
	}
	return "default"
}

func tenantIDForAgentLog(agentID string) string {
	return tenantIDForAgent(agentID)
}

func createAgentLogAlerts(logItem db.AgentLog) {
	tenantID := strings.TrimSpace(logItem.TenantID)
	if tenantID == "" {
		tenantID = tenantIDForAgentLog(logItem.AgentID)
	}
	var rules []db.AgentLogAlertRule
	db.DB.Where("tenant_id = ? AND enabled = ?", tenantID, true).Find(&rules)
	for _, rule := range rules {
		if rule.AgentID != "" && rule.AgentID != logItem.AgentID {
			continue
		}
		if rule.Level != "" && !strings.EqualFold(rule.Level, logItem.Level) {
			continue
		}
		if rule.Keyword != "" && !strings.Contains(strings.ToLower(logItem.Message), strings.ToLower(rule.Keyword)) {
			continue
		}
		_ = db.DB.Create(&db.AgentLogAlertEvent{
			TenantID:  tenantID,
			RuleID:    rule.ID,
			AgentID:   logItem.AgentID,
			Level:     logItem.Level,
			Message:   logItem.Message,
			LogID:     logItem.ID,
			CreatedAt: time.Now(),
		}).Error
	}
}

// ============================================================================
// StreamDebug — 接收 Agent 侧 POC 调试事件（不入库）
// ============================================================================

func (s *Server) StreamDebug(stream pb.AgentService_StreamDebugServer) error {
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.Ack{Success: true})
		}
		if err != nil {
			return err
		}
		if event == nil {
			continue
		}
		if db.DebugEventHook != nil {
			db.DebugEventHook(event)
		}
	}
}

// ============================================================================
// 内部辅助方法
// ============================================================================

func (s *Server) matchAgentSelector(taskID string, nodeTags string) bool {
	var sub db.SubTask
	if db.DB.Select("agent_selector", "agent_selector_rules").Where("id = ?", taskID).First(&sub).Error != nil {
		return true
	}

	selector := strings.TrimSpace(sub.AgentSelector)
	var selectorMap map[string]string
	if selector != "" && selector != "{}" {
		_ = json.Unmarshal([]byte(selector), &selectorMap)
	}
	rules := db.ParseSelectorRulesJSON(sub.AgentSelectorRules)
	matched, _ := db.NodeMatchesSelectorRules(selectorMap, rules, nodeTags)
	return matched
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
