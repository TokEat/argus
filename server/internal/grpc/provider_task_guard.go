package grpc

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
)

// taskRequestsLegacyProviderDiscovery detects persisted pre-migration task
// configs. Old rows remain readable for audit/history, but must never reach an
// Agent because Provider credentials and execution now belong to Server-only
// asset discovery.
func taskRequestsLegacyProviderDiscovery(task *pb.Task) bool {
	if task == nil || len(task.Config) == 0 {
		return false
	}
	var config struct {
		Hunter            bool
		Fofa              bool
		Quake             bool
		LowPerceptionMode bool
		OnlyIPPort        bool
		APIConfigFilePath string
	}
	if json.Unmarshal(task.Config, &config) != nil {
		return false
	}
	return config.Hunter || config.Fofa || config.Quake || config.LowPerceptionMode || config.OnlyIPPort || strings.TrimSpace(config.APIConfigFilePath) != ""
}

func (s *Server) rejectLegacyProviderTask(task *pb.Task, messageID string, sub db.SubTask) error {
	if s.ackTaskHook == nil {
		return fmt.Errorf("reject legacy Provider task %s: queue ACK hook is unavailable", task.TaskId)
	}
	finishedAt := time.Now()
	result := db.DB.Model(&db.SubTask{}).
		Where("id = ? AND tenant_id = ? AND status IN ?", sub.ID, sub.TenantID, claimableSubTaskStatuses).
		Updates(map[string]interface{}{
			"status": "Failed", "failure_reason": "Provider discovery configuration is Server-only",
			"finished_at": finishedAt, "agent_id": "", "stream_msg_id": "",
		})
	if result.Error != nil {
		return fmt.Errorf("record legacy Provider rejection for task %s: %w", task.TaskId, result.Error)
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("record legacy Provider rejection for task %s: claimable attempt changed concurrently", task.TaskId)
	}
	if sub.RootTaskID != "" {
		_ = db.SyncTaskBatchStatuses(db.DB, sub.TenantID, sub.RootTaskID)
		db.RefreshRootTaskStatus(sub.RootTaskID)
	}
	// Persist the terminal rejection before acknowledging the queue message. If
	// ACK fails, redelivery observes the Failed attempt and safely ACKs it as a
	// stale terminal message instead of losing a still-claimable attempt.
	if err := s.ackTaskHook(messageID); err != nil {
		return fmt.Errorf("ack rejected legacy Provider task %s: %w", task.TaskId, err)
	}
	log.Printf("[ClaimTask] Rejected legacy Provider discovery task %s", task.TaskId)
	return nil
}
