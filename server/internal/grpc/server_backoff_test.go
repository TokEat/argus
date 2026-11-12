package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	pb "github.com/TokEat/argus/shared/proto/go/scan"
)

// A retry whose exponential backoff has not yet elapsed must not be claimed:
// ClaimTask returns the message to the queue (Nack requeue) and yields an empty
// task, leaving the lease untouched so the controller can route it once eligible.
func TestClaimTaskRequeuesSubTaskWhoseBackoffHasNotElapsed(t *testing.T) {
	store := setupRegisterTestDB(t)
	eligibleAt := time.Now().Add(2 * time.Minute)
	if err := store.Create(&db.SubTask{
		ID:             "sub-backoff-pending",
		TenantID:       "default",
		Status:         "Pending",
		NextEligibleAt: &eligibleAt,
	}).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}

	server := NewServer(50051)
	acked := 0
	returned := 0
	server.SetClaimTaskHook(func(agentID string) (*pb.Task, string, error) {
		if acked+returned > 0 {
			return nil, "", nil
		}
		return &pb.Task{TaskId: "sub-backoff-pending", Targets: []string{"https://example.com"}}, "msg-backoff", nil
	})
	server.SetAckTaskHook(func(msgID string) error {
		if msgID == "msg-backoff" {
			acked++
		}
		return nil
	})
	server.SetReturnTaskHook(func(task *pb.Task, msgID string) error {
		if msgID == "msg-backoff" {
			returned++
		}
		return nil
	})

	task, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{
		AgentId:   "agent-1",
		FreeSlots: 1,
	})
	if err != nil {
		t.Fatalf("claim task: %v", err)
	}
	if task.GetTaskId() != "" {
		t.Fatalf("expected backed-off claim to return empty task, got %+v", task)
	}
	if acked != 0 || returned != 1 {
		t.Fatalf("expected backed-off message returned once and not acked, acked=%d returned=%d", acked, returned)
	}
	var sub db.SubTask
	if err := store.First(&sub, "id = ?", "sub-backoff-pending").Error; err != nil {
		t.Fatalf("reload subtask: %v", err)
	}
	if sub.Status != "Pending" || sub.AgentID != "" || sub.StreamMsgID != "" {
		t.Fatalf("backoff gate must not mutate the lease, got %+v", sub)
	}
}

// Once the backoff window has elapsed the gate is a no-op: the normal claim path
// proceeds and the retry binds to the claiming Agent. Seeded with a stable batch
// so the full claim machinery (selector, reuse, quota, CAS) is satisfied.
func TestClaimTaskClaimsSubTaskWhoseBackoffHasElapsed(t *testing.T) {
	store := setupRegisterTestDB(t)
	target := "https://elapsed.example.test"
	project := db.Project{ID: "project-backoff-elapsed", TenantID: "tenant-backoff-elapsed", Scope: `{}`}
	root := db.RootTask{ID: "root-backoff-elapsed", TenantID: project.TenantID, ProjectID: project.ID, Status: "Queued", TotalChunks: 1, TotalTargets: 1}
	eligibleAt := time.Now().Add(-time.Second)
	attempt := db.SubTask{
		ID: "attempt-backoff-elapsed", TenantID: project.TenantID, ProjectID: project.ID, RootTaskID: root.ID,
		BatchID: "batch-backoff-elapsed", AttemptNo: 1, Trigger: db.AttemptTriggerInitial,
		ChunkTargets: `[` + `"` + target + `"` + `]`, Status: "Pending", Config: grpcReusableTestConfig,
		Priority: 1, TimeoutSec: 60, ConfigVersion: 1, RuleVersion: "rules-v1",
		AgentSelector: `{}`, AgentSelectorRules: `{}`, NextEligibleAt: &eligibleAt,
	}
	batch := db.TaskBatch{
		ID: attempt.BatchID, TenantID: attempt.TenantID, ProjectID: project.ID, RootTaskID: root.ID,
		Sequence: 0, Kind: "asset_scan", Targets: attempt.ChunkTargets, TargetCount: 1, Status: "Pending",
		ControlState: string(db.BatchControlActive), ConfigVersion: 1, RuleVersion: attempt.RuleVersion,
		LatestAttemptID: attempt.ID, CurrentAttemptNo: 1, AttemptCount: 1,
	}
	for _, record := range []interface{}{
		&project, &root,
		&db.Node{AgentID: "agent-backoff-elapsed", TenantID: project.TenantID, Status: "Alive", Capacity: 1},
		&batch, &attempt,
	} {
		if err := store.Create(record).Error; err != nil {
			t.Fatalf("seed elapsed-backoff claim: %v", err)
		}
	}

	server := NewServer(50051)
	server.SetClaimTaskHook(func(string) (*pb.Task, string, error) {
		return &pb.Task{TaskId: attempt.ID, Targets: []string{target}, Config: []byte(grpcReusableTestConfig)}, "msg-elapsed", nil
	})
	server.SetAckTaskHook(func(string) error { return nil })
	server.SetReturnTaskHook(func(*pb.Task, string) error {
		t.Fatal("elapsed-backoff task was returned instead of claimed")
		return nil
	})

	claimed, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{
		AgentId:   "agent-backoff-elapsed",
		FreeSlots: 1,
	})
	if err != nil {
		t.Fatalf("claim task: %v", err)
	}
	if claimed.GetTaskId() != attempt.ID {
		t.Fatalf("expected elapsed-backoff task to be claimable, got %+v", claimed)
	}
	var bound db.SubTask
	if err := store.First(&bound, "id = ?", attempt.ID).Error; err != nil {
		t.Fatalf("reload subtask: %v", err)
	}
	if db.CanonicalAttemptState(bound.Status) != db.AttemptStateRunning || bound.AgentID != "agent-backoff-elapsed" {
		t.Fatalf("elapsed-backoff task was not bound to the agent: %+v", bound)
	}
}
