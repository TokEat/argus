package grpc

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

func setupRegisterTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&db.Node{}, &db.CloudInstance{}, &db.RootTask{}, &db.SubTask{}, &db.TenantQuota{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	old := db.DB
	db.DB = store
	t.Cleanup(func() {
		db.DB = old
	})
	return store
}

func TestClaimTaskRespectsTenantRunningSubTaskQuota(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.TenantQuota{TenantID: "default", MaxRunningSubTasks: 1}).Error; err != nil {
		t.Fatalf("seed quota: %v", err)
	}
	if err := store.Create(&db.SubTask{ID: "already-running", TenantID: "default", Status: "Running"}).Error; err != nil {
		t.Fatalf("seed running subtask: %v", err)
	}
	if err := store.Create(&db.SubTask{ID: "queued-task", TenantID: "default", Status: "Dispatching"}).Error; err != nil {
		t.Fatalf("seed queued subtask: %v", err)
	}

	server := NewServer(50051)
	returned := 0
	server.SetClaimTaskHook(func(agentID string) (*pb.Task, string, error) {
		return &pb.Task{TaskId: "queued-task", Targets: []string{"https://example.com"}}, "msg-1", nil
	})
	server.SetReturnTaskHook(func(task *pb.Task, msgID string) error {
		returned++
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
		t.Fatalf("expected quota-blocked claim to return empty task, got %+v", task)
	}
	if returned != 1 {
		t.Fatalf("expected quota-blocked task to be returned to queue once, got %d", returned)
	}
	var sub db.SubTask
	if err := store.First(&sub, "id = ?", "queued-task").Error; err != nil {
		t.Fatalf("load queued task: %v", err)
	}
	if sub.Status != "Dispatching" || sub.AgentID != "" {
		t.Fatalf("quota-blocked task should remain unclaimed, got %+v", sub)
	}
}

func TestRegisterPromotesWaitingCloudInstanceToRunning(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.CloudInstance{
		ID:       "ci-1",
		TenantID: "default",
		AgentID:  "agent-1",
		Status:   db.CloudStatusWaitingReady,
	}).Error; err != nil {
		t.Fatalf("seed cloud instance: %v", err)
	}

	server := NewServer(50051)
	resp, err := server.Register(context.Background(), &pb.RegisterReq{
		AgentId:  "agent-1",
		Version:  "1.0.0",
		Capacity: 2,
		Tags:     map[string]string{"cloud": "auto-scaled"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !resp.Success || resp.Token == "" {
		t.Fatalf("unexpected register response: %+v", resp)
	}

	var instance db.CloudInstance
	if err := store.First(&instance, "id = ?", "ci-1").Error; err != nil {
		t.Fatalf("load cloud instance: %v", err)
	}
	if instance.Status != db.CloudStatusRunning {
		t.Fatalf("expected status %s, got %s", db.CloudStatusRunning, instance.Status)
	}
	if instance.ReadyAt == nil {
		t.Fatalf("expected ready_at to be populated after register")
	}

	secondResp, err := server.Register(context.Background(), &pb.RegisterReq{
		AgentId:  "agent-1",
		Version:  "1.0.1",
		Capacity: 2,
		Tags:     map[string]string{"cloud": "auto-scaled"},
	})
	if err != nil {
		t.Fatalf("second register: %v", err)
	}
	if secondResp.Token == "" || secondResp.Token == resp.Token {
		t.Fatalf("expected re-register to rotate session token, first=%q second=%q", resp.Token, secondResp.Token)
	}
	var node db.Node
	if err := store.First(&node, "agent_id = ?", "agent-1").Error; err != nil {
		t.Fatalf("load node: %v", err)
	}
	if node.Token != secondResp.Token || node.Version != "1.0.1" {
		t.Fatalf("expected node to store rotated token and latest version, got %+v", node)
	}
}
