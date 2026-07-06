package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-server/internal/db"
	"google.golang.org/grpc/metadata"
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

func TestClaimTaskDropsQueuedMessageWhenRootTaskPaused(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.RootTask{ID: "root-paused", TenantID: "default", Status: "Paused"}).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	if err := store.Create(&db.SubTask{ID: "queued-paused", TenantID: "default", RootTaskID: "root-paused", Status: "Pending"}).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}

	server := NewServer(50051)
	acked := 0
	returned := 0
	server.SetClaimTaskHook(func(agentID string) (*pb.Task, string, error) {
		if acked+returned > 0 {
			return nil, "", nil
		}
		return &pb.Task{TaskId: "queued-paused", Targets: []string{"https://example.com"}}, "msg-paused", nil
	})
	server.SetAckTaskHook(func(msgID string) error {
		if msgID == "msg-paused" {
			acked++
		}
		return nil
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
		t.Fatalf("expected paused task claim to return empty task, got %+v", task)
	}
	if acked != 1 || returned != 0 {
		t.Fatalf("expected paused queue message to be acked once and not returned, acked=%d returned=%d", acked, returned)
	}
	var sub db.SubTask
	if err := store.First(&sub, "id = ?", "queued-paused").Error; err != nil {
		t.Fatalf("load queued task: %v", err)
	}
	if sub.Status != "Paused" || sub.AgentID != "" || sub.StreamMsgID != "" {
		t.Fatalf("expected queued task to be marked Paused and unassigned, got %+v", sub)
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

func TestHeartbeatDoesNotOverwriteServerConfirmedRunningTasks(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.Node{
		TenantID:       "default",
		AgentID:        "agent-heartbeat",
		Status:         "Alive",
		RunningTasks:   3,
		RunningTaskIDs: `["server-confirmed"]`,
		LastBeat:       1,
	}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}

	server := NewServer(50051)
	if _, err := server.Heartbeat(context.Background(), &pb.HeartbeatReq{
		AgentId:      "agent-heartbeat",
		RunningTasks: 0,
	}); err != nil {
		t.Fatalf("heartbeat with empty running task report: %v", err)
	}

	var node db.Node
	if err := store.First(&node, "agent_id = ?", "agent-heartbeat").Error; err != nil {
		t.Fatalf("load node: %v", err)
	}
	if node.RunningTasks != 3 {
		t.Fatalf("expected server-confirmed running task count to be preserved, got %d", node.RunningTasks)
	}
	if node.RunningTaskIDs != `["server-confirmed"]` {
		t.Fatalf("expected empty heartbeat to preserve task ids, got %s", node.RunningTaskIDs)
	}

	if _, err := server.Heartbeat(context.Background(), &pb.HeartbeatReq{
		AgentId:        "agent-heartbeat",
		RunningTasks:   4,
		RunningTaskIds: []string{"agent-task-1", "agent-task-2"},
	}); err != nil {
		t.Fatalf("heartbeat with running task ids: %v", err)
	}
	if err := store.First(&node, "agent_id = ?", "agent-heartbeat").Error; err != nil {
		t.Fatalf("reload node: %v", err)
	}
	if node.RunningTasks != 4 {
		t.Fatalf("expected heartbeat to raise running task count, got %d", node.RunningTasks)
	}
	var ids []string
	if err := json.Unmarshal([]byte(node.RunningTaskIDs), &ids); err != nil {
		t.Fatalf("decode running task ids: %v", err)
	}
	if len(ids) != 2 || ids[0] != "agent-task-1" || ids[1] != "agent-task-2" {
		t.Fatalf("expected non-empty heartbeat to refresh task ids, got %v", ids)
	}
}

func TestSubscribeMarksExistingOfflineNodeAlive(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.Node{
		TenantID: "default",
		AgentID:  "agent-subscribe",
		Status:   "Offline",
		Capacity: 1,
		LastBeat: 1,
		Tags:     `{"target_type":"all"}`,
		Version:  "v2.3.0",
	}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}

	server := NewServer(50051)
	stream := &subscribeTestStream{
		recv: []*pb.AgentSignal{{AgentId: "agent-subscribe", FreeSlots: 3, SignalType: "ready"}},
	}
	if err := server.Subscribe(stream); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	var node db.Node
	if err := store.First(&node, "agent_id = ?", "agent-subscribe").Error; err != nil {
		t.Fatalf("load node: %v", err)
	}
	if node.Status != "Alive" || node.LastBeat <= 1 || node.Capacity != 1 {
		t.Fatalf("expected subscribe to revive node, got %+v", node)
	}
	if node.Tags != `{"target_type":"all"}` || node.Version != "v2.3.0" {
		t.Fatalf("subscribe should preserve existing node metadata, got %+v", node)
	}
}

type subscribeTestStream struct {
	recv []*pb.AgentSignal
	sent []*pb.TaskNotify
}

func (s *subscribeTestStream) Recv() (*pb.AgentSignal, error) {
	if len(s.recv) == 0 {
		return nil, io.EOF
	}
	msg := s.recv[0]
	s.recv = s.recv[1:]
	return msg, nil
}

func (s *subscribeTestStream) Send(msg *pb.TaskNotify) error {
	s.sent = append(s.sent, msg)
	return nil
}

func (s *subscribeTestStream) SetHeader(metadata.MD) error  { return nil }
func (s *subscribeTestStream) SendHeader(metadata.MD) error { return nil }
func (s *subscribeTestStream) SetTrailer(metadata.MD)       {}
func (s *subscribeTestStream) Context() context.Context     { return context.Background() }
func (s *subscribeTestStream) SendMsg(interface{}) error    { return nil }
func (s *subscribeTestStream) RecvMsg(interface{}) error    { return io.EOF }
