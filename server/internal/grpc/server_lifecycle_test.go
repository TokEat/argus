package grpc

import (
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"google.golang.org/grpc/metadata"
)

func TestHeartbeatDoesNotOverwriteServerConfirmedRunningTasks(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-heartbeat", Status: "Alive", RunningTasks: 3, RunningTaskIDs: `["server-confirmed"]`, LastBeat: 1}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	server := NewServer(50051)
	if _, err := server.Heartbeat(context.Background(), &pb.HeartbeatReq{AgentId: "agent-heartbeat"}); err != nil {
		t.Fatalf("heartbeat with empty running task report: %v", err)
	}
	var node db.Node
	if err := store.First(&node, "agent_id = ?", "agent-heartbeat").Error; err != nil {
		t.Fatalf("load node: %v", err)
	}
	if node.RunningTasks != 3 || node.RunningTaskIDs != `["server-confirmed"]` {
		t.Fatalf("empty heartbeat overwrote server-confirmed tasks: %+v", node)
	}
	if _, err := server.Heartbeat(context.Background(), &pb.HeartbeatReq{AgentId: "agent-heartbeat", RunningTasks: 4, RunningTaskIds: []string{"agent-task-1", "agent-task-2"}}); err != nil {
		t.Fatalf("heartbeat with running task ids: %v", err)
	}
	if err := store.First(&node, "agent_id = ?", "agent-heartbeat").Error; err != nil {
		t.Fatalf("reload node: %v", err)
	}
	var ids []string
	if err := json.Unmarshal([]byte(node.RunningTaskIDs), &ids); err != nil {
		t.Fatalf("decode running task ids: %v", err)
	}
	if node.RunningTasks != 4 || len(ids) != 2 || ids[0] != "agent-task-1" || ids[1] != "agent-task-2" {
		t.Fatalf("non-empty heartbeat did not refresh tasks: count=%d ids=%v", node.RunningTasks, ids)
	}
}

func TestValidationAffinityAllowsUsesBoundedFallbackWindows(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	config := `{"ExecutionMode":"credential_validation","PreferredAgentID":"agent-a","PreferredNetworkZone":"zone-a","PreferredAgentUntilUnix":1800000015,"PreferredNetworkUntilUnix":1800000030}`
	if !validationAffinityAllows(config, "agent-a", `{"network_zone":"zone-a"}`, now) || validationAffinityAllows(config, "agent-b", `{"network_zone":"zone-a"}`, now) {
		t.Fatal("preferred Agent window was not enforced")
	}
	if !validationAffinityAllows(config, "agent-b", `{"network_zone":"ZONE-A"}`, now.Add(16*time.Second)) || validationAffinityAllows(config, "agent-c", `{"network_zone":"zone-b"}`, now.Add(16*time.Second)) {
		t.Fatal("network-zone fallback window was not enforced")
	}
	if !validationAffinityAllows(config, "agent-c", `{"network_zone":"zone-b"}`, now.Add(31*time.Second)) {
		t.Fatal("compatible Agent should be eligible after both windows")
	}
	if !validationAffinityAllows(`{"ExecutionMode":"asset_scan","PreferredAgentID":"agent-a","PreferredAgentUntilUnix":1900000000}`, "agent-b", `{}`, now) {
		t.Fatal("asset discovery must not be constrained by validation affinity")
	}
}

func TestSubscribeMarksExistingOfflineNodeAlive(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.Node{TenantID: "default", AgentID: "agent-subscribe", Status: "Offline", Capacity: 1, LastBeat: 1, Tags: `{"target_type":"all"}`, Version: "v2.3.0"}).Error; err != nil {
		t.Fatalf("seed node: %v", err)
	}
	server := NewServer(50051)
	stream := &subscribeTestStream{recv: []*pb.AgentSignal{{AgentId: "agent-subscribe", FreeSlots: 3, SignalType: "ready"}}}
	if err := server.Subscribe(stream); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	var node db.Node
	if err := store.First(&node, "agent_id = ?", "agent-subscribe").Error; err != nil {
		t.Fatalf("load node: %v", err)
	}
	if node.Status != "Alive" || node.LastBeat <= 1 || node.Capacity != 1 || node.Tags != `{"target_type":"all"}` || node.Version != "v2.3.0" {
		t.Fatalf("subscribe did not safely revive node: %+v", node)
	}
}

type subscribeTestStream struct {
	recv     []*pb.AgentSignal
	sent     []*pb.TaskNotify
	blockCh  chan struct{}
	closeErr error
}

func (s *subscribeTestStream) Recv() (*pb.AgentSignal, error) {
	if len(s.recv) == 0 {
		if s.blockCh != nil {
			<-s.blockCh
		}
		if s.closeErr != nil {
			return nil, s.closeErr
		}
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
