package grpc

import (
	"context"
	"io"
	"testing"

	pb "github.com/user/dddd-proto/go/scan"
	"google.golang.org/grpc/metadata"
)

func TestNotifyHubIgnoresStaleUnregister(t *testing.T) {
	hub := NewNotifyHub()
	oldStream := &notifyHubTestStream{}
	newStream := &notifyHubTestStream{}

	hub.Register("agent-1", oldStream, 1, nil)
	hub.Register("agent-1", newStream, 1, nil)
	hub.Unregister("agent-1", oldStream)

	if !hub.IsAgentOnline("agent-1") {
		t.Fatalf("stale unregister removed the active stream")
	}
	if err := hub.SendDebugCommand("agent-1", &pb.DebugCommand{Action: "start_debug"}); err != nil {
		t.Fatalf("send debug command: %v", err)
	}
	if len(oldStream.sent) != 0 {
		t.Fatalf("old stream should not receive commands after replacement")
	}
	if len(newStream.sent) != 1 {
		t.Fatalf("new stream should receive command, got %d", len(newStream.sent))
	}
}

func TestNotifyHubBroadcastAPIConfigUpdated(t *testing.T) {
	hub := NewNotifyHub()
	streamA := &notifyHubTestStream{}
	streamB := &notifyHubTestStream{}
	hub.Register("agent-a", streamA, 0, nil)
	hub.Register("agent-b", streamB, 2, nil)

	hub.BroadcastAPIConfigUpdated("default")

	for name, stream := range map[string]*notifyHubTestStream{"agent-a": streamA, "agent-b": streamB} {
		if len(stream.sent) != 1 {
			t.Fatalf("%s received %d notifications, want 1", name, len(stream.sent))
		}
		if got := stream.sent[0].NotifyType; got != "api_config_updated" {
			t.Fatalf("%s notify_type = %q, want api_config_updated", name, got)
		}
		if stream.sent[0].AvailableTasks != 0 {
			t.Fatalf("%s api config notification should not advertise tasks", name)
		}
	}
}

func TestNotifyHubBroadcastAPIConfigUpdatedIsTenantScoped(t *testing.T) {
	hub := NewNotifyHub()
	tenantAStream := &notifyHubTestStream{}
	tenantBStream := &notifyHubTestStream{}
	defaultStream := &notifyHubTestStream{}
	hub.Register("agent-a", tenantAStream, 1, map[string]string{"tenant_id": "tenant-a"})
	hub.Register("agent-b", tenantBStream, 1, map[string]string{"tenant_id": "tenant-b"})
	hub.Register("agent-default", defaultStream, 1, nil)

	hub.BroadcastAPIConfigUpdated("tenant-a")

	if len(tenantAStream.sent) != 1 || tenantAStream.sent[0].NotifyType != "api_config_updated" {
		t.Fatalf("tenant-a agent should receive api_config_updated, got %#v", tenantAStream.sent)
	}
	if len(tenantBStream.sent) != 0 {
		t.Fatalf("tenant-b agent should not receive tenant-a api config notification, got %#v", tenantBStream.sent)
	}
	if len(defaultStream.sent) != 0 {
		t.Fatalf("default tenant agent should not receive tenant-a api config notification, got %#v", defaultStream.sent)
	}
}

type notifyHubTestStream struct {
	sent []*pb.TaskNotify
}

func (s *notifyHubTestStream) Send(msg *pb.TaskNotify) error {
	s.sent = append(s.sent, msg)
	return nil
}

func (s *notifyHubTestStream) Recv() (*pb.AgentSignal, error) { return nil, io.EOF }
func (s *notifyHubTestStream) SetHeader(metadata.MD) error    { return nil }
func (s *notifyHubTestStream) SendHeader(metadata.MD) error   { return nil }
func (s *notifyHubTestStream) SetTrailer(metadata.MD)         {}
func (s *notifyHubTestStream) Context() context.Context       { return context.Background() }
func (s *notifyHubTestStream) SendMsg(interface{}) error      { return nil }
func (s *notifyHubTestStream) RecvMsg(interface{}) error      { return io.EOF }
