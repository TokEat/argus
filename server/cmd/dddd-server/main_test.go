package main

import (
	"context"
	"io"
	"testing"

	pb "github.com/user/dddd-proto/go/scan"
	grpcpkg "github.com/user/dddd-server/internal/grpc"
	"google.golang.org/grpc/metadata"
)

func TestAgentOfflineUpdatesPreserveSessionToken(t *testing.T) {
	updates := agentOfflineUpdates()
	if updates["status"] != "Offline" {
		t.Fatalf("unexpected status update: %#v", updates["status"])
	}
	if updates["running_tasks"] != 0 {
		t.Fatalf("unexpected running_tasks update: %#v", updates["running_tasks"])
	}
	if _, ok := updates["token"]; ok {
		t.Fatalf("offline liveness update must not clear token: %#v", updates)
	}
	if _, ok := updates["token_revoked_at"]; ok {
		t.Fatalf("offline liveness update must not revoke token: %#v", updates)
	}
}

func TestShouldMarkAgentOfflineHonorsActiveSubscribe(t *testing.T) {
	hub := grpcpkg.NewNotifyHub()
	stream := &subscribeTestStream{}
	hub.Register("agent-1", stream, 1, nil)

	if shouldMarkAgentOffline(hub, "agent-1") {
		t.Fatalf("active subscribe stream should keep agent online")
	}
	if !shouldMarkAgentOffline(hub, "missing-agent") {
		t.Fatalf("missing subscribe stream should allow offline marking")
	}
}

func TestBuildCloudAdvertiseAddrsUsesDetectedHostForWildcardBind(t *testing.T) {
	grpcAddr, apiURL, err := buildCloudAdvertiseAddrs(50051, ":8085", "", "", func() (string, error) {
		return "10.0.0.12", nil
	})
	if err != nil {
		t.Fatalf("buildCloudAdvertiseAddrs: %v", err)
	}
	if grpcAddr != "10.0.0.12:50051" {
		t.Fatalf("unexpected gRPC advertise addr: %s", grpcAddr)
	}
	if apiURL != "http://10.0.0.12:8085" {
		t.Fatalf("unexpected API advertise URL: %s", apiURL)
	}
}

func TestBuildCloudAdvertiseAddrsHonorsExplicitPublicOverrides(t *testing.T) {
	grpcAddr, apiURL, err := buildCloudAdvertiseAddrs(50051, ":8085", "198.51.100.8", "https://scan.example.com", func() (string, error) {
		t.Fatal("detectHost should not be called when public overrides are set")
		return "", nil
	})
	if err != nil {
		t.Fatalf("buildCloudAdvertiseAddrs: %v", err)
	}
	if grpcAddr != "198.51.100.8:50051" {
		t.Fatalf("unexpected gRPC advertise addr: %s", grpcAddr)
	}
	if apiURL != "https://scan.example.com" {
		t.Fatalf("unexpected API advertise URL: %s", apiURL)
	}
}

type subscribeTestStream struct{}

func (s *subscribeTestStream) Send(*pb.TaskNotify) error      { return nil }
func (s *subscribeTestStream) Recv() (*pb.AgentSignal, error) { return nil, io.EOF }
func (s *subscribeTestStream) SetHeader(metadata.MD) error    { return nil }
func (s *subscribeTestStream) SendHeader(metadata.MD) error   { return nil }
func (s *subscribeTestStream) SetTrailer(metadata.MD)         {}
func (s *subscribeTestStream) Context() context.Context       { return context.Background() }
func (s *subscribeTestStream) SendMsg(interface{}) error      { return nil }
func (s *subscribeTestStream) RecvMsg(interface{}) error      { return io.EOF }
