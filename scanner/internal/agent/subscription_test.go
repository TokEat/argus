package agent

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

func TestSubscribeAndClaimStopsWhenWorkerStops(t *testing.T) {
	stream := &fakeSubscribeClientStream{block: true, started: make(chan struct{})}
	client := &fakeAgentClient{subscribeStream: stream}
	worker := NewWorker("agent-stopping", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client
	done := make(chan struct{})
	go func() {
		worker.subscribeAndClaim(make(chan struct{}))
		close(done)
	}()
	select {
	case <-stream.started:
	case <-time.After(time.Second):
		t.Fatal("Subscribe Recv did not start")
	}
	worker.requestStop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stop signal did not cancel pending Subscribe Recv")
	}
}

func TestDrainingWorkerRejectsDebugCommands(t *testing.T) {
	worker := NewWorker("agent-draining-debug", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.draining.Store(true)
	worker.handleDebugCommand(&pb.DebugCommand{SessionId: "debug-1", Action: "start_debug"})
	worker.debugMu.Lock()
	defer worker.debugMu.Unlock()
	if worker.debugSession != "" || worker.debugCancel != nil {
		t.Fatal("draining worker accepted a debug command")
	}
}

type fakeSubscribeClientStream struct {
	recv        []*pb.TaskNotify
	sentSignals int
	ctx         context.Context
	block       bool
	started     chan struct{}
	startOnce   sync.Once
}

func (s *fakeSubscribeClientStream) setContext(ctx context.Context) { s.ctx = ctx }
func (s *fakeSubscribeClientStream) Send(*pb.AgentSignal) error {
	s.sentSignals++
	return nil
}
func (s *fakeSubscribeClientStream) Recv() (*pb.TaskNotify, error) {
	if s.block {
		s.startOnce.Do(func() { close(s.started) })
		<-s.ctx.Done()
		return nil, s.ctx.Err()
	}
	if len(s.recv) == 0 {
		return nil, io.EOF
	}
	msg := s.recv[0]
	s.recv = s.recv[1:]
	return msg, nil
}
func (s *fakeSubscribeClientStream) Header() (metadata.MD, error) { return nil, nil }
func (s *fakeSubscribeClientStream) Trailer() metadata.MD         { return nil }
func (s *fakeSubscribeClientStream) CloseSend() error             { return nil }
func (s *fakeSubscribeClientStream) Context() context.Context     { return s.ctx }
func (s *fakeSubscribeClientStream) SendMsg(message any) error {
	if signal, ok := message.(*pb.AgentSignal); ok {
		return s.Send(signal)
	}
	return nil
}
func (s *fakeSubscribeClientStream) RecvMsg(message any) error {
	notify, err := s.Recv()
	if err != nil {
		return err
	}
	if target, ok := message.(*pb.TaskNotify); ok {
		proto.Reset(target)
		proto.Merge(target, notify)
	}
	return nil
}
