package agent

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"dddd/scanner/internal/engine"
	pb "github.com/user/dddd-proto/go/scan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestWorkerExecuteTaskReportsCancelled(t *testing.T) {
	origNewScanContext := newScanContext
	origRunScanTask := runScanTask
	defer func() {
		newScanContext = origNewScanContext
		runScanTask = origRunScanTask
	}()

	started := make(chan struct{})
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		ctx, cancel := context.WithCancel(context.Background())
		return &engine.ScanContext{
			Config: cfg,
			Ctx:    ctx,
			Cancel: cancel,
		}, nil
	}
	runScanTask = func(ctx *engine.ScanContext) error {
		close(started)
		<-ctx.Ctx.Done()
		return ctx.Ctx.Err()
	}

	client := &fakeAgentClient{
		stream: &fakeResultStream{},
	}
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 4)
	worker.client = client

	done := make(chan struct{})
	go func() {
		defer close(done)
		worker.executeTask(&pb.Task{TaskId: "task-cancel", Targets: []string{"127.0.0.1"}})
	}()

	<-started

	var cancel context.CancelFunc
	for cancel == nil {
		worker.mu.Lock()
		cancel = worker.runningTasks["task-cancel"]
		worker.mu.Unlock()
	}
	cancel()

	<-done

	if len(client.taskCompleteReqs) != 1 {
		t.Fatalf("expected 1 TaskComplete request, got %d", len(client.taskCompleteReqs))
	}

	req := client.taskCompleteReqs[0]
	if req.Status != "CANCELLED" {
		t.Fatalf("expected status CANCELLED, got %s", req.Status)
	}
	if req.ErrorMessage != "task cancelled by control plane" {
		t.Fatalf("unexpected cancel error message: %q", req.ErrorMessage)
	}
}

func TestWorkerExecuteTaskFailsOnResultStreamSendError(t *testing.T) {
	origNewScanContext := newScanContext
	origRunScanTask := runScanTask
	defer func() {
		newScanContext = origNewScanContext
		runScanTask = origRunScanTask
	}()

	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		ctx, cancel := context.WithCancel(context.Background())
		return &engine.ScanContext{
			Config: cfg,
			Ctx:    ctx,
			Cancel: cancel,
		}, nil
	}
	runScanTask = func(ctx *engine.ScanContext) error {
		if ctx.OutputHook != nil {
			ctx.OutputHook(engine.OutputMessage{Type: "finger"})
		}
		return ctx.Ctx.Err()
	}

	client := &fakeAgentClient{
		stream: &fakeResultStream{
			sendErr: errors.New("stream broken"),
		},
	}
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 1)
	worker.client = client

	worker.executeTask(&pb.Task{TaskId: "task-stream", Targets: []string{"127.0.0.1"}})

	if len(client.taskCompleteReqs) != 1 {
		t.Fatalf("expected 1 TaskComplete request, got %d", len(client.taskCompleteReqs))
	}

	req := client.taskCompleteReqs[0]
	if req.Status != "FAILED" {
		t.Fatalf("expected status FAILED, got %s", req.Status)
	}
	if req.ErrorMessage == "" || req.ErrorMessage == context.Canceled.Error() {
		t.Fatalf("expected stream failure to be surfaced, got %q", req.ErrorMessage)
	}
}

func TestEffectiveWorkerCountCapsToEngineLimit(t *testing.T) {
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 8)
	if got := worker.effectiveWorkerCount(); got != 1 {
		t.Fatalf("expected effective worker count to be capped at 1, got %d", got)
	}
}

type fakeAgentClient struct {
	stream            grpc.ClientStreamingClient[pb.ScanResult, pb.Ack]
	streamErr         error
	taskCompleteReqs  []*pb.TaskCompleteReq
	taskCompleteReqsM sync.Mutex
}

func (c *fakeAgentClient) Register(ctx context.Context, in *pb.RegisterReq, opts ...grpc.CallOption) (*pb.RegisterResp, error) {
	return &pb.RegisterResp{Success: true}, nil
}

func (c *fakeAgentClient) Heartbeat(ctx context.Context, in *pb.HeartbeatReq, opts ...grpc.CallOption) (*pb.HeartbeatResp, error) {
	return &pb.HeartbeatResp{Ack: true}, nil
}

func (c *fakeAgentClient) FetchTask(ctx context.Context, in *pb.FetchTaskReq, opts ...grpc.CallOption) (*pb.Task, error) {
	return &pb.Task{}, nil
}

func (c *fakeAgentClient) StreamResult(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[pb.ScanResult, pb.Ack], error) {
	if c.streamErr != nil {
		return nil, c.streamErr
	}
	return c.stream, nil
}

func (c *fakeAgentClient) TaskComplete(ctx context.Context, in *pb.TaskCompleteReq, opts ...grpc.CallOption) (*pb.Ack, error) {
	c.taskCompleteReqsM.Lock()
	defer c.taskCompleteReqsM.Unlock()
	c.taskCompleteReqs = append(c.taskCompleteReqs, in)
	return &pb.Ack{Success: true}, nil
}

func (c *fakeAgentClient) EmergencyDump(ctx context.Context, in *pb.EmergencyReq, opts ...grpc.CallOption) (*pb.Ack, error) {
	return &pb.Ack{Success: true}, nil
}

type fakeResultStream struct {
	sendErr  error
	closeErr error
	ack      *pb.Ack
}

func (s *fakeResultStream) Send(*pb.ScanResult) error {
	return s.sendErr
}

func (s *fakeResultStream) CloseAndRecv() (*pb.Ack, error) {
	if s.closeErr != nil {
		return nil, s.closeErr
	}
	if s.ack != nil {
		return s.ack, nil
	}
	return &pb.Ack{Success: true}, nil
}

func (s *fakeResultStream) Header() (metadata.MD, error) {
	return nil, nil
}

func (s *fakeResultStream) Trailer() metadata.MD {
	return nil
}

func (s *fakeResultStream) CloseSend() error {
	return nil
}

func (s *fakeResultStream) Context() context.Context {
	return context.Background()
}

func (s *fakeResultStream) SendMsg(m any) error {
	if req, ok := m.(*pb.ScanResult); ok {
		return s.Send(req)
	}
	return nil
}

func (s *fakeResultStream) RecvMsg(m any) error {
	if ack, ok := m.(*pb.Ack); ok {
		resp, err := s.CloseAndRecv()
		if err != nil {
			return err
		}
		*ack = *resp
		return nil
	}
	return io.EOF
}
