package agent

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

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
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 4, nil)
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
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
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

func TestWorkerExecuteTaskFailsOnInvalidTaskConfig(t *testing.T) {
	client := &fakeAgentClient{
		stream: &fakeResultStream{},
	}
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client

	worker.executeTask(&pb.Task{
		TaskId:  "task-invalid-config",
		Targets: []string{"127.0.0.1"},
		Config:  []byte("{invalid"),
	})

	if len(client.taskCompleteReqs) != 1 {
		t.Fatalf("expected 1 TaskComplete request, got %d", len(client.taskCompleteReqs))
	}

	req := client.taskCompleteReqs[0]
	if req.Status != "FAILED" {
		t.Fatalf("expected status FAILED, got %s", req.Status)
	}
	if req.ErrorMessage == "" {
		t.Fatalf("expected invalid config error message")
	}
}

func TestReportTaskCompletionRetriesTransientFailures(t *testing.T) {
	client := &fakeAgentClient{
		stream:           &fakeResultStream{},
		taskCompleteErrs: []error{errors.New("temporary"), errors.New("temporary")},
	}
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client

	worker.reportTaskCompletion("task-retry", "DONE", "")

	if len(client.taskCompleteReqs) != 3 {
		t.Fatalf("expected 3 TaskComplete attempts, got %d", len(client.taskCompleteReqs))
	}
}

func TestEffectiveWorkerCountCapsToEngineLimit(t *testing.T) {
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 8, nil)
	expected := engine.MaxConcurrentTasks()
	if expected > 8 {
		expected = 8
	}
	if got := worker.effectiveWorkerCount(); got != expected {
		t.Fatalf("expected effective worker count to be capped at %d, got %d", expected, got)
	}
}

func TestShouldMirrorAgentOutput(t *testing.T) {
	cases := map[string]bool{
		"Finger":        true,
		"Active-Finger": true,
		"GoPoc":         true,
		"Domain-Bind":   true,
		"Web":           false,
	}

	for messageType, expected := range cases {
		if got := shouldMirrorAgentOutput(messageType); got != expected {
			t.Fatalf("unexpected mirror decision for %s: got %v want %v", messageType, got, expected)
		}
	}
}

func TestToDDOutOutputMessageKeepsShowMsg(t *testing.T) {
	src := engine.OutputMessage{
		Type: "GoPoc",
		GoPoc: engine.GoPocsResultType{
			PocName:  "Shiro Weak Key",
			ShowMsg:  "http://127.0.0.1:8081 key=xxx",
			Security: "CRITICAL",
		},
	}

	got := toDDOutOutputMessage(src)
	if got.GoPoc.ShowMsg != src.GoPoc.ShowMsg {
		t.Fatalf("show message lost during conversion: got %q want %q", got.GoPoc.ShowMsg, src.GoPoc.ShowMsg)
	}
}

func TestWorkerPythonScratchpadRunStreamsCompletion(t *testing.T) {
	stream := &fakeDebugStream{sent: make(chan *pb.DebugEvent, 4)}
	client := &fakeAgentClient{debugStream: stream}
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 4, nil)
	worker.client = client

	worker.handleDebugCommand(&pb.DebugCommand{
		Action:     "python_scratchpad_run",
		SessionId:  "scratch-1",
		TenantId:   "default",
		TimeoutSec: 5,
		Params:     `{"command":"python_version","timeout_sec":5}`,
	})

	seenComplete := false
	deadline := time.After(5 * time.Second)
	for !seenComplete {
		select {
		case event := <-stream.sent:
			if event.SessionId != "scratch-1" || event.TenantId != "default" {
				t.Fatalf("unexpected event scope: %#v", event)
			}
			if event.Type == "debug_complete" {
				seenComplete = true
				if !event.Matched || event.Error != "" {
					t.Fatalf("unexpected completion event: %#v", event)
				}
			}
		case <-deadline:
			t.Fatalf("timed out waiting for python scratchpad completion")
		}
	}
}

type fakeAgentClient struct {
	stream            grpc.ClientStreamingClient[pb.ScanResult, pb.Ack]
	streamErr         error
	debugStream       grpc.ClientStreamingClient[pb.DebugEvent, pb.Ack]
	debugErr          error
	taskCompleteReqs  []*pb.TaskCompleteReq
	taskCompleteReqsM sync.Mutex
	taskCompleteErrs  []error
	taskCompleteAck   *pb.Ack
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
	if len(c.taskCompleteErrs) > 0 {
		err := c.taskCompleteErrs[0]
		c.taskCompleteErrs = c.taskCompleteErrs[1:]
		if err != nil {
			return nil, err
		}
	}
	if c.taskCompleteAck != nil {
		return c.taskCompleteAck, nil
	}
	return &pb.Ack{Success: true}, nil
}

func (c *fakeAgentClient) EmergencyDump(ctx context.Context, in *pb.EmergencyReq, opts ...grpc.CallOption) (*pb.Ack, error) {
	return &pb.Ack{Success: true}, nil
}

func (c *fakeAgentClient) Subscribe(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[pb.AgentSignal, pb.TaskNotify], error) {
	return nil, nil
}

func (c *fakeAgentClient) ClaimTask(ctx context.Context, in *pb.ClaimTaskReq, opts ...grpc.CallOption) (*pb.Task, error) {
	return &pb.Task{}, nil
}

func (c *fakeAgentClient) StreamLogs(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[pb.LogPayload, pb.Ack], error) {
	return nil, nil
}

func (c *fakeAgentClient) StreamDebug(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[pb.DebugEvent, pb.Ack], error) {
	if c.debugErr != nil {
		return nil, c.debugErr
	}
	return c.debugStream, nil
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
		ack.Success = resp.Success
		ack.Message = resp.Message
		return nil
	}
	return io.EOF
}

type fakeDebugStream struct {
	sendErr error
	sent    chan *pb.DebugEvent
}

func (s *fakeDebugStream) Send(event *pb.DebugEvent) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	if s.sent != nil {
		s.sent <- event
	}
	return nil
}

func (s *fakeDebugStream) CloseAndRecv() (*pb.Ack, error) {
	return &pb.Ack{Success: true}, nil
}

func (s *fakeDebugStream) Header() (metadata.MD, error) {
	return nil, nil
}

func (s *fakeDebugStream) Trailer() metadata.MD {
	return nil
}

func (s *fakeDebugStream) CloseSend() error {
	return nil
}

func (s *fakeDebugStream) Context() context.Context {
	return context.Background()
}

func (s *fakeDebugStream) SendMsg(m any) error {
	if event, ok := m.(*pb.DebugEvent); ok {
		return s.Send(event)
	}
	return nil
}

func (s *fakeDebugStream) RecvMsg(m any) error {
	if ack, ok := m.(*pb.Ack); ok {
		ack.Success = true
		return nil
	}
	return io.EOF
}
