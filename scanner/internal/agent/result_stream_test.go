package agent

import (
	"errors"
	"os"
	"testing"
	"time"

	pb "github.com/TokEat/argus/shared/proto/go/scan"
	"google.golang.org/grpc"
)

// fakeFlakyResultStream 实现 grpc.ClientStreamingClient[ScanResult, Ack]。
// failSends 控制前 N 次 Send 返回错误（模拟断线）；recorded 收集成功送达的帧。
type fakeFlakyResultStream struct {
	grpc.ClientStream
	failSends int
	sent      int
	recorded  []*pb.ScanResult
	closeErr  error
	ack       *pb.Ack
	closed    bool
}

func (f *fakeFlakyResultStream) Send(res *pb.ScanResult) error {
	if f.sent < f.failSends {
		f.sent++
		return errors.New("connection reset by peer")
	}
	f.sent++
	f.recorded = append(f.recorded, res)
	return nil
}

func (f *fakeFlakyResultStream) CloseAndRecv() (*pb.Ack, error) {
	f.closed = true
	if f.closeErr != nil {
		return nil, f.closeErr
	}
	if f.ack == nil {
		return &pb.Ack{Success: true}, nil
	}
	return f.ack, nil
}

// noBackoff 让重连测试瞬间完成。
func noBackoff(int) time.Duration { return 0 }

func newTestResilientStream(open func() (grpc.ClientStreamingClient[pb.ScanResult, pb.Ack], error), wal *resultWAL, stopCh <-chan struct{}) *resilientResultStream {
	s := newResilientResultStream(open, wal, stopCh)
	s.backoff = noBackoff
	return s
}

func TestResilientStreamReconnectReplaysAllFramesInOrder(t *testing.T) {
	dir := t.TempDir()
	wal, err := OpenWAL(dir, "task-replay")
	if err != nil {
		t.Fatal(err)
	}
	stopCh := make(chan struct{})
	defer close(stopCh)

	var streams []*fakeFlakyResultStream
	open := func() (grpc.ClientStreamingClient[pb.ScanResult, pb.Ack], error) {
		// 第一个流对所有 Send 报错（模拟建连后立刻断线），后续流正常。
		fail := 0
		if len(streams) == 0 {
			fail = 1000
		}
		fs := &fakeFlakyResultStream{failSends: fail}
		streams = append(streams, fs)
		return fs, nil
	}

	s := newTestResilientStream(open, wal, stopCh)
	// A 触发首流失败 → 重连重放；B、C 走新流。
	for _, ptype := range []string{"A", "B", "C"} {
		if err := s.Send(&pb.ScanResult{TaskId: "task-replay", PayloadType: ptype}); err != nil {
			t.Fatalf("Send(%s) unexpected error: %v", ptype, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if len(streams) < 2 {
		t.Fatalf("expected reconnect to open a new stream, got %d streams", len(streams))
	}
	healthy := streams[len(streams)-1]
	want := []string{"A", "B", "C"}
	if len(healthy.recorded) != len(want) {
		t.Fatalf("healthy stream got %d frames, want %d (%v)", len(healthy.recorded), len(want), healthy.recorded)
	}
	for i, ptype := range want {
		if healthy.recorded[i].PayloadType != ptype {
			t.Errorf("frame %d = %s, want %s (frames must replay in order, no loss)", i, healthy.recorded[i].PayloadType, ptype)
		}
	}
	// Close 成功后 WAL 应被丢弃。
	if _, err := os.Stat(WALPath(dir, "task-replay")); !os.IsNotExist(err) {
		t.Errorf("wal should be discarded after successful close, stat err=%v", err)
	}
}

func TestResilientStreamTerminalWhenReconnectBudgetExhausted(t *testing.T) {
	dir := t.TempDir()
	wal, _ := OpenWAL(dir, "task-dead")
	stopCh := make(chan struct{})
	defer close(stopCh)

	openCalls := 0
	open := func() (grpc.ClientStreamingClient[pb.ScanResult, pb.Ack], error) {
		openCalls++
		return nil, errors.New("server unreachable")
	}
	s := newTestResilientStream(open, wal, stopCh)
	err := s.Send(&pb.ScanResult{TaskId: "task-dead"})
	if err == nil {
		t.Fatal("expected terminal error when reconnect budget exhausted")
	}
	if !errors.Is(s.terminal, err) {
		t.Errorf("terminal not latched: terminal=%v err=%v", s.terminal, err)
	}
	// 后续 Send 应立即返回 terminal，不再重试。
	if again := s.Send(&pb.ScanResult{}); !errors.Is(again, s.terminal) {
		t.Errorf("subsequent Send should return terminal, got %v", again)
	}
}

func TestResilientStreamStopsOnShutdown(t *testing.T) {
	dir := t.TempDir()
	wal, _ := OpenWAL(dir, "task-stop")
	stopCh := make(chan struct{})

	open := func() (grpc.ClientStreamingClient[pb.ScanResult, pb.Ack], error) {
		return nil, errors.New("server unreachable")
	}
	s := newTestResilientStream(open, wal, stopCh)
	close(stopCh) // 模拟 Agent 停机。

	err := s.Send(&pb.ScanResult{TaskId: "task-stop"})
	if !errors.Is(err, errResultStreamStopped) {
		t.Fatalf("expected errResultStreamStopped, got %v", err)
	}
}

func TestResilientStreamCloseRetriesAfterFailedClose(t *testing.T) {
	dir := t.TempDir()
	wal, _ := OpenWAL(dir, "task-close")
	stopCh := make(chan struct{})
	defer close(stopCh)

	var streams []*fakeFlakyResultStream
	open := func() (grpc.ClientStreamingClient[pb.ScanResult, pb.Ack], error) {
		fs := &fakeFlakyResultStream{}
		streams = append(streams, fs)
		return fs, nil
	}
	s := newTestResilientStream(open, wal, stopCh)
	if err := s.Send(&pb.ScanResult{TaskId: "task-close", PayloadType: "A"}); err != nil {
		t.Fatal(err)
	}
	// 让当前流的 CloseAndRecv 失败一次，触发 Close 内重连重放再收尾。
	streams[len(streams)-1].closeErr = errors.New("close failed transiently")
	if err := s.Close(); err != nil {
		t.Fatalf("Close should recover after transient close failure: %v", err)
	}
	if !streams[len(streams)-1].closed {
		t.Error("expected final stream to be closed")
	}
}
