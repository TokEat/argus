package agent

import (
	"errors"
	"fmt"
	"time"

	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"google.golang.org/grpc"
)

// resultSender 抽象结果流发送端，worker 的所有结果/阶段/进度帧都经它发出。
// 实现：resilientResultStream（WAL 缓冲 + 断线重连重放）与 plainResultStream（旧行为，无重放）。
type resultSender interface {
	Send(res *pb.ScanResult) error
	Close() error
}

// errResultStreamStopped 表示发送端因 Agent 停机（stopCh 关闭）而放弃，属于正常退出而非故障。
var errResultStreamStopped = errors.New("result stream stopped by agent shutdown")

// maxReconnectAttempts 是单次发送遇错后的重连预算；耗尽即判 terminal，交由上层失败处理。
const maxReconnectAttempts = 8

// reconnectBackoff 返回第 attempt 次重连前的退避时长：1s/2s/5s/10s/30s(cap)。
func reconnectBackoff(attempt int) time.Duration {
	switch {
	case attempt <= 1:
		return time.Second
	case attempt == 2:
		return 2 * time.Second
	case attempt == 3:
		return 5 * time.Second
	case attempt == 4:
		return 10 * time.Second
	default:
		return 30 * time.Second
	}
}

// resilientResultStream 在裸 gRPC 流之上提供断线重连 + 全量重放。
// 调用方（worker）以 streamMu 串行化所有 Send/Close，故本类型不再自带锁；
// 重连期间 Send 阻塞即对引擎形成反压。所有帧先落 WAL，重连成功后从第 0 帧重放
// （服务端结果写入幂等，重复帧只 upsert）。
type resilientResultStream struct {
	open      func() (grpc.ClientStreamingClient[pb.ScanResult, pb.Ack], error)
	wal       *resultWAL
	stopCh    <-chan struct{}
	backoff   func(attempt int) time.Duration
	stream    grpc.ClientStreamingClient[pb.ScanResult, pb.Ack]
	terminal  error
}

// newResilientResultStream 构造发送端；open 由调用方提供（内部带好 token 元数据与 ctx）。
func newResilientResultStream(open func() (grpc.ClientStreamingClient[pb.ScanResult, pb.Ack], error), wal *resultWAL, stopCh <-chan struct{}) *resilientResultStream {
	return &resilientResultStream{open: open, wal: wal, stopCh: stopCh, backoff: reconnectBackoff}
}

// Send 先落 WAL，再确保送达当前流。重连/首开流会把 WAL 全量重放到新流（含本帧），
// 因此重连后不再对本帧做二次直发——保证同一帧在同一流上只出现一次（跨流重复由服务端幂等吸收）。
// 返回 nil 表示帧已被接受；errResultStreamStopped 表示停机；其余为 terminalErr，上层据此判失败。
func (s *resilientResultStream) Send(res *pb.ScanResult) error {
	if s.terminal != nil {
		return s.terminal
	}
	if s.wal != nil {
		if err := s.wal.Append(res); err != nil {
			return fmt.Errorf("append result to wal: %w", err)
		}
	}
	if s.stream == nil {
		stream, err := s.reconnect()
		if err != nil {
			s.terminal = err
			return err
		}
		s.stream = stream
		return nil
	}
	if err := s.stream.Send(res); err != nil {
		stream, retryErr := s.reconnect()
		if retryErr != nil {
			s.terminal = retryErr
			return retryErr
		}
		s.stream = stream
	}
	return nil
}

// Close 正常收尾：对当前流 CloseAndRecv 取最终 Ack，成功后丢弃 WAL。
// 流已断时先重连重放再收尾；重连预算耗尽则返回 terminalErr，由上层判失败。
func (s *resilientResultStream) Close() error {
	if s.terminal != nil {
		return s.terminal
	}
	if s.stream == nil {
		// 从未成功建立流（如整个扫描期间 server 都不可达）：尽力重连重放一次。
		stream, err := s.reconnect()
		if err != nil {
			s.terminal = err
			return err
		}
		s.stream = stream
	}
	if err := s.closeAndRecv(); err != nil {
		stream, retryErr := s.reconnect()
		if retryErr != nil {
			s.terminal = retryErr
			return retryErr
		}
		s.stream = stream
		if err := s.closeAndRecv(); err != nil {
			s.terminal = err
			return err
		}
	}
	if s.wal != nil {
		return s.wal.Discard()
	}
	return nil
}

func (s *resilientResultStream) closeAndRecv() error {
	ack, err := s.stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("close grpc result stream: %w", err)
	}
	if ack != nil && !ack.Success {
		return fmt.Errorf("result stream rejected by server: %s", ack.Message)
	}
	return nil
}

// reconnect 关闭旧流，按退避预算反复「开新流 + 全量重放」，直到成功或预算耗尽/停机。
func (s *resilientResultStream) reconnect() (grpc.ClientStreamingClient[pb.ScanResult, pb.Ack], error) {
	if s.stream != nil {
		// 旧流已坏，best-effort 关闭，避免泄漏；忽略错误。
		_, _ = s.stream.CloseAndRecv()
		s.stream = nil
	}
	var lastErr error
	for attempt := 1; attempt <= maxReconnectAttempts; attempt++ {
		select {
		case <-s.stopCh:
			return nil, errResultStreamStopped
		case <-time.After(s.backoff(attempt)):
		}
		stream, err := s.open()
		if err != nil {
			lastErr = err
			continue
		}
		if s.wal != nil {
			if err := s.replay(stream); err != nil {
				lastErr = err
				_, _ = stream.CloseAndRecv()
				continue
			}
		}
		return stream, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no reconnect attempt made")
	}
	return nil, fmt.Errorf("result stream reconnect budget exhausted after %d attempts: %w", maxReconnectAttempts, lastErr)
}

// replay 把 WAL 里的全部帧按序重放到新流。任一帧发送失败即中止并返回错误，
// 交由 reconnect 的退避循环重开新流再整体重放（服务端幂等，重复无害）。
func (s *resilientResultStream) replay(stream grpc.ClientStreamingClient[pb.ScanResult, pb.Ack]) error {
	return s.wal.Replay(0, func(res *pb.ScanResult) error {
		return stream.Send(res)
	})
}

// plainResultStream 保留旧行为：裸流、出错即返回，由上层立即判失败。
// 通过 ARGUS_RESULT_REPLAY=off 回退到该路径。
type plainResultStream struct {
	stream grpc.ClientStreamingClient[pb.ScanResult, pb.Ack]
}

func (p *plainResultStream) Send(res *pb.ScanResult) error {
	return p.stream.Send(res)
}

func (p *plainResultStream) Close() error {
	return closeResultStream(p.stream)
}
