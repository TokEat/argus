package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dddd/scanner/common"
	"dddd/scanner/internal/vuln/nuclei"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	pb "github.com/user/dddd-proto/go/scan"
	"google.golang.org/grpc"
)

const defaultAgentDebugTimeout = 60 * time.Second

func (w *Worker) handleDebugCommand(cmd *pb.DebugCommand) {
	if cmd == nil || strings.TrimSpace(cmd.SessionId) == "" {
		return
	}

	switch cmd.Action {
	case "start_debug":
		w.startDebugSession(cmd)
	case "cancel_debug":
		w.cancelDebugSession(cmd.SessionId)
	default:
		logDebugLocal("WARN", "unknown debug command action: %s", cmd.Action)
	}
}

func (w *Worker) startDebugSession(cmd *pb.DebugCommand) {
	w.debugMu.Lock()
	if w.debugCancel != nil {
		w.debugMu.Unlock()
		w.sendOneShotDebugComplete(cmd, "agent already has a running debug session")
		return
	}

	timeout := time.Duration(cmd.TimeoutSec) * time.Second
	if timeout <= 0 || timeout > defaultAgentDebugTimeout {
		timeout = defaultAgentDebugTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	w.debugCancel = cancel
	w.debugSession = cmd.SessionId
	w.debugMu.Unlock()

	go func() {
		defer func() {
			cancel()
			w.debugMu.Lock()
			if w.debugSession == cmd.SessionId {
				w.debugCancel = nil
				w.debugSession = ""
			}
			w.debugMu.Unlock()
		}()
		w.runDebugSession(ctx, cmd, timeout)
	}()
}

func (w *Worker) cancelDebugSession(sessionID string) {
	w.debugMu.Lock()
	cancel := w.debugCancel
	activeSession := w.debugSession
	w.debugMu.Unlock()

	if cancel != nil && activeSession == sessionID {
		cancel()
	}
}

func (w *Worker) runDebugSession(ctx context.Context, cmd *pb.DebugCommand, timeout time.Duration) {
	stream, err := w.client.StreamDebug(context.Background())
	if err != nil {
		logDebugLocal("ERROR", "failed to open debug stream: %v", err)
		return
	}

	var sendMu sync.Mutex
	var stopped atomic.Bool
	var completeSent atomic.Bool
	startedAt := time.Now()

	send := func(event *pb.DebugEvent) {
		if event == nil {
			return
		}
		if event.Timestamp == 0 {
			event.Timestamp = time.Now().UnixMilli()
		}
		event.AgentId = w.agentID
		event.TenantId = cmd.TenantId
		event.SessionId = cmd.SessionId
		sendMu.Lock()
		defer sendMu.Unlock()
		_ = stream.Send(event)
	}

	sendComplete := func(errMsg string) {
		if !completeSent.CompareAndSwap(false, true) {
			return
		}
		stopped.Store(true)
		send(&pb.DebugEvent{
			Type:       "debug_complete",
			Error:      errMsg,
			DurationMs: time.Since(startedAt).Milliseconds(),
		})
	}

	defer func() {
		if !completeSent.Load() {
			sendComplete("")
		}
		_ = closeDebugStream(stream)
	}()

	send(&pb.DebugEvent{Type: "debug_log", Level: "INFO", Message: "agent accepted poc debug session"})

	tmpDir, err := os.MkdirTemp("", "argus-poc-debug-*")
	if err != nil {
		sendComplete(fmt.Sprintf("create temp dir: %v", err))
		return
	}
	defer os.RemoveAll(tmpDir)

	templateName := "debug-poc.yaml"
	templatePath := filepath.Join(tmpDir, templateName)
	if err := os.WriteFile(templatePath, []byte(cmd.PocContent), 0600); err != nil {
		sendComplete(fmt.Sprintf("write temp poc: %v", err))
		return
	}

	send(&pb.DebugEvent{
		Type:    "debug_log",
		Level:   "INFO",
		Message: fmt.Sprintf("running nuclei debug against %s (timeout=%s)", cmd.TargetUrl, timeout),
	})

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			sendComplete(ctx.Err().Error())
		case <-done:
		}
	}()

	targetAndPocs := map[string][]string{
		cmd.TargetUrl: []string{templateName},
	}

	// CallDebug 启用 MatcherStatus=true，Nuclei 对未命中模板也会触发回调
	// （通过 WriteFailure），回调中 MatcherStatus 为 false 的就是未命中事件。
	nuclei.CallDebug(targetAndPocs, cmd.Proxy, func(result output.ResultEvent) {
		if stopped.Load() {
			return
		}

		reqData := result.Request
		respData := result.Response

		// 多步骤模板：result.Packet 包含所有请求/响应对（按步骤索引），
		// result.Request/Response 只有最后一步的数据。
		if len(result.Packet) > 1 {
			reqData, respData = mergePacketPairs(result.Packet)
		}

		send(&pb.DebugEvent{
			Type:       "debug_result",
			Matched:    result.MatcherStatus,
			TemplateId: result.TemplateID,
			Severity:   result.Info.SeverityHolder.Severity.String(),
			MatchedAt:  result.Matched,
			Request:    reqData,
			Response:   respData,
			Extracted:  result.ExtractedResults,
		})
	}, "", true, common.EmbedNucleiPocs, tmpDir, nil, nil)

	close(done)
	if !completeSent.Load() {
		sendComplete("")
	}
}

func (w *Worker) sendOneShotDebugComplete(cmd *pb.DebugCommand, errMsg string) {
	stream, err := w.client.StreamDebug(context.Background())
	if err != nil {
		logDebugLocal("ERROR", "failed to open debug stream for rejection: %v", err)
		return
	}
	_ = stream.Send(&pb.DebugEvent{
		AgentId:   w.agentID,
		TenantId:  cmd.TenantId,
		SessionId: cmd.SessionId,
		Type:      "debug_complete",
		Timestamp: time.Now().UnixMilli(),
		Error:     errMsg,
	})
	_ = closeDebugStream(stream)
}

func closeDebugStream(stream grpc.ClientStreamingClient[pb.DebugEvent, pb.Ack]) error {
	if stream == nil {
		return nil
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		return err
	}
	if ack != nil && !ack.Success {
		return fmt.Errorf("debug stream rejected by server: %s", ack.Message)
	}
	return nil
}

func logDebugLocal(level, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	switch strings.ToUpper(level) {
	case "ERROR":
		fmt.Printf("[Debug][ERROR] %s\n", msg)
	case "WARN":
		fmt.Printf("[Debug][WARN] %s\n", msg)
	default:
		fmt.Printf("[Debug][INFO] %s\n", msg)
	}
}

// mergePacketPairs 将多步骤模板的所有请求/响应对按序合并，
// 用分隔线标注步骤编号，方便在单个 Editor 中查看所有步骤。
func mergePacketPairs(packets map[int]output.RequestResponsePair) (string, string) {
	if len(packets) == 0 {
		return "", ""
	}

	// 按步骤索引排序
	keys := make([]int, 0, len(packets))
	for k := range packets {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	if len(packets) == 1 {
		// 单步骤，保持 Request 和 Response 分离
		pair := packets[keys[0]]
		return pair.Request, pair.Response
	}

	// 多步骤，交织合并到 Request 中作为完整 trace
	var traceParts []string
	for i, idx := range keys {
		pair := packets[idx]
		sep := fmt.Sprintf("============= Step %d =============", i+1)
		traceParts = append(traceParts, sep)
		if pair.Request != "" {
			traceParts = append(traceParts, "[Request]\n"+strings.TrimRight(pair.Request, "\r\n"))
		}
		if pair.Response != "" {
			traceParts = append(traceParts, "[Response]\n"+strings.TrimRight(pair.Response, "\r\n"))
		}
	}

	return strings.Join(traceParts, "\n\n"), ""
}
