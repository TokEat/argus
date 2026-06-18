package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dddd/scanner/common"
	"dddd/scanner/internal/engine"
	"dddd/scanner/internal/exploit"
	"dddd/scanner/internal/vuln/nuclei"
	"dddd/scanner/lib/ddfinger"
	"dddd/scanner/structs"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-proto/pyexp"
	"google.golang.org/grpc"
)

const defaultAgentDebugTimeout = 60 * time.Second

// nucleiDebugResult represents the JSON structure of Nuclei debug output
type nucleiDebugResult struct {
	TemplateID string `json:"template-id"`
	Matched    string `json:"matched-at"`
	Info       struct {
		Severity string `json:"severity"`
	} `json:"info"`
	ExtractedResults []string `json:"extracted-results"`
	MatcherStatus    bool     `json:"matcher-status"`
}

func (w *Worker) handleDebugCommand(cmd *pb.DebugCommand) {
	if cmd == nil || strings.TrimSpace(cmd.SessionId) == "" {
		return
	}

	switch cmd.Action {
	case "start_debug":
		w.startDebugSession(cmd)
	case "start_fingerprint_debug":
		w.startDebugSession(cmd)
	case "cancel_debug":
		w.cancelDebugSession(cmd.SessionId)
		w.cancelExploitSession(cmd.SessionId)
	case "start_exp":
		w.handleExploitCommand(cmd)
	case "cleanup_exp":
		w.handleExploitCleanup(cmd)
	case "start_exp_debug":
		w.handleExploitCommand(cmd)
	case "cleanup_exp_debug":
		w.handleExploitCleanup(cmd)
	case "cancel_exp":
		w.cancelExploitSession(cmd.SessionId)
	case "install_pyexp_requirements":
		w.handlePyexpRequirementInstall(cmd)
	case "python_scratchpad_run":
		w.handlePythonScratchpadRun(cmd)
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
		if err := closeDebugStream(stream); err != nil {
			logDebugLocal("WARN", "failed to close debug stream: %v", err)
		}
	}()

	if cmd.Action == "start_fingerprint_debug" {
		send(&pb.DebugEvent{Type: "debug_log", Level: "INFO", Message: "agent accepted fingerprint debug session"})
		w.runFingerprintDebugSession(ctx, cmd, timeout, send, sendComplete)
		return
	}

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

	if w.logTee != nil {
		w.logTee.SetDebugSink(func(level, message string) {
			send(&pb.DebugEvent{
				Type:    "debug_log",
				Level:   level,
				Message: message,
			})
		})
		defer w.logTee.ClearDebugSink()
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

type fingerprintDebugOptions struct {
	IncludeDir       bool   `json:"include_dir"`
	IncludePoc       bool   `json:"include_poc"`
	CustomProduct    string `json:"custom_product"`
	CustomRule       string `json:"custom_rule"`
	CustomWfProduct  string `json:"custom_wf_product"`
	CustomWfTypes    string `json:"custom_wf_types"`
	CustomWfPocs     string `json:"custom_wf_pocs"`
	CustomPocContent string `json:"custom_poc_content"`
}

func (w *Worker) runFingerprintDebugSession(
	ctx context.Context,
	cmd *pb.DebugCommand,
	timeout time.Duration,
	send func(*pb.DebugEvent),
	sendComplete func(string),
) {
	options := fingerprintDebugOptions{}
	_ = json.Unmarshal([]byte(cmd.PocContent), &options)

	cfg := structs.DefaultConfig()
	cfg.Targets = []string{cmd.TargetUrl}
	cfg.HTTPProxy = cmd.Proxy
	cfg.NoPoc = !options.IncludePoc
	cfg.NoHostBind = true
	cfg.NoDirSearch = !options.IncludeDir
	cfg.SkipHostDiscovery = true
	cfg.WebTimeout = int(timeout.Seconds())
	if cfg.WebTimeout <= 0 || cfg.WebTimeout > int(defaultAgentDebugTimeout.Seconds()) {
		cfg.WebTimeout = int(defaultAgentDebugTimeout.Seconds())
	}
	cfg.WebThreads = 8

	sc, err := newScanContext(engine.Config(cfg))
	if err != nil {
		sendComplete(fmt.Sprintf("create scan context: %v", err))
		return
	}
	originalCancel := sc.Cancel
	defer sc.Close()
	if originalCancel != nil {
		defer originalCancel()
	}
	sc.TaskID = cmd.SessionId
	sc.Ctx = ctx
	sc.Cancel = func() {}

	// --- 注入自定义指纹规则 ---
	customProducts := make(map[string]bool)
	if options.CustomProduct != "" && options.CustomRule != "" {
		rule := strings.TrimSpace(options.CustomRule)
		parsed := ddfinger.ParseRule(rule)
		if len(parsed) > 0 {
			engineRules := make([]engine.RuleData, 0, len(parsed))
			for _, r := range parsed {
				engineRules = append(engineRules, engine.RuleData(r))
			}
			sc.FingerprintDB = append(sc.FingerprintDB, engine.FingerPEntity{
				ProductName: options.CustomProduct,
				AllString:   rule,
				Rule:        engineRules,
			})
			customProducts[options.CustomProduct] = true
			send(&pb.DebugEvent{
				Type:    "debug_log",
				Level:   "INFO",
				Message: fmt.Sprintf("injected custom fingerprint: %s → %s", options.CustomProduct, rule),
			})
		} else {
			send(&pb.DebugEvent{
				Type:    "debug_log",
				Level:   "WARN",
				Message: fmt.Sprintf("custom rule expression could not be parsed: %s", rule),
			})
		}
	}

	// --- 注入自定义 Workflow 规则 ---
	if options.CustomWfProduct != "" && options.CustomWfPocs != "" {
		var pocs []string
		for _, p := range strings.Split(options.CustomWfPocs, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				pocs = append(pocs, p)
			}
		}
		if len(pocs) > 0 {
			types := strings.Split(options.CustomWfTypes, ",")
			typeSet := make(map[string]bool)
			for _, t := range types {
				typeSet[strings.TrimSpace(strings.ToLower(t))] = true
			}
			wf := structs.WorkFlowEntity{
				RootType:    typeSet["root"],
				BaseType:    typeSet["base"],
				DirType:     typeSet["dir"],
				DirFallback: typeSet["dir-fallback"],
				PocsName:    pocs,
			}
			if sc.WorkFlowDB == nil {
				sc.WorkFlowDB = make(map[string]structs.WorkFlowEntity)
			}
			sc.WorkFlowDB[options.CustomWfProduct] = wf
			send(&pb.DebugEvent{
				Type:    "debug_log",
				Level:   "INFO",
				Message: fmt.Sprintf("injected custom workflow: %s → pocs=%v types=%v", options.CustomWfProduct, pocs, types),
			})
		}
	}

	// --- 注入自定义 POC 内容 ---
	if options.CustomPocContent != "" {
		pocFile, err := safeDebugPocFileName(options.CustomWfPocs)
		if err != nil {
			sendComplete(err.Error())
			return
		}

		tmpPocDir, err := os.MkdirTemp("", "argus-custom-poc-*")
		if err != nil {
			sendComplete(fmt.Sprintf("create custom poc temp dir: %v", err))
			return
		}
		defer os.RemoveAll(tmpPocDir)

		templatePath := filepath.Clean(filepath.Join(tmpPocDir, pocFile))
		relPath, err := filepath.Rel(tmpPocDir, templatePath)
		if err != nil || relPath == "." || relPath == ".." || strings.HasPrefix(relPath, ".."+string(os.PathSeparator)) {
			sendComplete("custom poc path escaped temp dir")
			return
		}
		if err := os.WriteFile(templatePath, []byte(options.CustomPocContent), 0600); err != nil {
			sendComplete(fmt.Sprintf("write custom poc: %v", err))
			return
		}

		sc.Config.NucleiTemplate = tmpPocDir
		send(&pb.DebugEvent{
			Type:    "debug_log",
			Level:   "INFO",
			Message: fmt.Sprintf("injected custom POC: %s (%d bytes)", pocFile, len(options.CustomPocContent)),
		})
	}

	sc.PhaseHook = func(phase engine.PhaseEvent) {
		send(&pb.DebugEvent{
			Type:    "debug_log",
			Level:   "DEBUG",
			Message: fmt.Sprintf("%s %s %s", phase.Phase, phase.Status, phase.Message),
		})
	}
	sc.OutputHook = func(msg engine.OutputMessage) {
		switch msg.Type {
		case "Web":
			send(&pb.DebugEvent{
				Type:      "debug_log",
				Level:     "INFO",
				Message:   fmt.Sprintf("web probe %s status=%s title=%s", msg.URI, msg.Web.Status, msg.Web.Title),
				MatchedAt: msg.URI,
				Request:   fmt.Sprintf("status=%s\ntitle=%s", msg.Web.Status, msg.Web.Title),
			})
		case "Finger", "Active-Finger":
			// 对自定义规则命中的 product 加 [custom] 前缀
			tagged := make([]string, 0, len(msg.Finger))
			for _, fp := range msg.Finger {
				if customProducts[fp] {
					tagged = append(tagged, "[custom]"+fp)
				} else {
					tagged = append(tagged, fp)
				}
			}
			send(&pb.DebugEvent{
				Type:       "debug_result",
				Matched:    len(msg.Finger) > 0,
				TemplateId: msg.Type,
				MatchedAt:  msg.URI,
				Extracted:  tagged,
				Message:    msg.AdditionalMsg,
			})
		default:
			if msg.Type == "Nuclei" && msg.Nuclei != "" {
				// 解析 Nuclei JSON 结果
				var nr nucleiDebugResult
				if json.Unmarshal([]byte(msg.Nuclei), &nr) == nil {
					send(&pb.DebugEvent{
						Type:       "debug_result",
						Matched:    nr.MatcherStatus,
						TemplateId: "Nuclei:" + nr.TemplateID,
						Severity:   nr.Info.Severity,
						MatchedAt:  nr.Matched,
						Extracted:  nr.ExtractedResults,
					})
				} else {
					send(&pb.DebugEvent{
						Type:    "debug_log",
						Level:   "DEBUG",
						Message: fmt.Sprintf("Nuclei %s", msg.Show),
					})
				}
			} else if msg.GoPoc.PocName != "" {
				send(&pb.DebugEvent{
					Type:       "debug_result",
					Matched:    true,
					TemplateId: "GoPoc:" + msg.GoPoc.PocName,
					Severity:   msg.GoPoc.Security,
					MatchedAt:  msg.GoPoc.Target,
					Message:    msg.GoPoc.Description,
				})
			} else if msg.Type != "" {
				send(&pb.DebugEvent{
					Type:    "debug_log",
					Level:   "DEBUG",
					Message: fmt.Sprintf("%s %s", msg.Type, msg.URI),
				})
			}
		}
	}

	send(&pb.DebugEvent{
		Type:    "debug_log",
		Level:   "INFO",
		Message: fmt.Sprintf("running fingerprint debug against %s (timeout=%s, dir=%v, poc=%v)", cmd.TargetUrl, timeout, options.IncludeDir, options.IncludePoc),
	})

	if err := runScanTask(sc); err != nil && ctx.Err() == nil {
		sendComplete(fmt.Sprintf("fingerprint debug failed: %v", err))
		return
	}
	if ctx.Err() != nil {
		sendComplete(ctx.Err().Error())
		return
	}
	sendComplete("")
}

func safeDebugPocFileName(pocName string) (string, error) {
	pocName = strings.TrimSpace(pocName)
	if pocName == "" {
		return "", fmt.Errorf("custom poc id is required")
	}
	if filepath.IsAbs(pocName) || strings.ContainsAny(pocName, `/\`) || strings.Contains(pocName, ",") {
		return "", fmt.Errorf("custom poc id must be a single safe filename")
	}
	for _, r := range pocName {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return "", fmt.Errorf("custom poc id contains unsupported character %q", r)
	}
	if !strings.HasSuffix(strings.ToLower(pocName), ".yaml") &&
		!strings.HasSuffix(strings.ToLower(pocName), ".yml") {
		pocName += ".yaml"
	}
	return pocName, nil
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
	if err := closeDebugStream(stream); err != nil {
		logDebugLocal("WARN", "failed to close debug stream for rejection: %v", err)
	}
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

// ============================================================================
// EXP 执行
// ============================================================================

func (w *Worker) handleExploitCommand(cmd *pb.DebugCommand) {
	if cmd == nil || strings.TrimSpace(cmd.PocContent) == "" {
		w.sendExploitResult(cmd, "Failed", nil, "empty EXP content")
		return
	}

	go func() {
		timeout := time.Duration(cmd.TimeoutSec) * time.Second
		if timeout <= 0 {
			timeout = defaultAgentDebugTimeout
		}
		ctx, cancel := context.WithCancel(context.Background())
		if !w.registerExploitSession(cmd.SessionId, cancel) {
			cancel()
			w.sendExploitResult(cmd, "Failed", nil, "agent already has a running EXP session with this id")
			return
		}
		defer func() {
			w.finishExploitSession(cmd.SessionId)
			cancel()
		}()

		eng := exploit.NewEngine(timeout, cmd.Proxy)
		tmpl, err := exploit.ParseTemplate([]byte(cmd.PocContent))
		if err != nil {
			w.sendExploitResult(cmd, "Failed", nil, fmt.Sprintf("parse error: %v", err))
			return
		}

		var params map[string]interface{}
		if cmd.Params != "" {
			if err := json.Unmarshal([]byte(cmd.Params), &params); err != nil {
				w.sendExploitResult(cmd, "Failed", nil, fmt.Sprintf("parse params JSON: %v", err))
				return
			}
		}
		if params == nil {
			params = make(map[string]interface{})
		}

		logDebugLocal("INFO", "[EXP] executing %s against %s (engine=%s)", tmpl.ID, cmd.TargetUrl, tmpl.RuntimeEngine)

		result, err := eng.RunContext(ctx, tmpl, cmd.TargetUrl, params)
		if err != nil {
			w.sendExploitResult(cmd, "Failed", nil, fmt.Sprintf("execution error: %v", err))
			return
		}
		if ctx.Err() != nil {
			w.sendExploitResult(cmd, "Cancelled", nil, ctx.Err().Error())
			return
		}

		w.sendExploitResult(cmd, result.Status, result, result.ErrorMsg)
	}()
}

func (w *Worker) handleExploitCleanup(cmd *pb.DebugCommand) {
	if cmd == nil || strings.TrimSpace(cmd.PocContent) == "" {
		w.sendExploitResult(cmd, "CleanupFailed", nil, "empty EXP content for cleanup")
		return
	}

	go func() {
		timeout := time.Duration(cmd.TimeoutSec) * time.Second
		if timeout <= 0 {
			timeout = defaultAgentDebugTimeout
		}
		ctx, cancel := context.WithCancel(context.Background())
		if !w.registerExploitSession(cmd.SessionId, cancel) {
			cancel()
			w.sendExploitResult(cmd, "CleanupFailed", nil, "agent already has a running EXP session with this id")
			return
		}
		defer func() {
			w.finishExploitSession(cmd.SessionId)
			cancel()
		}()

		eng := exploit.NewEngine(timeout, cmd.Proxy)
		tmpl, err := exploit.ParseTemplate([]byte(cmd.PocContent))
		if err != nil {
			w.sendExploitResult(cmd, "CleanupFailed", nil, fmt.Sprintf("parse error: %v", err))
			return
		}

		var params map[string]interface{}
		if cmd.Params != "" {
			if err := json.Unmarshal([]byte(cmd.Params), &params); err != nil {
				w.sendExploitResult(cmd, "CleanupFailed", nil, fmt.Sprintf("parse params JSON: %v", err))
				return
			}
		}

		if err := eng.CleanupContext(ctx, tmpl, cmd.TargetUrl, params); err != nil {
			w.sendExploitResult(cmd, "CleanupFailed", nil, fmt.Sprintf("cleanup error: %v", err))
			return
		}
		if ctx.Err() != nil {
			w.sendExploitResult(cmd, "Cancelled", nil, ctx.Err().Error())
			return
		}
		w.sendExploitResult(cmd, "CleanupSucceeded", nil, "")
	}()
}

type pyexpInstallParams struct {
	JobID            string   `json:"job_id"`
	Requirements     []string `json:"requirements"`
	RequirementsHash string   `json:"requirements_hash"`
	TimeoutSec       int      `json:"timeout_sec"`
}

func (w *Worker) handlePyexpRequirementInstall(cmd *pb.DebugCommand) {
	if cmd == nil {
		return
	}
	go func() {
		var params pyexpInstallParams
		if err := json.Unmarshal([]byte(cmd.Params), &params); err != nil {
			w.sendPyenvEvent(cmd, "pyenv_result", "ERROR", "", "Failed", fmt.Sprintf("parse params JSON: %v", err))
			return
		}
		if strings.TrimSpace(params.JobID) == "" {
			params.JobID = cmd.SessionId
		}
		if strings.TrimSpace(params.JobID) == "" {
			w.sendPyenvEvent(cmd, "pyenv_result", "ERROR", "", "Failed", "job_id is required")
			return
		}
		if params.RequirementsHash != "" && pyexp.RequirementsHash(params.Requirements) != params.RequirementsHash {
			w.sendPyenvEvent(cmd, "pyenv_result", "ERROR", "", "Failed", "requirements_hash does not match requirements")
			return
		}
		cmd.SessionId = params.JobID
		timeout := time.Duration(params.TimeoutSec) * time.Second
		if timeout <= 0 {
			timeout = 5 * time.Minute
		}

		w.sendPyenvEvent(cmd, "pyenv_log", "INFO", "accepted Python EXP dependency install job", "", "")
		err := exploit.InstallRequirements(context.Background(), params.Requirements, timeout, func(level, message string) {
			w.sendPyenvEvent(cmd, "pyenv_log", level, message, "", "")
		})
		if err != nil {
			w.sendPyenvEvent(cmd, "pyenv_result", "ERROR", "Python EXP dependency install failed", "Failed", err.Error())
			return
		}
		w.sendPyenvEvent(cmd, "pyenv_result", "INFO", "Python EXP dependency install succeeded", "Succeeded", "")
	}()
}

func (w *Worker) handlePythonScratchpadRun(cmd *pb.DebugCommand) {
	if cmd == nil {
		return
	}
	go func() {
		var req exploit.PythonScratchpadRequest
		if err := json.Unmarshal([]byte(cmd.Params), &req); err != nil {
			w.sendPythonScratchpadResult(cmd, "Failed", nil, fmt.Sprintf("parse params JSON: %v", err))
			return
		}
		if req.TimeoutSec <= 0 {
			req.TimeoutSec = int(cmd.TimeoutSec)
		}
		result, err := exploit.RunPythonScratchpad(context.Background(), req)
		if err != nil {
			w.sendPythonScratchpadResult(cmd, "Failed", nil, err.Error())
			return
		}
		status := "Succeeded"
		if result.ExitCode != 0 || result.TimedOut {
			status = "Failed"
		}
		w.sendPythonScratchpadResult(cmd, status, &result, "")
	}()
}

func (w *Worker) registerExploitSession(sessionID string, cancel context.CancelFunc) bool {
	w.expMu.Lock()
	defer w.expMu.Unlock()
	if w.expCancels == nil {
		w.expCancels = make(map[string]context.CancelFunc)
	}
	if _, exists := w.expCancels[sessionID]; exists {
		return false
	}
	w.expCancels[sessionID] = cancel
	return true
}

func (w *Worker) finishExploitSession(sessionID string) {
	w.expMu.Lock()
	defer w.expMu.Unlock()
	delete(w.expCancels, sessionID)
}

func (w *Worker) cancelExploitSession(sessionID string) {
	w.expMu.Lock()
	cancel := w.expCancels[sessionID]
	w.expMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (w *Worker) sendExploitResult(cmd *pb.DebugCommand, status string, result *exploit.Result, errMsg string) {
	payload := map[string]interface{}{
		"run_id": cmd.SessionId,
		"status": status,
	}
	if result != nil {
		payload["evidence"] = result.Evidence
		payload["side_effects"] = result.SideEffects
		payload["duration_ms"] = result.DurationMs
	}
	if errMsg != "" {
		payload["error_message"] = errMsg
	}

	payloadJSON, _ := json.Marshal(payload)
	if cmd.Action == "start_exp_debug" || cmd.Action == "cleanup_exp_debug" {
		w.sendExploitDebugEvent(cmd, status, result, errMsg, string(payloadJSON))
		return
	}

	stream, err := w.client.StreamDebug(context.Background())
	if err != nil {
		logDebugLocal("ERROR", "[EXP] failed to open debug stream: %v", err)
		return
	}
	defer stream.CloseSend()

	event := &pb.DebugEvent{
		AgentId:   w.agentID,
		SessionId: cmd.SessionId,
		Type:      "exp_result",
		Message:   string(payloadJSON),
		Matched:   status == "Succeeded",
		Timestamp: time.Now().UnixMilli(),
	}

	stream.Send(event)
	logDebugLocal("INFO", "[EXP] result sent: status=%s session=%s", status, cmd.SessionId)
}

func (w *Worker) sendPyenvEvent(cmd *pb.DebugCommand, eventType, level, message, status, errMsg string) {
	stream, err := w.client.StreamDebug(context.Background())
	if err != nil {
		logDebugLocal("ERROR", "[PYENV] failed to open debug stream: %v", err)
		return
	}
	defer stream.CloseSend()
	event := &pb.DebugEvent{
		AgentId:   w.agentID,
		TenantId:  cmd.TenantId,
		SessionId: cmd.SessionId,
		Type:      eventType,
		Level:     strings.ToUpper(level),
		Message:   message,
		Severity:  status,
		Error:     errMsg,
		Timestamp: time.Now().UnixMilli(),
	}
	_ = stream.Send(event)
}

func (w *Worker) sendExploitDebugEvent(cmd *pb.DebugCommand, status string, result *exploit.Result, errMsg string, payloadJSON string) {
	stream, err := w.client.StreamDebug(context.Background())
	if err != nil {
		logDebugLocal("ERROR", "[EXP-DEBUG] failed to open debug stream: %v", err)
		return
	}
	defer stream.CloseSend()

	durationMs := int64(0)
	extracted := make([]string, 0)
	if result != nil {
		durationMs = result.DurationMs
		for key, value := range result.Evidence {
			extracted = append(extracted, fmt.Sprintf("%s=%v", key, value))
		}
		sort.Strings(extracted)
	}

	matched := status == "Succeeded" || status == "CleanupSucceeded"
	now := time.Now().UnixMilli()
	_ = stream.Send(&pb.DebugEvent{
		AgentId:    w.agentID,
		TenantId:   cmd.TenantId,
		SessionId:  cmd.SessionId,
		Type:       "debug_result",
		Timestamp:  now,
		Level:      "INFO",
		Message:    payloadJSON,
		Matched:    matched,
		TemplateId: "EXP",
		Severity:   status,
		MatchedAt:  cmd.TargetUrl,
		Extracted:  extracted,
		DurationMs: durationMs,
		Error:      errMsg,
	})
	_ = stream.Send(&pb.DebugEvent{
		AgentId:    w.agentID,
		TenantId:   cmd.TenantId,
		SessionId:  cmd.SessionId,
		Type:       "debug_complete",
		Timestamp:  time.Now().UnixMilli(),
		Level:      "INFO",
		Message:    "EXP debug completed",
		Matched:    matched,
		DurationMs: durationMs,
		Error:      errMsg,
	})
	logDebugLocal("INFO", "[EXP-DEBUG] result sent: status=%s session=%s", status, cmd.SessionId)
}

func (w *Worker) sendPythonScratchpadResult(cmd *pb.DebugCommand, status string, result *exploit.PythonScratchpadResult, errMsg string) {
	stream, err := w.client.StreamDebug(context.Background())
	if err != nil {
		logDebugLocal("ERROR", "[PY-SCRATCH] failed to open debug stream: %v", err)
		return
	}
	defer stream.CloseSend()

	payload := map[string]interface{}{
		"status": status,
	}
	durationMs := int64(0)
	if result != nil {
		payload["command"] = result.Command
		payload["python_path"] = result.PythonPath
		payload["stdout"] = result.Stdout
		payload["stderr"] = result.Stderr
		payload["exit_code"] = result.ExitCode
		payload["timed_out"] = result.TimedOut
		payload["duration_ms"] = result.DurationMs
		durationMs = result.DurationMs
	}
	if errMsg != "" {
		payload["error_message"] = errMsg
	}
	payloadJSON, _ := json.Marshal(payload)
	matched := status == "Succeeded"
	now := time.Now().UnixMilli()
	_ = stream.Send(&pb.DebugEvent{
		AgentId:    w.agentID,
		TenantId:   cmd.TenantId,
		SessionId:  cmd.SessionId,
		Type:       "debug_result",
		Timestamp:  now,
		Level:      "INFO",
		Message:    string(payloadJSON),
		Matched:    matched,
		TemplateId: "python_scratchpad",
		Severity:   status,
		DurationMs: durationMs,
		Error:      errMsg,
	})
	_ = stream.Send(&pb.DebugEvent{
		AgentId:    w.agentID,
		TenantId:   cmd.TenantId,
		SessionId:  cmd.SessionId,
		Type:       "debug_complete",
		Timestamp:  time.Now().UnixMilli(),
		Level:      "INFO",
		Message:    "Python scratchpad completed",
		Matched:    matched,
		DurationMs: durationMs,
		Error:      errMsg,
	})
}
