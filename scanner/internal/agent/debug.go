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

	"github.com/P0lar1ght/argus/scanner/common"
	"github.com/P0lar1ght/argus/scanner/internal/engine"
	"github.com/P0lar1ght/argus/scanner/internal/vuln/nuclei"
	"github.com/P0lar1ght/argus/scanner/lib/ddfinger"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/shared/proto/go/activefingerprint"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"google.golang.org/grpc"
)

const defaultAgentDebugTimeout = 60 * time.Second
const defaultDebugFingerprintProduct = "DebugFingerprint"

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
	if cmd == nil || strings.TrimSpace(cmd.SessionId) == "" || w.draining.Load() {
		return
	}

	switch cmd.Action {
	case "start_debug":
		w.startDebugSession(cmd)
	case "start_fingerprint_debug":
		w.startDebugSession(cmd)
	case "start_active_fingerprint_debug":
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
		if err := closeDebugStream(stream); err != nil {
			logDebugLocal("WARN", "failed to close debug stream: %v", err)
		}
	}()

	if cmd.Action == "start_fingerprint_debug" {
		send(&pb.DebugEvent{Type: "debug_log", Level: "INFO", Message: "agent accepted fingerprint debug session"})
		w.runFingerprintDebugSession(ctx, cmd, timeout, send, sendComplete)
		return
	}

	activeProbe := cmd.Action == "start_active_fingerprint_debug"
	var activeClassification activefingerprint.Classification
	if activeProbe {
		var err error
		activeClassification, err = activefingerprint.Inspect("debug-active-fingerprint.yaml", []byte(cmd.PocContent))
		if err != nil {
			sendComplete(fmt.Sprintf("validate active fingerprint: %v", err))
			return
		}
		send(&pb.DebugEvent{Type: "debug_log", Level: "INFO", Message: fmt.Sprintf("agent accepted %s active fingerprint debug session (%s)", activeClassification.ComputedProfile, activeClassification.ID)})
	} else {
		send(&pb.DebugEvent{Type: "debug_log", Level: "INFO", Message: "agent accepted poc debug session"})
	}

	tmpDir, err := os.MkdirTemp("", "argus-poc-debug-*")
	if err != nil {
		sendComplete(fmt.Sprintf("create temp dir: %v", err))
		return
	}
	defer os.RemoveAll(tmpDir)

	templateName := "debug-poc.yaml"
	if activeProbe {
		templateName = "debug-active-fingerprint.yaml"
	}
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
	_, nucleiErr := nuclei.CallDebug(targetAndPocs, cmd.Proxy, func(result output.ResultEvent) {
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

		templateID := result.TemplateID
		extracted := result.ExtractedResults
		if activeProbe {
			templateID, extracted = activeFingerprintDebugResult(result.MatcherStatus, activeClassification.Product)
		}
		send(&pb.DebugEvent{
			Type:       "debug_result",
			Matched:    result.MatcherStatus,
			TemplateId: templateID,
			Severity:   result.Info.SeverityHolder.Severity.String(),
			MatchedAt:  result.Matched,
			Request:    reqData,
			Response:   respData,
			Extracted:  extracted,
		})
	}, "", true, true, common.EmbedNucleiPocs, tmpDir, nil, nil)

	close(done)
	if !completeSent.Load() {
		completeNucleiDebug(sendComplete, nucleiErr)
	}
}

func activeFingerprintDebugResult(matched bool, product string) (string, []string) {
	if !matched {
		return "Active-Finger", nil
	}
	return "Active-Finger", []string{product}
}

type fingerprintDebugOptions struct {
	IncludeDir       bool     `json:"include_dir"`
	IncludePoc       bool     `json:"include_poc"`
	CustomOnly       bool     `json:"custom_only"`
	CustomProduct    string   `json:"custom_product"`
	CustomRule       string   `json:"custom_rule"`
	CustomRules      []string `json:"custom_rules"`
	CustomDirProduct string   `json:"custom_dir_product"`
	CustomDirPaths   []string `json:"custom_dir_paths"`
	CustomWfProduct  string   `json:"custom_wf_product"`
	CustomWfTypes    string   `json:"custom_wf_types"`
	CustomWfPocs     string   `json:"custom_wf_pocs"`
	CustomPocContent string   `json:"custom_poc_content"`
}

func cleanCustomFingerprintRules(options fingerprintDebugOptions) []string {
	if len(options.CustomRules) > 0 {
		rules := make([]string, 0, len(options.CustomRules))
		for _, rule := range options.CustomRules {
			rule = strings.TrimSpace(rule)
			if rule != "" {
				rules = append(rules, rule)
			}
		}
		if len(rules) > 0 {
			return rules
		}
	}
	if rule := strings.TrimSpace(options.CustomRule); rule != "" {
		return []string{rule}
	}
	return nil
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
	cfg.NoDirSearch = !options.IncludeDir && len(options.CustomDirPaths) == 0
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
	// Debug may replace or append rules below. Never mutate a shared knowledge
	// snapshot retained by normal Agent tasks.
	sc.DetachKnowledge()
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
	if options.CustomOnly {
		sc.FingerprintDB = nil
	}
	customRules := cleanCustomFingerprintRules(options)
	if len(customRules) > 0 {
		productName := strings.TrimSpace(options.CustomProduct)
		if productName == "" {
			productName = defaultDebugFingerprintProduct
		}
		for _, rule := range customRules {
			parsed := ddfinger.ParseRule(rule)
			if len(parsed) > 0 {
				engineRules := make([]engine.RuleData, 0, len(parsed))
				for _, r := range parsed {
					engineRules = append(engineRules, engine.RuleData(r))
				}
				sc.FingerprintDB = append(sc.FingerprintDB, engine.FingerPEntity{
					ProductName: productName,
					AllString:   rule,
					Rule:        engineRules,
				})
				customProducts[productName] = true
				send(&pb.DebugEvent{
					Type:    "debug_log",
					Level:   "INFO",
					Message: fmt.Sprintf("injected custom fingerprint: %s → %s", productName, rule),
				})
			} else {
				send(&pb.DebugEvent{
					Type:    "debug_log",
					Level:   "WARN",
					Message: fmt.Sprintf("custom rule expression could not be parsed: %s", rule),
				})
			}
		}
	}
	if options.CustomOnly && len(customProducts) == 0 {
		sendComplete("custom_only fingerprint debug requires a valid custom fingerprint rule")
		return
	}

	dirPaths := make([]string, 0, len(options.CustomDirPaths))
	for _, path := range options.CustomDirPaths {
		path = strings.TrimSpace(path)
		if path != "" {
			dirPaths = append(dirPaths, path)
		}
	}
	if len(dirPaths) > 0 {
		productName := strings.TrimSpace(options.CustomDirProduct)
		if productName == "" {
			productName = defaultDebugFingerprintProduct
		}
		if sc.DirDB == nil {
			sc.DirDB = map[string][]string{}
		}
		for _, path := range dirPaths {
			sc.DirDB[path] = append(sc.DirDB[path], productName)
		}
		send(&pb.DebugEvent{
			Type:    "debug_log",
			Level:   "INFO",
			Message: fmt.Sprintf("injected custom dir paths: %s → %v", productName, dirPaths),
		})
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
		Message: fmt.Sprintf("running fingerprint debug against %s (timeout=%s, dir=%v, poc=%v, custom_only=%v)", cmd.TargetUrl, timeout, options.IncludeDir, options.IncludePoc, options.CustomOnly),
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
