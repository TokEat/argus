// Package engine executes Yaklang EXP scripts inside a fresh VM per request.
package engine

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/yaklang/yaklang/common/utils/cli"
	"github.com/yaklang/yaklang/common/yak/antlr4yak"

	"github.com/P0lar1ght/argus/yaksha/internal/egress"
	"github.com/P0lar1ght/argus/yaksha/internal/protocol"
	"github.com/P0lar1ght/argus/yaksha/internal/resolver"
	"github.com/P0lar1ght/argus/yaksha/internal/validator"
)

const (
	maxLogEntries       = 256
	maxLogEntryBytes    = 4 << 10
	maxEvidenceEntries  = 128
	maxEvidenceKeyBytes = 128
	maxHTTPBodyBytes    = egress.MaxHTTPBodyBytes
)

func Execute(req protocol.Request) protocol.Response {
	return ExecuteWithEgress(req, egress.DisabledClient{})
}

func ExecuteWithEgress(req protocol.Request, outbound egress.Client) protocol.Response {
	return execute(req, nil, req.Action == protocol.ActionDebug, outbound)
}

func ExecuteTestCase(req protocol.Request, fixture *protocol.Fixture) protocol.Response {
	return ExecuteTestCaseWithEgress(req, fixture, egress.DisabledClient{})
}

func ExecuteTestCaseWithEgress(req protocol.Request, fixture *protocol.Fixture, outbound egress.Client) protocol.Response {
	if fixture == nil {
		fixture = &protocol.Fixture{}
	}
	return execute(req, fixture, true, outbound)
}

func execute(req protocol.Request, fixture *protocol.Fixture, diagnostic bool, outbound egress.Client) protocol.Response {
	if err := protocol.ValidateRequest(req); err != nil {
		return protocol.Response{ID: req.ID, Status: protocol.StatusFailed, Context: protocol.ExecutionContextFor(req), Error: "request rejected: " + err.Error()}
	}
	validation := validator.Validate(req)
	if !validation.Validation.Valid {
		var collector *debugCollector
		if diagnostic {
			collector = newDebugCollector()
		}
		return protocol.Response{ID: req.ID, Status: protocol.StatusFailed, Context: protocol.ExecutionContextFor(req), Inspection: &validation.Inspection, Validation: &validation.Validation, Debug: debugReport(collector), Error: validationError(validation.Validation)}
	}
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Duration(protocol.DefaultTimeoutMS) * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	state := executionState{
		ctx: ctx, bundle: validation.Bundle, fixture: fixture, diagnostic: diagnostic,
		outbound: outbound, budget: &callBudget{}, networkTargets: append([]string(nil), req.NetworkTargets...),
	}
	return executeValidated(req, validation, state)
}

type callBudget struct {
	mu    sync.Mutex
	count int
}

func (b *callBudget) acquire() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.count >= protocol.MaxCalls {
		return false
	}
	b.count++
	return true
}

type executionState struct {
	ctx            context.Context
	bundle         *resolver.Bundle
	fixture        *protocol.Fixture
	diagnostic     bool
	outbound       egress.Client
	budget         *callBudget
	path           []resolver.DependencyKey
	networkTargets []string
}

func executeValidated(req protocol.Request, validation validator.Result, state executionState) protocol.Response {
	var collector *debugCollector
	if state.diagnostic {
		collector = newDebugCollector()
	}
	sess := &session{
		ctx: state.ctx, evidence: map[string]any{}, debug: collector, fixture: state.fixture,
		bundle: state.bundle, outbound: state.outbound, budget: state.budget, path: state.path,
		diagnostic: state.diagnostic, networkTargets: state.networkTargets,
	}
	eng := antlr4yak.New()
	eng.SetSandboxMode(true)
	eng.EnableStrictMode()
	cliApp := cli.NewCliApp()
	cliApp.SetArgs(validation.CLIArgs)
	cliApp.SetCliCheckCallback(func() { panic("cli.check failed after Yaksha validation") })
	libs := yakshaLibs(sess)
	libs["cli"] = cliLibs(cliApp)
	eng.ImportLibs(libs)
	if len(req.Params) > 0 {
		eng.ImportLibs(map[string]interface{}{"params": req.Params})
	}

	err := eng.SafeEval(state.ctx, req.Script)
	asyncDone := make(chan struct{})
	go func() {
		eng.GetVM().AsyncWait()
		close(asyncDone)
	}()
	select {
	case <-asyncDone:
	case <-state.ctx.Done():
		if err == nil {
			err = state.ctx.Err()
		}
	}
	result, evidence, logs, calls := sess.snapshot()
	if err != nil {
		status := protocol.StatusFailed
		if state.ctx.Err() == context.DeadlineExceeded {
			status = protocol.StatusTimeout
		} else if state.ctx.Err() == context.Canceled {
			status = protocol.StatusCanceled
		}
		return protocol.Response{
			ID: req.ID, Status: status, Context: protocol.ExecutionContextFor(req), Inspection: &validation.Inspection,
			Validation: &validation.Validation, Debug: debugReport(collector), Evidence: evidence, Logs: logs, Calls: calls, Error: err.Error(),
		}
	}
	return protocol.Response{
		ID: req.ID, Status: protocol.StatusSucceeded, Context: protocol.ExecutionContextFor(req), Result: result,
		Inspection: &validation.Inspection, Validation: &validation.Validation, Debug: debugReport(collector), Evidence: evidence, Logs: logs, Calls: calls,
	}
}

func debugReport(collector *debugCollector) *protocol.DebugReport {
	if collector == nil {
		return nil
	}
	report := collector.result()
	return &report
}

func validationError(validation protocol.Validation) string {
	for _, diagnostic := range validation.Diagnostics {
		if diagnostic.Severity == "error" && diagnostic.Message != "" {
			return "EXP validation failed: " + diagnostic.Message
		}
	}
	return "EXP validation failed"
}

func cliLibs(app *cli.CliApp) map[string]interface{} {
	return map[string]interface{}{
		"String": app.String, "Text": app.Text, "Int": app.Int, "Integer": app.Integer,
		"Float": app.Float, "Bool": app.Bool, "StringSlice": app.StringSlice,
		"setRequired": app.SetRequired, "setDefault": app.SetDefault, "setHelp": app.SetHelp,
		"setVerboseName": app.SetVerboseName, "setCliGroup": app.SetCliGroup,
		"setSelectOption": app.SetSelectOption, "setMultipleSelect": app.SetMultipleSelect, "check": app.Check,
	}
}

type session struct {
	mu             sync.Mutex
	ctx            context.Context
	result         any
	evidence       map[string]any
	logs           []string
	calls          []protocol.CallRecord
	debug          *debugCollector
	fixture        *protocol.Fixture
	bundle         *resolver.Bundle
	outbound       egress.Client
	budget         *callBudget
	path           []resolver.DependencyKey
	diagnostic     bool
	networkTargets []string
}

func (s *session) log(msg any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.logs) >= maxLogEntries {
		return
	}
	text := fmt.Sprint(msg)
	if len(text) > maxLogEntryBytes {
		text = text[:maxLogEntryBytes]
	}
	s.logs = append(s.logs, text)
}

func (s *session) setResult(value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result = value
}

func (s *session) addEvidence(key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key == "" || len(key) > maxEvidenceKeyBytes {
		return
	}
	if _, exists := s.evidence[key]; !exists && len(s.evidence) >= maxEvidenceEntries {
		return
	}
	s.evidence[key] = value
}

func (s *session) addCall(record protocol.CallRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, record)
}

func (s *session) snapshot() (any, map[string]any, []string, []protocol.CallRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	evidence := make(map[string]any, len(s.evidence))
	for key, value := range s.evidence {
		evidence[key] = value
	}
	return s.result, evidence, append([]string(nil), s.logs...), append([]protocol.CallRecord(nil), s.calls...)
}

func (s *session) asset(assetID string) (string, error) {
	if s.bundle == nil {
		return "", fmt.Errorf("asset %s is unavailable: no sealed resolver bundle", assetID)
	}
	value, ok := s.bundle.Assets[assetID]
	if !ok {
		return "", fmt.Errorf("asset %s is unavailable", assetID)
	}
	return value, nil
}

func (s *session) call(expID string, revision int, params map[string]any) (any, error) {
	if s.bundle == nil {
		return nil, fmt.Errorf("dependency %s revision %d is unavailable: no sealed resolver bundle", expID, revision)
	}
	key := resolver.DependencyKey{ExpID: expID, Revision: revision}
	dependency, ok := s.bundle.Dependencies[key]
	if !ok {
		return nil, fmt.Errorf("dependency %s revision %d is unavailable", expID, revision)
	}
	if len(s.path) >= protocol.MaxCallDepth {
		return nil, fmt.Errorf("dependency call depth exceeds %d", protocol.MaxCallDepth)
	}
	for _, active := range s.path {
		if active == key {
			return nil, fmt.Errorf("dependency call cycle reaches %s revision %d", expID, revision)
		}
	}
	if !s.budget.acquire() {
		return nil, fmt.Errorf("dependency call count exceeds %d", protocol.MaxCalls)
	}
	childReq := protocol.Request{
		ID: "call-" + expID, Action: protocol.ActionRun, Script: dependency.Definition.Script, Params: params,
		ExpID: expID, Revision: revision, SourceSHA256: dependency.Definition.SourceSHA256,
	}
	childValidation := validator.ValidateChild(childReq)
	var response protocol.Response
	if !childValidation.Validation.Valid {
		response = protocol.Response{ID: childReq.ID, Status: protocol.StatusFailed, Context: protocol.ExecutionContextFor(childReq), Validation: &childValidation.Validation, Error: validationError(childValidation.Validation)}
	} else {
		childState := executionState{
			ctx: s.ctx, bundle: s.bundle, fixture: s.fixture, diagnostic: s.diagnostic, outbound: s.outbound,
			budget: s.budget, path: append(append([]resolver.DependencyKey(nil), s.path...), key), networkTargets: s.networkTargets,
		}
		response = executeValidated(childReq, childValidation, childState)
	}
	s.addCall(protocol.CallRecord{
		Context: response.Context, Status: response.Status, Result: response.Result, Validation: response.Validation,
		Debug: response.Debug, Evidence: response.Evidence, Logs: response.Logs, Error: response.Error, Calls: response.Calls,
	})
	if response.Status != protocol.StatusSucceeded {
		return nil, fmt.Errorf("dependency %s revision %d failed: %s", expID, revision, response.Error)
	}
	return response.Result, nil
}

func yakshaLibs(sess *session) map[string]interface{} {
	return map[string]interface{}{"yaksha": map[string]interface{}{
		"log": sess.log, "result": sess.setResult, "evidence": sess.addEvidence,
		"toString": func(value any) string { return fmt.Sprint(value) }, "echo": func(value any) any { return value },
		"httpGet": func(target string) (string, error) { return tracedHTTPGet(sess, target) },
		"dial":    func(address string) (string, error) { return tracedDial(sess, address) },
		"call":    sess.call, "asset": sess.asset,
		"b64encode": b64encode, "b64decode": b64decode, "md5": md5Hex, "sha256": sha256Hex,
		"jsonDumps": jsonDumps, "jsonLoads": jsonLoads, "regexMatch": regexMatch,
	}}
}

func tracedHTTPGet(sess *session, target string) (string, error) {
	started := time.Now()
	var result string
	var err error
	if sess.fixture != nil {
		result, err = fixtureHTTPGet(sess.fixture, target)
	} else if sess.outbound == nil {
		err = fmt.Errorf("Yaksha egress is unavailable")
	} else {
		response, requestErr := sess.outbound.HTTPGet(sess.ctx, target, sess.networkTargets)
		if requestErr != nil {
			err = requestErr
		} else {
			result = fmt.Sprintf("%d %s", response.StatusCode, response.Body)
		}
	}
	if sess.debug != nil {
		event := protocol.DebugEvent{Kind: "http", Operation: "GET", Target: target, DurationMS: time.Since(started).Milliseconds()}
		if err != nil {
			event.Error = err.Error()
		} else {
			fmt.Sscanf(result, "%d", &event.StatusCode)
		}
		sess.debug.addEvent(event)
	}
	return result, err
}

func tracedDial(sess *session, address string) (string, error) {
	started := time.Now()
	var result string
	var err error
	if sess.fixture != nil {
		result, err = fixtureDial(sess.fixture, address)
	} else if sess.outbound == nil {
		err = fmt.Errorf("Yaksha egress is unavailable")
	} else {
		result, err = sess.outbound.Dial(sess.ctx, address, sess.networkTargets)
	}
	if sess.debug != nil {
		event := protocol.DebugEvent{Kind: "tcp", Operation: "connect", Target: address, DurationMS: time.Since(started).Milliseconds()}
		if err != nil {
			event.Error = err.Error()
		}
		sess.debug.addEvent(event)
	}
	return result, err
}

func fixtureHTTPGet(fixture *protocol.Fixture, target string) (string, error) {
	for _, item := range fixture.HTTP {
		if item.Method != "GET" || item.URL != target {
			continue
		}
		if item.Fail {
			return "", fmt.Errorf("HTTP fixture failure for GET %s", target)
		}
		return fmt.Sprintf("%d %s", item.StatusCode, item.Body), nil
	}
	return "", fmt.Errorf("no matching HTTP fixture for GET %s", target)
}

func fixtureDial(fixture *protocol.Fixture, address string) (string, error) {
	for _, item := range fixture.TCP {
		if item.Address != address {
			continue
		}
		if !item.Success {
			return "", fmt.Errorf("TCP fixture failure for %s", address)
		}
		if item.RemoteAddress != "" {
			return item.RemoteAddress, nil
		}
		return address, nil
	}
	return "", fmt.Errorf("no matching TCP fixture for %s", address)
}

func b64encode(value string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(value)), nil
}
func b64decode(value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	return string(raw), err
}
func md5Hex(value string) string { sum := md5.Sum([]byte(value)); return hex.EncodeToString(sum[:]) }
func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func jsonDumps(value any) (string, error) { raw, err := json.Marshal(value); return string(raw), err }
func jsonLoads(value string) (any, error) {
	var result any
	err := json.Unmarshal([]byte(value), &result)
	return result, err
}
func regexMatch(pattern, value string) (bool, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(value), nil
}
