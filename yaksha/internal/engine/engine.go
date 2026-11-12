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
	"strings"
	"sync"
	"time"

	"github.com/yaklang/yaklang/common/gmsm/sm4"
	"github.com/yaklang/yaklang/common/utils/cli"
	"github.com/yaklang/yaklang/common/yak/antlr4yak"
	yakcodec "github.com/yaklang/yaklang/common/yak/yaklib/codec"
	"github.com/yaklang/yaklang/common/yso"

	"github.com/TokEat/argus/yaksha/internal/egress"
	"github.com/TokEat/argus/yaksha/internal/protocol"
	"github.com/TokEat/argus/yaksha/internal/resolver"
	"github.com/TokEat/argus/yaksha/internal/validator"
)

const (
	maxLogEntries       = 256
	maxLogEntryBytes    = 4 << 10
	maxEvidenceEntries  = 128
	maxEvidenceKeyBytes = 128
	maxHTTPBodyBytes    = egress.MaxHTTPBodyBytes
	maxYSOBytes         = 1 << 20
	maxYSODirtyBytes    = 64 << 10
	maxYSOCommandBytes  = 8 << 10
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
		fixtureCursor: &fixtureCursor{},
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
	fixtureCursor  *fixtureCursor
}

type fixtureCursor struct {
	mu   sync.Mutex
	http int
	tcp  int
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
		fixtureCursor: state.fixtureCursor,
	}
	eng := antlr4yak.New()
	eng.SetSandboxMode(true)
	eng.EnableStrictMode()
	cliApp := cli.NewCliApp()
	cliApp.SetArgs(validation.CLIArgs)
	cliApp.SetCliCheckCallback(func() { panic("cli.check failed after Yaksha validation") })
	libs := yakshaLibs(sess)
	libs["cli"] = cliLibs(cliApp)
	libs["codec"] = codecLibs()
	libs["yso"] = ysoLibs()
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
	if err == nil && collector != nil && collector.exceeded() {
		err = fmt.Errorf("debug trace exceeds protocol limits")
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
		"setInputType":    func(_ string) cli.SetCliExtraParam { return app.SetVerboseName("") },
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
	fixtureCursor  *fixtureCursor
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
			fixtureCursor: s.fixtureCursor,
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
		"httpGet":     func(target string) (string, error) { return tracedHTTPGet(sess, target) },
		"dial":        func(address string) (string, error) { return tracedDial(sess, address) },
		"httpRequest": func(input map[string]any) (map[string]any, error) { return tracedHTTPRequest(sess, input) },
		"tcpExchange": func(input map[string]any) (map[string]any, error) { return tracedTCPExchange(sess, input) },
		"call":        sess.call, "asset": sess.asset, "sleep": sess.sleep,
		"b64encode": b64encode, "b64decode": b64decode, "md5": md5Hex, "sha256": sha256Hex,
		"jsonDumps": jsonDumps, "jsonLoads": jsonLoads, "regexMatch": regexMatch,
	}}
}

func (s *session) sleep(seconds float64) error {
	if seconds < 0 || seconds > 5 {
		return fmt.Errorf("sleep duration must be between 0 and 5 seconds")
	}
	timer := time.NewTimer(time.Duration(seconds * float64(time.Second)))
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func ysoLibs() map[string]interface{} {
	out := make(map[string]interface{}, len(yso.Exports))
	for k, v := range yso.Exports {
		out[k] = v
	}
	out["dirtyDataLength"] = func(length int) yso.MarshalOptionFun {
		if length < 0 || length > maxYSODirtyBytes {
			panic(fmt.Sprintf("YSO dirty data exceeds %d bytes", maxYSODirtyBytes))
		}
		return yso.SetToBytesDirtyDataLength(length)
	}
	out["command"] = func(command string) yso.GenClassOptionFun {
		if len(command) > maxYSOCommandBytes {
			panic(fmt.Sprintf("YSO command exceeds %d bytes", maxYSOCommandBytes))
		}
		return yso.SetExecCommand(command)
	}
	out["GenerateRuntimeExecTransletBytes"] = runtimeExecTransletBytes
	out["ToBytes"] = func(value interface{}, options ...yso.MarshalOptionFun) ([]byte, error) {
		raw, err := yso.ToBytes(value, options...)
		if err == nil && len(raw) > maxYSOBytes {
			return nil, fmt.Errorf("YSO output exceeds %d bytes", maxYSOBytes)
		}
		return raw, err
	}
	return out
}
func codecLibs() map[string]interface{} {
	return map[string]interface{}{
		"EncodeToHex": yakcodec.EncodeToHex, "DecodeHex": yakcodec.DecodeHex,
		"EncodeBase64": yakcodec.EncodeBase64, "DecodeBase64": yakcodec.DecodeBase64,
		"EncodeBase64Url": yakcodec.EncodeBase64Url, "DecodeBase64Url": yakcodec.DecodeBase64Url,
		"EncodeUrl": yakcodec.EncodeUrlCode, "DecodeUrl": yakcodec.QueryUnescape,
		"EscapePathUrl": yakcodec.PathEscape, "UnescapePathUrl": yakcodec.PathUnescape,
		"PKCS5Padding": yakcodec.PKCS5Padding, "PKCS5UnPadding": yakcodec.PKCS5UnPadding,
		"PKCS7Padding": sm4.PKCS7Padding, "PKCS7UnPadding": sm4.PKCS7UnPadding,
		"AESCBCEncrypt": yakcodec.AESEncryptCBCWithPKCSPadding, "AESCBCDecrypt": yakcodec.AESDecryptCBCWithPKCSPadding,
		"AESGCMEncrypt": yakcodec.AESGCMEncrypt, "AESGCMDecrypt": yakcodec.AESGCMDecrypt,
		"AESGCMEncryptWithNonceSize12": yakcodec.AESGCMEncryptWithNonceSize12, "AESGCMDecryptWithNonceSize12": yakcodec.AESGCMDecryptWithNonceSize12,
		"AESGCMEncryptWithNonceSize16": yakcodec.AESGCMEncryptWithNonceSize16, "AESGCMDecryptWithNonceSize16": yakcodec.AESGCMDecryptWithNonceSize16,
		"HmacSha256": yakcodec.HmacSha256, "RandBytes": yakcodec.RandBytes, "CryptoRandBytes": yakcodec.RandBytes,
	}
}

func decodeMap(input map[string]any, target any) error {
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func tracedHTTPRequest(sess *session, input map[string]any) (map[string]any, error) {
	var request egress.HTTPRequest
	if err := decodeMap(input, &request); err != nil {
		return nil, fmt.Errorf("invalid httpRequest input: %w", err)
	}
	started := time.Now()
	var response egress.HTTPResult
	var err error
	if sess.fixture != nil {
		response, err = fixtureHTTPRequest(sess, request)
	} else if sess.outbound == nil {
		err = fmt.Errorf("Yaksha egress is unavailable")
	} else if extended, ok := sess.outbound.(egress.ExtendedClient); !ok {
		err = fmt.Errorf("Yaksha HTTP request capability is unavailable")
	} else {
		response, err = extended.HTTPRequest(sess.ctx, request, sess.networkTargets)
	}
	if sess.debug != nil {
		event := protocol.DebugEvent{Kind: "http", Operation: strings.ToUpper(request.Method), Target: request.URL, DurationMS: time.Since(started).Milliseconds(), Request: request}
		if err != nil {
			event.Error = err.Error()
		} else {
			event.StatusCode = response.StatusCode
			event.Response = response
		}
		sess.debug.addEvent(event)
	}
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(response)
	var result map[string]any
	_ = json.Unmarshal(raw, &result)
	return result, nil
}

func tracedTCPExchange(sess *session, input map[string]any) (map[string]any, error) {
	var request egress.TCPExchangeRequest
	if err := decodeMap(input, &request); err != nil {
		return nil, fmt.Errorf("invalid tcpExchange input: %w", err)
	}
	started := time.Now()
	var response egress.TCPExchangeResult
	var err error
	if sess.fixture != nil {
		response, err = fixtureTCPExchange(sess, request)
	} else if sess.outbound == nil {
		err = fmt.Errorf("Yaksha egress is unavailable")
	} else if extended, ok := sess.outbound.(egress.ExtendedClient); !ok {
		err = fmt.Errorf("Yaksha TCP exchange capability is unavailable")
	} else {
		response, err = extended.TCPExchange(sess.ctx, request, sess.networkTargets)
	}
	if sess.debug != nil {
		event := protocol.DebugEvent{Kind: "tcp", Operation: "exchange", Target: request.Address, DurationMS: time.Since(started).Milliseconds(), Request: request}
		if err != nil {
			event.Error = err.Error()
		} else {
			event.Response = response
		}
		sess.debug.addEvent(event)
	}
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(response)
	var result map[string]any
	_ = json.Unmarshal(raw, &result)
	return result, nil
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
		event := protocol.DebugEvent{Kind: "http", Operation: "GET", Target: target, DurationMS: time.Since(started).Milliseconds(), Request: egress.HTTPRequest{Method: "GET", URL: target, FollowRedirects: true}}
		if err != nil {
			event.Error = err.Error()
		} else {
			fmt.Sscanf(result, "%d", &event.StatusCode)
			event.Response = result
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
		event := protocol.DebugEvent{Kind: "tcp", Operation: "connect", Target: address, DurationMS: time.Since(started).Milliseconds(), Request: map[string]any{"address": address}}
		if err != nil {
			event.Error = err.Error()
		} else {
			event.Response = map[string]any{"remote_address": result}
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

func fixtureHTTPRequest(sess *session, request egress.HTTPRequest) (egress.HTTPResult, error) {
	sess.fixtureCursor.mu.Lock()
	defer sess.fixtureCursor.mu.Unlock()
	if sess.fixtureCursor.http >= len(sess.fixture.HTTP) {
		return egress.HTTPResult{}, fmt.Errorf("no remaining HTTP fixture for %s %s", request.Method, request.URL)
	}
	item := sess.fixture.HTTP[sess.fixtureCursor.http]
	if strings.ToUpper(item.Method) != strings.ToUpper(request.Method) || item.URL != request.URL {
		return egress.HTTPResult{}, fmt.Errorf("next HTTP fixture expected %s %s", item.Method, item.URL)
	}
	for name, matcher := range item.RequestHeaders {
		if !matchFixture(matcher, headerValue(request.Headers, name)) {
			return egress.HTTPResult{}, fmt.Errorf("HTTP fixture header %s did not match", name)
		}
	}
	body, decodeErr := decodeFixturePayload(request.Body, request.BodyEncoding)
	if decodeErr != nil {
		return egress.HTTPResult{}, decodeErr
	}
	if item.RequestBody != nil && !matchFixture(*item.RequestBody, string(body)) {
		return egress.HTTPResult{}, fmt.Errorf("HTTP fixture body did not match")
	}
	sess.fixtureCursor.http++
	if item.Fail {
		return egress.HTTPResult{}, fmt.Errorf("HTTP fixture failure for %s %s", request.Method, request.URL)
	}
	encoding := item.BodyEncoding
	if encoding == "" {
		encoding = "utf8"
	}
	return egress.HTTPResult{StatusCode: item.StatusCode, FinalURL: item.URL, Headers: httpHeaders(item.ResponseHeaders), Body: item.Body, BodyEncoding: encoding}, nil
}

func fixtureTCPExchange(sess *session, request egress.TCPExchangeRequest) (egress.TCPExchangeResult, error) {
	sess.fixtureCursor.mu.Lock()
	defer sess.fixtureCursor.mu.Unlock()
	if sess.fixtureCursor.tcp >= len(sess.fixture.TCP) {
		return egress.TCPExchangeResult{}, fmt.Errorf("no remaining TCP fixture for %s", request.Address)
	}
	item := sess.fixture.TCP[sess.fixtureCursor.tcp]
	if item.Address != request.Address {
		return egress.TCPExchangeResult{}, fmt.Errorf("next TCP fixture expected %s", item.Address)
	}
	sess.fixtureCursor.tcp++
	if !item.Success {
		return egress.TCPExchangeResult{}, fmt.Errorf("TCP fixture failure for %s", request.Address)
	}
	if len(item.Steps) > 0 && len(item.Steps) != len(request.Steps) {
		return egress.TCPExchangeResult{}, fmt.Errorf("TCP fixture step count did not match")
	}
	result := egress.TCPExchangeResult{RemoteAddress: item.RemoteAddress, Responses: []string{}, Encodings: []string{}}
	if result.RemoteAddress == "" {
		result.RemoteAddress = request.Address
	}
	for index, step := range request.Steps {
		if len(item.Steps) == 0 {
			continue
		}
		expected := item.Steps[index]
		if expected.Operation != step.Operation {
			return egress.TCPExchangeResult{}, fmt.Errorf("TCP fixture step %d operation did not match", index+1)
		}
		if expected.Data != nil && !matchFixture(*expected.Data, step.Data) {
			return egress.TCPExchangeResult{}, fmt.Errorf("TCP fixture step %d data did not match", index+1)
		}
		if expected.Operation == "read" {
			encoding := expected.Encoding
			if encoding == "" {
				encoding = "utf8"
			}
			result.Responses = append(result.Responses, expected.Response)
			result.Encodings = append(result.Encodings, encoding)
		}
	}
	return result, nil
}

func matchFixture(m protocol.FixtureMatcher, value string) bool {
	if m.Exact != "" {
		return value == m.Exact
	}
	if m.Contains != "" {
		return strings.Contains(value, m.Contains)
	}
	if m.Regex != "" {
		ok, _ := regexp.MatchString(m.Regex, value)
		return ok
	}
	return false
}
func decodeFixturePayload(value, encoding string) ([]byte, error) {
	if encoding == "" || encoding == "utf8" {
		return []byte(value), nil
	}
	if encoding == "base64" {
		return base64.StdEncoding.DecodeString(value)
	}
	return nil, fmt.Errorf("unsupported encoding")
}
func httpHeaders(values map[string]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range values {
		out[k] = []string{v}
	}
	return out
}
func headerValue(values map[string]string, name string) string {
	for key, value := range values {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
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
