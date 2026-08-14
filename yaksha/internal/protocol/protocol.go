// Package protocol defines the JSON-lines protocol between a controller and
// the Yaksha runtime process.
//
// Wire format: one JSON object per line on stdin (request) and stdout
// (response). Yaksha reads requests until stdin EOF; the controller is
// responsible for process-level timeout and cancellation.
package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Protocol limits bound memory use before a request reaches the Yaklang VM.
const (
	DefaultTimeoutMS     int64 = 15_000
	MaxTimeoutMS         int64 = 120_000
	MaxRequestLineBytes        = 4 << 20
	MaxScriptBytes             = 1 << 20
	MaxParamsBytes             = 1 << 20
	MaxIDBytes                 = 128
	MaxResponseLineBytes       = 2 << 20
	MaxTestCases               = 32
	MaxFixturesPerCase         = 64
	MaxDependencies            = 16
	MaxAssets                  = 32
	MaxNetworkTargets          = 32
	MaxResolvedItemBytes       = 1 << 20
	MaxProxyURLBytes           = 2 << 10
	MaxCallDepth               = 8
	MaxCalls                   = 32
	MaxExchangeSteps           = 16
	MaxExchangeBytes           = 1 << 20
)

// Request is a single EXP runtime request. Action defaults to run for
// compatibility with the first protocol revision.
type Request struct {
	ID             string         `json:"id"`
	Action         string         `json:"action,omitempty"`
	Script         string         `json:"script"`
	Params         map[string]any `json:"params,omitempty"`
	TimeoutMS      int64          `json:"timeout_ms,omitempty"`
	TestCases      []TestCase     `json:"test_cases,omitempty"`
	ExpID          string         `json:"exp_id,omitempty"`
	Revision       int            `json:"revision,omitempty"`
	SourceSHA256   string         `json:"source_sha256,omitempty"`
	Dependencies   []Dependency   `json:"dependencies,omitempty"`
	Assets         []Asset        `json:"assets,omitempty"`
	NetworkTargets []string       `json:"network_targets,omitempty"`
	Egress         *EgressConfig  `json:"egress,omitempty"`
	ValidationMode string         `json:"validation_mode,omitempty"`
}

const (
	ValidationExecution = "execution"
	ValidationContract  = "contract"
)

// EgressConfig selects the network path for one top-level execution. The
// daemon consumes this field before forwarding the request to a worker, so
// proxy credentials are never visible to Yaklang code.
type EgressConfig struct {
	Mode        string `json:"mode"`
	SOCKS5Proxy string `json:"socks5_proxy,omitempty"`
	RouteID     string `json:"route_id,omitempty"`
}

const (
	EgressDisabled = "disabled"
	EgressDirect   = "direct"
	EgressSOCKS5   = "socks5"
	EgressRelay    = "relay"
)

const (
	ActionRun      = "run"
	ActionInspect  = "inspect"
	ActionValidate = "validate"
	ActionDebug    = "debug"
	ActionTest     = "test"
)

// Response status values.
const (
	StatusSucceeded     = "Succeeded"
	StatusFailed        = "Failed"
	StatusTimeout       = "Timeout"
	StatusCanceled      = "Canceled"
	StatusInternalError = "InternalError"
)

// Response is the result of a single execution.
type Response struct {
	ID         string            `json:"id"`
	Action     string            `json:"action,omitempty"`
	Status     string            `json:"status"`
	Context    *ExecutionContext `json:"context,omitempty"`
	Result     any               `json:"result,omitempty"`
	Inspection *Inspection       `json:"inspection,omitempty"`
	Validation *Validation       `json:"validation,omitempty"`
	Debug      *DebugReport      `json:"debug,omitempty"`
	Test       *TestReport       `json:"test,omitempty"`
	Evidence   map[string]any    `json:"evidence,omitempty"`
	Logs       []string          `json:"logs,omitempty"`
	Error      string            `json:"error,omitempty"`
	Calls      []CallRecord      `json:"calls,omitempty"`
}

// ExecutionContext binds one runtime response to the exact single-file EXP
// identity supplied by its controller. SourceSHA256 is always calculated by
// Yaksha from Script; it is never copied from the request.
type ExecutionContext struct {
	ExpID        string `json:"exp_id,omitempty"`
	Revision     int    `json:"revision,omitempty"`
	SourceSHA256 string `json:"source_sha256"`
}

type Dependency struct {
	ExpID        string `json:"exp_id"`
	Revision     int    `json:"revision"`
	SourceSHA256 string `json:"source_sha256"`
	Script       string `json:"script"`
}

type Asset struct {
	AssetID  string `json:"asset_id"`
	SHA256   string `json:"sha256"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

type DependencyReference struct {
	ExpID    string `json:"exp_id"`
	Revision int    `json:"revision"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
}

type AssetReference struct {
	AssetID string `json:"asset_id"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
}

type CallRecord struct {
	Context    *ExecutionContext `json:"context,omitempty"`
	Status     string            `json:"status"`
	Result     any               `json:"result,omitempty"`
	Validation *Validation       `json:"validation,omitempty"`
	Debug      *DebugReport      `json:"debug,omitempty"`
	Evidence   map[string]any    `json:"evidence,omitempty"`
	Logs       []string          `json:"logs,omitempty"`
	Error      string            `json:"error,omitempty"`
	Calls      []CallRecord      `json:"calls,omitempty"`
}

var (
	expIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	sourceHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func SourceHash(source string) string {
	sum := sha256.Sum256([]byte(source))
	return fmt.Sprintf("%x", sum[:])
}

func ExecutionContextFor(req Request) *ExecutionContext {
	if req.Script == "" {
		return nil
	}
	return &ExecutionContext{ExpID: req.ExpID, Revision: req.Revision, SourceSHA256: SourceHash(req.Script)}
}

// Inspection is the side-effect-free, source-derived contract used to render
// an EXP parameter form. Positions in diagnostics are one-based.
type Inspection struct {
	Valid        bool                  `json:"valid"`
	SourceSHA256 string                `json:"source_sha256"`
	SourceBytes  int                   `json:"source_bytes"`
	SourceLines  int                   `json:"source_lines"`
	Parameters   []CLIParameter        `json:"parameters"`
	Dependencies []DependencyReference `json:"dependencies"`
	AssetRefs    []AssetReference      `json:"asset_refs"`
	Diagnostics  []Diagnostic          `json:"diagnostics"`
}

type CLIParameter struct {
	Name           string      `json:"name"`
	Type           string      `json:"type"`
	Required       bool        `json:"required"`
	Default        any         `json:"default,omitempty"`
	HasDefault     bool        `json:"has_default"`
	Help           string      `json:"help,omitempty"`
	VerboseName    string      `json:"verbose_name,omitempty"`
	Group          string      `json:"group,omitempty"`
	MultipleSelect bool        `json:"multiple_select,omitempty"`
	Options        []CLIOption `json:"options,omitempty"`
}

type CLIOption struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type Diagnostic struct {
	Severity  string `json:"severity"`
	Code      string `json:"code"`
	Message   string `json:"message"`
	Field     string `json:"field,omitempty"`
	Line      int    `json:"line"`
	Column    int    `json:"column"`
	EndLine   int    `json:"end_line,omitempty"`
	EndColumn int    `json:"end_column,omitempty"`
}

// Validation reports whether one source/parameter pair is safe to hand to the
// VM. It does not echo parameter values because those may contain secrets.
type Validation struct {
	Valid        bool         `json:"valid"`
	SourceSHA256 string       `json:"source_sha256"`
	Checks       []string     `json:"checks"`
	Diagnostics  []Diagnostic `json:"diagnostics"`
}

type DebugReport struct {
	Events    []DebugEvent `json:"events"`
	Truncated bool         `json:"truncated"`
}

type DebugEvent struct {
	Kind       string `json:"kind"`
	Operation  string `json:"operation"`
	Target     string `json:"target"`
	StatusCode int    `json:"status_code,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
	Request    any    `json:"request,omitempty"`
	Response   any    `json:"response,omitempty"`
}

type TestCase struct {
	ID      string          `json:"id"`
	Params  map[string]any  `json:"params,omitempty"`
	Fixture *Fixture        `json:"fixture,omitempty"`
	Expect  TestExpectation `json:"expect"`
}

type Fixture struct {
	HTTP []HTTPFixture `json:"http,omitempty"`
	TCP  []TCPFixture  `json:"tcp,omitempty"`
}

type HTTPFixture struct {
	Method          string                    `json:"method"`
	URL             string                    `json:"url"`
	RequestHeaders  map[string]FixtureMatcher `json:"request_headers,omitempty"`
	RequestBody     *FixtureMatcher           `json:"request_body,omitempty"`
	StatusCode      int                       `json:"status_code,omitempty"`
	ResponseHeaders map[string]string         `json:"response_headers,omitempty"`
	Body            string                    `json:"body,omitempty"`
	BodyEncoding    string                    `json:"body_encoding,omitempty"`
	Fail            bool                      `json:"fail,omitempty"`
}

type TCPFixture struct {
	Address       string           `json:"address"`
	Success       bool             `json:"success"`
	RemoteAddress string           `json:"remote_address,omitempty"`
	Steps         []TCPFixtureStep `json:"steps,omitempty"`
}

type FixtureMatcher struct {
	Exact    string `json:"exact,omitempty"`
	Contains string `json:"contains,omitempty"`
	Regex    string `json:"regex,omitempty"`
}

type TCPFixtureStep struct {
	Operation string          `json:"operation"`
	Data      *FixtureMatcher `json:"data,omitempty"`
	Response  string          `json:"response,omitempty"`
	Encoding  string          `json:"encoding,omitempty"`
}

type TestExpectation struct {
	Status        string                     `json:"status,omitempty"`
	Result        json.RawMessage            `json:"result,omitempty"`
	Evidence      map[string]json.RawMessage `json:"evidence,omitempty"`
	LogsContain   []string                   `json:"logs_contain,omitempty"`
	ErrorContains string                     `json:"error_contains,omitempty"`
}

type TestReport struct {
	Passed int              `json:"passed"`
	Failed int              `json:"failed"`
	Cases  []TestCaseResult `json:"cases"`
}

type TestCaseResult struct {
	ID                string         `json:"id"`
	Passed            bool           `json:"passed"`
	Status            string         `json:"status"`
	Result            any            `json:"result,omitempty"`
	Evidence          map[string]any `json:"evidence,omitempty"`
	Logs              []string       `json:"logs,omitempty"`
	Error             string         `json:"error,omitempty"`
	Events            []DebugEvent   `json:"events,omitempty"`
	AssertionFailures []string       `json:"assertion_failures"`
	Calls             []CallRecord   `json:"calls,omitempty"`
}

// ParseRequest decodes a single request JSON line.
func ParseRequest(line string) (Request, error) {
	if len(line) > MaxRequestLineBytes {
		return Request{}, fmt.Errorf("request exceeds %d bytes", MaxRequestLineBytes)
	}
	var req Request
	decoder := json.NewDecoder(bytes.NewBufferString(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, fmt.Errorf("invalid request JSON: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return req, err
	}
	if req.ID == "" {
		req.ID = "anon"
	}
	if req.Action == "" {
		req.Action = ActionRun
	}
	if err := ValidateRequest(req); err != nil {
		return req, err
	}
	return req, nil
}

// ValidateRequest applies the same bounds to parsed and in-process requests.
func ValidateRequest(req Request) error {
	action := req.Action
	if action == "" {
		action = ActionRun
	}
	if action != ActionRun && action != ActionInspect && action != ActionValidate && action != ActionDebug && action != ActionTest {
		return fmt.Errorf("unsupported action %q", req.Action)
	}
	if strings.TrimSpace(req.Script) == "" {
		return fmt.Errorf("missing script")
	}
	if len(req.ID) > MaxIDBytes {
		return fmt.Errorf("request id exceeds %d bytes", MaxIDBytes)
	}
	if len(req.Script) > MaxScriptBytes {
		return fmt.Errorf("script exceeds %d bytes", MaxScriptBytes)
	}
	if len(req.Dependencies) > MaxDependencies {
		return fmt.Errorf("dependencies must contain at most %d entries", MaxDependencies)
	}
	if len(req.Assets) > MaxAssets {
		return fmt.Errorf("assets must contain at most %d entries", MaxAssets)
	}
	if len(req.NetworkTargets) > MaxNetworkTargets {
		return fmt.Errorf("network_targets must contain at most %d entries", MaxNetworkTargets)
	}
	if req.Egress != nil {
		if err := validateEgress(*req.Egress); err != nil {
			return err
		}
	}
	if req.ValidationMode != "" && req.ValidationMode != ValidationContract && req.ValidationMode != ValidationExecution {
		return fmt.Errorf("validation_mode must be contract or execution")
	}
	if action != ActionValidate && req.ValidationMode != "" && req.ValidationMode != ValidationExecution {
		return fmt.Errorf("validation_mode contract is only valid for validate")
	}
	for _, dependency := range req.Dependencies {
		if !expIDPattern.MatchString(dependency.ExpID) || dependency.Revision < 1 {
			return fmt.Errorf("dependency identity is invalid")
		}
		if !sourceHashPattern.MatchString(dependency.SourceSHA256) || dependency.SourceSHA256 != SourceHash(dependency.Script) {
			return fmt.Errorf("dependency %s revision %d source_sha256 mismatch", dependency.ExpID, dependency.Revision)
		}
		if strings.TrimSpace(dependency.Script) == "" || len(dependency.Script) > MaxResolvedItemBytes {
			return fmt.Errorf("dependency %s revision %d script exceeds protocol limits", dependency.ExpID, dependency.Revision)
		}
	}
	for _, asset := range req.Assets {
		if !expIDPattern.MatchString(asset.AssetID) || !sourceHashPattern.MatchString(asset.SHA256) {
			return fmt.Errorf("asset identity is invalid")
		}
		if asset.Encoding != "utf8" && asset.Encoding != "base64" {
			return fmt.Errorf("asset %s encoding must be utf8 or base64", asset.AssetID)
		}
		if len(asset.Content) > MaxResolvedItemBytes*2 {
			return fmt.Errorf("asset %s content exceeds protocol limits", asset.AssetID)
		}
	}
	boundContext := req.ExpID != "" || req.Revision != 0 || req.SourceSHA256 != ""
	if boundContext {
		if !expIDPattern.MatchString(req.ExpID) {
			return fmt.Errorf("exp_id must match %s", expIDPattern.String())
		}
		if req.Revision < 1 {
			return fmt.Errorf("revision must be greater than zero for a bound EXP context")
		}
		if !sourceHashPattern.MatchString(req.SourceSHA256) {
			return fmt.Errorf("source_sha256 must contain 64 lowercase hexadecimal characters")
		}
		actual := SourceHash(req.Script)
		if req.SourceSHA256 != actual {
			return fmt.Errorf("source_sha256 mismatch: expected %s, actual %s", req.SourceSHA256, actual)
		}
	}
	if req.TimeoutMS < 0 || req.TimeoutMS > MaxTimeoutMS {
		return fmt.Errorf("timeout_ms must be between 0 and %d", MaxTimeoutMS)
	}
	if req.Params != nil {
		raw, err := json.Marshal(req.Params)
		if err != nil {
			return fmt.Errorf("params are not JSON-compatible: %w", err)
		}
		if len(raw) > MaxParamsBytes {
			return fmt.Errorf("params exceed %d bytes", MaxParamsBytes)
		}
	}
	if action == ActionTest {
		if len(req.TestCases) == 0 || len(req.TestCases) > MaxTestCases {
			return fmt.Errorf("test_cases must contain between 1 and %d cases", MaxTestCases)
		}
		if len(req.Params) > 0 {
			return fmt.Errorf("top-level params are not allowed for test; use test_cases[].params")
		}
		seenCaseIDs := make(map[string]struct{}, len(req.TestCases))
		for _, testCase := range req.TestCases {
			if testCase.ID == "" || len(testCase.ID) > MaxIDBytes {
				return fmt.Errorf("test case id must contain 1 to %d bytes", MaxIDBytes)
			}
			if _, exists := seenCaseIDs[testCase.ID]; exists {
				return fmt.Errorf("duplicate test case id %q", testCase.ID)
			}
			seenCaseIDs[testCase.ID] = struct{}{}
			paramsRaw, err := json.Marshal(testCase.Params)
			if err != nil || len(paramsRaw) > MaxParamsBytes {
				return fmt.Errorf("test case %q params exceed protocol limits", testCase.ID)
			}
			if err := validateFixture(testCase.ID, testCase.Fixture); err != nil {
				return err
			}
			if testCase.Expect.Status != "" && !isResponseStatus(testCase.Expect.Status) {
				return fmt.Errorf("test case %q has unsupported expected status %q", testCase.ID, testCase.Expect.Status)
			}
		}
	} else if len(req.TestCases) > 0 {
		return fmt.Errorf("test_cases require action %q", ActionTest)
	}
	return nil
}

func validateEgress(config EgressConfig) error {
	switch config.Mode {
	case EgressDisabled, EgressDirect:
		if config.SOCKS5Proxy != "" || config.RouteID != "" {
			return fmt.Errorf("egress mode %s does not accept socks5_proxy or route_id", config.Mode)
		}
	case EgressSOCKS5:
		if config.RouteID != "" {
			return fmt.Errorf("egress mode socks5 does not accept route_id")
		}
		return validateSOCKS5Proxy(config.SOCKS5Proxy)
	case EgressRelay:
		if config.SOCKS5Proxy != "" {
			return fmt.Errorf("egress mode relay does not accept socks5_proxy")
		}
		if !expIDPattern.MatchString(config.RouteID) {
			return fmt.Errorf("egress.route_id must contain 1 to %d safe identifier bytes", MaxIDBytes)
		}
	default:
		return fmt.Errorf("egress.mode must be one of disabled, direct, socks5, relay")
	}
	return nil
}

func validateSOCKS5Proxy(raw string) error {
	if len(raw) == 0 || len(raw) > MaxProxyURLBytes {
		return fmt.Errorf("egress.socks5_proxy must contain 1 to %d bytes", MaxProxyURLBytes)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "socks5" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("egress.socks5_proxy must be socks5://[user:password@]host:port")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("egress.socks5_proxy has an invalid port")
	}
	return nil
}

func validateFixture(caseID string, fixture *Fixture) error {
	if fixture == nil {
		return nil
	}
	if len(fixture.HTTP) > MaxFixturesPerCase || len(fixture.TCP) > MaxFixturesPerCase {
		return fmt.Errorf("test case %q fixtures exceed %d entries per protocol", caseID, MaxFixturesPerCase)
	}
	for _, item := range fixture.HTTP {
		if !allowedHTTPMethod(item.Method) || item.URL == "" {
			return fmt.Errorf("test case %q HTTP fixture has an unsupported method or missing URL", caseID)
		}
		if !item.Fail && (item.StatusCode < 100 || item.StatusCode > 599) {
			return fmt.Errorf("test case %q HTTP fixture status_code must be between 100 and 599", caseID)
		}
		if len(item.Body) > MaxScriptBytes {
			return fmt.Errorf("test case %q HTTP fixture body exceeds %d bytes", caseID, MaxScriptBytes)
		}
		if item.BodyEncoding != "" && item.BodyEncoding != "utf8" && item.BodyEncoding != "base64" {
			return fmt.Errorf("test case %q HTTP fixture body_encoding must be utf8 or base64", caseID)
		}
		for _, matcher := range item.RequestHeaders {
			if err := validateMatcher(matcher); err != nil {
				return fmt.Errorf("test case %q: %w", caseID, err)
			}
		}
		if item.RequestBody != nil {
			if err := validateMatcher(*item.RequestBody); err != nil {
				return fmt.Errorf("test case %q: %w", caseID, err)
			}
		}
	}
	for _, item := range fixture.TCP {
		if item.Address == "" {
			return fmt.Errorf("test case %q TCP fixture requires an address", caseID)
		}
		if len(item.Steps) > MaxExchangeSteps {
			return fmt.Errorf("test case %q TCP fixture exceeds %d steps", caseID, MaxExchangeSteps)
		}
		for _, step := range item.Steps {
			if step.Operation != "write" && step.Operation != "read" && step.Operation != "half_close" {
				return fmt.Errorf("test case %q TCP fixture has unsupported operation %q", caseID, step.Operation)
			}
			if step.Encoding != "" && step.Encoding != "utf8" && step.Encoding != "base64" {
				return fmt.Errorf("test case %q TCP fixture encoding must be utf8 or base64", caseID)
			}
			if step.Data != nil {
				if err := validateMatcher(*step.Data); err != nil {
					return fmt.Errorf("test case %q: %w", caseID, err)
				}
			}
		}
	}
	return nil
}

func allowedHTTPMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return true
	default:
		return false
	}
}

func validateMatcher(m FixtureMatcher) error {
	count := 0
	if m.Exact != "" {
		count++
	}
	if m.Contains != "" {
		count++
	}
	if m.Regex != "" {
		count++
		if _, err := regexp.Compile(m.Regex); err != nil {
			return fmt.Errorf("invalid fixture regex")
		}
	}
	if count != 1 {
		return fmt.Errorf("fixture matcher must set exactly one of exact, contains, regex")
	}
	return nil
}

func isResponseStatus(status string) bool {
	switch status {
	case StatusSucceeded, StatusFailed, StatusTimeout, StatusCanceled, StatusInternalError:
		return true
	default:
		return false
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("invalid request JSON: multiple values")
		}
		return fmt.Errorf("invalid request JSON: %w", err)
	}
	return nil
}

// EncodeResponse serializes a response as a single JSON line.
func EncodeResponse(resp Response) ([]byte, error) {
	raw, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxResponseLineBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", MaxResponseLineBytes)
	}
	return raw, nil
}
