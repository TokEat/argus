package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"dddd/scanner/internal/arsenal"
	"dddd/scanner/internal/engine"
	pb "github.com/user/dddd-proto/go/scan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestWorkerExecuteTaskReportsCancelled(t *testing.T) {
	prepareUsableAgentConfig(t)

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
	prepareUsableAgentConfig(t)

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

func TestWorkerExecuteTaskForcesRuleFilesOnlyConfig(t *testing.T) {
	prepareUsableAgentConfig(t)

	origNewScanContext := newScanContext
	origRunScanTask := runScanTask
	defer func() {
		newScanContext = origNewScanContext
		runScanTask = origRunScanTask
	}()

	var captured engine.Config
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		captured = cfg
		ctx, cancel := context.WithCancel(context.Background())
		return &engine.ScanContext{
			Config: cfg,
			Ctx:    ctx,
			Cancel: cancel,
		}, nil
	}
	runScanTask = func(ctx *engine.ScanContext) error {
		return nil
	}

	client := &fakeAgentClient{
		stream: &fakeResultStream{},
	}
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client
	worker.executeTask(&pb.Task{
		TaskId:  "task-rule-files",
		Targets: []string{"127.0.0.1"},
		Config: []byte(`{
			"FingerConfigFilePath": "data/arsenal.db",
			"WorkflowYamlPath": "data/arsenal.db",
			"DirSearchYaml": "data/arsenal.db",
			"NucleiTemplate": "data/arsenal.db"
		}`),
	})

	if !captured.RuleFilesOnly {
		t.Fatalf("expected agent task to force RuleFilesOnly")
	}
	if captured.FingerConfigFilePath != filepath.Join("config", "finger.yaml") {
		t.Fatalf("unexpected finger file path: %q", captured.FingerConfigFilePath)
	}
	if captured.WorkflowYamlPath != filepath.Join("config", "workflow.yaml") {
		t.Fatalf("unexpected workflow file path: %q", captured.WorkflowYamlPath)
	}
	if captured.DirSearchYaml != filepath.Join("config", "dir.yaml") {
		t.Fatalf("unexpected dir file path: %q", captured.DirSearchYaml)
	}
	if captured.NucleiTemplate != filepath.Join("config", "pocs") {
		t.Fatalf("unexpected nuclei template path: %q", captured.NucleiTemplate)
	}
	if len(client.taskCompleteReqs) != 1 || client.taskCompleteReqs[0].Status != "DONE" {
		t.Fatalf("expected task completion DONE, got %#v", client.taskCompleteReqs)
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

func TestSyncRulesMaterializesLocalDBWhenHashMatchesButManifestMissing(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	mustWriteAgentFile(t, filepath.Join("data", ".arsenal_hash"), []byte("samehash"))
	createAgentTestArsenalDB(t, filepath.Join("data", "arsenal.db"), "HashMatchProduct", "hash-match.yaml")

	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://server.local", 1, nil)
	worker.apiGetFn = func(url string) (*http.Response, error) {
		switch {
		case strings.HasSuffix(url, "/api/v1/agents/config/api-keys"):
			return testHTTPResponse("", nil), nil
		case strings.HasSuffix(url, "/api/v1/arsenals/db/hash"):
			return testHTTPResponse(`{"hash":"samehash","rule_version":"v1","arsenal_count":4}`, nil), nil
		case strings.HasSuffix(url, "/api/v1/arsenals/db"):
			t.Fatalf("hash match with missing manifest should materialize local DB without downloading")
		}
		return testHTTPResponse(`not found`, nil), nil
	}
	worker.syncRules()

	if !arsenal.IsRulePackageMaterialized("config", "samehash") {
		t.Fatalf("expected local DB to be materialized when hash matches but manifest is missing")
	}
	if _, err := os.Stat(filepath.Join("config", "pocs", "hash-match.yaml")); err != nil {
		t.Fatalf("expected materialized poc from local DB: %v", err)
	}
	if _, err := os.Stat(filepath.Join("config", "pocs", "helpers", "payloads", "agent.txt")); err != nil {
		t.Fatalf("expected materialized poc helper asset from local DB: %v", err)
	}
	assertAgentFileContent(t, filepath.Join("config", "dict", "mysql.txt"), "agent:mysql\n")
	assertAgentFileContent(t, filepath.Join("config", "subdomains.txt"), "www\napi\n")
}

func TestSyncRulesWritesAgentAPIConfigFromInternalEndpoint(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)

	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://server.local", 1, nil)
	worker.apiGetFn = func(url string) (*http.Response, error) {
		switch {
		case strings.HasSuffix(url, "/api/v1/agents/config/api-keys"):
			return testHTTPResponse("quake:\n  - synced-key\n", map[string]string{"Content-Type": "application/x-yaml"}), nil
		case strings.HasSuffix(url, "/api/v1/arsenals/db/hash"):
			return testHTTPResponse(`{"hash":"","rule_version":"v-api","arsenal_count":0}`, nil), nil
		default:
			t.Fatalf("unexpected sync request: %s", url)
		}
		return testHTTPResponse(`not found`, nil), nil
	}

	worker.syncRules()

	assertAgentFileContent(t, filepath.Join("config", "api-config.yaml"), "quake:\n  - synced-key\n")
}

func TestSyncRulesRemovesAgentAPIConfigWhenServerReturnsEmpty(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	mustWriteAgentFile(t, filepath.Join("config", "api-config.yaml"), []byte("quake:\n  - stale-key\n"))

	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://server.local", 1, nil)
	worker.apiGetFn = func(url string) (*http.Response, error) {
		switch {
		case strings.HasSuffix(url, "/api/v1/agents/config/api-keys"):
			return testHTTPResponse("", nil), nil
		case strings.HasSuffix(url, "/api/v1/arsenals/db/hash"):
			return testHTTPResponse(`{"hash":"","rule_version":"v-api","arsenal_count":0}`, nil), nil
		default:
			t.Fatalf("unexpected sync request: %s", url)
		}
		return testHTTPResponse(`not found`, nil), nil
	}

	worker.syncRules()

	if _, err := os.Stat(filepath.Join("config", "api-config.yaml")); !os.IsNotExist(err) {
		t.Fatalf("expected stale api-config.yaml to be removed when server returns empty config, stat err=%v", err)
	}
}

func TestSubscribeAPIConfigUpdatedSyncsOnlyAPIConfig(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)

	stream := &fakeSubscribeClientStream{
		recv: []*pb.TaskNotify{{NotifyType: "api_config_updated"}},
	}
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://server.local", 1, nil)
	worker.client = &fakeAgentClient{subscribeStream: stream}
	worker.apiGetFn = func(url string) (*http.Response, error) {
		switch {
		case strings.HasSuffix(url, "/api/v1/agents/config/api-keys"):
			return testHTTPResponse("quake:\n  - notify-key\n", map[string]string{"Content-Type": "application/x-yaml"}), nil
		case strings.Contains(url, "/api/v1/arsenals/db"):
			t.Fatalf("api_config_updated should not fetch arsenal DB endpoint: %s", url)
		default:
			t.Fatalf("unexpected api config notify request: %s", url)
		}
		return testHTTPResponse(`not found`, nil), nil
	}

	worker.subscribeAndClaim(make(chan struct{}))

	assertAgentFileContent(t, filepath.Join("config", "api-config.yaml"), "quake:\n  - notify-key\n")
	if stream.sentSignals == 0 {
		t.Fatalf("expected subscribe to send initial ready signal")
	}
}

func TestHandleCommandSyncAPIConfigWritesConfig(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)

	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://server.local", 1, nil)
	worker.apiGetFn = func(url string) (*http.Response, error) {
		if !strings.HasSuffix(url, "/api/v1/agents/config/api-keys") {
			t.Fatalf("sync_api_config command should only fetch api config, got %s", url)
		}
		return testHTTPResponse("quake:\n  - command-key\n", map[string]string{"Content-Type": "application/x-yaml"}), nil
	}

	worker.handleAgentCommandResponse([]byte(`{"sync_api_config":true,"api_config_hash":"remote-hash"}`))

	assertAgentFileContent(t, filepath.Join("config", "api-config.yaml"), "quake:\n  - command-key\n")
}

func TestLocalAPIConfigHash(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://server.local", 1, nil)
	if got := worker.localAPIConfigHash(); got != "" {
		t.Fatalf("missing api config hash = %q, want empty", got)
	}
	mustWriteAgentFile(t, filepath.Join("config", "api-config.yaml"), []byte("quake:\n  - hash-key\n"))
	if got := worker.localAPIConfigHash(); got != "012e6f1b6ec96f9b190dd35aaa629028" {
		t.Fatalf("api config md5 = %q", got)
	}
}

func TestSyncRulesDefersActivationWhileTasksRunning(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	dbBytes := createAgentTestArsenalDBBytes(t, "DeferredProduct", "deferred.yaml")

	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://server.local", 1, nil)
	worker.apiGetFn = func(url string) (*http.Response, error) {
		switch {
		case strings.HasSuffix(url, "/api/v1/agents/config/api-keys"):
			return testHTTPResponse("", nil), nil
		case strings.HasSuffix(url, "/api/v1/arsenals/db/hash"):
			return testHTTPResponse(`{"hash":"newhash","rule_version":"v2","arsenal_count":4}`, nil), nil
		case strings.HasSuffix(url, "/api/v1/arsenals/db"):
			return testHTTPResponseBytes(dbBytes, map[string]string{"X-Arsenal-Hash": "newhash"}), nil
		}
		return testHTTPResponse(`not found`, nil), nil
	}
	worker.runningTasks["task-running"] = func() {}
	worker.syncRules()

	if _, err := os.Stat(filepath.Join("data", "arsenal.db")); err != nil {
		t.Fatalf("expected downloaded db to be cached: %v", err)
	}
	if _, err := os.Stat(filepath.Join("config", ".argus-arsenal.json")); !os.IsNotExist(err) {
		t.Fatalf("expected activation to be deferred while tasks run, stat err=%v", err)
	}
	if got := worker.loadLocalDBHash(); got != "" {
		t.Fatalf("expected hash not to be saved before activation, got %q", got)
	}

	delete(worker.runningTasks, "task-running")
	worker.activatePendingRulesIfIdle()

	if !arsenal.IsRulePackageMaterialized("config", "newhash") {
		t.Fatalf("expected pending rules to activate after tasks finish")
	}
	if got := worker.loadLocalDBHash(); got != "newhash" {
		t.Fatalf("expected hash saved after activation, got %q", got)
	}
}

func TestSyncRulesDownloadsViaHTTPAndMaterializes(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	dbBytes := createAgentTestArsenalDBBytes(t, "HTTPProduct", "http-sync.yaml")

	var sawHashRequest, sawDBRequest bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agents/config/api-keys":
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/arsenals/db/hash":
			sawHashRequest = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"hash":"http-hash","rule_version":"v-http","arsenal_count":5}`))
		case "/api/v1/arsenals/db":
			sawDBRequest = true
			w.Header().Set("X-Arsenal-Hash", "sqlite-file-hash")
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(dbBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	worker := NewWorker("agent-http", "127.0.0.1:50051", server.URL, 1, nil)
	worker.syncRules()

	if !sawHashRequest || !sawDBRequest {
		t.Fatalf("expected syncRules to call hash and db endpoints, saw hash=%v db=%v", sawHashRequest, sawDBRequest)
	}
	if got := worker.loadLocalDBHash(); got != "http-hash" {
		t.Fatalf("expected aggregate hash saved after materialization, got %q", got)
	}
	if !arsenal.IsRulePackageMaterialized("config", "http-hash") {
		t.Fatalf("expected HTTP-downloaded rule package to be materialized")
	}
	if _, err := os.Stat(filepath.Join("config", "pocs", "http-sync.yaml")); err != nil {
		t.Fatalf("expected HTTP-downloaded POC to be materialized: %v", err)
	}
	if _, err := os.Stat(filepath.Join("config", "pocs", "helpers", "payloads", "agent.txt")); err != nil {
		t.Fatalf("expected HTTP-downloaded POC helper asset to be materialized: %v", err)
	}
	assertAgentFileContent(t, filepath.Join("config", "dict", "mysql.txt"), "agent:mysql\n")
	assertAgentFileContent(t, filepath.Join("config", "subdomains.txt"), "www\napi\n")
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

func TestInstallGlobalLogTeeStreamsStandardLogs(t *testing.T) {
	originalOutput := log.Writer()
	defer log.SetOutput(originalOutput)

	stream := &fakeLogStream{}
	client := &fakeAgentClient{logStream: stream}
	worker := NewWorker("agent-log", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client

	tee := worker.installGlobalLogTeeWriter()
	if tee == nil {
		t.Fatal("expected log tee to be installed")
	}
	defer tee.Close()

	log.Print("runtime log should reach server")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if stream.contains("agent-log", "runtime log should reach server") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected standard log to be streamed, got %+v", stream.payloads)
}

func createAgentTestArsenalDBBytes(t *testing.T, product, pocFile string) []byte {
	t.Helper()
	root := t.TempDir()
	dbPath := filepath.Join(root, "arsenal.db")
	createAgentTestArsenalDB(t, dbPath, product, pocFile)
	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read test arsenal db: %v", err)
	}
	return data
}

func createAgentTestArsenalDB(t *testing.T, dbPath, product, pocFile string) {
	t.Helper()
	if err := arsenal.OpenDB(dbPath); err != nil {
		t.Fatalf("open test arsenal db: %v", err)
	}
	t.Cleanup(func() { arsenal.DB = nil })
	if err := arsenal.DB.Create(&arsenal.Fingerprint{ProductName: product, RuleExpr: `body="` + product + `"`, Enabled: true}).Error; err != nil {
		t.Fatalf("create fingerprint: %v", err)
	}
	if err := arsenal.DB.Create(&arsenal.Workflow{ProductName: product, PocName: pocFile, MatchType: "root", Enabled: true}).Error; err != nil {
		t.Fatalf("create workflow: %v", err)
	}
	if err := arsenal.DB.Create(&arsenal.DirProbe{ProductName: product, Path: "/demo", Enabled: true}).Error; err != nil {
		t.Fatalf("create dir probe: %v", err)
	}
	if err := arsenal.DB.Create(&arsenal.Poc{
		Name:     pocFile,
		FileName: pocFile,
		Content:  "id: " + pocFile + "\ninfo:\n  name: demo\n  author: test\n  severity: info\nrequests: []\n",
		Enabled:  true,
	}).Error; err != nil {
		t.Fatalf("create poc: %v", err)
	}
	if err := arsenal.DB.Create(&arsenal.PocAsset{
		RelativePath: "helpers/payloads/agent.txt",
		Content:      "payload\n",
		Enabled:      true,
	}).Error; err != nil {
		t.Fatalf("create poc asset: %v", err)
	}
	if err := arsenal.DB.Create(&arsenal.ConfigAsset{
		RelativePath: "dict/mysql.txt",
		Content:      "agent:mysql\n",
		Enabled:      true,
	}).Error; err != nil {
		t.Fatalf("create dict config asset: %v", err)
	}
	if err := arsenal.DB.Create(&arsenal.ConfigAsset{
		RelativePath: "subdomains.txt",
		Content:      "www\napi\n",
		Enabled:      true,
	}).Error; err != nil {
		t.Fatalf("create subdomains config asset: %v", err)
	}
}

func mustWriteAgentFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func assertAgentFileContent(t *testing.T, path, expected string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(data) != expected {
		t.Fatalf("content %s = %q, want %q", path, string(data), expected)
	}
}

func testHTTPResponse(body string, headers map[string]string) *http.Response {
	return testHTTPResponseBytes([]byte(body), headers)
}

func testHTTPResponseBytes(body []byte, headers map[string]string) *http.Response {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
	for key, value := range headers {
		resp.Header.Set(key, value)
	}
	return resp
}

func prepareUsableAgentConfig(t *testing.T) {
	t.Helper()
	t.Chdir(t.TempDir())
	mustWriteAgentFile(t, filepath.Join("config", "finger.yaml"), []byte("TestProduct:\n  - 'body=\"test\"'\n"))
	mustWriteAgentFile(t, filepath.Join("config", "workflow.yaml"), []byte("TestProduct:\n  type:\n    - root\n  pocs:\n    - test.yaml\n"))
	mustWriteAgentFile(t, filepath.Join("config", "dir.yaml"), []byte("TestProduct:\n  - /test\n"))
	if err := os.MkdirAll(filepath.Join("config", "pocs"), 0o755); err != nil {
		t.Fatalf("mkdir test pocs: %v", err)
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

func TestFingerprintDebugCustomOnlyUsesSingleCustomRule(t *testing.T) {
	origNewScanContext := newScanContext
	origRunScanTask := runScanTask
	defer func() {
		newScanContext = origNewScanContext
		runScanTask = origRunScanTask
	}()

	var scannedProducts []string
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		ctx, cancel := context.WithCancel(context.Background())
		return &engine.ScanContext{
			Config: cfg,
			Ctx:    ctx,
			Cancel: cancel,
			FingerprintDB: []engine.FingerPEntity{
				{ProductName: "ExistingOne"},
				{ProductName: "ExistingTwo"},
			},
		}, nil
	}
	runScanTask = func(ctx *engine.ScanContext) error {
		for _, fp := range ctx.FingerprintDB {
			scannedProducts = append(scannedProducts, fp.ProductName)
		}
		return nil
	}

	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	completed := false

	worker.runFingerprintDebugSession(
		context.Background(),
		&pb.DebugCommand{
			Action:     "start_fingerprint_debug",
			SessionId:  "debug-finger-1",
			TenantId:   "default",
			TargetUrl:  "https://target.local/",
			TimeoutSec: 5,
			PocContent: `{"custom_only":true,"custom_product":"OnlyOne","custom_rule":"body=\"only-one\""}`,
		},
		5*time.Second,
		func(*pb.DebugEvent) {},
		func(string) { completed = true },
	)

	if !completed {
		t.Fatalf("expected debug session to complete")
	}
	if !slices.Equal(scannedProducts, []string{"OnlyOne"}) {
		t.Fatalf("expected only custom fingerprint to be scanned, got %#v", scannedProducts)
	}
}

func TestFingerprintDebugCustomOnlyUsesMultipleCustomRules(t *testing.T) {
	origNewScanContext := newScanContext
	origRunScanTask := runScanTask
	defer func() {
		newScanContext = origNewScanContext
		runScanTask = origRunScanTask
	}()

	var scannedProducts []string
	var scannedRules []string
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		ctx, cancel := context.WithCancel(context.Background())
		return &engine.ScanContext{
			Config: cfg,
			Ctx:    ctx,
			Cancel: cancel,
			FingerprintDB: []engine.FingerPEntity{
				{ProductName: "ExistingOne"},
				{ProductName: "ExistingTwo"},
			},
		}, nil
	}
	runScanTask = func(ctx *engine.ScanContext) error {
		for _, fp := range ctx.FingerprintDB {
			scannedProducts = append(scannedProducts, fp.ProductName)
			scannedRules = append(scannedRules, fp.AllString)
		}
		return nil
	}

	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	completed := false
	var completeErr string

	worker.runFingerprintDebugSession(
		context.Background(),
		&pb.DebugCommand{
			Action:     "start_fingerprint_debug",
			SessionId:  "debug-finger-multi",
			TenantId:   "default",
			TargetUrl:  "https://target.local/",
			TimeoutSec: 5,
			PocContent: `{"custom_only":true,"custom_product":"OnlyOne","custom_rules":["body=\"only-one\"","title=\"OnlyOne\""]}`,
		},
		5*time.Second,
		func(*pb.DebugEvent) {},
		func(errMsg string) {
			completed = true
			completeErr = errMsg
		},
	)

	if !completed {
		t.Fatalf("expected debug session to complete")
	}
	if completeErr != "" {
		t.Fatalf("expected multi-rule debug to complete without error, got %q", completeErr)
	}
	if !slices.Equal(scannedProducts, []string{"OnlyOne", "OnlyOne"}) {
		t.Fatalf("expected one custom fingerprint entity per rule, got %#v", scannedProducts)
	}
	if !slices.Equal(scannedRules, []string{`body="only-one"`, `title="OnlyOne"`}) {
		t.Fatalf("expected custom rules to remain separate, got %#v", scannedRules)
	}
}

func TestFingerprintDebugCustomRulesFallbackToCustomRuleWhenEmpty(t *testing.T) {
	origNewScanContext := newScanContext
	origRunScanTask := runScanTask
	defer func() {
		newScanContext = origNewScanContext
		runScanTask = origRunScanTask
	}()

	var scannedRules []string
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		ctx, cancel := context.WithCancel(context.Background())
		return &engine.ScanContext{
			Config:        cfg,
			Ctx:           ctx,
			Cancel:        cancel,
			FingerprintDB: []engine.FingerPEntity{{ProductName: "ExistingOne"}},
		}, nil
	}
	runScanTask = func(ctx *engine.ScanContext) error {
		for _, fp := range ctx.FingerprintDB {
			scannedRules = append(scannedRules, fp.AllString)
		}
		return nil
	}

	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	var completeErr string

	worker.runFingerprintDebugSession(
		context.Background(),
		&pb.DebugCommand{
			Action:     "start_fingerprint_debug",
			SessionId:  "debug-finger-fallback",
			TenantId:   "default",
			TargetUrl:  "https://target.local/",
			TimeoutSec: 5,
			PocContent: `{"custom_only":true,"custom_product":"OnlyOne","custom_rules":[" ",""],"custom_rule":"body=\"fallback\""}`,
		},
		5*time.Second,
		func(*pb.DebugEvent) {},
		func(errMsg string) {
			completeErr = errMsg
		},
	)

	if completeErr != "" {
		t.Fatalf("expected empty custom_rules to fall back to custom_rule, got %q", completeErr)
	}
	if !slices.Equal(scannedRules, []string{`body="fallback"`}) {
		t.Fatalf("expected fallback custom_rule to be scanned, got %#v", scannedRules)
	}
}

func TestFingerprintDebugCustomOnlyAllowsRuleWithoutProduct(t *testing.T) {
	origNewScanContext := newScanContext
	origRunScanTask := runScanTask
	defer func() {
		newScanContext = origNewScanContext
		runScanTask = origRunScanTask
	}()

	var scannedProducts []string
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		ctx, cancel := context.WithCancel(context.Background())
		return &engine.ScanContext{
			Config: cfg,
			Ctx:    ctx,
			Cancel: cancel,
			FingerprintDB: []engine.FingerPEntity{
				{ProductName: "ExistingOne"},
			},
		}, nil
	}
	runScanTask = func(ctx *engine.ScanContext) error {
		for _, fp := range ctx.FingerprintDB {
			scannedProducts = append(scannedProducts, fp.ProductName)
		}
		return nil
	}

	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	completed := false
	var completeErr string

	worker.runFingerprintDebugSession(
		context.Background(),
		&pb.DebugCommand{
			Action:     "start_fingerprint_debug",
			SessionId:  "debug-finger-rule-only",
			TenantId:   "default",
			TargetUrl:  "https://target.local/",
			TimeoutSec: 5,
			PocContent: `{"custom_only":true,"custom_rule":"body=\"only-one\""}`,
		},
		5*time.Second,
		func(*pb.DebugEvent) {},
		func(errMsg string) {
			completed = true
			completeErr = errMsg
		},
	)

	if !completed {
		t.Fatalf("expected debug session to complete")
	}
	if completeErr != "" {
		t.Fatalf("expected rule-only debug to complete without error, got %q", completeErr)
	}
	if !slices.Equal(scannedProducts, []string{"DebugFingerprint"}) {
		t.Fatalf("expected synthetic debug fingerprint to be scanned, got %#v", scannedProducts)
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
	subscribeStream   grpc.BidiStreamingClient[pb.AgentSignal, pb.TaskNotify]
	debugStream       grpc.ClientStreamingClient[pb.DebugEvent, pb.Ack]
	debugErr          error
	logStream         grpc.ClientStreamingClient[pb.LogPayload, pb.Ack]
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
	return c.subscribeStream, nil
}

func (c *fakeAgentClient) ClaimTask(ctx context.Context, in *pb.ClaimTaskReq, opts ...grpc.CallOption) (*pb.Task, error) {
	return &pb.Task{}, nil
}

func (c *fakeAgentClient) StreamLogs(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[pb.LogPayload, pb.Ack], error) {
	return c.logStream, nil
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

type fakeSubscribeClientStream struct {
	recv        []*pb.TaskNotify
	sentSignals int
}

func (s *fakeSubscribeClientStream) Send(*pb.AgentSignal) error {
	s.sentSignals++
	return nil
}

func (s *fakeSubscribeClientStream) Recv() (*pb.TaskNotify, error) {
	if len(s.recv) == 0 {
		return nil, io.EOF
	}
	msg := s.recv[0]
	s.recv = s.recv[1:]
	return msg, nil
}

func (s *fakeSubscribeClientStream) Header() (metadata.MD, error) { return nil, nil }
func (s *fakeSubscribeClientStream) Trailer() metadata.MD         { return nil }
func (s *fakeSubscribeClientStream) CloseSend() error             { return nil }
func (s *fakeSubscribeClientStream) Context() context.Context     { return context.Background() }
func (s *fakeSubscribeClientStream) SendMsg(m any) error {
	if signal, ok := m.(*pb.AgentSignal); ok {
		return s.Send(signal)
	}
	return nil
}
func (s *fakeSubscribeClientStream) RecvMsg(m any) error {
	msg, err := s.Recv()
	if err != nil {
		return err
	}
	if notify, ok := m.(*pb.TaskNotify); ok {
		*notify = *msg
	}
	return nil
}

type fakeLogStream struct {
	mu       sync.Mutex
	payloads []*pb.LogPayload
}

func (s *fakeLogStream) Send(payload *pb.LogPayload) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.payloads = append(s.payloads, payload)
	return nil
}

func (s *fakeLogStream) CloseAndRecv() (*pb.Ack, error) {
	return &pb.Ack{Success: true}, nil
}

func (s *fakeLogStream) Header() (metadata.MD, error) {
	return nil, nil
}

func (s *fakeLogStream) Trailer() metadata.MD {
	return nil
}

func (s *fakeLogStream) CloseSend() error {
	return nil
}

func (s *fakeLogStream) Context() context.Context {
	return context.Background()
}

func (s *fakeLogStream) SendMsg(m any) error {
	if payload, ok := m.(*pb.LogPayload); ok {
		return s.Send(payload)
	}
	return nil
}

func (s *fakeLogStream) RecvMsg(m any) error {
	if ack, ok := m.(*pb.Ack); ok {
		ack.Success = true
		return nil
	}
	return io.EOF
}

func (s *fakeLogStream) contains(agentID, message string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, payload := range s.payloads {
		if payload.GetAgentId() == agentID && strings.Contains(payload.GetMessage(), message) {
			return true
		}
	}
	return false
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
