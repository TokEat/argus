package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/P0lar1ght/argus/scanner/internal/arsenal"
	"github.com/P0lar1ght/argus/scanner/internal/engine"
	"github.com/P0lar1ght/argus/scanner/structs"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
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

func TestClaimAvailableTasksStopsWhenWorkerIsDraining(t *testing.T) {
	client := &fakeAgentClient{}
	worker := NewWorker("agent-draining", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client
	worker.sem = make(chan struct{}, 1)
	worker.freeSlots.Store(1)
	worker.draining.Store(true)

	worker.claimAvailableTasks()
	if client.claimTaskCalls != 0 {
		t.Fatalf("draining worker called ClaimTask %d times, want 0", client.claimTaskCalls)
	}
}

func TestClaimAvailableTasksDoesNotExecuteInFlightClaimAfterDrain(t *testing.T) {
	worker := NewWorker("agent-draining-race", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	client := &fakeAgentClient{}
	client.claimTaskHook = func() *pb.Task {
		worker.draining.Store(true)
		return &pb.Task{TaskId: "task-after-drain"}
	}
	worker.client = client
	worker.sem = make(chan struct{}, 1)
	worker.freeSlots.Store(1)

	worker.claimAvailableTasks()
	if client.claimTaskCalls != 1 {
		t.Fatalf("ClaimTask calls = %d, want 1 in-flight call", client.claimTaskCalls)
	}
	if len(worker.sem) != 0 || worker.freeSlots.Load() != 1 {
		t.Fatalf("in-flight claim consumed capacity after drain: sem=%d free=%d", len(worker.sem), worker.freeSlots.Load())
	}
	worker.mu.Lock()
	running := len(worker.runningTasks)
	worker.mu.Unlock()
	if running != 0 {
		t.Fatalf("in-flight claim started %d tasks after drain", running)
	}
}

func TestSubscribeAndClaimDoesNotReconnectWhileDraining(t *testing.T) {
	client := &fakeAgentClient{}
	worker := NewWorker("agent-draining", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client
	worker.draining.Store(true)

	worker.subscribeAndClaim(make(chan struct{}))
	if client.subscribeCalls != 0 {
		t.Fatalf("draining worker opened Subscribe stream %d times, want 0", client.subscribeCalls)
	}
}

func TestRunSpotTerminationListenerDrainsAndCancelsAfterAcceptedDump(t *testing.T) {
	metadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("2026-07-11T09:30:00+08:00"))
	}))
	defer metadataServer.Close()

	client := &fakeAgentClient{emergencyDumpAcks: []*pb.Ack{{Success: false, Message: "retry"}, {Success: true}}}
	worker := NewWorker("agent-spot", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client
	worker.sessionToken = "session-token"
	cancelled := make(chan struct{}, 1)
	worker.runningTasks["task-running"] = func() { cancelled <- struct{}{} }

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	worker.runSpotTerminationListener(ctx, metadataServer.Client(), metadataServer.URL, time.Millisecond, time.Millisecond)

	if !worker.draining.Load() {
		t.Fatal("worker did not enter draining state")
	}
	if len(client.emergencyDumpReqs) != 2 {
		t.Fatalf("EmergencyDump calls = %d, want rejected call plus retry", len(client.emergencyDumpReqs))
	}
	if got := client.emergencyDumpTokens; len(got) != 2 || got[0] != "session-token" || got[1] != "session-token" {
		t.Fatalf("EmergencyDump session tokens = %v, want session-token on every call", got)
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("accepted EmergencyDump did not cancel local running task")
	}
}

func TestRunSpotTerminationListenerDoesNotCancelWhenDumpNeverSucceeds(t *testing.T) {
	metadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("termination pending"))
	}))
	defer metadataServer.Close()

	rejectedAcks := make([]*pb.Ack, 100)
	for i := range rejectedAcks {
		rejectedAcks[i] = &pb.Ack{Success: false}
	}
	client := &fakeAgentClient{emergencyDumpAcks: rejectedAcks}
	worker := NewWorker("agent-spot", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client
	worker.sessionToken = "session-token"
	cancelled := make(chan struct{}, 1)
	worker.runningTasks["task-running"] = func() { cancelled <- struct{}{} }

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	worker.runSpotTerminationListener(ctx, metadataServer.Client(), metadataServer.URL, time.Millisecond, time.Millisecond)

	if !worker.draining.Load() {
		t.Fatal("worker should stay draining after a rejected emergency dump")
	}
	select {
	case <-cancelled:
		t.Fatal("rejected EmergencyDump cancelled local task before lease release")
	default:
	}
}

func TestSpotTerminationURLUsesEnvironmentOverride(t *testing.T) {
	t.Setenv("ARGUS_SPOT_TERMINATION_URL", "http://127.0.0.1:18099/termination")
	if got := spotTerminationURL(); got != "http://127.0.0.1:18099/termination" {
		t.Fatalf("spotTerminationURL() = %q", got)
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

func TestWorkerRejectsLegacyProviderConfigBeforeRuleOrContextInitialization(t *testing.T) {
	origNewScanContext := newScanContext
	t.Cleanup(func() { newScanContext = origNewScanContext })
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		t.Fatal("legacy Provider config reached scanner initialization")
		return nil, nil
	}
	client := &fakeAgentClient{stream: &fakeResultStream{}}
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client
	worker.executeTask(&pb.Task{TaskId: "task-legacy-provider", Targets: []string{"127.0.0.1"}, Config: []byte(`{"Quake":true}`)})
	if len(client.taskCompleteReqs) != 1 || client.taskCompleteReqs[0].Status != "FAILED" || !strings.Contains(client.taskCompleteReqs[0].ErrorMessage, "legacy Provider") {
		t.Fatalf("expected legacy Provider rejection, got %#v", client.taskCompleteReqs)
	}
}

func TestWorkerRejectsUnconfirmedPocConfigFromOrdinaryTask(t *testing.T) {
	origNewScanContext := newScanContext
	t.Cleanup(func() { newScanContext = origNewScanContext })
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		t.Fatal("unconfirmed POC config reached scanner initialization")
		return nil, nil
	}
	client := &fakeAgentClient{stream: &fakeResultStream{}}
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client
	worker.executeTask(&pb.Task{
		TaskId: "task-unconfirmed-poc", Targets: []string{"127.0.0.1"},
		Config: []byte(`{"NoPoc":false,"GolangPoc":true}`),
	})
	if len(client.taskCompleteReqs) != 1 || client.taskCompleteReqs[0].Status != "FAILED" || !strings.Contains(client.taskCompleteReqs[0].ErrorMessage, "risk-validation") {
		t.Fatalf("expected unconfirmed POC rejection, got %#v", client.taskCompleteReqs)
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
	worker.ruleVersion = "rules-v1"
	worker.executeTask(&pb.Task{
		TaskId:  "task-rule-files",
		Targets: []string{"127.0.0.1"},
		Config: []byte(`{
			"ExecutionMode": "risk_validation",
			"RequiredRuleVersion": "rules-v1",
			"RiskValidationTargets": {"127.0.0.1": ["safe.yaml"]},
			"RiskValidationPocHashes": {"safe.yaml": "0123456789abcdef0123456789abcdef"},
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
	if captured.ExecutionMode != "risk_validation" || captured.RequiredRuleVersion != "rules-v1" || captured.RiskValidationPocHashes["safe.yaml"] == "" || len(captured.RiskValidationTargets["127.0.0.1"]) != 1 || captured.RiskValidationTargets["127.0.0.1"][0] != "safe.yaml" {
		t.Fatalf("internal risk validation config was not preserved: %+v", captured)
	}
	if len(client.taskCompleteReqs) != 1 || client.taskCompleteReqs[0].Status != "DONE" {
		t.Fatalf("expected task completion DONE, got %#v", client.taskCompleteReqs)
	}
}

func TestWorkerReportsTerminalCoverageEventsWithoutTrustBoundaryDimensions(t *testing.T) {
	prepareUsableAgentConfig(t)
	origNewScanContext := newScanContext
	origRunScanTask := runScanTask
	t.Cleanup(func() {
		newScanContext = origNewScanContext
		runScanTask = origRunScanTask
	})
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		ctx, cancel := context.WithCancel(context.Background())
		return &engine.ScanContext{Config: cfg, Ctx: ctx, Cancel: cancel}, nil
	}
	runScanTask = func(ctx *engine.ScanContext) error {
		ctx.PhaseHook(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "start"})
		ctx.OutputHook(engine.OutputMessage{Type: "Web", URI: "https://example.test"})
		ctx.PhaseHook(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "end"})
		return nil
	}

	stream := &fakeResultStream{}
	client := &fakeAgentClient{stream: stream}
	worker := NewWorker("agent-coverage", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client
	worker.ruleVersion = "rules-v1"
	worker.executeTask(&pb.Task{TaskId: "attempt-coverage", Targets: []string{"https://example.test"}, Config: []byte(`{}`)})

	var events []scanplan.StageObservationEvent
	for _, result := range stream.results() {
		if result.PayloadType != scanplan.StageObservationPayloadType {
			continue
		}
		var event scanplan.StageObservationEvent
		if err := json.Unmarshal(result.Payload, &event); err != nil {
			t.Fatalf("decode coverage event: %v", err)
		}
		if err := event.Validate(); err != nil {
			t.Fatalf("invalid coverage event: %v", err)
		}
		events = append(events, event)
	}
	if len(events) != len(assetObservationStages) {
		t.Fatalf("coverage events=%d, want %d", len(events), len(assetObservationStages))
	}
	var httpSuccess, skipped int
	for _, event := range events {
		if event.AttemptID != "attempt-coverage" || event.AgentID != "agent-coverage" || event.RuleVersion != "rules-v1" {
			t.Fatalf("coverage source identity mismatch: %+v", event)
		}
		if event.Stage == scanplan.StageHTTPProbe && event.Outcome == scanplan.ObservationSuccess {
			httpSuccess++
		}
		if event.Outcome == scanplan.ObservationSkipped {
			skipped++
		}
	}
	if httpSuccess != 1 || skipped != len(assetObservationStages)-1 {
		t.Fatalf("httpSuccess=%d skipped=%d", httpSuccess, skipped)
	}
}

func TestWorkerExecutesValidatedResumeSuffixAndReportsOnlyExecutedStages(t *testing.T) {
	prepareUsableAgentConfig(t)
	origNewScanContext := newScanContext
	origRunScanTask := runScanTask
	t.Cleanup(func() {
		newScanContext = origNewScanContext
		runScanTask = origRunScanTask
	})
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		ctx, cancel := context.WithCancel(context.Background())
		return &engine.ScanContext{Config: cfg, Ctx: ctx, Cancel: cancel, IPPortMap: make(map[string]string)}, nil
	}
	runScanTask = func(ctx *engine.ScanContext) error {
		if ctx.ResumePlan == nil || ctx.ResumePlan.StartStage != scanplan.StageProtocolIdentify {
			t.Fatalf("resume plan did not reach Pipeline context: %+v", ctx.ResumePlan)
		}
		// A reused phase must never create a skipped/negative replacement event.
		ctx.PhaseHook(engine.PhaseEvent{Phase: engine.PhasePortScan, Status: "start"})
		ctx.PhaseHook(engine.PhaseEvent{Phase: engine.PhasePortScan, Status: "end"})
		ctx.PhaseHook(engine.PhaseEvent{Phase: engine.PhaseProtocol, Status: "start"})
		ctx.PhaseHook(engine.PhaseEvent{Phase: engine.PhaseProtocol, Status: "end"})
		ctx.PhaseHook(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "start"})
		ctx.PhaseHook(engine.PhaseEvent{Phase: engine.PhaseHTTPProbe, Status: "end"})
		return nil
	}

	target := "192.0.2.10"
	checkpoint := scanplan.StageCheckpoint{SchemaVersion: scanplan.CheckpointSchemaVersion, Stage: scanplan.StagePortScan, OpenPorts: []string{"192.0.2.10:443"}}
	canonicalCheckpoint, err := checkpoint.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	checkpointDigest := sha256.Sum256(canonicalCheckpoint)
	plan := &scanplan.ResumePlan{
		SchemaVersion: scanplan.ResumePlanSchemaVersion,
		TenantID:      "tenant-a", ProjectID: "project-a", NetworkZone: "public", Target: target,
		ScopeHash: workerTestHash("scope"), ConfigHash: workerTestHash("config"), RuleVersion: "rules-v1",
		RequiredStages:  []scanplan.Stage{scanplan.StagePortScan, scanplan.StageProtocolIdentify, scanplan.StageHTTPProbe, scanplan.StageFingerprint},
		ReusedStages:    []scanplan.Stage{scanplan.StagePortScan},
		ExecutionStages: []scanplan.Stage{scanplan.StageProtocolIdentify, scanplan.StageHTTPProbe, scanplan.StageFingerprint},
		StartStage:      scanplan.StageProtocolIdentify,
		Checkpoints: []scanplan.ResumeCheckpoint{{
			Stage: scanplan.StagePortScan, WorkKeyHash: workerTestHash("work"), CoverageID: 1,
			SourceObservationID: 1, ObservationHash: workerTestHash("observation"),
			CheckpointHash: hex.EncodeToString(checkpointDigest[:]), Checkpoint: checkpoint,
		}},
	}
	planHash, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	config := map[string]interface{}{
		"NoPoc": true, "GolangPoc": false, "DisableGeneralPoc": true,
		"SkipHostDiscovery": true, "NoHostBind": true, "NoDirSearch": true,
		"ResumePlan": plan, "ResumePlanHash": planHash, "ObservationConfigHash": strings.Repeat("b", 64),
	}
	encodedConfig, _ := json.Marshal(config)
	stream := &fakeResultStream{}
	client := &fakeAgentClient{stream: stream}
	worker := NewWorker("agent-resume", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client
	worker.ruleVersion = "rules-v1"
	worker.executeTask(&pb.Task{TaskId: "attempt-resume", Targets: []string{target}, Config: encodedConfig})

	var stages []scanplan.Stage
	for _, result := range stream.results() {
		if result.PayloadType != scanplan.StageObservationPayloadType {
			continue
		}
		var event scanplan.StageObservationEvent
		if err := json.Unmarshal(result.Payload, &event); err != nil {
			t.Fatal(err)
		}
		if event.ConfigHash != strings.Repeat("b", 64) {
			t.Fatalf("event used injected config hash instead of authoritative base hash: %s", event.ConfigHash)
		}
		stages = append(stages, event.Stage)
	}
	if !slices.Equal(stages, plan.ExecutionStages) {
		t.Fatalf("reported stages=%v, want execution suffix=%v", stages, plan.ExecutionStages)
	}
	if len(client.taskCompleteReqs) != 1 || client.taskCompleteReqs[0].Status != "DONE" {
		t.Fatalf("unexpected completion: %#v", client.taskCompleteReqs)
	}
}

func TestWorkerRejectsTamperedResumePlanBeforeScannerInitialization(t *testing.T) {
	prepareUsableAgentConfig(t)
	origNewScanContext := newScanContext
	t.Cleanup(func() { newScanContext = origNewScanContext })
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		t.Fatal("tampered resume plan reached scanner initialization")
		return nil, nil
	}
	client := &fakeAgentClient{stream: &fakeResultStream{}}
	worker := NewWorker("agent-resume", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client
	worker.ruleVersion = "rules-v1"
	worker.executeTask(&pb.Task{
		TaskId: "attempt-tampered", Targets: []string{"192.0.2.10"},
		Config: []byte(`{"NoPoc":true,"DisableGeneralPoc":true,"ResumePlanHash":"bad","ObservationConfigHash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`),
	})
	if len(client.taskCompleteReqs) != 1 || client.taskCompleteReqs[0].Status != "FAILED" || !strings.Contains(client.taskCompleteReqs[0].ErrorMessage, "resume") {
		t.Fatalf("tampered plan was not failed closed: %#v", client.taskCompleteReqs)
	}
}

func workerTestHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func TestWorkerRejectsRiskValidationWithDifferentRuleVersion(t *testing.T) {
	prepareUsableAgentConfig(t)
	origNewScanContext := newScanContext
	t.Cleanup(func() { newScanContext = origNewScanContext })
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		t.Fatal("rule-version mismatch reached scanner initialization")
		return nil, nil
	}
	client := &fakeAgentClient{stream: &fakeResultStream{}}
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = client
	worker.ruleVersion = "rules-v1"
	worker.executeTask(&pb.Task{
		TaskId: "task-stale-risk-rules", Targets: []string{"127.0.0.1"},
		Config: []byte(`{"ExecutionMode":"risk_validation","RequiredRuleVersion":"rules-confirmed"}`),
	})
	if len(client.taskCompleteReqs) != 1 || client.taskCompleteReqs[0].Status != "FAILED" || !strings.Contains(client.taskCompleteReqs[0].ErrorMessage, "rules-confirmed") {
		t.Fatalf("expected safe rule-version rejection, got %#v", client.taskCompleteReqs)
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

func TestSyncRulesDoesNotFetchAgentProviderConfig(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	worker := NewWorker("agent-1", "127.0.0.1:50051", "http://server.local", 1, nil)
	worker.apiGetFn = func(url string) (*http.Response, error) {
		if strings.Contains(url, "api-keys") {
			t.Fatalf("Agent must not request Provider credentials: %s", url)
		}
		if strings.HasSuffix(url, "/api/v1/arsenals/db/hash") {
			return testHTTPResponse(`{"hash":"","rule_version":"v1","arsenal_count":0}`, nil), nil
		}
		t.Fatalf("unexpected sync request: %s", url)
		return nil, nil
	}
	worker.syncRules()
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
			return testHTTPResponseBytes(dbBytes, arsenalDownloadHeaders(dbBytes, "newhash")), nil
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
			w.Header().Set("X-Arsenal-SHA256", fmt.Sprintf("%x", sha256.Sum256(dbBytes)))
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

func TestSyncRulesRejectsDownloadedPackageWithMismatchedSHA256(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	dbBytes := createAgentTestArsenalDBBytes(t, "RejectedProduct", "rejected.yaml")
	worker := NewWorker("agent-sha", "127.0.0.1:50051", "http://server.local", 1, nil)
	worker.apiGetFn = func(url string) (*http.Response, error) {
		switch {
		case strings.HasSuffix(url, "/api/v1/agents/config/api-keys"):
			return testHTTPResponse("", nil), nil
		case strings.HasSuffix(url, "/api/v1/arsenals/db/hash"):
			return testHTTPResponse(`{"hash":"rejected-hash","rule_version":"v-rejected","arsenal_count":4}`, nil), nil
		case strings.HasSuffix(url, "/api/v1/arsenals/db"):
			return testHTTPResponseBytes(dbBytes, map[string]string{"X-Arsenal-SHA256": strings.Repeat("0", 64)}), nil
		default:
			return testHTTPResponse(`not found`, nil), nil
		}
	}
	worker.syncRules()
	if _, err := os.Stat(filepath.Join("data", "arsenal.db")); !os.IsNotExist(err) {
		t.Fatalf("mismatched package was persisted, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join("config", ".argus-arsenal.json")); !os.IsNotExist(err) {
		t.Fatalf("mismatched package was materialized, stat err=%v", err)
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
	t.Cleanup(func() { _ = arsenal.CloseDB() })
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

func arsenalDownloadHeaders(body []byte, legacyHash string) map[string]string {
	return map[string]string{
		"X-Arsenal-Hash":   legacyHash,
		"X-Arsenal-SHA256": fmt.Sprintf("%x", sha256.Sum256(body)),
	}
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
	dbBytes := testAgentPackageBytes()
	mustWriteAgentFile(t, filepath.Join("data", "arsenal.db"), dbBytes)
	manifest := arsenal.RulePackageManifest{
		SchemaVersion: arsenal.RulePackageSchemaVersion,
		Hash:          "test-rule-hash",
		RuleVersion:   "rules-v1",
		PackageSHA256: fmt.Sprintf("%x", sha256.Sum256(dbBytes)),
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal test rule manifest: %v", err)
	}
	mustWriteAgentFile(t, filepath.Join("config", ".argus-arsenal.json"), data)
	mustWriteAgentFile(t, filepath.Join("data", ".arsenal_hash"), []byte(manifest.Hash))
}

func testAgentPackageBytes() []byte {
	return append([]byte("SQLite format 3\x00"), []byte("g35-agent-test-package")...)
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

func TestFingerprintDebugDetachesKnowledgeBeforeCustomWorkflowMutation(t *testing.T) {
	origNewScanContext := newScanContext
	origRunScanTask := runScanTask
	t.Cleanup(func() {
		newScanContext = origNewScanContext
		runScanTask = origRunScanTask
	})
	sharedWorkflow := map[string]structs.WorkFlowEntity{"existing": {}}
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		ctx, cancel := context.WithCancel(context.Background())
		return &engine.ScanContext{Config: cfg, Ctx: ctx, Cancel: cancel, WorkFlowDB: sharedWorkflow}, nil
	}
	runScanTask = func(*engine.ScanContext) error { return nil }
	worker := NewWorker("agent-debug-detach", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.runFingerprintDebugSession(context.Background(), &pb.DebugCommand{
		Action: "start_fingerprint_debug", SessionId: "debug-detach", TargetUrl: "https://target.local",
		PocContent: `{"custom_wf_product":"custom","custom_wf_pocs":"custom.yaml"}`,
	}, time.Second, func(*pb.DebugEvent) {}, func(string) {})
	if _, exists := sharedWorkflow["custom"]; exists {
		t.Fatal("debug workflow mutation leaked into the original knowledge map")
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
	stream              grpc.ClientStreamingClient[pb.ScanResult, pb.Ack]
	streamErr           error
	subscribeStream     grpc.BidiStreamingClient[pb.AgentSignal, pb.TaskNotify]
	debugStream         grpc.ClientStreamingClient[pb.DebugEvent, pb.Ack]
	debugErr            error
	logStream           grpc.ClientStreamingClient[pb.LogPayload, pb.Ack]
	taskCompleteReqs    []*pb.TaskCompleteReq
	taskCompleteReqsM   sync.Mutex
	taskCompleteErrs    []error
	taskCompleteAck     *pb.Ack
	claimTaskCalls      int
	claimTaskHook       func() *pb.Task
	subscribeCalls      int
	emergencyDumpReqs   []*pb.EmergencyReq
	emergencyDumpAcks   []*pb.Ack
	emergencyDumpErrs   []error
	emergencyDumpTokens []string
	streamResultCtx     context.Context
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
	c.streamResultCtx = ctx
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
	c.emergencyDumpReqs = append(c.emergencyDumpReqs, in)
	md, _ := metadata.FromOutgoingContext(ctx)
	tokens := md.Get("x-agent-token")
	if len(tokens) > 0 {
		c.emergencyDumpTokens = append(c.emergencyDumpTokens, tokens[0])
	} else {
		c.emergencyDumpTokens = append(c.emergencyDumpTokens, "")
	}
	if len(c.emergencyDumpErrs) > 0 {
		err := c.emergencyDumpErrs[0]
		c.emergencyDumpErrs = c.emergencyDumpErrs[1:]
		if err != nil {
			return nil, err
		}
	}
	if len(c.emergencyDumpAcks) > 0 {
		ack := c.emergencyDumpAcks[0]
		c.emergencyDumpAcks = c.emergencyDumpAcks[1:]
		return ack, nil
	}
	return &pb.Ack{Success: true}, nil
}

func (c *fakeAgentClient) Subscribe(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[pb.AgentSignal, pb.TaskNotify], error) {
	c.subscribeCalls++
	if stream, ok := c.subscribeStream.(interface{ setContext(context.Context) }); ok {
		stream.setContext(ctx)
	}
	return c.subscribeStream, nil
}

func (c *fakeAgentClient) ClaimTask(ctx context.Context, in *pb.ClaimTaskReq, opts ...grpc.CallOption) (*pb.Task, error) {
	c.claimTaskCalls++
	if c.claimTaskHook != nil {
		return c.claimTaskHook(), nil
	}
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
	mu       sync.Mutex
	sent     []*pb.ScanResult
}

func (s *fakeResultStream) Send(result *pb.ScanResult) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	copyResult := proto.Clone(result).(*pb.ScanResult)
	s.sent = append(s.sent, copyResult)
	return nil
}

func (s *fakeResultStream) results() []*pb.ScanResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*pb.ScanResult(nil), s.sent...)
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
