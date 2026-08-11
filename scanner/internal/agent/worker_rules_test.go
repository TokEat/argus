package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"dddd/scanner/internal/arsenal"
	"dddd/scanner/internal/engine"
	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-proto/go/scanplan"
)

func TestWorkerInitializationWindowDefersPendingActivation(t *testing.T) {
	prepareUsableAgentConfig(t)
	origNewScanContext := newScanContext
	origRunScanTask := runScanTask
	t.Cleanup(func() {
		newScanContext = origNewScanContext
		runScanTask = origRunScanTask
	})

	entered := make(chan struct{})
	allowContext := make(chan struct{})
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		close(entered)
		<-allowContext
		ctx, cancel := context.WithCancel(context.Background())
		return &engine.ScanContext{Config: cfg, Ctx: ctx, Cancel: cancel}, nil
	}
	runScanTask = func(*engine.ScanContext) error { return nil }
	worker := NewWorker("agent-init-window", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = &fakeAgentClient{stream: &fakeResultStream{}}
	worker.ruleVersion = "rules-v1"
	worker.pendingRules = &arsenal.PreparedRulePackage{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		worker.executeTask(&pb.Task{TaskId: "init-window", Targets: []string{"127.0.0.1"}})
	}()
	<-entered

	worker.rulesMu.Lock()
	worker.activatePendingRulesLocked()
	pending := worker.pendingRules
	count := worker.runningTaskCount()
	worker.rulesMu.Unlock()
	if pending == nil || count != 1 {
		t.Fatalf("initializing task did not block activation: pending=%v count=%d", pending, count)
	}
	close(allowContext)
	<-done
}

func TestWorkerCapturesRuleVersionForContextAndCoverage(t *testing.T) {
	prepareUsableAgentConfig(t)
	origNewScanContext := newScanContext
	origRunScanTask := runScanTask
	t.Cleanup(func() {
		newScanContext = origNewScanContext
		runScanTask = origRunScanTask
	})
	var captured engine.Config
	newScanContext = func(cfg engine.Config) (*engine.ScanContext, error) {
		captured = cfg
		ctx, cancel := context.WithCancel(context.Background())
		return &engine.ScanContext{Config: cfg, Ctx: ctx, Cancel: cancel}, nil
	}
	runScanTask = func(*engine.ScanContext) error { return nil }
	stream := &fakeResultStream{}
	worker := NewWorker("agent-captured-version", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = &fakeAgentClient{stream: stream}
	worker.ruleVersion = "rules-v1"
	worker.executeTask(&pb.Task{TaskId: "captured-version", Targets: []string{"127.0.0.1"}})
	worker.ruleVersion = "rules-v2"

	expectedPackageSHA256 := fmt.Sprintf("%x", sha256.Sum256(testAgentPackageBytes()))
	if captured.KnowledgePackageHash != expectedPackageSHA256 || captured.KnowledgeRuleVersion != "rules-v1" {
		t.Fatalf("context identity=%q/%q, want %s/rules-v1", captured.KnowledgePackageHash, captured.KnowledgeRuleVersion, expectedPackageSHA256)
	}
	for _, result := range stream.results() {
		if result.PayloadType != scanplan.StageObservationPayloadType {
			continue
		}
		var event scanplan.StageObservationEvent
		if err := json.Unmarshal(result.Payload, &event); err != nil {
			t.Fatal(err)
		}
		if event.RuleVersion != "rules-v1" {
			t.Fatalf("coverage rule version=%q, want captured rules-v1", event.RuleVersion)
		}
	}
}

func TestWorkerReleasesRuleUseWhenContextInitializationFails(t *testing.T) {
	prepareUsableAgentConfig(t)
	origNewScanContext := newScanContext
	t.Cleanup(func() { newScanContext = origNewScanContext })
	newScanContext = func(engine.Config) (*engine.ScanContext, error) { return nil, errors.New("context failed") }
	worker := NewWorker("agent-init-failure", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	worker.client = &fakeAgentClient{stream: &fakeResultStream{}}
	worker.ruleVersion = "rules-v1"
	worker.executeTask(&pb.Task{TaskId: "init-failure", Targets: []string{"127.0.0.1"}})
	if got := worker.runningTaskCount(); got != 0 {
		t.Fatalf("failed initialization leaked rule use count: %d", got)
	}
}

func TestWorkerRejectsMismatchedMaterializedManifestBeforeContextInitialization(t *testing.T) {
	prepareUsableAgentConfig(t)
	manifest := arsenal.RulePackageManifest{SchemaVersion: arsenal.RulePackageSchemaVersion, Hash: "different-hash", RuleVersion: "rules-v1"}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	mustWriteAgentFile(t, filepath.Join("config", ".argus-arsenal.json"), data)
	origNewScanContext := newScanContext
	t.Cleanup(func() { newScanContext = origNewScanContext })
	newScanContext = func(engine.Config) (*engine.ScanContext, error) {
		t.Fatal("mismatched manifest reached context initialization")
		return nil, nil
	}
	worker := NewWorker("agent-manifest-mismatch", "127.0.0.1:50051", "http://127.0.0.1:8085", 1, nil)
	client := &fakeAgentClient{stream: &fakeResultStream{}}
	worker.client = client
	worker.ruleVersion = "rules-v1"
	worker.executeTask(&pb.Task{TaskId: "manifest-mismatch", Targets: []string{"127.0.0.1"}})
	if len(client.taskCompleteReqs) != 1 || client.taskCompleteReqs[0].Status != "FAILED" {
		t.Fatalf("mismatched manifest was not failed closed: %#v", client.taskCompleteReqs)
	}
}
