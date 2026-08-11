package engine

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

func resetKnowledgeCacheForTest(t *testing.T) {
	t.Helper()
	knowledgeCache.Lock()
	knowledgeCache.entries = make(map[knowledgeCacheKey]*knowledgeCacheEntry)
	knowledgeCache.lru = nil
	knowledgeCache.Unlock()
	oldFinger, oldWorkflow, oldDir := knowledgeFingerLoader, knowledgeWorkflowLoader, knowledgeDirLoader
	t.Cleanup(func() {
		knowledgeFingerLoader, knowledgeWorkflowLoader, knowledgeDirLoader = oldFinger, oldWorkflow, oldDir
	})
}

func testKnowledgeLoaders(calls *atomic.Int32, fail *atomic.Bool) {
	knowledgeFingerLoader = func(Config) ([]FingerPEntity, error) {
		calls.Add(1)
		if fail != nil && fail.Load() {
			return nil, fmt.Errorf("loader failed")
		}
		return []FingerPEntity{{ProductName: "product", Rule: []RuleData{{}}}}, nil
	}
	knowledgeWorkflowLoader = func(Config) (map[string]WorkFlowEntity, error) {
		return map[string]WorkFlowEntity{"product": {PocsName: []string{"poc"}}}, nil
	}
	knowledgeDirLoader = func(Config) (map[string][]string, error) { return map[string][]string{"/": {"product"}}, nil }
}

func cachedContext(t *testing.T, hash, version string) *ScanContext {
	t.Helper()
	ctx, err := NewScanContext(Config{RuleFilesOnly: true, KnowledgePackageHash: hash, KnowledgeRuleVersion: version})
	if err != nil {
		t.Fatalf("NewScanContext: %v", err)
	}
	return ctx
}

func TestKnowledgeCacheSingleBuildAndIdentityIsolation(t *testing.T) {
	resetKnowledgeCacheForTest(t)
	var calls atomic.Int32
	testKnowledgeLoaders(&calls, nil)
	start := make(chan struct{})
	contexts := make(chan *ScanContext, 32)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; contexts <- cachedContext(t, "package-a", "v1") }()
	}
	close(start)
	wg.Wait()
	close(contexts)
	for ctx := range contexts {
		defer ctx.Close()
		if ctx.knowledge == nil || ctx.FingerprintDB != nil {
			t.Fatal("shared knowledge leaked through public fields")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("builds=%d want 1", got)
	}
	other := cachedContext(t, "package-b", "v1")
	defer other.Close()
	if got := calls.Load(); got != 2 {
		t.Fatalf("different identity reused snapshot: builds=%d", got)
	}
}

func TestKnowledgeCacheFailureRetryAndEvictionKeepsOldSnapshot(t *testing.T) {
	resetKnowledgeCacheForTest(t)
	var calls atomic.Int32
	var fail atomic.Bool
	fail.Store(true)
	testKnowledgeLoaders(&calls, &fail)
	if _, err := NewScanContext(Config{RuleFilesOnly: true, KnowledgePackageHash: "bad", KnowledgeRuleVersion: "v1"}); err == nil {
		t.Fatal("expected loader error")
	}
	fail.Store(false)
	old := cachedContext(t, "bad", "v1")
	defer old.Close()
	for i := 0; i < knowledgeCacheCapacity; i++ {
		ctx := cachedContext(t, fmt.Sprintf("other-%d", i), "v1")
		defer ctx.Close()
	}
	knowledgeCache.Lock()
	_, retained := knowledgeCache.entries[knowledgeCacheKey{"bad", "v1"}]
	knowledgeCache.Unlock()
	if retained {
		t.Fatal("old entry was not evicted")
	}
	if got := old.knowledge.fingerprintDB[0].ProductName; got != "product" {
		t.Fatalf("evicted snapshot not retained: %q", got)
	}
	if got := calls.Load(); got != int32(knowledgeCacheCapacity+2) {
		t.Fatalf("builds=%d want %d", got, knowledgeCacheCapacity+2)
	}
}

func TestKnowledgeCacheRejectsPartialOrUnverifiedIdentity(t *testing.T) {
	resetKnowledgeCacheForTest(t)
	for name, cfg := range map[string]Config{
		"missing version": {RuleFilesOnly: true, KnowledgePackageHash: "package"},
		"missing hash":    {RuleFilesOnly: true, KnowledgeRuleVersion: "version"},
		"not rule files":  {KnowledgePackageHash: "package", KnowledgeRuleVersion: "version"},
		"spaced hash":     {RuleFilesOnly: true, KnowledgePackageHash: " package", KnowledgeRuleVersion: "version"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewScanContext(cfg); err == nil {
				t.Fatal("invalid cache identity was accepted")
			}
		})
	}
}

func TestDetachKnowledgeDeepCopiesAndTaskStateIsolated(t *testing.T) {
	resetKnowledgeCacheForTest(t)
	var calls atomic.Int32
	testKnowledgeLoaders(&calls, nil)
	first := cachedContext(t, "package", "v1")
	defer first.Close()
	second := cachedContext(t, "package", "v1")
	defer second.Close()
	first.DetachKnowledge()
	if first.knowledge != nil {
		t.Fatal("DetachKnowledge retained shared snapshot")
	}
	first.FingerprintDB[0].ProductName = "debug"
	first.WorkFlowDB["product"] = WorkFlowEntity{PocsName: []string{"debug"}}
	first.DirDB["/"][0] = "debug"
	if second.knowledge.fingerprintDB[0].ProductName != "product" || second.knowledge.workflowDB["product"].PocsName[0] != "poc" || second.knowledge.dirDB["/"][0] != "product" {
		t.Fatal("detach modified shared snapshot")
	}
	first.IPPortMap["127.0.0.1:80"] = "http"
	if len(second.IPPortMap) != 0 {
		t.Fatal("task state shared across contexts")
	}
	first.Reset()
	if first.knowledge != nil || len(first.IPPortMap) != 0 {
		t.Fatal("Reset did not preserve snapshot or clear task state")
	}
}
