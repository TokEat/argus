package db

import (
	"testing"
	"time"
)

func TestBackoffForRetryValues(t *testing.T) {
	cases := map[int]time.Duration{
		0:  5 * time.Second,
		1:  5 * time.Second,
		2:  20 * time.Second,
		3:  80 * time.Second,
		4:  5 * time.Minute, // 320s hits the cap
		10: 5 * time.Minute,
	}
	for in, want := range cases {
		if got := BackoffForRetry(in); got != want {
			t.Fatalf("BackoffForRetry(%d) = %v, want %v", in, got, want)
		}
	}
}

func TestPrepareSubTaskRetryStampsBackoffWhenConsumingBudget(t *testing.T) {
	store := setupTaskLifecycleTestDB(t)
	root := RootTask{ID: "root-bo", TenantID: "tenant-a", Status: "Running", TotalChunks: 1}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	sub := SubTask{
		ID: "sub-bo", TenantID: "tenant-a", RootTaskID: "root-bo", Status: "Failed",
		ChunkTargets: `["https://one.test"]`, RetryCount: 0, MaxRetry: 3, ConfigVersion: 1,
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}

	prepared, ok := PrepareSubTaskRetry(&sub)
	if !ok {
		t.Fatal("expected retry to be appended")
	}
	if prepared.NextEligibleAt == nil {
		t.Fatal("expected NextEligibleAt stamped when consuming retry budget")
	}
	// retryCount 1 -> 5s base with ±20% jitter => [4s, 6s] from now.
	if delta := time.Until(*prepared.NextEligibleAt); delta < 4*time.Second || delta > 6*time.Second {
		t.Fatalf("NextEligibleAt delta %v outside [4s,6s]", delta)
	}
}

func TestAppendSubTaskAttemptBudgetFreeRetryStaysEligible(t *testing.T) {
	store := setupTaskLifecycleTestDB(t)
	root := RootTask{ID: "root-offline", TenantID: "tenant-a", Status: "Running", TotalChunks: 1}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	sub := SubTask{
		ID: "sub-offline", TenantID: "tenant-a", RootTaskID: "root-offline", Status: "Running",
		ChunkTargets: `["https://one.test"]`, RetryCount: 1, MaxRetry: 3, ConfigVersion: 1,
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}

	prepared, ok := AppendSubTaskAttempt(&sub, AttemptRetryOptions{
		Trigger:              AttemptTriggerAgentOfflineRecovery,
		TerminalStatus:       "Failed",
		ConsumeRetryBudget:   false,
		UseCurrentTaskConfig: true,
	})
	if !ok {
		t.Fatal("expected offline-recovery retry to be appended")
	}
	if prepared.NextEligibleAt != nil {
		t.Fatalf("budget-free recovery must stay immediately eligible, got %v", prepared.NextEligibleAt)
	}
}

func TestSplitFailedSubTaskStampsBackoffOnBothHalves(t *testing.T) {
	store := setupTaskLifecycleTestDB(t)
	root := RootTask{ID: "root-split-bo", TenantID: "tenant-a", Status: "Running", TotalChunks: 1}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	sub := SubTask{
		ID: "sub-split-bo", TenantID: "tenant-a", RootTaskID: "root-split-bo", Status: "Running",
		ChunkTargets: `["https://one.test","https://two.test","https://three.test","https://four.test"]`,
		RetryCount: 0, MaxRetry: 3, ConfigVersion: 1,
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}

	split, didSplit, _ := SplitFailedSubTask(&sub, false)
	if !didSplit || len(split) != 2 {
		t.Fatalf("expected split into two halves, didSplit=%v split=%d", didSplit, len(split))
	}
	for _, half := range split {
		if half.NextEligibleAt == nil {
			t.Fatalf("split half %s missing backoff stamp", half.ID)
		}
		if delta := time.Until(*half.NextEligibleAt); delta < 4*time.Second || delta > 6*time.Second {
			t.Fatalf("split half %s backoff delta %v outside [4s,6s]", half.ID, delta)
		}
		if half.RoutedAgentID != "" || half.RoutedAt != nil {
			t.Fatalf("split half %s must start unrouted, got agent=%q at=%v", half.ID, half.RoutedAgentID, half.RoutedAt)
		}
	}
}
