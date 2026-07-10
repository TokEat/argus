package db

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupTaskLifecycleTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&RootTask{}, &SubTask{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	old := DB
	DB = store
	t.Cleanup(func() {
		DB = old
	})
	return store
}

func TestRefreshRootTaskStatusTerminalConvergence(t *testing.T) {
	tests := []struct {
		name            string
		subTaskStatuses []string
		wantStatus      string
		wantChunks      int
		wantTargets     int
	}{
		{
			name:            "all done finishes root task",
			subTaskStatuses: []string{"DONE", "DONE"},
			wantStatus:      "FINISHED",
			wantChunks:      2,
			wantTargets:     4,
		},
		{
			name:            "done and running remains partial",
			subTaskStatuses: []string{"DONE", "Running"},
			wantStatus:      "PartialDone",
			wantChunks:      1,
			wantTargets:     2,
		},
		{
			name:            "done and pending remains partial",
			subTaskStatuses: []string{"DONE", "Pending"},
			wantStatus:      "PartialDone",
			wantChunks:      1,
			wantTargets:     2,
		},
		{
			name:            "done and dispatching remains partial",
			subTaskStatuses: []string{"DONE", "Dispatching"},
			wantStatus:      "PartialDone",
			wantChunks:      1,
			wantTargets:     2,
		},
		{
			name:            "done and failed converges failed",
			subTaskStatuses: []string{"DONE", "FAILED"},
			wantStatus:      "Failed",
			wantChunks:      1,
			wantTargets:     2,
		},
		{
			name:            "done and timeout converges timeout",
			subTaskStatuses: []string{"DONE", "TIMEOUT"},
			wantStatus:      "Timeout",
			wantChunks:      1,
			wantTargets:     2,
		},
		{
			name:            "all cancelled converges cancelled",
			subTaskStatuses: []string{"CANCELLED", "Cancelled"},
			wantStatus:      "Cancelled",
			wantChunks:      0,
			wantTargets:     0,
		},
		{
			name:            "dispatching retry remains non terminal",
			subTaskStatuses: []string{"FAILED", "Dispatching"},
			wantStatus:      "Running",
			wantChunks:      0,
			wantTargets:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := setupTaskLifecycleTestDB(t)
			rootID := "root-1"
			root := RootTask{ID: rootID, TenantID: "default", Name: tt.name, Status: "Running"}
			if err := store.Create(&root).Error; err != nil {
				t.Fatalf("seed root task: %v", err)
			}
			for i, status := range tt.subTaskStatuses {
				sub := SubTask{
					ID:           fmt.Sprintf("sub-%d", i),
					TenantID:     "default",
					RootTaskID:   rootID,
					Status:       status,
					ChunkTargets: fmt.Sprintf(`["https://example-%d.test","https://alt-%d.test"]`, i, i),
				}
				if err := store.Create(&sub).Error; err != nil {
					t.Fatalf("seed subtask %d: %v", i, err)
				}
			}

			RefreshRootTaskStatus(rootID)

			var got RootTask
			if err := store.Where("id = ?", rootID).First(&got).Error; err != nil {
				t.Fatalf("load root task: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Fatalf("status = %s, want %s", got.Status, tt.wantStatus)
			}
			if got.CompletedChunks != tt.wantChunks {
				t.Fatalf("completed chunks = %d, want %d", got.CompletedChunks, tt.wantChunks)
			}
			if got.CompletedTargets != tt.wantTargets {
				t.Fatalf("completed targets = %d, want %d", got.CompletedTargets, tt.wantTargets)
			}
		})
	}
}

func TestRefreshRootTaskStatusTerminalPriority(t *testing.T) {
	store := setupTaskLifecycleTestDB(t)
	rootID := "root-priority"
	root := RootTask{ID: rootID, TenantID: "default", Name: "priority", Status: "Running"}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}

	statuses := []string{"DONE", "FAILED", "TIMEOUT", "CANCELLED"}
	for i, status := range statuses {
		sub := SubTask{
			ID:           fmt.Sprintf("priority-sub-%d", i),
			TenantID:     "default",
			RootTaskID:   rootID,
			Status:       status,
			ChunkTargets: `["https://example.test"]`,
		}
		if err := store.Create(&sub).Error; err != nil {
			t.Fatalf("seed subtask %d: %v", i, err)
		}
	}

	RefreshRootTaskStatus(rootID)

	var got RootTask
	if err := store.Where("id = ?", rootID).First(&got).Error; err != nil {
		t.Fatalf("load root task: %v", err)
	}
	if got.Status != "Timeout" {
		t.Fatalf("status = %s, want Timeout", got.Status)
	}
	if got.CompletedChunks != 1 || got.CompletedTargets != 1 {
		t.Fatalf("completed progress = chunks:%d targets:%d, want chunks:1 targets:1", got.CompletedChunks, got.CompletedTargets)
	}
}

func TestRefreshRootTaskStatusPreservesPausedRoot(t *testing.T) {
	store := setupTaskLifecycleTestDB(t)
	rootID := "root-paused"
	if err := store.Create(&RootTask{ID: rootID, TenantID: "default", Name: "paused", Status: "Paused"}).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	if err := store.Create(&SubTask{ID: "sub-running", TenantID: "default", RootTaskID: rootID, Status: "Running"}).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}

	RefreshRootTaskStatus(rootID)

	var got RootTask
	if err := store.First(&got, "id = ?", rootID).Error; err != nil {
		t.Fatalf("load root task: %v", err)
	}
	if got.Status != "Paused" {
		t.Fatalf("expected paused root status to be preserved, got %s", got.Status)
	}
}

func TestRefreshRootTaskStatusAllowsPausedRootToReachTerminalStatus(t *testing.T) {
	store := setupTaskLifecycleTestDB(t)
	rootID := "root-paused-finished"
	if err := store.Create(&RootTask{ID: rootID, TenantID: "default", Name: "paused-finished", Status: "Paused"}).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	for i := 0; i < 2; i++ {
		sub := SubTask{
			ID:           fmt.Sprintf("paused-done-%d", i),
			TenantID:     "default",
			RootTaskID:   rootID,
			Status:       "DONE",
			ChunkTargets: `["https://example.test"]`,
		}
		if err := store.Create(&sub).Error; err != nil {
			t.Fatalf("seed subtask %d: %v", i, err)
		}
	}

	RefreshRootTaskStatus(rootID)

	var got RootTask
	if err := store.First(&got, "id = ?", rootID).Error; err != nil {
		t.Fatalf("load root task: %v", err)
	}
	if got.Status != "FINISHED" {
		t.Fatalf("expected paused root to converge to FINISHED when no paused or active subtasks remain, got %s", got.Status)
	}
	if got.CompletedChunks != 2 || got.CompletedTargets != 2 {
		t.Fatalf("completed progress = chunks:%d targets:%d, want chunks:2 targets:2", got.CompletedChunks, got.CompletedTargets)
	}
}

func TestSplitFailedSubTaskRespectsRootLifecycleAndTenant(t *testing.T) {
	tests := []struct {
		name       string
		rootStatus string
		rootTenant string
		subTenant  string
		wantSplit  bool
		wantRetry  bool
	}{
		{name: "active root can split", rootStatus: "Running", rootTenant: "tenant-a", subTenant: "tenant-a", wantSplit: true, wantRetry: true},
		{name: "cancelled root blocks split", rootStatus: "Cancelled", rootTenant: "tenant-a", subTenant: "tenant-a"},
		{name: "paused root blocks split", rootStatus: "Paused", rootTenant: "tenant-a", subTenant: "tenant-a"},
		{name: "tenant mismatch blocks split", rootStatus: "Running", rootTenant: "tenant-a", subTenant: "tenant-b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := setupTaskLifecycleTestDB(t)
			root := RootTask{ID: "root-split", TenantID: tt.rootTenant, Status: tt.rootStatus, TotalChunks: 1}
			if err := store.Create(&root).Error; err != nil {
				t.Fatalf("seed root: %v", err)
			}
			sub := SubTask{
				ID:           "sub-split",
				TenantID:     tt.subTenant,
				RootTaskID:   root.ID,
				Status:       "Running",
				ChunkTargets: `["https://one.test","https://two.test"]`,
				RetryCount:   0,
				MaxRetry:     3,
			}
			if err := store.Create(&sub).Error; err != nil {
				t.Fatalf("seed subtask: %v", err)
			}

			split, didSplit, retryAllowed := SplitFailedSubTask(&sub, false)
			if didSplit != tt.wantSplit || retryAllowed != tt.wantRetry {
				t.Fatalf("SplitFailedSubTask = split:%v retry:%v, want split:%v retry:%v", didSplit, retryAllowed, tt.wantSplit, tt.wantRetry)
			}
			if tt.wantSplit {
				if len(split) != 2 {
					t.Fatalf("expected two split subtasks, got %d", len(split))
				}
				var count int64
				if err := store.Model(&SubTask{}).Where("root_task_id = ? AND tenant_id = ?", root.ID, tt.subTenant).Count(&count).Error; err != nil {
					t.Fatalf("count split subtasks: %v", err)
				}
				if count != 2 {
					t.Fatalf("split subtask count = %d, want 2", count)
				}
				return
			}

			var got SubTask
			if err := store.First(&got, "id = ?", sub.ID).Error; err != nil {
				t.Fatalf("reload blocked subtask: %v", err)
			}
			if got.Status != "Running" || got.ChunkTargets != sub.ChunkTargets {
				t.Fatalf("blocked split changed subtask: %+v", got)
			}
		})
	}
}

func TestSplitFailedSubTaskCanResetExhaustedRetryBudget(t *testing.T) {
	store := setupTaskLifecycleTestDB(t)
	root := RootTask{ID: "root-last-resort", TenantID: "tenant-a", Status: "Running", TotalChunks: 1}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	sub := SubTask{
		ID:           "sub-last-resort",
		TenantID:     root.TenantID,
		RootTaskID:   root.ID,
		Status:       "Running",
		ChunkTargets: `["https://one.test","https://two.test"]`,
		RetryCount:   3,
		MaxRetry:     3,
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}

	split, didSplit, retryAllowed := SplitFailedSubTask(&sub, true)
	if !didSplit || !retryAllowed || len(split) != 2 {
		t.Fatalf("last-resort split = count:%d split:%v retry:%v, want 2/true/true", len(split), didSplit, retryAllowed)
	}
	if sub.RetryCount != 1 {
		t.Fatalf("reset split retry_count = %d, want 1", sub.RetryCount)
	}
}

func TestPrepareSubTaskRetryRespectsRootLifecycle(t *testing.T) {
	tests := []struct {
		name       string
		rootStatus string
		want       bool
	}{
		{name: "active root", rootStatus: "Running", want: true},
		{name: "paused root", rootStatus: "Paused"},
		{name: "cancelled root", rootStatus: "Cancelled"},
		{name: "finished root", rootStatus: "FINISHED"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := setupTaskLifecycleTestDB(t)
			root := RootTask{ID: "root-retry", TenantID: "tenant-a", Status: tt.rootStatus, TotalChunks: 1}
			if err := store.Create(&root).Error; err != nil {
				t.Fatalf("seed root: %v", err)
			}
			sub := SubTask{
				ID:           "sub-retry",
				TenantID:     root.TenantID,
				RootTaskID:   root.ID,
				Status:       "FAILED",
				ChunkTargets: `["https://one.test"]`,
				MaxRetry:     3,
			}
			if err := store.Create(&sub).Error; err != nil {
				t.Fatalf("seed subtask: %v", err)
			}

			prepared, ok := PrepareSubTaskRetry(&sub)
			if ok != tt.want {
				t.Fatalf("PrepareSubTaskRetry = %v, want %v", ok, tt.want)
			}
			var got SubTask
			if err := store.First(&got, "id = ?", sub.ID).Error; err != nil {
				t.Fatalf("reload subtask: %v", err)
			}
			if tt.want {
				if prepared.Status != "Dispatching" || got.Status != "Dispatching" || got.RetryCount != 1 {
					t.Fatalf("prepared retry = %+v persisted=%+v", prepared, got)
				}
			} else if got.Status != "FAILED" || got.RetryCount != 0 {
				t.Fatalf("blocked retry changed subtask: %+v", got)
			}
		})
	}
}

func TestRefreshRootTaskStatusIgnoresForeignTenantSubTasks(t *testing.T) {
	store := setupTaskLifecycleTestDB(t)
	root := RootTask{ID: "root-tenant-scope", TenantID: "tenant-a", Status: "Running", TotalChunks: 1}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	for _, sub := range []SubTask{
		{ID: "sub-owned", TenantID: "tenant-a", RootTaskID: root.ID, Status: "DONE", ChunkTargets: `["https://owned.test"]`},
		{ID: "sub-foreign", TenantID: "tenant-b", RootTaskID: root.ID, Status: "FAILED", ChunkTargets: `["https://foreign.test"]`},
	} {
		if err := store.Create(&sub).Error; err != nil {
			t.Fatalf("seed subtask %s: %v", sub.ID, err)
		}
	}

	RefreshRootTaskStatus(root.ID)
	var got RootTask
	if err := store.First(&got, "id = ?", root.ID).Error; err != nil {
		t.Fatalf("reload root: %v", err)
	}
	if got.Status != "FINISHED" || got.CompletedChunks != 1 || got.CompletedTargets != 1 {
		t.Fatalf("tenant-scoped root aggregate = %+v", got)
	}
}

func TestRefreshRootTaskStatusRetriesAfterCASConflict(t *testing.T) {
	store := setupTaskLifecycleTestDB(t)
	root := RootTask{ID: "root-cas-retry", TenantID: "tenant-a", Status: "Running", TotalChunks: 1}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	if err := store.Create(&SubTask{
		ID: "sub-cas-retry", TenantID: root.TenantID, RootTaskID: root.ID,
		Status: "DONE", ChunkTargets: `["https://done.test"]`,
	}).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}

	var injected atomic.Bool
	callbackName := "argus:test-root-status-cas-conflict"
	if err := store.Callback().Update().Before("gorm:update").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Table != "root_tasks" || !injected.CompareAndSwap(false, true) {
			return
		}
		_ = tx.Session(&gorm.Session{NewDB: true, SkipHooks: true}).
			Model(&RootTask{}).
			Where("id = ?", root.ID).
			UpdateColumn("status", "PartialDone").Error
	}); err != nil {
		t.Fatalf("register CAS conflict callback: %v", err)
	}
	t.Cleanup(func() { _ = store.Callback().Update().Remove(callbackName) })

	RefreshRootTaskStatus(root.ID)
	var got RootTask
	if err := store.First(&got, "id = ?", root.ID).Error; err != nil {
		t.Fatalf("reload root: %v", err)
	}
	if !injected.Load() {
		t.Fatal("test did not inject a CAS conflict")
	}
	if got.Status != "FINISHED" || got.CompletedChunks != 1 || got.CompletedTargets != 1 {
		t.Fatalf("root did not converge after CAS conflict: %+v", got)
	}
}
