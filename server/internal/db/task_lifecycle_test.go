package db

import (
	"fmt"
	"strings"
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
