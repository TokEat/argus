package db

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupProgressTestDB(t *testing.T) *gorm.DB {
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
	t.Cleanup(func() { DB = old })
	return store
}

func TestUpdateSubTaskProgressScopesTenantAndAggregatesRoot(t *testing.T) {
	store := setupProgressTestDB(t)
	root := RootTask{ID: "root-progress", TenantID: "tenant-a", Status: "Running"}
	subs := []SubTask{
		{ID: "sub-1", TenantID: "tenant-a", RootTaskID: root.ID, Status: "Running", ChunkTargets: `["a"]`},
		{ID: "sub-2", TenantID: "tenant-a", RootTaskID: root.ID, Status: "Running", ChunkTargets: `["b"]`},
		{ID: "sub-3", TenantID: "tenant-a", RootTaskID: root.ID, Status: "Done", ChunkTargets: `["c"]`},
	}
	if err := store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	for i := range subs {
		if err := store.Create(&subs[i]).Error; err != nil {
			t.Fatal(err)
		}
	}

	// 记录 sub-1 与 sub-2 的实时进度；终态 sub-3 不参与聚合。
	UpdateSubTaskProgress("tenant-a", "sub-1", "port_scan", 10, 8000, 40.5, 2500)
	UpdateSubTaskProgress("tenant-a", "sub-2", "protocol_identify", 7, 500, 12.5, 1000)
	UpdateSubTaskProgress("tenant-a", "sub-3", "fingerprint", 99, 100, 0, 0)

	var sub1 SubTask
	if err := store.First(&sub1, "id = ?", "sub-1").Error; err != nil {
		t.Fatal(err)
	}
	if sub1.ProgressPhase != "port_scan" || sub1.ProgressDone != 10 || sub1.ProgressTotal != 8000 {
		t.Fatalf("sub-1 progress not persisted: %+v", sub1)
	}
	if sub1.ProgressRate != 40.5 || sub1.ProgressEtaMs != 2500 {
		t.Fatalf("sub-1 rate/eta not persisted: %+v", sub1)
	}
	if sub1.ProgressUpdatedAt == nil {
		t.Fatal("sub-1 progress_updated_at not set")
	}

	// 根任务聚合 = 运行中子任务的活动计数之和（10 + 7）、吞吐之和（40.5 + 12.5），终态 sub-3 不计入。
	var gotRoot RootTask
	if err := store.First(&gotRoot, "id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if gotRoot.ProgressDone != 17 {
		t.Fatalf("root progress_done = %d, want 17 (sum of running attempts)", gotRoot.ProgressDone)
	}
	if gotRoot.ProgressRate != 53.0 {
		t.Fatalf("root progress_rate = %v, want 53 (sum of running attempts)", gotRoot.ProgressRate)
	}
}

func TestUpdateSubTaskProgressDoesNotTouchUpdatedAt(t *testing.T) {
	store := setupProgressTestDB(t)
	root := RootTask{ID: "root-updatedat", TenantID: "tenant-a", Status: "Running"}
	sub := SubTask{ID: "sub-ua", TenantID: "tenant-a", RootTaskID: root.ID, Status: "Running", ChunkTargets: `["x"]`}
	if err := store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatal(err)
	}
	// 把 updated_at 拨到过去，确保进度刷新不会 bumped 它（超时守护依赖 updated_at+timeout_sec）。
	past := time.Now().Add(-time.Hour)
	if err := store.Model(&SubTask{}).Where("id = ?", sub.ID).Update("updated_at", past).Error; err != nil {
		t.Fatal(err)
	}

	UpdateSubTaskProgress("tenant-a", sub.ID, "http_probe", 3, 200, 0, 0)

	var got SubTask
	if err := store.First(&got, "id = ?", sub.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.ProgressDone != 3 {
		t.Fatalf("progress_done = %d, want 3", got.ProgressDone)
	}
	if got.UpdatedAt.After(time.Now().Add(-time.Minute)) {
		t.Fatalf("updated_at was bumped by progress update: %v", got.UpdatedAt)
	}
}

func TestUpdateSubTaskProgressRejectsOtherTenant(t *testing.T) {
	store := setupProgressTestDB(t)
	root := RootTask{ID: "root-tenant", TenantID: "tenant-a", Status: "Running"}
	sub := SubTask{ID: "sub-t", TenantID: "tenant-a", RootTaskID: root.ID, Status: "Running", ChunkTargets: `["y"]`}
	if err := store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatal(err)
	}
	// 跨租户写入必须被 tenant 范围过滤拒绝。
	UpdateSubTaskProgress("tenant-b", sub.ID, "port_scan", 50, 100, 9, 100)

	var got SubTask
	if err := store.First(&got, "id = ?", sub.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.ProgressDone != 0 || got.ProgressPhase != "" {
		t.Fatalf("cross-tenant progress leaked: %+v", got)
	}
}
