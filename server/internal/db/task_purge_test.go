package db

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// setupPurgeTestDB 建一个含全部级联目标表的内存 sqlite：RootTask/TaskAudit 走 AutoMigrate
// （purge 用模型读 root、写审计），其余纯删除目标表用裸 DDL 建最小列，scan_coverages 用
// source_task_id。与生产一致的表名集合来自被测代码同一常量 purgeChildTables。
func setupPurgeTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&RootTask{}, &TaskAudit{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	for _, tbl := range purgeChildTables {
		if tbl == "task_audits" {
			continue // 已由 AutoMigrate 建
		}
		if err := store.Exec("CREATE TABLE " + tbl + " (tenant_id TEXT, project_id TEXT, root_task_id TEXT)").Error; err != nil {
			t.Fatalf("create %s: %v", tbl, err)
		}
	}
	if err := store.Exec("CREATE TABLE scan_coverages (tenant_id TEXT, project_id TEXT, source_task_id TEXT)").Error; err != nil {
		t.Fatalf("create scan_coverages: %v", err)
	}
	old := DB
	DB = store
	t.Cleanup(func() { DB = old })
	return store
}

// insertPurgeFixtures 为某任务在其多数级联表里各塞一行，并塞一行同 root_task_id 但异租户的行
// 用于验证租户隔离。
func insertPurgeFixtures(t *testing.T, store *gorm.DB, tenantID, projectID, taskID string, withIsolation bool) {
	t.Helper()
	if err := store.Create(&RootTask{ID: taskID, TenantID: tenantID, ProjectID: projectID, Status: "Done"}).Error; err != nil {
		t.Fatal(err)
	}
	for _, tbl := range purgeChildTables {
		if tbl == "task_audits" {
			// 一条旧审计，purge 后应被清掉、仅留 hard_delete 一条。
			if err := store.Create(&TaskAudit{TenantID: tenantID, ProjectID: projectID, RootTaskID: taskID, Action: "archive"}).Error; err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := store.Exec("INSERT INTO "+tbl+" (tenant_id, project_id, root_task_id) VALUES (?,?,?)", tenantID, projectID, taskID).Error; err != nil {
			t.Fatalf("insert %s: %v", tbl, err)
		}
	}
	if err := store.Exec("INSERT INTO scan_coverages (tenant_id, project_id, source_task_id) VALUES (?,?,?)", tenantID, projectID, taskID).Error; err != nil {
		t.Fatal(err)
	}
	if withIsolation {
		// 其他租户同名 root_task_id 的行，绝不应被删。
		if err := store.Exec("INSERT INTO assets (tenant_id, project_id, root_task_id) VALUES (?,?,?)", "other-tenant", projectID, taskID).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.Exec("INSERT INTO sub_tasks (tenant_id, project_id, root_task_id) VALUES (?,?,?)", "other-tenant", projectID, taskID).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func countWhere(t *testing.T, store *gorm.DB, table, where string, args ...interface{}) int64 {
	t.Helper()
	var n int64
	if err := store.Table(table).Where(where, args...).Count(&n).Error; err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestPurgeRootTaskDeletesAllAssociatedDataAtomically(t *testing.T) {
	store := setupPurgeTestDB(t)
	insertPurgeFixtures(t, store, "tenant-a", "project-a", "task-purge-1", true)

	counts, err := PurgeRootTask(t.Context(), "tenant-a", "project-a", "task-purge-1", "user-1")
	if err != nil {
		t.Fatalf("PurgeRootTask: %v", err)
	}

	for _, tbl := range purgeChildTables {
		if tbl == "task_audits" {
			continue
		}
		// 仅统计本租户行：其他租户同 root_task_id 的行是必须保留的（见文末隔离断言）。
		if got := countWhere(t, store, tbl, "tenant_id = ? AND root_task_id = ?", "tenant-a", "task-purge-1"); got != 0 {
			t.Errorf("%s still has %d tenant-a rows for purged task", tbl, got)
		}
	}
	if got := countWhere(t, store, "scan_coverages", "tenant_id = ? AND source_task_id = ?", "tenant-a", "task-purge-1"); got != 0 {
		t.Errorf("scan_coverages still has %d rows", got)
	}
	if got := countWhere(t, store, "root_tasks", "id = ?", "task-purge-1"); got != 0 {
		t.Errorf("root_tasks still has the purged row")
	}
	// 恰好一条 hard_delete 审计留存，旧 archive 审计已被清掉。
	var audits []TaskAudit
	if err := store.Where("root_task_id = ?", "task-purge-1").Find(&audits).Error; err != nil {
		t.Fatal(err)
	}
	if len(audits) != 1 || audits[0].Action != purgeAuditAction {
		t.Fatalf("expected exactly one %s audit, got %+v", purgeAuditAction, audits)
	}
	if audits[0].OperatorID != "user-1" || audits[0].BeforeStatus != "Done" || audits[0].AfterStatus != "purged" {
		t.Errorf("audit fields wrong: %+v", audits[0])
	}
	if counts["assets"] != 1 || counts["root_tasks"] != 1 || counts["scan_coverages"] != 1 {
		t.Errorf("counts wrong: %+v", counts)
	}
	// 租户隔离：other-tenant 的行原样保留。
	if got := countWhere(t, store, "assets", "tenant_id = ? AND root_task_id = ?", "other-tenant", "task-purge-1"); got != 1 {
		t.Errorf("other-tenant assets row should survive, got %d", got)
	}
	if got := countWhere(t, store, "sub_tasks", "tenant_id = ? AND root_task_id = ?", "other-tenant", "task-purge-1"); got != 1 {
		t.Errorf("other-tenant sub_tasks row should survive, got %d", got)
	}
}

func TestPurgeRootTaskRejectsNonTerminal(t *testing.T) {
	store := setupPurgeTestDB(t)
	if err := store.Create(&RootTask{ID: "task-running", TenantID: "tenant-a", ProjectID: "project-a", Status: "Running"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Exec("INSERT INTO assets (tenant_id, project_id, root_task_id) VALUES (?,?,?)", "tenant-a", "project-a", "task-running").Error; err != nil {
		t.Fatal(err)
	}

	_, err := PurgeRootTask(t.Context(), "tenant-a", "project-a", "task-running", "user-1")
	if !errors.Is(err, ErrTaskNotTerminal) {
		t.Fatalf("expected ErrTaskNotTerminal, got %v", err)
	}
	if got := countWhere(t, store, "assets", "root_task_id = ?", "task-running"); got != 1 {
		t.Errorf("non-terminal purge must delete nothing, assets=%d", got)
	}
	if got := countWhere(t, store, "root_tasks", "id = ?", "task-running"); got != 1 {
		t.Errorf("root task should remain on non-terminal purge")
	}
}
