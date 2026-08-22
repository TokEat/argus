package subdomainpassive

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func testWorkerStore(t *testing.T) *gorm.DB {
	t.Helper()
	store, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AutoMigrate(&db.SubdomainPassiveCache{}, &db.SubdomainPassiveJob{}, &db.SubTask{}, &db.TaskAudit{}); err != nil {
		t.Fatal(err)
	}
	return store
}

func seedJob(t *testing.T, store *gorm.DB, id string, state string, age time.Duration, domains []string) db.SubdomainPassiveJob {
	t.Helper()
	domainsJSON, _ := json.Marshal(domains)
	job := db.SubdomainPassiveJob{
		ID: id, TenantID: "tenant-a", ProjectID: "p", RootTaskID: "root-1",
		BatchID: id + "-batch", AttemptID: id + "-attempt", Domains: string(domainsJSON),
		DomainsDone: 0, State: state,
	}
	if err := store.Create(&job).Error; err != nil {
		t.Fatal(err)
	}
	if age > 0 {
		store.Model(&db.SubdomainPassiveJob{}).Where("id = ?", id).
			Update("created_at", time.Now().Add(-age))
		job.CreatedAt = time.Now().Add(-age)
	}
	return job
}

func seedHeldAttempt(t *testing.T, store *gorm.DB, attemptID string) db.SubTask {
	t.Helper()
	sub := db.SubTask{
		ID: attemptID, TenantID: "tenant-a", ProjectID: "p", RootTaskID: "root-1",
		BatchID: attemptID + "-batch", Status: HoldStatus, Config: `{"Subdomain":true,"NoSubFinder":false}`,
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatal(err)
	}
	return sub
}

func TestClaimPendingCASesOneJob(t *testing.T) {
	store := testWorkerStore(t)
	w := &Worker{DB: store, Now: time.Now}
	seedJob(t, store, "j1", JobStatePending, 0, []string{"a.test"})

	first, ok := w.claimPending()
	if !ok || first.ID != "j1" {
		t.Fatalf("first claim = %+v ok=%v", first, ok)
	}
	// 已 running 的任务不能被重复认领。
	if _, ok := w.claimPending(); ok {
		t.Fatal("running job must not be claimable again")
	}
	// 终态任务不参与认领。
	store.Model(&db.SubdomainPassiveJob{}).Where("id = ?", "j1").Update("state", JobStateReleased)
	if _, ok := w.claimPending(); ok {
		t.Fatal("terminal job must not be claimable")
	}
}

func TestReleaseAttemptForCASQueuedToDispatching(t *testing.T) {
	store := testWorkerStore(t)
	var enqueued []db.SubTask
	w := &Worker{
		DB: store, Now: time.Now,
		Enqueue: func(_ context.Context, sub db.SubTask) error {
			enqueued = append(enqueued, sub)
			return nil
		},
	}
	job := seedJob(t, store, "j1", JobStateRunning, 0, []string{"a.test"})
	seedHeldAttempt(t, store, job.AttemptID)

	w.releaseAttemptFor(job, db.SubTask{ID: job.AttemptID, TenantID: job.TenantID, Status: HoldStatus})
	if len(enqueued) != 1 {
		t.Fatalf("enqueue calls = %d, want 1", len(enqueued))
	}
	var sub db.SubTask
	store.Where("id = ?", job.AttemptID).First(&sub)
	if sub.Status != "Dispatching" {
		t.Fatalf("attempt status = %s, want Dispatching", sub.Status)
	}

	// 非 Queued（已暂停/已派发）的尝试不得再次释放或重复入队。
	w.releaseAttemptFor(job, sub)
	if len(enqueued) != 1 {
		t.Fatalf("non-Queued attempt must not enqueue again, got %d calls", len(enqueued))
	}
}

func TestReleaseExpiredHoldsReleasesBeforeFinishing(t *testing.T) {
	store := testWorkerStore(t)
	var enqueued []db.SubTask
	w := &Worker{
		DB: store, Now: time.Now, HoldLimit: time.Minute,
		Enqueue: func(_ context.Context, sub db.SubTask) error {
			enqueued = append(enqueued, sub)
			return nil
		},
	}
	job := seedJob(t, store, "j1", JobStatePending, 10*time.Minute, []string{"a.test"})
	seedHeldAttempt(t, store, job.AttemptID)

	w.releaseExpiredHolds()
	if len(enqueued) != 1 {
		t.Fatalf("expired hold must dispatch, got %d calls", len(enqueued))
	}
	var updated db.SubdomainPassiveJob
	store.Where("id = ?", job.ID).First(&updated)
	if updated.State != JobStateFailed {
		t.Fatalf("job state = %s, want failed", updated.State)
	}
	var audits []db.TaskAudit
	store.Where("attempt_id = ?", job.AttemptID).Find(&audits)
	if len(audits) != 1 {
		t.Fatalf("audit rows = %d, want exactly 1", len(audits))
	}
}

func TestDisabledModeDrainsAllHolds(t *testing.T) {
	store := testWorkerStore(t)
	var enqueued []db.SubTask
	w := &Worker{
		DB: store, Now: time.Now,
		Enqueue: func(_ context.Context, sub db.SubTask) error {
			enqueued = append(enqueued, sub)
			return nil
		},
	}
	j1 := seedJob(t, store, "j1", JobStatePending, 0, []string{"a.test"})
	j2 := seedJob(t, store, "j2", JobStateRunning, 0, []string{"b.test"})
	seedHeldAttempt(t, store, j1.AttemptID)
	seedHeldAttempt(t, store, j2.AttemptID)

	w.releaseAllHolds("feature disabled")
	if len(enqueued) != 2 {
		t.Fatalf("drain must release both holds, got %d", len(enqueued))
	}
	var remaining int64
	store.Model(&db.SubdomainPassiveJob{}).Where("state IN ?", []string{JobStatePending, JobStateRunning}).Count(&remaining)
	if remaining != 0 {
		t.Fatalf("active jobs after drain = %d, want 0", remaining)
	}
}

func TestProcessJobSealsReleasesAndInheritsProgress(t *testing.T) {
	store := testWorkerStore(t)
	var enqueued []db.SubTask
	collector := NewCollector()
	// 用固定桩源避免真实外呼：a.test 收集到 1 个子域，b.test 命中缓存。
	collector.Sources = []SourceClient{
		{Name: "stub", Fetch: func(_ context.Context, _ *http.Client, domain string) ([]string, error) {
			return []string{"x." + domain}, nil
		}},
	}
	collector.LookupIP = func(_ context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.1")}, nil
	}
	w := &Worker{
		DB: store, Collector: collector, CacheTTL: time.Hour, HoldLimit: time.Hour, Now: time.Now,
		Enqueue: func(_ context.Context, sub db.SubTask) error {
			enqueued = append(enqueued, sub)
			return nil
		},
	}
	cachedJSON, _ := json.Marshal([]string{"y.b.test"})
	if err := store.Create(&db.SubdomainPassiveCache{
		Domain: "b.test", Subdomains: string(cachedJSON), Sources: `["crt.name"]`,
		CollectedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}
	job := seedJob(t, store, "j1", JobStatePending, 0, []string{"a.test", "b.test"})
	// 模拟此前一次中断已推进 1 个域名。
	store.Model(&db.SubdomainPassiveJob{}).Where("id = ?", job.ID).Update("domains_done", 1)
	job.DomainsDone = 1
	seedHeldAttempt(t, store, job.AttemptID)

	w.processJob(context.Background(), job)

	if len(enqueued) != 1 {
		t.Fatalf("processed job must dispatch once, got %d", len(enqueued))
	}
	var sub db.SubTask
	store.Where("id = ?", job.AttemptID).First(&sub)
	if sub.Status != "Dispatching" {
		t.Fatalf("attempt status = %s, want Dispatching", sub.Status)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(sub.Config), &payload); err != nil {
		t.Fatal(err)
	}
	results, _ := payload["SubdomainPassiveResults"].(map[string]interface{})
	if len(results) != 2 {
		t.Fatalf("both domains must be sealed, got %v", results)
	}
	if payload["NoSubFinder"] == true {
		t.Fatal("release seal must never force NoSubFinder (review C1)")
	}
	var updated db.SubdomainPassiveJob
	store.Where("id = ?", job.ID).First(&updated)
	if updated.State != JobStateReleased {
		t.Fatalf("job state = %s, want released", updated.State)
	}
	if updated.DomainsDone != 2 {
		t.Fatalf("domains_done = %d, want 2", updated.DomainsDone)
	}
}
