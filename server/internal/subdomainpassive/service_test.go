package subdomainpassive

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func testStore(t *testing.T) *gorm.DB {
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

func TestHoldAppliesRequiresDomainBatchAndCapability(t *testing.T) {
	cases := []struct {
		name                   string
		subdomain, noSubFinder bool
		targetType             string
		capable                bool
		want                   bool
	}{
		{"happy path", true, false, "domain", true, true},
		{"brute-only config", false, true, "domain", true, false},
		{"non-domain batch", true, false, "url", true, false},
		{"no capable agent", true, false, "domain", false, false},
	}
	for _, tc := range cases {
		if got := HoldApplies(tc.subdomain, tc.noSubFinder, tc.targetType, tc.capable); got != tc.want {
			t.Errorf("%s: HoldApplies = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCapableAgentMatchesSelector(t *testing.T) {
	capable := db.Node{AgentID: "a1", Status: "ALIVE", Tags: `{"target_type":"domain","passive_server":"v1"}`}
	incapable := db.Node{AgentID: "a2", Status: "ALIVE", Tags: `{"target_type":"domain"}`}
	nodes := []db.Node{capable, incapable}

	if !CapableAgentMatchesSelector(nodes, map[string]string{"target_type": "domain"}, db.AgentSelectorRules{}) {
		t.Fatal("capable node matching the selector must qualify")
	}
	if CapableAgentMatchesSelector(nodes, map[string]string{"target_type": "ip"}, db.AgentSelectorRules{}) {
		t.Fatal("selector excluding every capable node must not qualify")
	}
	zoneRules := db.AgentSelectorRules{Match: db.SelectorValues{"zone": []string{"dmz"}}}
	if CapableAgentMatchesSelector(nodes, map[string]string{}, zoneRules) {
		t.Fatal("capability without the required zone tag must not qualify")
	}
}

func TestAgentHasCapability(t *testing.T) {
	if AgentHasCapability("") || AgentHasCapability("not-json") {
		t.Fatal("empty or malformed tags must not be capable")
	}
	if !AgentHasCapability(`{"passive_server":"v1"}`) {
		t.Fatal("passive_server=v1 tag must be capable")
	}
	if AgentHasCapability(`{"passive_server":"v2"}`) {
		t.Fatal("unknown capability version must not be capable")
	}
}

func TestSealConfigInjectsWithoutForcingNoSubFinder(t *testing.T) {
	config := []byte(`{"Subdomain":true,"NoSubFinder":false,"Ports":"top-1000"}`)
	sealed, ok, err := SealConfig(config, map[string][]string{
		"example.test": {"a.example.test"},
	})
	if err != nil || !ok {
		t.Fatalf("seal: ok=%v err=%v", ok, err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(sealed, &payload); err != nil {
		t.Fatal(err)
	}
	// 释放密封绝不能强制 NoSubFinder：批次可能被旧 Agent 认领，
	// 强制置 true 会静默丢失被动枚举（review C1）。
	if payload["NoSubFinder"] != false {
		t.Fatalf("release seal must not force NoSubFinder, got %v", payload["NoSubFinder"])
	}
	results, _ := payload["SubdomainPassiveResults"].(map[string]interface{})
	if len(results) != 1 {
		t.Fatalf("expected sealed results, got %v", payload["SubdomainPassiveResults"])
	}
}

func TestSealConfigIdempotent(t *testing.T) {
	config := []byte(`{"Subdomain":true,"NoSubFinder":true,"SubdomainPassiveResults":{"a.test":["x.a.test"]}}`)
	sealed, ok, err := SealConfig(config, map[string][]string{"b.test": {"y.b.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if ok || string(sealed) != string(config) {
		t.Fatal("already sealed config must be returned untouched")
	}
}

func TestLoadFreshCacheSkipsExpired(t *testing.T) {
	store := testStore(t)
	now := time.Now()
	fresh, _ := json.Marshal([]string{"a.example.test"})
	expired, _ := json.Marshal([]string{"b.example.test"})
	if err := store.Create(&db.SubdomainPassiveCache{
		Domain: "example.test", Subdomains: string(fresh), Sources: `["crt.name"]`,
		CollectedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&db.SubdomainPassiveCache{
		Domain: "stale.test", Subdomains: string(expired), Sources: `["crtsh"]`,
		CollectedAt: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}

	cached := LoadFreshCache(store, []string{"example.test", "stale.test"}, now)
	if len(cached) != 1 {
		t.Fatalf("expected only fresh entry, got %v", cached)
	}
	if hit := cached["example.test"]; len(hit.Subdomains) != 1 || hit.Subdomains[0] != "a.example.test" {
		t.Fatalf("fresh entry payload mismatch: %+v", hit)
	}
}

func TestClaimSealGatesOnCapabilityAndConfig(t *testing.T) {
	store := testStore(t)
	now := time.Now()
	subdomains, _ := json.Marshal([]string{"a.example.test"})
	if err := store.Create(&db.SubdomainPassiveCache{
		Domain: "example.test", Subdomains: string(subdomains), Sources: `["crt.name"]`,
		CollectedAt: now, ExpiresAt: now.Add(time.Hour),
	}).Error; err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"Subdomain":true,"NoSubFinder":false}`)
	chunk := []string{"example.test"}

	capable := `{"passive_server":"v1"}`
	incapable := `{"scan_tcp":"v1"}`

	if sealed := ClaimSeal(store, incapable, chunk, config); string(sealed) != string(config) {
		t.Fatal("agent without capability must receive the unsealed config")
	}
	sealed := ClaimSeal(store, capable, chunk, config)
	var payload map[string]interface{}
	if err := json.Unmarshal(sealed, &payload); err != nil {
		t.Fatal(err)
	}
	// 全覆盖 + 能力 Agent：认领时才允许置 NoSubFinder=true。
	if payload["NoSubFinder"] != true {
		t.Fatalf("capable agent with full cache coverage must get NoSubFinder=true, got %v", payload["NoSubFinder"])
	}

	// 部分覆盖：另一个域名无缓存，必须保持 NoSubFinder=false 走 Agent 端收集。
	partial := ClaimSeal(store, capable, []string{"example.test", "other.test"}, config)
	var partialPayload map[string]interface{}
	if err := json.Unmarshal(partial, &partialPayload); err != nil {
		t.Fatal(err)
	}
	if partialPayload["NoSubFinder"] != false {
		t.Fatal("partial coverage must keep agent-side collection for uncovered domains")
	}

	sealedAlready := []byte(`{"Subdomain":true,"NoSubFinder":true,"SubdomainPassiveResults":{"example.test":["x.example.test"]}}`)
	if out := ClaimSeal(store, capable, chunk, sealedAlready); string(out) != string(sealedAlready) {
		t.Fatal("already sealed config must pass through unchanged")
	}
	passiveOff := []byte(`{"Subdomain":false,"NoSubFinder":true}`)
	if out := ClaimSeal(store, capable, chunk, passiveOff); string(out) != string(passiveOff) {
		t.Fatal("passive-disabled config must pass through unchanged")
	}
}

func TestCollectionProgressForTaskAggregatesJobs(t *testing.T) {
	store := testStore(t)
	mustJob := func(id, batchID string, domains []string, done int, state string) {
		domainsJSON, _ := json.Marshal(domains)
		if err := store.Create(&db.SubdomainPassiveJob{
			ID: id, TenantID: "tenant-a", ProjectID: "p", RootTaskID: "root-1",
			BatchID: batchID, AttemptID: batchID + "-a1", Domains: string(domainsJSON),
			DomainsDone: done, State: state,
		}).Error; err != nil {
			t.Fatal(err)
		}
	}
	mustJob("j1", "b1", []string{"a.test", "b.test"}, 2, JobStateReleased)
	mustJob("j2", "b2", []string{"c.test"}, 0, JobStateRunning)

	progress := CollectionProgressForTask(store, "tenant-a", "root-1")
	if !progress.Active {
		t.Fatal("running job must mark the task as actively collecting")
	}
	if progress.DomainsTotal != 3 || progress.DomainsDone != 2 {
		t.Fatalf("progress = %d/%d, want 2/3", progress.DomainsDone, progress.DomainsTotal)
	}
	if len(progress.HeldBatches) != 2 {
		t.Fatalf("held batches = %d, want 2", len(progress.HeldBatches))
	}
	if progress.State != JobStateRunning {
		t.Fatalf("state = %s, want running (lowest rank wins)", progress.State)
	}

	// 跨租户隔离：其他租户查询拿不到该任务的收集信息。
	other := CollectionProgressForTask(store, "tenant-b", "root-1")
	if other.Active || other.DomainsTotal != 0 {
		t.Fatalf("cross-tenant progress leaked: %+v", other)
	}
}
