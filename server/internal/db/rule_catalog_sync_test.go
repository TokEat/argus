package db

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupRuleCatalogSyncTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	store, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(
		&Arsenal{},
		&RuleCatalogBootstrap{},
		&FingerprintRule{},
		&PocRule{},
		&WorkflowRule{},
		&DirRule{},
		&ExploitRule{},
	); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	old := DB
	DB = store
	t.Cleanup(func() { DB = old })
	return store
}

func TestSyncRuleCatalogFromArsenalSerializesConcurrentCalls(t *testing.T) {
	store := setupRuleCatalogSyncTestDB(t)
	if err := store.Create(&Arsenal{
		ID:       BuildTenantArsenalID("default", "finger", "finger.yaml"),
		TenantID: "default",
		Type:     "finger",
		FileName: "finger.yaml",
		Content:  "ArgusMCPSyncLock:\n  - body=\"sync-lock\"\n",
		Hash:     "hash",
		Version:  1,
		State:    "Approved",
	}).Error; err != nil {
		t.Fatalf("seed arsenal: %v", err)
	}

	var mu sync.Mutex
	active := 0
	maxActive := 0
	ruleCatalogSyncAfterLoadHook = func() {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()
		time.Sleep(25 * time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
	}
	t.Cleanup(func() { ruleCatalogSyncAfterLoadHook = nil })

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- SyncRuleCatalogFromArsenal()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("sync returned error: %v", err)
		}
	}
	if maxActive != 1 {
		t.Fatalf("SyncRuleCatalogFromArsenal ran concurrently; max active calls = %d", maxActive)
	}
}
