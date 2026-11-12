package taskstore

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/TokEat/argus/scanner/structs"

	"github.com/projectdiscovery/hmap/store/hybrid"
)

func boundedConfig(targets ...string) structs.Config {
	return structs.Config{Targets: targets, NoDirSearch: true, NoHostBind: true}
}

func TestUsesMemoryConservativeBoundaries(t *testing.T) {
	tests := []struct {
		name string
		cfg  structs.Config
		want bool
	}{
		{name: "no targets", want: true},
		{name: "risk validation", cfg: structs.Config{ExecutionMode: "risk_validation", Targets: []string{"10.0.0.1"}}, want: true},
		{name: "eight explicit targets", cfg: boundedConfig("https://example.com", "192.0.2.1:443", "example.com:8443", "https://example.com/a", "192.0.2.2:443", "example.org:8443", "https://example.org", "192.0.2.3:443"), want: true},
		{name: "nine targets", cfg: boundedConfig("https://one.example.com", "https://two.example.com", "https://three.example.com", "https://four.example.com", "https://five.example.com", "https://six.example.com", "https://seven.example.com", "https://eight.example.com", "https://nine.example.com")},
		{name: "bare ip", cfg: boundedConfig("192.0.2.1")},
		{name: "bare domain", cfg: boundedConfig("example.com")},
		{name: "cidr", cfg: boundedConfig("192.0.2.0/24")},
		{name: "ip range", cfg: boundedConfig("192.0.2.1-192.0.2.8")},
		{name: "unknown", cfg: boundedConfig("not a target")},
		{name: "subdomain", cfg: structs.Config{Targets: []string{"https://one.example.com"}, Subdomain: true, NoDirSearch: true, NoHostBind: true}},
		{name: "directory probe enabled", cfg: structs.Config{Targets: []string{"https://example.com"}, NoHostBind: true}},
		{name: "host binding enabled", cfg: structs.Config{Targets: []string{"https://example.com"}, NoDirSearch: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := UsesMemory(tt.cfg); got != tt.want {
				t.Fatalf("UsesMemory() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewMapsHaveEquivalentReadWriteBehavior(t *testing.T) {
	for _, cfg := range []structs.Config{
		boundedConfig("https://one.example.com"),
		boundedConfig("example.com"),
	} {
		stores, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		for name, store := range map[string]*hybrid.HybridMap{"body": stores.Body, "header": stores.Header, "banner": stores.Banner} {
			if err := store.Set("key", []byte(name)); err != nil {
				t.Fatalf("%s Set: %v", name, err)
			}
			got, ok := store.Get("key")
			if !ok || string(got) != name {
				t.Fatalf("%s Get = %q, %v", name, got, ok)
			}
			defer store.Close()
		}
	}
}

func TestNewUsesOneStorageDecisionForAllMaps(t *testing.T) {
	original := newHybridMap
	t.Cleanup(func() { newHybridMap = original })

	for _, test := range []struct {
		name     string
		cfg      structs.Config
		wantType hybrid.MapType
	}{
		{name: "memory", cfg: boundedConfig("https://one.example.com"), wantType: hybrid.Memory},
		{name: "disk", cfg: boundedConfig("192.0.2.0/24"), wantType: hybrid.Disk},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := UsesMemory(test.cfg); got != (test.wantType == hybrid.Memory) {
				t.Fatalf("UsesMemory() = %v for expected type %v", got, test.wantType)
			}
			if hybrid.DefaultMemoryOptions.Type != hybrid.Memory || hybrid.DefaultDiskOptions.Type != hybrid.Disk {
				t.Fatalf("unexpected default types memory=%v disk=%v", hybrid.DefaultMemoryOptions.Type, hybrid.DefaultDiskOptions.Type)
			}
			var got []hybrid.MapType
			newHybridMap = func(options hybrid.Options) (*hybrid.HybridMap, error) {
				got = append(got, options.Type)
				return hybrid.New(hybrid.DefaultMemoryOptions)
			}
			stores, err := New(test.cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer stores.Body.Close()
			defer stores.Header.Close()
			defer stores.Banner.Close()
			if len(got) != 3 {
				t.Fatalf("constructor calls = %d, want 3", len(got))
			}
			for index, mapType := range got {
				if mapType != test.wantType {
					t.Fatalf("map %d type = %v, want %v", index, mapType, test.wantType)
				}
			}
		})
	}
}

func TestResponseStoreDiskLifecycleLeavesNoTemporaryFiles(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("TMP", tempDir)
	t.Setenv("TEMP", tempDir)
	t.Setenv("TMPDIR", tempDir)

	memory, err := New(boundedConfig("https://example.com"))
	if err != nil {
		t.Fatal(err)
	}
	_ = memory.Body.Close()
	_ = memory.Header.Close()
	_ = memory.Banner.Close()
	if entries, err := os.ReadDir(tempDir); err != nil || len(entries) != 0 {
		t.Fatalf("memory stores created temporary files: entries=%d err=%v", len(entries), err)
	}

	disk, err := New(boundedConfig("192.0.2.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(tempDir); err != nil || len(entries) != 3 {
		t.Fatalf("disk stores temporary directories = %d, want 3 (err=%v)", len(entries), err)
	}
	_ = disk.Body.Close()
	_ = disk.Header.Close()
	_ = disk.Banner.Close()
	if entries, err := os.ReadDir(tempDir); err != nil || len(entries) != 0 {
		t.Fatalf("disk stores left temporary files after Close: entries=%d err=%v", len(entries), err)
	}
}

func TestMemoryResponseStoresAreConcurrentAndTaskPrivate(t *testing.T) {
	const contexts = 32
	var wait sync.WaitGroup
	errors := make(chan error, contexts)
	for index := range contexts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			stores, err := New(boundedConfig("https://example.com"))
			if err != nil {
				errors <- err
				return
			}
			defer stores.Body.Close()
			defer stores.Header.Close()
			defer stores.Banner.Close()
			value := []byte(fmt.Sprintf("context-%d", index))
			if err := stores.Body.Set("shared-key", value); err != nil {
				errors <- err
				return
			}
			got, ok := stores.Body.Get("shared-key")
			if !ok || string(got) != string(value) {
				errors <- fmt.Errorf("context %d read %q, %v", index, got, ok)
			}
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

func TestNewRollsBackCreatedStoresOnFailure(t *testing.T) {
	original := newHybridMap
	t.Cleanup(func() { newHybridMap = original })
	for _, failAt := range []int{2, 3} {
		t.Run(fmt.Sprintf("map_%d", failAt), func(t *testing.T) {
			var created []*hybrid.HybridMap
			calls := 0
			newHybridMap = func(hybrid.Options) (*hybrid.HybridMap, error) {
				calls++
				if calls == failAt {
					return nil, errors.New("injected failure")
				}
				store, err := hybrid.New(hybrid.DefaultDiskOptions)
				if err == nil {
					created = append(created, store)
				}
				return store, err
			}

			if _, err := New(boundedConfig("https://one.example.com")); err == nil {
				t.Fatal("New succeeded after injected failure")
			}
			for _, store := range created {
				if err := store.Set("closed", []byte("value")); err == nil {
					t.Fatal("created store remained writable after rollback")
				}
			}
		})
	}
}

func BenchmarkNewResponseStores(b *testing.B) {
	for _, test := range []struct {
		name string
		cfg  structs.Config
	}{
		{name: "bounded_memory", cfg: boundedConfig("https://example.com")},
		{name: "range_disk", cfg: boundedConfig("192.0.2.0/24")},
	} {
		b.Run(test.name, func(b *testing.B) {
			for b.Loop() {
				stores, err := New(test.cfg)
				if err != nil {
					b.Fatal(err)
				}
				_ = stores.Body.Close()
				_ = stores.Header.Close()
				_ = stores.Banner.Close()
			}
		})
	}
}
