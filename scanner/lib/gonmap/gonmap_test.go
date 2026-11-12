package gonmap

import (
	"os"
	"os/exec"
	"sync"
	"testing"
)

func TestG32ProcessHelper(t *testing.T) {
	mode := os.Getenv("GONMAP_G32_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "uninitialized":
		if nmap != nil {
			t.Fatal("probe snapshot was built during package initialization")
		}
	case "concurrent-new":
		const workers = 32
		var wg sync.WaitGroup
		results := make(chan *Nmap, workers)
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results <- New()
			}()
		}
		wg.Wait()
		close(results)
		var sharedProbe *probe
		for scanner := range results {
			if scanner == nil || scanner.filter != 9 || len(scanner.probeNameMap) == 0 {
				t.Fatal("concurrent New returned an incomplete default snapshot")
			}
			if sharedProbe == nil {
				sharedProbe = scanner.probeNameMap["TCP_NULL"]
			} else if scanner.probeNameMap["TCP_NULL"] != sharedProbe {
				t.Fatal("concurrent New did not share one read-only probe snapshot")
			}
		}
	case "set-filter":
		SetFilter(1)
		old := New()
		if old.filter != 1 {
			t.Fatalf("first SetFilter filter = %d, want 1", old.filter)
		}
		SetFilter(2)
		current := New()
		if current.filter != 2 {
			t.Fatalf("rebuilt filter = %d, want 2", current.filter)
		}
		if old.filter != 1 || len(old.probeNameMap) == 0 {
			t.Fatal("existing scanner did not retain its original snapshot")
		}
		if old.probeNameMap["TCP_NULL"] == current.probeNameMap["TCP_NULL"] {
			t.Fatal("SetFilter rebuild reused the old probe snapshot")
		}
	case "banner":
		scanner := New()
		finger := scanner.getFinger("220 mail.example ESMTP\r\n", false, "TCP_NULL")
		if finger.Service != "smtp" || finger.Hostname != "mail.example" {
			t.Fatalf("SMTP banner fingerprint = %#v", finger)
		}
	case "initialization-failure":
		failure := "probe initialization failed"
		assertPanicValue(t, failure, func() {
			initializeNmap(9, func(int) *Nmap { panic(failure) })
		})
		if nmap != nil {
			t.Fatal("failed initialization published a partial snapshot")
		}
		assertPanicValue(t, failure, func() {
			initializeNmap(9, func(int) *Nmap {
				t.Fatal("sync.Once retried after the first initialization failure")
				return nil
			})
		})
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}

func assertPanicValue(t *testing.T, expected interface{}, fn func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != expected {
			t.Fatalf("panic = %#v, want %#v", recovered, expected)
		}
	}()
	fn()
	t.Fatal("expected panic")
}

func TestG32LazySnapshots(t *testing.T) {
	for _, mode := range []string{"uninitialized", "concurrent-new", "set-filter", "banner", "initialization-failure"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestG32ProcessHelper$")
			cmd.Env = append(os.Environ(), "GONMAP_G32_HELPER="+mode)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("helper %s failed: %v\n%s", mode, err, output)
			}
		})
	}
}
