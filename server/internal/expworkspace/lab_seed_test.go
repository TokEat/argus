package expworkspace

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/db"
)

func TestDevelopmentLabSeedsArePublishedActiveAndIdempotent(t *testing.T) {
	runtimeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request RuntimeRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.Action {
		case "inspect":
			_, _ = w.Write([]byte(`{"status":"Succeeded","inspection":{"valid":true,"parameters":[]}}`))
		case "validate":
			if request.ValidationMode != "contract" {
				t.Fatalf("validation mode=%q", request.ValidationMode)
			}
			_, _ = w.Write([]byte(`{"status":"Succeeded","validation":{"valid":true}}`))
		case "test":
			if len(request.TestCases) != 1 || stringValue(request.Egress, "mode") != "disabled" {
				t.Fatalf("test request=%+v", request)
			}
			_, _ = w.Write([]byte(`{"status":"Succeeded","test":{"passed":1,"failed":0}}`))
		default:
			t.Fatalf("unexpected action %q", request.Action)
		}
	}))
	defer runtimeServer.Close()

	service, database := newTestService(t)
	runtime, err := NewRuntimeClient(runtimeServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	service.runtime = runtime
	first, err := service.SeedDevelopmentLab(context.Background(), "tenant-lab", "seed-actor")
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.SeedDevelopmentLab(context.Background(), "tenant-lab", "seed-actor")
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || len(second) != 2 || second[0].Reused != true || second[1].Reused != true {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
	var exps []db.Exp
	if err := database.Where("tenant_id = ?", "tenant-lab").Order("name").Find(&exps).Error; err != nil {
		t.Fatal(err)
	}
	if len(exps) != 2 {
		t.Fatalf("exps=%+v", exps)
	}
	for _, item := range exps {
		if item.Status != db.ExpStatusPublished || item.ActiveRevision == nil || *item.ActiveRevision != 1 {
			t.Fatalf("EXP not published/active: %+v", item)
		}
		var revisions int64
		var cases int64
		database.Model(&db.ExpRevision{}).Where("exp_id = ?", item.ID).Count(&revisions)
		database.Model(&db.ExpTestCase{}).Where("exp_id = ?", item.ID).Count(&cases)
		if revisions != 1 || cases != 1 {
			t.Fatalf("exp=%s revisions=%d cases=%d", item.Name, revisions, cases)
		}
	}
}

func TestDevelopmentLabSourcesStayBoundToIsolatedTargets(t *testing.T) {
	sources := DevelopmentLabSeedSources()
	if len(sources) != 2 {
		t.Fatalf("sources=%v", sources)
	}
	if sources["lab-shiro-cve-2016-4437-rce"] == "" || sources["lab-telnet-unauth-rce"] == "" {
		t.Fatalf("missing embedded lab source")
	}
	if !strings.Contains(sources["lab-shiro-cve-2016-4437-rce"], `canary_token = "ARGUS_CANARY_" + codec.EncodeToHex(codec.CryptoRandBytes(12))`) {
		t.Fatal("Shiro seed must generate its one-time Canary token inside the EXP")
	}
	if !strings.Contains(sources["lab-telnet-unauth-rce"], `marker = "ARGUS_TELNET_" + codec.EncodeToHex(codec.CryptoRandBytes(12))`) {
		t.Fatal("Telnet seed must generate its one-time execution marker inside the EXP")
	}
	if !strings.Contains(sources["lab-telnet-unauth-rce"], `cli.setInputType("host_port")`) {
		t.Fatal("Telnet seed must declare its host:port CLI component")
	}
	if !strings.Contains(sources["lab-shiro-cve-2016-4437-rce"], `cli.setInputType("url")`) {
		t.Fatal("Shiro seed must declare its URL CLI component")
	}
}
