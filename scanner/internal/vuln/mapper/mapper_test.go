package mapper

import (
	"github.com/P0lar1ght/argus/scanner/structs"
	"reflect"
	"testing"
)

func TestGetPocsUsesExplicitStateAndDedupesYamlNames(t *testing.T) {
	resultMap := map[string][]string{
		"http://example.com/admin/login": {"Apache", "General-Poc-HTTP"},
	}

	workFlowDB := map[string]structs.WorkFlowEntity{
		"Apache": {
			RootType: true,
			BaseType: true,
			DirType:  true,
			PocsName: []string{"apache-detect", "apache-detect.yaml"},
		},
		"General-Poc-HTTP": {
			RootType: true,
			PocsName: []string{"generic-http"},
		},
	}

	got, count := GetPocs(resultMap, workFlowDB, false, true)
	if count != 4 {
		t.Fatalf("expected 4 workflow applications, got %d", count)
	}

	expect := map[string][]string{
		"http://example.com":             {"apache-detect.yaml", "generic-http.yaml"},
		"http://example.com/admin":       {"apache-detect.yaml"},
		"http://example.com/admin/login": {"apache-detect.yaml"},
	}

	if !reflect.DeepEqual(got, expect) {
		t.Fatalf("unexpected mapping:\nwant=%#v\ngot=%#v", expect, got)
	}
}

func TestGetPocsSkipsGeneralPocsWhenDisabled(t *testing.T) {
	resultMap := map[string][]string{
		"http://example.com": {"Apache"},
	}

	workFlowDB := map[string]structs.WorkFlowEntity{
		"Apache": {
			RootType: true,
			PocsName: []string{"apache-detect"},
		},
		"General-Poc-HTTP": {
			RootType: true,
			PocsName: []string{"generic-http"},
		},
	}

	got, count := GetPocs(resultMap, workFlowDB, true, true)
	if count != 1 {
		t.Fatalf("expected 1 workflow application, got %d", count)
	}

	expect := map[string][]string{
		"http://example.com": {"apache-detect.yaml"},
	}
	if !reflect.DeepEqual(got, expect) {
		t.Fatalf("unexpected mapping:\nwant=%#v\ngot=%#v", expect, got)
	}
}

func TestGetPocsAppliesRootTypeToNonHTTPTargets(t *testing.T) {
	resultMap := map[string][]string{
		"ssh://172.20.0.180:22":   {"OpenSSH", "SSH"},
		"ssh://172.20.0.180:2222": {"NonRoot"},
		"tcp://127.0.0.1:6379":    {"Redis"},
		"https://172.20.0.180/":   {"GitLab"},
	}
	workFlowDB := map[string]structs.WorkFlowEntity{
		"OpenSSH": {RootType: true, PocsName: []string{"CVE-2001-1473"}},
		"SSH":     {RootType: true, PocsName: []string{"CVE-2021-44228"}},
		"Redis":   {RootType: true, PocsName: []string{"redis-login"}},
		"GitLab":  {RootType: true, PocsName: []string{"gitlab-detect"}},
		"NonRoot": {RootType: false, PocsName: []string{"non-root-tcp"}},
	}

	got, count := GetPocs(resultMap, workFlowDB, false, false)
	if count != 4 {
		t.Fatalf("count = %d, want 4 (ssh root x2 + redis root + gitlab root) map=%#v", count, got)
	}
	ssh := got["ssh://172.20.0.180:22"]
	if len(ssh) != 2 || ssh[0] != "CVE-2001-1473.yaml" || ssh[1] != "CVE-2021-44228.yaml" {
		t.Fatalf("ssh root pocs = %q, want CVE-2001-1473 + CVE-2021-44228", ssh)
	}
	if _, ok := got["ssh://172.20.0.180:2222"]; ok {
		t.Fatalf("non-root non-HTTP target must be skipped: %#v", got)
	}
	if redis := got["tcp://127.0.0.1:6379"]; len(redis) != 1 || redis[0] != "redis-login.yaml" {
		t.Fatalf("tcp root pocs = %q, want redis-login", redis)
	}
	expect := map[string][]string{
		"https://172.20.0.180": {"gitlab-detect.yaml"},
	}
	if !reflect.DeepEqual(got["https://172.20.0.180"], expect["https://172.20.0.180"]) {
		t.Fatalf("http root mapping:\nwant=%#v\ngot=%#v", expect, got)
	}
}

func TestGetPocsSkipsManyFingerprintsWhenEnabled(t *testing.T) {
	resultMap := map[string][]string{
		"http://example.com": {
			"Product01", "Product02", "Product03", "Product04", "Product05", "Product06",
			"Product07", "Product08", "Product09", "Product10", "Product11",
		},
	}
	workFlowDB := map[string]structs.WorkFlowEntity{
		"Product01": {
			RootType: true,
			PocsName: []string{"product01"},
		},
	}

	got, count := GetPocs(resultMap, workFlowDB, false, true)
	if count != 0 {
		t.Fatalf("expected no workflow applications for many fingerprints, got %d", count)
	}
	if len(got) != 0 {
		t.Fatalf("expected no poc mapping for many fingerprints, got %#v", got)
	}
}

func TestGetPocsAllowsManyFingerprintsWhenDisabled(t *testing.T) {
	resultMap := map[string][]string{
		"http://example.com": {
			"Product01", "Product02", "Product03", "Product04", "Product05", "Product06",
			"Product07", "Product08", "Product09", "Product10", "Product11",
		},
	}
	workFlowDB := map[string]structs.WorkFlowEntity{
		"Product01": {
			RootType: true,
			PocsName: []string{"product01"},
		},
	}

	got, count := GetPocs(resultMap, workFlowDB, false, false)
	if count != 1 {
		t.Fatalf("expected workflow application when skip disabled, got %d", count)
	}
	expect := map[string][]string{
		"http://example.com": {"product01.yaml"},
	}
	if !reflect.DeepEqual(got, expect) {
		t.Fatalf("unexpected mapping:\nwant=%#v\ngot=%#v", expect, got)
	}
}
