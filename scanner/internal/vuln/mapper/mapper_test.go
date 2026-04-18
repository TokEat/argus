package mapper

import (
	"dddd/scanner/structs"
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

	got, count := GetPocs(resultMap, workFlowDB, false)
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
		"tcp://127.0.0.1:6379": {"Redis"},
	}

	workFlowDB := map[string]structs.WorkFlowEntity{
		"Redis": {
			RootType: true,
			PocsName: []string{"redis-login"},
		},
		"General-Poc-TCP": {
			RootType: true,
			PocsName: []string{"generic-tcp"},
		},
	}

	got, count := GetPocs(resultMap, workFlowDB, true)
	if count != 1 {
		t.Fatalf("expected 1 workflow application, got %d", count)
	}

	expect := map[string][]string{
		"tcp://127.0.0.1:6379": {"redis-login.yaml"},
	}
	if !reflect.DeepEqual(got, expect) {
		t.Fatalf("unexpected mapping:\nwant=%#v\ngot=%#v", expect, got)
	}
}
