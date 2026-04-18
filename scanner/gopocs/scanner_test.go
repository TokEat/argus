package gopocs

import (
	"dddd/scanner/structs"
	"reflect"
	"sort"
	"testing"
)

func TestBuildScanPlan(t *testing.T) {
	plan := buildScanPlan(map[string]string{
		"10.0.0.1:22":   "ssh",
		"10.0.0.2:445":  "smb",
		"10.0.0.3:5555": "tcp",
		"bad":           "ssh",
	}, "custom-pass", "custom-file", nil)

	got := make([]string, 0, len(plan))
	for _, item := range plan {
		got = append(got, item.Name+"@"+item.Info.Host+":"+item.Info.Ports)
	}
	sort.Strings(got)

	want := []string{
		"ADB-Scan@10.0.0.3:5555",
		"NetBios-GetHostInfo@10.0.0.2:445",
		"SSH-Crack@10.0.0.1:22",
		"SMB-MS17-010@10.0.0.2:445",
		"SMB-Crack@10.0.0.2:445",
	}
	sort.Strings(want)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected scan plan:\nwant=%v\ngot=%v", want, got)
	}

	for _, item := range plan {
		if item.Info.Password != "custom-pass" || item.Info.PasswordFile != "custom-file" {
			t.Fatalf("expected credential overrides to be propagated, got %#v", item.Info)
		}
	}
}

func TestGoPocWriteResultAppendsSummary(t *testing.T) {
	original := structs.GoPocsResults
	structs.GoPocsResults = nil
	defer func() {
		structs.GoPocsResults = original
	}()

	result := structs.GoPocsResultType{
		PocName:  "TestPoc",
		Target:   "127.0.0.1:22",
		Security: "HIGH",
	}

	GoPocWriteResult(result)

	if len(structs.GoPocsResults) != 1 {
		t.Fatalf("expected one summary result, got %d", len(structs.GoPocsResults))
	}
	if !reflect.DeepEqual(structs.GoPocsResults[0], result) {
		t.Fatalf("unexpected stored result: want=%#v got=%#v", result, structs.GoPocsResults[0])
	}
}
