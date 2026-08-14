package engine

import (
	"reflect"
	"sort"
	"testing"
)

func TestBuildDirProbeURLsSkipsMalformedInputsAndDeduplicates(t *testing.T) {
	got := buildDirProbeURLs(
		[]string{"https://example.test/", "https://example.test", ""},
		map[string][]string{
			"":                             {"Empty"},
			"relative":                     {"Relative"},
			"//untrusted.example/path":     {"SchemeRelative"},
			"/manager/html":                {"Tomcat"},
			" /actuator/health?full=true ": {"Spring"},
		},
	)
	want := []string{
		"https://example.test/manager/html",
		"https://example.test/actuator/health?full=true",
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("probe URLs = %v, want %v", got, want)
	}
}
