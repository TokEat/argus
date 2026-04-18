package portscan

import (
	"reflect"
	"sort"
	"testing"
)

func TestRemoveFirewall(t *testing.T) {
	got := RemoveFirewall([]string{
		"10.0.0.1:80",
		"10.0.0.1:443",
		"10.0.0.2:22",
		"10.0.0.2:22",
	}, 2)
	sort.Strings(got)

	want := []string{"10.0.0.2:22"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected firewall filtering: want=%v got=%v", want, got)
	}
}
