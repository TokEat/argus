package subdomainpassive

import (
	"slices"
	"testing"
)

func TestApexDomainUsesRegistrableRoot(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"harbor-arm.uhomecp.com", "uhomecp.com"},
		{"UHOMEcp.com", "uhomecp.com"},
		{"jslgroup.cn", "jslgroup.cn"},
		{"www.jslgroup.cn", "jslgroup.cn"},
		{"www.example.co.uk", "example.co.uk"},
		{"foo.github.io", "foo.github.io"},
		{"www.example.test", "example.test"},
		{"example.test", "example.test"},
		{"harbor-arm.uhomecp.com:443", "uhomecp.com"},
		{"127.0.0.1", ""},
		{"", ""},
		{"localhost", ""},
	}
	for _, tc := range cases {
		if got := ApexDomain(tc.in); got != tc.want {
			t.Errorf("ApexDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCollectionDomainsDedupsSharedApex(t *testing.T) {
	got := CollectionDomains([]string{
		"harbor-arm.uhomecp.com",
		"api.uhomecp.com",
		"jslgroup.cn",
		"www.jslgroup.cn",
		"61.155.21.117",
	})
	want := []string{"uhomecp.com", "jslgroup.cn"}
	if !slices.Equal(got, want) {
		t.Fatalf("CollectionDomains = %v, want %v", got, want)
	}
}

func TestDropInputHostsRemovesOriginalFQDNs(t *testing.T) {
	got := DropInputHosts(map[string][]string{
		"uhomecp.com": {
			"harbor-arm.uhomecp.com",
			"www.uhomecp.com",
			"api.uhomecp.com",
		},
		"jslgroup.cn": {"www.jslgroup.cn", "jslgroup.cn"},
	}, []string{"harbor-arm.uhomecp.com", "jslgroup.cn"})
	if !slices.Equal(got["uhomecp.com"], []string{"www.uhomecp.com", "api.uhomecp.com"}) {
		t.Fatalf("uhomecp.com = %v, want new hosts only", got["uhomecp.com"])
	}
	if !slices.Equal(got["jslgroup.cn"], []string{"www.jslgroup.cn"}) {
		t.Fatalf("jslgroup.cn = %v, want www only", got["jslgroup.cn"])
	}
}

func TestDropInputHostsKeepsEmptyApexEntry(t *testing.T) {
	got := DropInputHosts(map[string][]string{
		"example.test": {"www.example.test"},
	}, []string{"www.example.test"})
	hosts, ok := got["example.test"]
	if !ok || len(hosts) != 0 {
		t.Fatalf("apex entry must remain empty after dropping the input, got %v ok=%v", hosts, ok)
	}
}
