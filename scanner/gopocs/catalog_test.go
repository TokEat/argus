package gopocs

import (
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestPluginCatalogClassifiesEveryRuntimePlugin(t *testing.T) {
	if len(PluginDescriptors) != len(PluginList) {
		t.Fatalf("descriptor count %d != plugin count %d", len(PluginDescriptors), len(PluginList))
	}
	for name := range PluginList {
		descriptor, exists := PluginDescriptors[name]
		if !exists {
			t.Errorf("plugin %q is unclassified", name)
			continue
		}
		switch descriptor.Capability {
		case CapabilityCredential, CapabilityProtocolCheck, CapabilityVulnerabilityCheck:
		default:
			t.Errorf("plugin %q has invalid capability %q", name, descriptor.Capability)
		}
	}
}

func TestCredentialPluginEligibility(t *testing.T) {
	if err := CredentialPluginEligible("SSH-Crack", "ssh", "2222", "protocol"); err != nil {
		t.Fatal(err)
	}
	if err := CredentialPluginEligible("SSH-Crack", "unknown", "22", "standard_port"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ plugin, service, port, eligibility string }{
		{"SSH-Crack", "http", "80", "protocol"},
		{"SSH-Crack", "http", "22", "standard_port"},
		{"SSH-Crack", "smtp", "22", "standard_port"},
		{"SSH-Crack", "unknown", "2222", "standard_port"},
		{"SMB-MS17-010", "smb", "445", "protocol"},
	} {
		if err := CredentialPluginEligible(test.plugin, test.service, test.port, test.eligibility); err == nil {
			t.Fatalf("unexpected eligibility for %+v", test)
		}
	}
}

func TestDispatchCredentialTargetsRejectsHTTPAndNonCredentialPlugins(t *testing.T) {
	for _, target := range []structs.CredentialValidationTarget{
		{Endpoint: "https://example.test", Service: "http", Plugin: "SSH-Crack", Eligibility: "protocol"},
		{Endpoint: "192.0.2.1:445", Service: "smb", Plugin: "SMB-MS17-010", Eligibility: "protocol"},
	} {
		if _, err := DispatchCredentialTargets([]structs.CredentialValidationTarget{target}, nil, 50_000, 1, nil); err == nil {
			t.Fatalf("unexpected credential dispatch acceptance: %+v", target)
		}
	}
}

func TestDispatchCredentialTargetsEnforcesPairLimitAtBoundary(t *testing.T) {
	target := structs.CredentialValidationTarget{
		Endpoint: "192.0.2.1:22", Service: "ssh", Plugin: "SSH-Crack", Eligibility: "protocol",
	}
	if _, err := DispatchCredentialTargets([]structs.CredentialValidationTarget{target}, []structs.UserPasswd{{}, {}}, 1, 1, nil); err == nil {
		t.Fatal("oversized credential bundle was accepted")
	}
	if _, err := DispatchCredentialTargets([]structs.CredentialValidationTarget{target}, nil, 0, 1, nil); err == nil {
		t.Fatal("zero credential pair limit was accepted")
	}
}

func TestIncrementalCredentialPairsAreUnionedWithBuiltInDictionary(t *testing.T) {
	info := &structs.HostInfo{
		UserPassPairs:       []structs.UserPasswd{{UserName: "custom", Password: "incremental"}},
		CredentialPairLimit: 10,
	}
	got := sortUserPassword(info, "root : builtin\n", nil)
	want := map[structs.UserPasswd]bool{
		{UserName: "custom", Password: "incremental"}: true,
		{UserName: "root", Password: "builtin"}:       true,
	}
	for _, pair := range got {
		delete(want, pair)
	}
	if len(want) != 0 {
		t.Fatalf("credential union is missing pairs: %+v; got %+v", want, got)
	}
}

func TestCredentialPairLimitAppliesAfterBuiltInUnion(t *testing.T) {
	info := &structs.HostInfo{
		UserPassPairs:       []structs.UserPasswd{{UserName: "custom", Password: "one"}},
		CredentialPairLimit: 1,
	}
	if got := sortUserPassword(info, "root : builtin\n", nil); len(got) != 1 {
		t.Fatalf("credential pair count = %d, want 1", len(got))
	} else if got[0] != (structs.UserPasswd{UserName: "root", Password: "builtin"}) {
		t.Fatalf("custom credentials displaced built-in defaults: %+v", got)
	}
}
