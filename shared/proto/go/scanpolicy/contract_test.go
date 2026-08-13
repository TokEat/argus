package scanpolicy

import (
	"strings"
	"testing"
)

func TestPresetPolicies(t *testing.T) {
	tests := []struct {
		preset Preset
		ports  PortProfile
		poc    bool
	}{
		{PresetQuick, PortProfileCommon100, false},
		{PresetStandard, PortProfileTop1000, true},
		{PresetDeep, PortProfileAll, true},
	}
	for _, test := range tests {
		policy, err := PresetPolicy(test.preset)
		if err != nil {
			t.Fatalf("PresetPolicy(%s): %v", test.preset, err)
		}
		policy.Authorization.ValidationConfirmed = policy.Capabilities.RiskValidation
		normalized, err := Normalize(policy)
		if err != nil {
			t.Fatalf("Normalize(%s): %v", test.preset, err)
		}
		if normalized.PortProfile != test.ports || normalized.Capabilities.RiskValidation != test.poc {
			t.Fatalf("unexpected %s policy: %+v", test.preset, normalized)
		}
		if normalized.Capabilities.CredentialValidation {
			t.Fatalf("credential validation must default off for %s", test.preset)
		}
	}
}

func TestPresetOverrideRequiresCustom(t *testing.T) {
	policy, _ := PresetPolicy(PresetQuick)
	policy.PortProfile = PortProfileAll
	if _, err := Normalize(policy); err == nil || !strings.Contains(err.Error(), "preset=custom") {
		t.Fatalf("expected preset override rejection, got %v", err)
	}
}

func TestCredentialValidationCanBeEnabledOnEveryPreset(t *testing.T) {
	for _, preset := range []Preset{PresetQuick, PresetStandard, PresetDeep} {
		policy, _ := PresetPolicy(preset)
		policy.Capabilities.CredentialValidation = true
		policy.Authorization.ValidationConfirmed = true
		normalized, err := Normalize(policy)
		if err != nil {
			t.Fatalf("enable credential validation on %s: %v", preset, err)
		}
		if !normalized.Capabilities.CredentialValidation {
			t.Fatalf("credential validation was lost for %s", preset)
		}
	}
}

func TestCustomPolicyValidationAndStableHash(t *testing.T) {
	policy := Policy{
		SchemaVersion: SchemaVersion,
		Preset:        PresetCustom, PortProfile: PortProfileCustom,
		CustomPorts: "443,80,80,81-82", ScanMethod: ScanMethodSYN, Intensity: IntensityBalanced,
		Capabilities: Capabilities{RiskValidation: true, CredentialValidation: true},
		Selector:     Selector{Match: map[string][]string{"region": {"b", "a", "a"}}},
		Credentials: CredentialPolicy{
			PairLimit:     50000,
			UsernameBooks: []DictionaryRef{{ID: "users", Revision: 2, SHA256: strings.Repeat("a", 64), Count: 2}},
			PasswordBooks: []DictionaryRef{{ID: "passwords", Revision: 3, SHA256: strings.Repeat("b", 64), Count: 3}},
		},
		Authorization: Authorization{ValidationConfirmed: true},
	}
	normalized, err := Normalize(policy)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.CustomPorts != "80,81,82,443" {
		t.Fatalf("custom ports = %q", normalized.CustomPorts)
	}
	first, err := Hash(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.Selector.Match["region"] = []string{"a", "b"}
	second, err := Hash(policy)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("semantic-equivalent policies hashed differently: %s != %s", first, second)
	}
}

func TestValidationRequiresOneAuthorization(t *testing.T) {
	policy, _ := PresetPolicy(PresetStandard)
	if _, err := Normalize(policy); err == nil || !strings.Contains(err.Error(), "authorization") {
		t.Fatalf("expected authorization failure, got %v", err)
	}
}

func TestCredentialDictionaryRequiresCredentialValidation(t *testing.T) {
	policy := Policy{
		SchemaVersion: SchemaVersion, Preset: PresetCustom,
		PortProfile: PortProfileCommon100, ScanMethod: ScanMethodTCP, Intensity: IntensityLow,
		Credentials: CredentialPolicy{PairLimit: 1, UsernameBooks: []DictionaryRef{{ID: "users", Revision: 1, SHA256: strings.Repeat("a", 64)}}},
	}
	if _, err := Normalize(policy); err == nil || !strings.Contains(err.Error(), "require credential validation") {
		t.Fatalf("expected dictionary capability rejection, got %v", err)
	}
}

func TestDictionaryReferencesAreCanonicalizedBeforeHashing(t *testing.T) {
	base := Policy{
		SchemaVersion: SchemaVersion, Preset: PresetCustom,
		PortProfile: PortProfileCommon100, ScanMethod: ScanMethodTCP, Intensity: IntensityLow,
		Capabilities: Capabilities{CredentialValidation: true},
		Credentials: CredentialPolicy{
			PairLimit:     10,
			UsernameBooks: []DictionaryRef{{ID: " users ", Revision: 2, SHA256: strings.Repeat("A", 64), Count: 3}},
		},
		Authorization: Authorization{ValidationConfirmed: true},
	}
	normalized, err := Normalize(base)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Credentials.UsernameBooks[0].ID != "users" || normalized.Credentials.UsernameBooks[0].SHA256 != strings.Repeat("a", 64) {
		t.Fatalf("dictionary reference was not canonicalized: %+v", normalized.Credentials.UsernameBooks[0])
	}
	first, err := Hash(base)
	if err != nil {
		t.Fatal(err)
	}
	if base.Credentials.UsernameBooks[0].ID != " users " || base.Credentials.UsernameBooks[0].SHA256 != strings.Repeat("A", 64) {
		t.Fatalf("Normalize mutated caller-owned dictionary references: %+v", base.Credentials.UsernameBooks[0])
	}
	base.Credentials.UsernameBooks[0].ID = "users"
	base.Credentials.UsernameBooks[0].SHA256 = strings.Repeat("a", 64)
	second, err := Hash(base)
	if err != nil || first != second {
		t.Fatalf("equivalent dictionary references hashed differently: %q != %q err=%v", first, second, err)
	}
}

func TestNormalizePortsRejectsInvalidRanges(t *testing.T) {
	for _, value := range []string{"", "0", "65536", "100-1", "1-2-3", "80junk"} {
		if _, err := NormalizePorts(value); err == nil {
			t.Fatalf("NormalizePorts(%q) succeeded", value)
		}
	}
}

func TestNamedPortProfilesHaveExactCardinality(t *testing.T) {
	if got := PortCount(Common100Ports); got != 100 {
		t.Fatalf("common port count = %d", got)
	}
	if got := PortCount(Top1000TCPPorts); got != 1000 {
		t.Fatalf("top port count = %d", got)
	}
	if got := PortCount("1-65535"); got != 65535 {
		t.Fatalf("all port count = %d", got)
	}
}
