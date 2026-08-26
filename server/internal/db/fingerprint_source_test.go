package db

import "testing"

func TestClassifyFingerprintSourceFromEvidence(t *testing.T) {
	cases := []struct {
		name     string
		ruleName string
		evidence string
		want     string
	}{
		{
			name:     "directory probe",
			evidence: `{"type":"Active-Finger","uri":"https://example.test/jenkins/login","finger":["Jenkins"]}`,
			want:     FingerprintSourceDirectory,
		},
		{
			name:     "directory probe from rule name",
			ruleName: "Active-Finger",
			evidence: `{"uri":"https://example.test/druid"}`,
			want:     FingerprintSourceDirectory,
		},
		{
			name:     "dir fallback",
			evidence: `{"type":"Active-Finger","uri":"https://example.test/actuator","am":"[dir-fallback]"}`,
			want:     FingerprintSourceFallback,
		},
		{
			name:     "behavior probe",
			ruleName: "behavior-probe",
			evidence: `{"type":"Active-Finger","uri":"http://127.0.0.1:8081","additional_msg":"[behavior-probe:shiro-detect]"}`,
			want:     FingerprintSourceBehavior,
		},
		{
			name:     "passive fingerprint",
			evidence: `{"type":"Finger","uri":"https://example.test/","finger":["nginx"]}`,
			want:     FingerprintSourcePassive,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyFingerprintSource(tc.ruleName, tc.evidence); got != tc.want {
				t.Fatalf("ClassifyFingerprintSource() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFingerprintMatchedURLPrefersEvidenceURI(t *testing.T) {
	got := FingerprintMatchedURL("https://example.test:443", `{"type":"Active-Finger","uri":"https://example.test/jenkins/login"}`)
	if got != "https://example.test/jenkins/login" {
		t.Fatalf("matched url = %q", got)
	}
}

func TestFingerprintRuleNameFromPayload(t *testing.T) {
	if got := fingerprintRuleName("Active-Finger", map[string]interface{}{"am": "[dir-fallback]"}); got != "dir-fallback" {
		t.Fatalf("dir-fallback rule name = %q", got)
	}
	if got := fingerprintRuleName("Active-Finger", map[string]interface{}{"additional_msg": "[behavior-probe:shiro-detect]"}); got != "behavior-probe" {
		t.Fatalf("behavior probe rule name = %q", got)
	}
	if got := fingerprintRuleName("Active-Finger", map[string]interface{}{}); got != "Active-Finger" {
		t.Fatalf("directory probe rule name = %q", got)
	}
}

func TestUniqueFingerprintSourcesKeepsDisplayOrder(t *testing.T) {
	got := UniqueFingerprintSources([]string{"passive", "directory", "passive", "fallback"})
	want := []string{FingerprintSourceDirectory, FingerprintSourceFallback, FingerprintSourcePassive}
	if len(got) != len(want) {
		t.Fatalf("sources = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sources = %#v, want %#v", got, want)
		}
	}
}
