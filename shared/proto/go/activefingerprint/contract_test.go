package activefingerprint

import (
	"strings"
	"testing"
)

const safeShiro = `id: shiro-detect
info:
  name: Detect Apache Shiro
  severity: info
  metadata:
    argus-rule-kind: active-fingerprint
    argus-product: APACHE-Shiro
    argus-behavior-kind: cookie
    argus-auto-profile: controlled
    max-request: 1
http:
  - method: GET
    path: ['{{BaseURL}}']
    headers:
      Cookie: rememberMe={{randstr}}
    matchers:
      - type: word
        part: header
        words: ['rememberMe=deleteMe']
`

func TestInspectComputesSafeProfileWithoutTrustingDeclaration(t *testing.T) {
	classification, err := Inspect("shiro-detect.yaml", []byte(safeShiro))
	if err != nil {
		t.Fatal(err)
	}
	if !classification.AutoEligible || classification.ComputedProfile != AutoProfileSafe || classification.DeclaredProfile != AutoProfileControlled || classification.Product != "APACHE-Shiro" || classification.BehaviorKind != BehaviorKindCookie {
		t.Fatalf("unexpected classification: %#v", classification)
	}
}

func TestInspectRejectsOrdinaryResponseAndPathFingerprints(t *testing.T) {
	ordinary := strings.Replace(safeShiro, "    argus-behavior-kind: cookie\n", "", 1)
	ordinary = strings.Replace(ordinary, "    headers:\n      Cookie: rememberMe={{randstr}}\n", "", 1)
	if _, err := Inspect("ordinary.yaml", []byte(ordinary)); err == nil || !strings.Contains(err.Error(), "argus-behavior-kind is required") {
		t.Fatalf("ordinary response fingerprint was accepted: %v", err)
	}

	pathOnly := strings.Replace(safeShiro, "    argus-behavior-kind: cookie", "    argus-behavior-kind: query", 1)
	pathOnly = strings.Replace(pathOnly, "    path: ['{{BaseURL}}']", "    path: ['{{BaseURL}}/admin/login']", 1)
	pathOnly = strings.Replace(pathOnly, "    headers:\n      Cookie: rememberMe={{randstr}}\n", "", 1)
	if _, err := Inspect("path-only.yaml", []byte(pathOnly)); err == nil || !strings.Contains(err.Error(), "query parameter") {
		t.Fatalf("ordinary path fingerprint was accepted: %v", err)
	}
}

func TestInspectAcceptsDeclaredRandomBehaviorStimuli(t *testing.T) {
	header := strings.Replace(safeShiro, "argus-behavior-kind: cookie", "argus-behavior-kind: header", 1)
	header = strings.Replace(header, "Cookie: rememberMe={{randstr}}", "X-Product-Probe: '{{randstr}}'", 1)
	query := strings.Replace(safeShiro, "argus-behavior-kind: cookie", "argus-behavior-kind: query", 1)
	query = strings.Replace(query, "path: ['{{BaseURL}}']", "path: ['{{BaseURL}}?probe={{randstr}}']", 1)
	query = strings.Replace(query, "    headers:\n      Cookie: rememberMe={{randstr}}\n", "", 1)
	for name, source := range map[string]string{"header": header, "query": query} {
		classification, err := Inspect(name+".yaml", []byte(source))
		if err != nil || !classification.AutoEligible || classification.BehaviorKind != name {
			t.Fatalf("%s behavior stimulus rejected: classification=%#v err=%v", name, classification, err)
		}
	}
}

func TestInspectRequiresRandomValueToBeTransmitted(t *testing.T) {
	cookieNameOnly := strings.Replace(safeShiro, "Cookie: rememberMe={{randstr}}", "Cookie: '{{randstr}}=fixed'", 1)
	if _, err := Inspect("cookie-name.yaml", []byte(cookieNameOnly)); err == nil || !strings.Contains(err.Error(), "Cookie value") {
		t.Fatalf("random cookie name was accepted as a random value: %v", err)
	}

	fragmentOnly := strings.Replace(safeShiro, "argus-behavior-kind: cookie", "argus-behavior-kind: query", 1)
	fragmentOnly = strings.Replace(fragmentOnly, "path: ['{{BaseURL}}']", "path: ['{{BaseURL}}?probe=fixed#{{randstr}}']", 1)
	fragmentOnly = strings.Replace(fragmentOnly, "    headers:\n      Cookie: rememberMe={{randstr}}\n", "", 1)
	if _, err := Inspect("query-fragment.yaml", []byte(fragmentOnly)); err == nil || !strings.Contains(err.Error(), "query parameter") {
		t.Fatalf("URL fragment was accepted as a transmitted query value: %v", err)
	}
}

func TestInspectKeepsFullHTTPYAMLControlled(t *testing.T) {
	controlled := strings.Replace(safeShiro, "method: GET", "method: POST\n    body: change=true", 1)
	classification, err := Inspect("controlled.yaml", []byte(controlled))
	if err != nil {
		t.Fatal(err)
	}
	if classification.AutoEligible || classification.ComputedProfile != AutoProfileControlled || len(classification.Reasons) == 0 {
		t.Fatalf("expected controlled classification: %#v", classification)
	}
}

func TestInspectKeepsRawBehaviorProbeControlled(t *testing.T) {
	raw := strings.Replace(safeShiro, "  - method: GET\n    path: ['{{BaseURL}}']\n    headers:\n      Cookie: rememberMe={{randstr}}", "  - raw:\n      - |\n        GET / HTTP/1.1\n        Host: {{Hostname}}\n        Cookie: rememberMe={{randstr}}", 1)
	classification, err := Inspect("raw-cookie.yaml", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if classification.AutoEligible || classification.ComputedProfile != AutoProfileControlled {
		t.Fatalf("expected raw behavior probe to remain controlled: %#v", classification)
	}
}

func TestInspectTreatsUnknownNucleiCapabilitiesAsControlled(t *testing.T) {
	for name, source := range map[string]string{
		"top-level-flow":    safeShiro + "\nflow: http(1)\n",
		"request-extractor": strings.Replace(safeShiro, "    matchers:", "    extractors: [{type: regex, regex: ['.*']}]\n    matchers:", 1),
	} {
		classification, err := Inspect(name+".yaml", []byte(source))
		if err != nil {
			t.Fatal(err)
		}
		if classification.AutoEligible || len(classification.Reasons) == 0 {
			t.Fatalf("expected %s to require controlled execution: %#v", name, classification)
		}
	}
}

func TestInspectRejectsNonHTTPProtocol(t *testing.T) {
	network := strings.Replace(safeShiro, "http:\n  - method: GET\n    path: ['{{BaseURL}}']\n    headers:\n      Cookie: rememberMe={{randstr}}\n    matchers:\n      - type: word\n        part: header\n        words: ['rememberMe=deleteMe']", "network:\n  - host: ['{{Hostname}}']", 1)
	if _, err := Inspect("network.yaml", []byte(network)); err == nil {
		t.Fatal("expected non-HTTP template rejection")
	}
}

func TestInspectRejectsUnsafeFilenameAndMissingMetadata(t *testing.T) {
	if _, err := Inspect("../shiro.yaml", []byte(safeShiro)); err == nil {
		t.Fatal("expected unsafe filename rejection")
	}
	missingProduct := strings.Replace(safeShiro, "    argus-product: APACHE-Shiro\n", "", 1)
	if _, err := Inspect("missing.yaml", []byte(missingProduct)); err == nil {
		t.Fatal("expected missing product rejection")
	}
	if _, err := Inspect(`..\shiro.yaml`, []byte(safeShiro)); err == nil {
		t.Fatal("expected Windows-style unsafe filename rejection")
	}
	invalidID := strings.Replace(safeShiro, "id: shiro-detect", "id: shiro detect", 1)
	if _, err := Inspect("invalid-id.yaml", []byte(invalidID)); err == nil {
		t.Fatal("expected invalid template id rejection")
	}
}

func TestInspectAutomaticSafetyMatrix(t *testing.T) {
	tests := map[string]string{
		"raw":              strings.Replace(safeShiro, "method: GET", "raw: ['GET / HTTP/1.1']", 1),
		"body":             strings.Replace(safeShiro, "method: GET", "method: GET\n    body: change=true", 1),
		"payload":          strings.Replace(safeShiro, "method: GET", "method: GET\n    payloads: {word: [one]}", 1),
		"oast":             strings.Replace(safeShiro, "{{BaseURL}}", "{{BaseURL}}/{{interactsh-url}}", 1),
		"redirect":         strings.Replace(safeShiro, "method: GET", "method: GET\n    redirects: true", 1),
		"dangerous header": strings.Replace(safeShiro, "Cookie: rememberMe={{randstr}}", "Cookie: rememberMe={{randstr}}\n      Authorization: Bearer test", 1),
		"multiple request": safeShiro + "\nrequests:\n  - method: HEAD\n    path: ['{{BaseURL}}']\n    matchers: [{type: status, status: [200]}]\n",
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			classification, err := Inspect(name+".yaml", []byte(source))
			if err != nil {
				t.Fatal(err)
			}
			if classification.AutoEligible || len(classification.Reasons) == 0 {
				t.Fatalf("expected controlled template: %#v", classification)
			}
		})
	}
}

func TestInspectRejectsAdditionalNonHTTPProtocols(t *testing.T) {
	for _, protocol := range []string{"tcp", "ssl", "websocket", "whois"} {
		t.Run(protocol, func(t *testing.T) {
			source := safeShiro + "\n" + protocol + ":\n  - host: ['{{Hostname}}']\n"
			if _, err := Inspect(protocol+".yaml", []byte(source)); err == nil {
				t.Fatalf("expected %s protocol rejection", protocol)
			}
		})
	}
}

func TestInspectRejectsInvalidRequestBudgetMetadata(t *testing.T) {
	invalid := strings.Replace(safeShiro, "max-request: 1", "max-request: many", 1)
	if _, err := Inspect("invalid-budget.yaml", []byte(invalid)); err == nil {
		t.Fatal("expected invalid max-request metadata rejection")
	}
}
