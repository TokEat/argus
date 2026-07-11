package ddfinger

import (
	"os"
	"path/filepath"
	"testing"

	"dddd/scanner/structs"
	"gopkg.in/yaml.v3"
)

func TestParseRuleMalformedExpressionsDoNotPanic(t *testing.T) {
	cases := []string{
		`="dangling-key"`,
		`=="dangling-key"`,
		`body="unterminated`,
		`body="`,
		`body="value" && = "bad"`,
	}
	for _, rule := range cases {
		t.Run(rule, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("ParseRule panicked for %q: %v", rule, r)
				}
			}()
			_ = ParseRule(rule)
		})
	}
}

func TestParseRuleEmptyStringValue(t *testing.T) {
	rules := ParseRule(`path="/__bes/__ejb" && status="200" && body==""`)
	if len(rules) != 3 {
		t.Fatalf("expected 3 parsed rules, got %d", len(rules))
	}
	if rules[2].Key != "body" {
		t.Fatalf("expected body rule, got %q", rules[2].Key)
	}
	if rules[2].Value != "" {
		t.Fatalf("expected empty body value, got %q", rules[2].Value)
	}
	if rules[2].Op != 2 {
		t.Fatalf("expected equality op, got %d", rules[2].Op)
	}
}

func TestDataCheckIntTreatsDoubleEqualsAsEquality(t *testing.T) {
	if !dataCheckInt(2, 588710312, 588710312) {
		t.Fatal("expected op=2 to match equal integer values")
	}
	if dataCheckInt(2, 588710312, 1) {
		t.Fatal("expected op=2 to reject different integer values")
	}
}

func TestParaviewPASGRedirectFingerprintRuleMatches(t *testing.T) {
	rules := loadFingerprintRules(t, "派拉身份认证IAM(西部)")
	header := "HTTP/1.1 302 Found\r\nx-powered-by: PASG\r\nLocation: /selfcare/\r\n"
	body := `<p></p><p>PASG Redirecting to <a href="/selfcare/">/selfcare/</a></p>`

	for _, rule := range rules {
		finger := structs.FingerPEntity{
			ProductName: "派拉身份认证IAM(西部)",
			AllString:   rule,
			Rule:        ParseRule(rule),
		}
		if SingleCheck(finger, "https", header, body, "", "", "", 999, "/", "", "", 302, "text/html", "") {
			return
		}
	}

	t.Fatalf("expected 派拉身份认证IAM(西部) to match PASG 302 redirect, rules=%v", rules)
}

func TestKingdeeK3CloudDoesNotMatchReflectedProbePath(t *testing.T) {
	rules := loadFingerprintRules(t, "金蝶云星空")
	body := `<html><title>400 Bad Request</title>URL: http://example.test/k3cloud</html>`

	for _, rule := range rules {
		finger := structs.FingerPEntity{
			ProductName: "金蝶云星空",
			AllString:   rule,
			Rule:        ParseRule(rule),
		}
		if SingleCheck(finger, "http", "Server: nginx\r\n", body, "nginx", "400 Bad Request", "", 80, "/k3cloud", "", "", 400, "text/html", "") {
			t.Fatalf("reflected probe path matched 金蝶云星空 rule %q", rule)
		}
	}
}

func TestKingdeeK3CloudMatchesStrongLoginAsset(t *testing.T) {
	rules := loadFingerprintRules(t, "金蝶云星空")
	body := `<html><title>金蝶云星空</title><link href="./k3cloud/HTML5/content/themes/kd.ui.login.css"></html>`

	for _, rule := range rules {
		finger := structs.FingerPEntity{
			ProductName: "金蝶云星空",
			AllString:   rule,
			Rule:        ParseRule(rule),
		}
		if SingleCheck(finger, "http", "Server: Microsoft-IIS/10.0\r\n", body, "Microsoft-IIS/10.0", "金蝶云星空", "", 80, "/k3cloud", "", "", 200, "text/html", "") {
			return
		}
	}

	t.Fatalf("expected 金蝶云星空 strong login response to match, rules=%v", rules)
}

func TestKingdeeK3CloudMatchesIconHash(t *testing.T) {
	rules := loadFingerprintRules(t, "金蝶云星空")
	for _, rule := range rules {
		finger := structs.FingerPEntity{
			ProductName: "金蝶云星空",
			AllString:   rule,
			Rule:        ParseRule(rule),
		}
		if SingleCheck(finger, "http", "", "", "", "", "", 80, "/", "", "-1629133697", 200, "text/html", "") {
			return
		}
	}
	t.Fatalf("expected 金蝶云星空 icon hash to match, rules=%v", rules)
}

func TestKingdeeK3CloudKeepsActiveProbePath(t *testing.T) {
	path := filepath.Join("..", "..", "common", "config", "dir.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var probes map[string][]string
	if err := yaml.Unmarshal(data, &probes); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, probe := range probes["金蝶云星空"] {
		if probe == "/k3cloud" {
			return
		}
	}
	t.Fatalf("expected 金蝶云星空 active probe /k3cloud, got %v", probes["金蝶云星空"])
}

func loadFingerprintRules(t *testing.T, product string) []string {
	t.Helper()

	path := filepath.Join("..", "..", "common", "config", "finger.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var fingerprints map[string][]string
	if err := yaml.Unmarshal(data, &fingerprints); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	rules, ok := fingerprints[product]
	if !ok {
		t.Fatalf("product %q not found in %s", product, path)
	}
	if len(rules) == 0 {
		t.Fatalf("product %q has no rules in %s", product, path)
	}
	return rules
}
