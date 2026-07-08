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
