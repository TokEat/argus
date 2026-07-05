package ddfinger

import "testing"

func TestParseRuleMalformedExpressionsDoNotPanic(t *testing.T) {
	cases := []string{
		`="dangling-key"`,
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
