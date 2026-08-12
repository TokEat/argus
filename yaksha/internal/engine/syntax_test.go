package engine

import (
	"fmt"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/yaksha/internal/protocol"
)

func TestYaklangSyntaxCompatibility(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   string
	}{
		{
			name:   "operator precedence and booleans",
			script: `yaksha.result((1 + 2 * 3 == 7) && !false)`,
			want:   "true",
		},
		{
			name: "range break continue and switch",
			script: `
items = [1, 2, 3, 4, 5]
sum = 0
for _, value := range items {
    if value == 2 { continue }
    if value == 5 { break }
    sum += value
}
switch sum {
case 8:
    yaksha.result("matched")
default:
    yaksha.result("unexpected:" + yaksha.toString(sum))
}`,
			want: "matched",
		},
		{
			name: "maps arrays negative index and template string",
			script: `
meta = {"name": "yaksha", "ports": [80, 443]}
meta.ports.Push(8080)
yaksha.result(f"${meta.name}:${meta.ports[-1]}")`,
			want: "yaksha:8080",
		},
		{
			name: "typed literals and unicode",
			script: `
ports = []int{80, 443}
labels = map[string]string{"name": "夜叉"}
yaksha.result(labels["name"] + ":" + yaksha.toString(ports[1]))`,
			want: "夜叉:443",
		},
		{
			name: "recursive function",
			script: `
factorial = func(n) {
    if n <= 1 { return 1 }
    return n * factorial(n - 1)
}
yaksha.result(factorial(6))`,
			want: "720",
		},
		{
			name:   "arrow function",
			script: `twice := (value) => { return value * 2 }; yaksha.result(twice(21))`,
			want:   "42",
		},
		{
			name: "try catch finally",
			script: `
value = 0
try {
    panic("expected")
} catch err {
    value = 1
} finally {
    value += 1
}
yaksha.result(value)`,
			want: "2",
		},
		{
			name: "unicode string iteration",
			script: `
text = "夜叉yak"
value = ""
for _, char := range text { value += char }
yaksha.result(value)`,
			want: "夜叉yak",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := execScript(t, tc.script, 5_000)
			if resp.Status != protocol.StatusSucceeded {
				t.Fatalf("status=%s error=%s", resp.Status, resp.Error)
			}
			if got := fmt.Sprint(resp.Result); got != tc.want {
				t.Fatalf("result=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestYaklangParserAndRuntimeFailures(t *testing.T) {
	tests := []struct {
		name     string
		script   string
		wantErr  string
		wantCode string
	}{
		{name: "syntax error", script: `if true {`, wantCode: "syntax_error"},
		{name: "upstream importmod parser gap", script: `importmod os`, wantCode: "syntax_error"},
		{name: "reserved type keyword as variable", script: `double = 1`, wantErr: "invalid left expression"},
		{name: "undefined call", script: `missingFunction()`, wantErr: "undefined variable"},
		{name: "invalid member call", script: `value = 1; value()`, wantErr: "cannot be called"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := execScript(t, tc.script, 5_000)
			if resp.Status != protocol.StatusFailed {
				t.Fatalf("status=%s, want Failed (error=%s)", resp.Status, resp.Error)
			}
			if tc.wantCode != "" {
				found := false
				if resp.Validation != nil {
					for _, diagnostic := range resp.Validation.Diagnostics {
						if diagnostic.Code == tc.wantCode {
							found = true
							break
						}
					}
				}
				if !found {
					t.Fatalf("validation=%#v, want diagnostic %q", resp.Validation, tc.wantCode)
				}
			} else if !strings.Contains(resp.Error, tc.wantErr) {
				t.Fatalf("error=%q, want substring %q", resp.Error, tc.wantErr)
			}
		})
	}
}
