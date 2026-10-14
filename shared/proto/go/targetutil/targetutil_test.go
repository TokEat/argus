package targetutil

import "testing"

func TestNormalizeTargetWithPath(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"url with path and query", "https://h/app1/x?y=1", "https://h:443/app1"},
		{"url with nested path", "http://h:8080/app1/login", "http://h:8080/app1"},
		{"root path behaves like NormalizeTarget", "http://h:8080/", "http://h:8080"},
		{"empty path behaves like NormalizeTarget", "http://h:8080", "http://h:8080"},
		{"uppercase segment lowered", "http://h/Admin", "http://h:80/admin"},
		{"leading slash no host", "/app1/x", "/app1/x"},
		{"empty", "", ""},
		{"unknown", "unknown", "unknown"},
		{"no scheme host:port/path unchanged", "host:8080/app1", "host:8080/app1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NormalizeTargetWithPath(c.raw); got != c.want {
				t.Fatalf("NormalizeTargetWithPath(%q) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

func TestNormalizeTargetStripsPathUnchanged(t *testing.T) {
	// 契约确认：NormalizeTarget 必须继续剥路径（lineage 依赖），路径场景走 WithPath。
	if got := NormalizeTarget("https://h/app1/x"); got != "https://h:443" {
		t.Fatalf("NormalizeTarget stripped path contract broken: got %q", got)
	}
}
