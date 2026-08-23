package engine

import (
	"reflect"
	"testing"
)

// A：CDN 域名补偿探测端口必须跟随任务配置的扫描端口（与 IP 端口扫描同源）。
func TestBuildCDNProbeURLsFollowsConfiguredPorts(t *testing.T) {
	cfg := Config{Ports: "80,443"}
	got := buildCDNProbeURLs(cfg, []string{"cdn.example.test"})
	want := []string{"http://cdn.example.test:80", "https://cdn.example.test:443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CDN 补偿探测 URLs = %#v, want %#v", got, want)
	}
}

func TestBuildCDNProbeURLsExpandsRangesLikePortScanner(t *testing.T) {
	cfg := Config{Ports: "8000-8001,8080"}
	got := buildCDNProbeURLs(cfg, []string{"cdn.example.test"})
	want := []string{
		"http://cdn.example.test:8000",
		"http://cdn.example.test:8001",
		"http://cdn.example.test:8080",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("区间展开 URLs = %#v, want %#v", got, want)
	}
}

func TestBuildCDNProbeURLsEmptyPortsOrDomains(t *testing.T) {
	if got := buildCDNProbeURLs(Config{Ports: ""}, []string{"cdn.example.test"}); got != nil {
		t.Fatalf("空端口配置应返回空，got %#v", got)
	}
	if got := buildCDNProbeURLs(Config{Ports: "80"}, []string{" ", ""}); got != nil {
		t.Fatalf("空域名列表应返回空，got %#v", got)
	}
}

func TestBuildCDNProbeURLsSkipsBlankDomainsAndDedupesPorts(t *testing.T) {
	cfg := Config{Ports: "8080,8080"}
	got := buildCDNProbeURLs(cfg, []string{" a.example.test ", "", "b.example.test"})
	want := []string{"http://a.example.test:8080", "http://b.example.test:8080"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("多域名探测 URLs = %#v, want %#v", got, want)
	}
}

func TestCDNHostSetLowercasesHostnames(t *testing.T) {
	hosts := cdnHostSet([]string{"CDN.Example.Test", " ", "edge.test"})
	if _, ok := hosts["cdn.example.test"]; !ok {
		t.Fatalf("host set = %#v", hosts)
	}
	if _, ok := hosts["edge.test"]; !ok {
		t.Fatalf("host set = %#v", hosts)
	}
	if len(hosts) != 2 {
		t.Fatalf("host set 应去重空白项，got %#v", hosts)
	}
	if cdnHostSet(nil) != nil {
		t.Fatal("空输入应返回 nil")
	}
}
