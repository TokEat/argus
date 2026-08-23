package engine

import (
	"reflect"
	"testing"
)

// A：CDN 域名补偿探测端口必须跟随任务配置的扫描端口（与 IP 端口扫描同源）。
func TestBuildDomainProbeURLsFollowsConfiguredPorts(t *testing.T) {
	cfg := Config{Ports: "80,443"}
	got := buildDomainProbeURLs(cfg, []string{"cdn.example.test"})
	want := []string{"http://cdn.example.test:80", "https://cdn.example.test:443"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("域名补偿探测 URLs = %#v, want %#v", got, want)
	}
}

func TestBuildDomainProbeURLsExpandsRangesLikePortScanner(t *testing.T) {
	cfg := Config{Ports: "8000-8001,8080"}
	got := buildDomainProbeURLs(cfg, []string{"cdn.example.test"})
	want := []string{
		"http://cdn.example.test:8000",
		"http://cdn.example.test:8001",
		"http://cdn.example.test:8080",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("区间展开 URLs = %#v, want %#v", got, want)
	}
}

func TestBuildDomainProbeURLsEmptyPortsOrDomains(t *testing.T) {
	if got := buildDomainProbeURLs(Config{Ports: ""}, []string{"cdn.example.test"}); got != nil {
		t.Fatalf("空端口配置应返回空，got %#v", got)
	}
	if got := buildDomainProbeURLs(Config{Ports: "80"}, []string{" ", ""}); got != nil {
		t.Fatalf("空域名列表应返回空，got %#v", got)
	}
}

func TestBuildDomainProbeURLsSkipsBlankDomainsAndDedupesPorts(t *testing.T) {
	cfg := Config{Ports: "8080,8080"}
	got := buildDomainProbeURLs(cfg, []string{" a.example.test ", "", "b.example.test"})
	want := []string{"http://a.example.test:8080", "http://b.example.test:8080"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("多域名探测 URLs = %#v, want %#v", got, want)
	}
}

// 修复「允许解析到内网」反转：默认跳过私网/回环解析 IP，开启后才纳入。
func TestFilterDomainIPsRespectsLocalAreaSwitch(t *testing.T) {
	ips := []string{"203.0.113.10", "192.168.1.5", "127.0.0.1"}

	got := filterDomainIPs(ips, Config{})
	want := []string{"203.0.113.10"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("默认必须跳过私网/回环 IP，got %#v want %#v", got, want)
	}

	got = filterDomainIPs(ips, Config{AllowLocalAreaDomain: true})
	if !reflect.DeepEqual(got, ips) {
		t.Fatalf("开启允许解析到内网后应全部纳入，got %#v", got)
	}
}

// 新开关：NoResolvedIPScan 时域名解析 IP 完全不进入存活探测/端口扫描。
func TestFilterDomainIPsSkipsAllWhenResolvedIPScanDisabled(t *testing.T) {
	ips := []string{"203.0.113.10", "192.168.1.5"}
	if got := filterDomainIPs(ips, Config{NoResolvedIPScan: true}); got != nil {
		t.Fatalf("NoResolvedIPScan 必须丢弃全部解析 IP，got %#v", got)
	}
	if got := filterDomainIPs(ips, Config{NoResolvedIPScan: true, AllowLocalAreaDomain: true}); got != nil {
		t.Fatalf("NoResolvedIPScan 优先于 AllowLocalAreaDomain，got %#v", got)
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
