package cdn

import (
	"net"
	"testing"
)

func withFakeDNS(t *testing.T, ips map[string][]net.IP, cnames map[string][]string) {
	t.Helper()
	previousLookupIP := lookupIP
	previousLookupCNAME := lookupCNAME
	lookupIP = func(host string) ([]net.IP, error) { return ips[host], nil }
	lookupCNAME = func(domain string) ([]string, error) { return cnames[domain], nil }
	t.Cleanup(func() {
		lookupIP = previousLookupIP
		lookupCNAME = previousLookupCNAME
	})
}

func ipv4(value string) net.IP { return net.ParseIP(value).To4() }

// B 规则：仅保留高置信度关键字判定，多 IP+CNAME 与 IPv6 启发式不再判 CDN。
func TestCheckCDNKeepsKeywordCNAMEClassification(t *testing.T) {
	withFakeDNS(t,
		map[string][]net.IP{"cdn.example.test": {ipv4("203.0.113.10")}},
		map[string][]string{"cdn.example.test": {"example.test.cloudfront.net"}},
	)
	isCDN, name, gotIPs := CheckCDN("cdn.example.test")
	if !isCDN || name == "" || len(gotIPs) != 1 {
		t.Fatalf("已知 CDN 关键字必须命中: isCDN=%v name=%q ips=%v", isCDN, name, gotIPs)
	}
}

func TestCheckCDNMultiIPPlainCNAMENoLongerClassified(t *testing.T) {
	withFakeDNS(t,
		map[string][]net.IP{"gslb.example.test": {ipv4("203.0.113.10"), ipv4("203.0.113.11")}},
		map[string][]string{"gslb.example.test": {"gslb-internal.example.test"}},
	)
	isCDN, _, _ := CheckCDN("gslb.example.test")
	if isCDN {
		t.Fatal("自建负载均衡（多 IP + 普通 CNAME）不得再被判为 CDN，否则会整域跳过漏扫")
	}
}

func TestCheckCDNDualStackNoLongerClassified(t *testing.T) {
	withFakeDNS(t,
		map[string][]net.IP{"dual.example.test": {ipv4("203.0.113.10"), net.ParseIP("2001:db8::1")}},
		nil,
	)
	isCDN, _, gotIPs := CheckCDN("dual.example.test")
	if isCDN {
		t.Fatal("双栈解析（含 IPv6）不得再被判为 CDN")
	}
	if len(gotIPs) != 2 {
		t.Fatalf("解析结果应原样返回，got %v", gotIPs)
	}
}

func TestCheckCDNExactIPIsStillHighConfidence(t *testing.T) {
	withFakeDNS(t,
		map[string][]net.IP{"special.example.test": {ipv4("223.4.77.85")}},
		nil,
	)
	isCDN, _, _ := CheckCDN("special.example.test")
	if !isCDN {
		t.Fatal("命中 ipItems 精确 IP 的判定必须保留")
	}
}

func TestCheckCDNCNAMESubstringKeywords(t *testing.T) {
	withFakeDNS(t,
		map[string][]net.IP{
			"a.example.test": {ipv4("203.0.113.1")},
			"b.example.test": {ipv4("203.0.113.2")},
		},
		map[string][]string{
			"a.example.test": {"gslb-internal.corp.example.test"},
			"b.example.test": {"waf-gateway.vendor.test"},
		},
	)
	// "a.example.test" 的 CNAME 不含任何关键字 → 非 CDN
	if isCDN, _, _ := CheckCDN("a.example.test"); isCDN {
		t.Fatal("普通 CNAME 不应命中")
	}
	// 含 waf 关键字 → CDN
	if isCDN, _, _ := CheckCDN("b.example.test"); !isCDN {
		t.Fatal("waf 关键字应命中")
	}
}

func TestCheckCDNsSplitsDomainsAndMapsNonCDNIPs(t *testing.T) {
	mapping := map[string][]string{}
	withFakeDNS(t,
		map[string][]net.IP{
			"plain.example.test": {ipv4("203.0.113.20")},
			"edge.example.test":  {ipv4("203.0.113.30"), ipv4("203.0.113.31")},
		},
		map[string][]string{"edge.example.test": {"edge.example.cdnvendor.net"}},
	)
	cdnDomains, normalDomains, ips := CheckCDNs(
		[]string{"plain.example.test", "edge.example.test"},
		4, mapping, nil, nil,
	)
	if len(cdnDomains) != 1 || cdnDomains[0] != "edge.example.test" {
		t.Fatalf("CDN 域名集合 = %v", cdnDomains)
	}
	if len(normalDomains) != 1 || normalDomains[0] != "plain.example.test" {
		t.Fatalf("非 CDN 域名集合 = %v", normalDomains)
	}
	if len(ips) != 1 || ips[0] != "203.0.113.20" {
		t.Fatalf("CDN 域名的解析 IP 不得进入端口扫描列表，got %v", ips)
	}
	if len(mapping["203.0.113.20"]) != 1 || mapping["203.0.113.20"][0] != "plain.example.test" {
		t.Fatalf("非 CDN 域名需写入 IP→域名映射，got %v", mapping)
	}
	if _, exists := mapping["203.0.113.30"]; exists {
		t.Fatal("CDN 域名不得建立 IP→域名映射")
	}
}
