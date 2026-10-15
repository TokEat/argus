package db

import "testing"

// TestCDNDomainNeverRoutesToVulnerability 锁死结果路由契约：
// CDN-Domain 只能进入 assets 表，永远不允许写入 vulnerabilities 表，
// 因此漏洞列表（GET /vulns）不会出现任何 CDN 记录。
func TestCDNDomainNeverRoutesToVulnerability(t *testing.T) {
	if !isAssetPayloadType("CDN-Domain") {
		t.Fatal("CDN-Domain 必须路由到资产表")
	}
	if isVulnerabilityPayloadType("CDN-Domain") {
		t.Fatal("CDN-Domain 不允许路由到漏洞表")
	}
}

// TestPayloadRoutingSetsAreMutuallyExclusive 保证三类结果集合两两互斥，
// 防止未来往任一集合添加类型时意外造成跨表重复或漏洞列表混入资产行。
func TestPayloadRoutingSetsAreMutuallyExclusive(t *testing.T) {
	assertNoOverlap := func(nameA string, a, b map[string]struct{}) {
		for payloadType := range a {
			if _, conflict := b[payloadType]; conflict {
				t.Fatalf("payload type %q 同时出现在 %s 与另一路由集合中", payloadType, nameA)
			}
		}
	}
	assertNoOverlap("asset", assetPayloadTypes, vulnerabilityPayloadTypes)
	assertNoOverlap("asset", assetPayloadTypes, fingerprintPayloadTypes)
	assertNoOverlap("fingerprint", fingerprintPayloadTypes, vulnerabilityPayloadTypes)
	assertNoOverlap("vulnerability", vulnerabilityPayloadTypes, assetPayloadTypes)
	assertNoOverlap("vulnerability", vulnerabilityPayloadTypes, fingerprintPayloadTypes)
}

// TestKnownPayloadTypesRouteExactlyOnce 覆盖历史出现过的全部 Type，
// 确保每个已知类型都命中且仅命中一个路由集合。
func TestKnownPayloadTypesRouteExactlyOnce(t *testing.T) {
	known := []string{
		"asset", "port_scan", "subdomain",
		"Web", "Protocol", "ProtocolCheck", "PortScan", "IPAlive",
		"Domain", "Domain-Bind", "Nmap", "DNS-SubFinder", "DNS-Brute",
		"CDN-Domain", "RealIP", "Quake", "Hunter", "Fofa",
		"fingerprint", "web_fingerprint", "tech", "Finger", "Active-Finger",
		"phase",
		"nuclei", "gopoc", "GoPoc", "Nuclei", "vulnerability",
	}
	for _, payloadType := range known {
		routes := 0
		if isAssetPayloadType(payloadType) {
			routes++
		}
		if isFingerprintPayloadType(payloadType) {
			routes++
		}
		if isVulnerabilityPayloadType(payloadType) {
			routes++
		}
		if payloadType == "phase" {
			if routes != 0 {
				t.Fatalf("phase 不应入任何结果表，实际路由数=%d", routes)
			}
			continue
		}
		if routes != 1 {
			t.Fatalf("payload type %q 路由数=%d，必须恰好为 1", payloadType, routes)
		}
	}
}

// TestCDNTagOnlyAffectsAssetRow 验证 tag=cdn 仅作为资产字段来源存在：
// 漏洞准入函数与 tag 无关，携带任意 tag 的漏洞类 Type 仍只走漏洞表，
// 资产类 Type 仍只走资产表。
func TestCDNTagOnlyAffectsAssetRow(t *testing.T) {
	if !isVulnerabilityPayloadType("Nuclei") || isAssetPayloadType("Nuclei") {
		t.Fatal("Nuclei 的路由不得受 tag 影响")
	}
	if !isAssetPayloadType("Web") || isVulnerabilityPayloadType("Web") {
		t.Fatal("Web 的路由不得受 tag 影响")
	}
}
