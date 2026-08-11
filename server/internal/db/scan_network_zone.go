package db

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"unicode"

	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
)

type scanTargetNetworkClass string

const (
	scanTargetNetworkPublic  scanTargetNetworkClass = "public"
	scanTargetNetworkPrivate scanTargetNetworkClass = "private"
)

var nonPublicNetworkRanges = mustScanNetworkRanges([]string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"100::/64",
	"2001:db8::/32",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
})

var privateDNSNames = []string{
	"localhost",
	".localhost",
	".local",
	".lan",
	".internal",
	".home",
	".home.arpa",
	".test",
	".invalid",
	".example",
	".onion",
}

// scanNetworkZoneForTarget derives a stable reuse boundary from Server-owned
// Agent registration data and the normalized target. Explicitly public IP
// space and unzoned public DNS names share the public zone. Private or
// ambiguous names use the Agent's network_zone label, falling back to an
// Agent-unique zone when the label is absent or invalid.
func scanNetworkZoneForTarget(agentID, nodeTags, target string) string {
	zoneLabel, networkScope := scanAgentNetworkMetadata(nodeTags)
	class := classifyScanTargetNetwork(target, zoneLabel != "", networkScope)
	if class == scanTargetNetworkPublic {
		return scanplan.PublicNetworkZone
	}
	if zoneLabel != "" {
		return "private:" + zoneLabel
	}
	return scanAgentFallbackZone(agentID)
}

func scanAgentNetworkMetadata(raw string) (string, string) {
	var tags map[string]string
	if json.Unmarshal([]byte(strings.TrimSpace(raw)), &tags) != nil {
		return "", ""
	}
	zone := normalizeScanNetworkZoneLabel(tags["network_zone"])
	scope := strings.ToLower(strings.TrimSpace(tags["network_scope"]))
	if scope != "public" && scope != "private" {
		scope = ""
	}
	return zone, scope
}

func normalizeScanNetworkZoneLabel(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.TrimPrefix(raw, "private:")
	raw = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '-'
		}
		return r
	}, raw)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if len(raw) > 180 {
		return "sha256-" + sha256Hex([]byte(raw))
	}
	return raw
}

func scanAgentFallbackZone(agentID string) string {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return "agent:_unknown"
	}
	if len(agentID) > 240 {
		return "agent:sha256-" + sha256Hex([]byte(agentID))
	}
	return "agent:" + agentID
}

func classifyScanTargetNetwork(target string, hasZone bool, networkScope string) scanTargetNetworkClass {
	target = strings.TrimSpace(target)
	if target == "" {
		return scanTargetNetworkPrivate
	}
	if parsed, err := url.Parse(target); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return classifyScanHostNetwork(parsed.Hostname(), hasZone, networkScope)
	}
	if ip := net.ParseIP(target); ip != nil {
		return classifyScanIPNetwork(ip)
	}
	if _, network, err := net.ParseCIDR(target); err == nil {
		if scanCIDRIsPublic(network) {
			return scanTargetNetworkPublic
		}
		return scanTargetNetworkPrivate
	}
	if parts := strings.SplitN(target, "-", 2); len(parts) == 2 {
		start := net.ParseIP(strings.TrimSpace(parts[0]))
		end := net.ParseIP(strings.TrimSpace(parts[1]))
		if start != nil && end != nil {
			if scanIPRangeIsPublic(start, end) {
				return scanTargetNetworkPublic
			}
			return scanTargetNetworkPrivate
		}
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		return classifyScanHostNetwork(host, hasZone, networkScope)
	}
	if parts := strings.Split(target, ":"); len(parts) == 2 {
		return classifyScanHostNetwork(parts[0], hasZone, networkScope)
	}
	return classifyScanHostNetwork(target, hasZone, networkScope)
}

func classifyScanHostNetwork(host string, hasZone bool, networkScope string) scanTargetNetworkClass {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return classifyScanIPNetwork(ip)
	}
	if networkScope == "private" || scanPrivateDNSName(host) || !strings.Contains(host, ".") {
		return scanTargetNetworkPrivate
	}
	if networkScope == "public" {
		return scanTargetNetworkPublic
	}
	// A network_zone label means DNS can be split-horizon. Without an explicit
	// public scope, keep such names inside that private reuse boundary.
	if hasZone {
		return scanTargetNetworkPrivate
	}
	return scanTargetNetworkPublic
}

func scanPrivateDNSName(host string) bool {
	for _, suffix := range privateDNSNames {
		if host == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func classifyScanIPNetwork(ip net.IP) scanTargetNetworkClass {
	if scanIPIsPublic(ip) {
		return scanTargetNetworkPublic
	}
	return scanTargetNetworkPrivate
}

func scanIPIsPublic(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, network := range nonPublicNetworkRanges {
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

func scanCIDRIsPublic(network *net.IPNet) bool {
	if network == nil || !scanIPIsPublic(network.IP) {
		return false
	}
	for _, reserved := range nonPublicNetworkRanges {
		if scanNetworksOverlap(network, reserved) {
			return false
		}
	}
	return true
}

func scanNetworksOverlap(left, right *net.IPNet) bool {
	if left == nil || right == nil || (left.IP.To4() == nil) != (right.IP.To4() == nil) {
		return false
	}
	return left.Contains(right.IP) || right.Contains(left.IP)
}

func scanIPRangeIsPublic(start, end net.IP) bool {
	first := start.To4()
	last := end.To4()
	if first == nil || last == nil || !scanIPIsPublic(first) || !scanIPIsPublic(last) {
		return false
	}
	firstValue := binary.BigEndian.Uint32(first)
	lastValue := binary.BigEndian.Uint32(last)
	if lastValue < firstValue {
		return false
	}
	for _, reserved := range nonPublicNetworkRanges {
		reservedIP := reserved.IP.To4()
		if reservedIP == nil {
			continue
		}
		reservedFirst := binary.BigEndian.Uint32(reservedIP)
		reservedLastIP := make(net.IP, net.IPv4len)
		for index := range reservedLastIP {
			reservedLastIP[index] = reservedIP[index] | ^reserved.Mask[index]
		}
		reservedLast := binary.BigEndian.Uint32(reservedLastIP)
		if firstValue <= reservedLast && reservedFirst <= lastValue {
			return false
		}
	}
	return true
}

func mustScanNetworkRanges(raw []string) []*net.IPNet {
	ranges := make([]*net.IPNet, 0, len(raw))
	for _, item := range raw {
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			panic(err)
		}
		ranges = append(ranges, network)
	}
	return ranges
}
