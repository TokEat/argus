package discovery

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"github.com/projectdiscovery/gologger"
)

const (
	maxTraceHops      = 20
	tracePerNet       = 2
	maxTraceSamples   = 32
	traceUDPBase      = 33434
	traceProbesPerHop = 3
)

// Route is one traceroute from the scanner to dest.
type Route struct {
	Dest string
	Hops []string // empty hop is "*"
}

// HostsFromTraceTargets expands standalone -tr inputs into IPv4 destinations.
// Small CIDRs and ranges are fully expanded; larger ones are sampled in place
// so a /8 does not materialize millions of addresses.
func HostsFromTraceTargets(targets []string) []string {
	var ips []string
	for _, raw := range targets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		switch utils.GetInputType(raw) {
		case structs.TypeIP:
			if usableTraceIP(raw) {
				ips = append(ips, raw)
			}
		case structs.TypeCIDR:
			ips = append(ips, sampleCIDRHosts(raw)...)
		case structs.TypeIPRange:
			ips = append(ips, sampleRangeHosts(raw)...)
		case structs.TypeIPPort:
			if host, _, ok := splitHostPort(raw); ok && usableTraceIP(host) {
				ips = append(ips, host)
			}
		case structs.TypeURL:
			if host := ipv4FromURL(raw); usableTraceIP(host) {
				ips = append(ips, host)
			}
		}
	}
	return Union(ips)
}

// TraceInputHosts prefers discovery hits, then open-port hosts, then a
// small explicit IP list. A leftover large CIDR without hits is not traced.
func TraceInputHosts(confirmed, allIPs, ipPorts []string) []string {
	if len(confirmed) > 0 {
		return Union(confirmed)
	}
	if ports := HostsFromIPPorts(ipPorts); len(ports) > 0 {
		return ports
	}
	if len(allIPs) > 0 && len(allIPs) <= 256 {
		return Union(allIPs)
	}
	return nil
}

// SampleTraceHosts keeps up to perNet addresses in each /24, capped at maxTotal.
func SampleTraceHosts(alive []string, perNet, maxTotal int) []string {
	if perNet <= 0 {
		perNet = 1
	}
	groups := make(map[string][]string)
	var nets []string
	for _, raw := range Union(alive) {
		if !usableTraceIP(raw) {
			continue
		}
		netn := hostNet24(raw)
		if _, seen := groups[netn]; !seen {
			nets = append(nets, netn)
		}
		groups[netn] = append(groups[netn], raw)
	}
	sort.Strings(nets)
	var out []string
	for _, netn := range nets {
		ips := groups[netn]
		sort.Strings(ips)
		take := perNet
		if take > len(ips) {
			take = len(ips)
		}
		out = append(out, ips[:take]...)
		if maxTotal > 0 && len(out) >= maxTotal {
			return out[:maxTotal]
		}
	}
	return out
}

// MapIntranet traceroutes sampled live hosts and emits [Path] plus a
// collapsed [Topo] blueprint. It is not part of host discovery.
func MapIntranet(alive []string, emit func(ddout.OutputMessage)) []Route {
	reps := SampleTraceHosts(alive, tracePerNet, maxTraceSamples)
	if len(reps) == 0 {
		return nil
	}
	gologger.Info().Msgf("内网路径探测：%d 代表 / %d 输入", len(reps), len(alive))
	routes := traceHosts(reps, maxTraceHops, 800*time.Millisecond)
	for _, route := range routes {
		if emit == nil || len(respondingHops(route.Hops)) == 0 {
			continue
		}
		emit(ddout.OutputMessage{
			Type:          "Path",
			IP:            route.Dest,
			IPs:           displayHops(route.Hops),
			AdditionalMsg: fmt.Sprintf("hops=%d", hopCount(route)),
		})
	}
	for _, line := range CollapseBlueprint(routes) {
		if emit == nil {
			continue
		}
		emit(ddout.OutputMessage{Type: "Topo", AdditionalMsg: line})
	}
	return routes
}

// CollapseBlueprint merges destination hosts into /24s and de-duplicates paths.
func CollapseBlueprint(routes []Route) []string {
	seen := make(map[string]struct{})
	var lines []string
	for _, route := range routes {
		if len(respondingHops(route.Hops)) == 0 {
			continue
		}
		hops := make([]string, 0, len(route.Hops))
		for i, hop := range route.Hops {
			if hop == "" {
				hops = append(hops, "*")
				continue
			}
			if i == len(route.Hops)-1 && hop == route.Dest {
				hops = append(hops, hostNet24(route.Dest))
				continue
			}
			hops = append(hops, hop)
		}
		line := strings.Join(hops, " -> ")
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return lines
}

func hopCount(route Route) int {
	for i := len(route.Hops) - 1; i >= 0; i-- {
		if route.Hops[i] == route.Dest {
			return i + 1
		}
	}
	return len(respondingHops(route.Hops))
}

func respondingHops(hops []string) []string {
	var out []string
	for _, hop := range hops {
		if hop != "" {
			out = append(out, hop)
		}
	}
	return out
}

func displayHops(hops []string) []string {
	out := make([]string, len(hops))
	for i, hop := range hops {
		if hop == "" {
			out[i] = "*"
			continue
		}
		out[i] = hop
	}
	return out
}

func hostNet24(raw string) string {
	ip := parseIPv4(raw)
	if ip == nil {
		return raw
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
}

func usableTraceIP(raw string) bool {
	ip := parseIPv4(raw)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	return true
}

func sampleCIDRHosts(raw string) []string {
	_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil || network == nil || network.IP.To4() == nil {
		return nil
	}
	return sampleIPNet(network)
}

func sampleRangeHosts(raw string) []string {
	ips := utils.RangerToIP(raw)
	if len(ips) == 0 {
		return nil
	}
	if len(ips) <= 256 {
		var out []string
		for _, ip := range ips {
			if usableTraceIP(ip.String()) {
				out = append(out, ip.String())
			}
		}
		return out
	}
	return sampleSpreadIPs(ips, maxTraceSamples)
}

func sampleIPNet(network *net.IPNet) []string {
	ip4 := network.IP.To4()
	if ip4 == nil {
		return nil
	}
	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		if usableTraceIP(ip4.String()) {
			return []string{ip4.String()}
		}
		return nil
	}
	if hostBits <= 8 {
		var out []string
		for _, ip := range utils.CIDRToIP(fmt.Sprintf("%s/%d", ip4.String(), ones)) {
			if usableTraceIP(ip.String()) {
				out = append(out, ip.String())
			}
		}
		return out
	}
	total := uint32(1) << uint(hostBits)
	base := ipv4ToUint32(ip4.Mask(network.Mask))
	start, usable := uint32(0), total
	if hostBits > 1 {
		start = 1
		usable = total - 2
	}
	n := maxTraceSamples
	if uint32(n) > usable {
		n = int(usable)
	}
	var out []string
	for i := 0; i < n; i++ {
		off := start
		if n > 1 {
			off = start + uint32(i)*usable/uint32(n)
		}
		addr := uint32ToIPv4(base + off)
		if network.Contains(addr) && usableTraceIP(addr.String()) {
			out = append(out, addr.String())
		}
	}
	return Union(out)
}

func sampleSpreadIPs(ips []net.IP, max int) []string {
	if max <= 0 {
		max = maxTraceSamples
	}
	if len(ips) == 0 {
		return nil
	}
	if len(ips) <= max {
		var out []string
		for _, ip := range ips {
			if usableTraceIP(ip.String()) {
				out = append(out, ip.String())
			}
		}
		return out
	}
	var out []string
	step := float64(len(ips)-1) / float64(max-1)
	for i := 0; i < max; i++ {
		idx := int(float64(i)*step + 0.5)
		if idx >= len(ips) {
			idx = len(ips) - 1
		}
		s := ips[idx].String()
		if usableTraceIP(s) {
			out = append(out, s)
		}
	}
	return Union(out)
}

func ipv4FromURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func ipv4ToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func uint32ToIPv4(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

var traceHosts = traceHostsImpl

func traceHostsImpl(hosts []string, maxHops int, wait time.Duration) []Route {
	if maxHops <= 0 {
		maxHops = maxTraceHops
	}
	if wait <= 0 {
		wait = 1200 * time.Millisecond
	}
	hub, closer, err := startICMPHub()
	if err != nil {
		gologger.Info().Msg("听不到 ICMP Time Exceeded，跳过路径探测（不调用系统 traceroute）")
		return nil
	}
	defer closer()

	var (
		mu     sync.Mutex
		routes []Route
		wg     sync.WaitGroup
	)
	limit := make(chan struct{}, 8)
	for _, host := range hosts {
		host := host
		wg.Add(1)
		limit <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-limit }()
			route := traceOne(host, maxHops, wait, hub)
			mu.Lock()
			routes = append(routes, route)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(routes, func(i, j int) bool { return routes[i].Dest < routes[j].Dest })
	return routes
}
