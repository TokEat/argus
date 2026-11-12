package engine

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/TokEat/argus/scanner/ddout"
	"github.com/TokEat/argus/scanner/internal/scanner/discovery"
)

func TestDiscoverLiveHostsARPThenICMPEmptyFallsBackToTCP(t *testing.T) {
	restoreDiscoveryProbes(t)
	localLinkNets = func() []discovery.LinkNet {
		_, ipnet, _ := net.ParseCIDR("10.0.0.0/24")
		return []discovery.LinkNet{{
			Iface: net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}},
			SrcIP: net.ParseIP("10.0.0.8").To4(),
			Net:   ipnet,
		}}
	}
	var arp, icmp, tcp []string
	probeARP = func(onLink []string, _ func(ddout.OutputMessage)) ([]string, bool) {
		arp = append([]string(nil), onLink...)
		return []string{"10.0.0.1"}, true
	}
	probeICMP = func(ips []string, _ bool, _ func(ddout.OutputMessage)) []string {
		icmp = append([]string(nil), ips...)
		return nil
	}
	probeTCP = func(ips []string, _, _, _ int, _ func(ddout.OutputMessage)) []string {
		tcp = append([]string(nil), ips...)
		return []string{"192.0.2.10"}
	}

	gotICMP, gotTCP := discoverLiveHosts(nil, Config{}, []string{"10.0.0.1", "10.0.0.2", "192.0.2.10"}, nil)
	if !reflect.DeepEqual(arp, []string{"10.0.0.1", "10.0.0.2"}) {
		t.Fatalf("ARP targets = %v", arp)
	}
	if !reflect.DeepEqual(icmp, []string{"10.0.0.2", "192.0.2.10"}) {
		t.Fatalf("ICMP targets = %v", icmp)
	}
	if !reflect.DeepEqual(tcp, []string{"10.0.0.2", "192.0.2.10"}) {
		t.Fatalf("TCP fallback targets = %v", tcp)
	}
	if !reflect.DeepEqual(discovery.Union(gotICMP, gotTCP), []string{"10.0.0.1", "192.0.2.10"}) {
		t.Fatalf("alive = %v %v", gotICMP, gotTCP)
	}
}

func TestDiscoverLiveHostsICMPMissesStillGetTCP(t *testing.T) {
	restoreDiscoveryProbes(t)
	localLinkNets = func() []discovery.LinkNet { return nil }
	probeICMP = func(ips []string, _ bool, _ func(ddout.OutputMessage)) []string {
		return []string{ips[0]}
	}
	var tcp []string
	probeTCP = func(ips []string, _, _, _ int, _ func(ddout.OutputMessage)) []string {
		tcp = append([]string(nil), ips...)
		return []string{"192.0.2.11"}
	}
	icmpAlive, tcpAlive := discoverLiveHosts(nil, Config{}, []string{"192.0.2.10", "192.0.2.11"}, nil)
	if !reflect.DeepEqual(icmpAlive, []string{"192.0.2.10"}) {
		t.Fatalf("icmp=%v", icmpAlive)
	}
	if !reflect.DeepEqual(tcp, []string{"192.0.2.11"}) || !reflect.DeepEqual(tcpAlive, []string{"192.0.2.11"}) {
		t.Fatalf("TCP remaining = %v alive=%v", tcp, tcpAlive)
	}
}

func TestDiscoverLiveHostsAllICMPHitsSkipTCP(t *testing.T) {
	restoreDiscoveryProbes(t)
	localLinkNets = func() []discovery.LinkNet { return nil }
	probeICMP = func(ips []string, _ bool, _ func(ddout.OutputMessage)) []string {
		return append([]string(nil), ips...)
	}
	probeTCP = func(ips []string, _, _, _ int, _ func(ddout.OutputMessage)) []string {
		t.Fatalf("TCP ran after every host already answered ICMP: %v", ips)
		return nil
	}
	icmpAlive, tcpAlive := discoverLiveHosts(nil, Config{}, []string{"192.0.2.10", "192.0.2.11"}, nil)
	if !reflect.DeepEqual(icmpAlive, []string{"192.0.2.10", "192.0.2.11"}) || len(tcpAlive) != 0 {
		t.Fatalf("icmp=%v tcp=%v", icmpAlive, tcpAlive)
	}
}

func TestDiscoverLiveHostsEmptyProbesDoNotCountAsHits(t *testing.T) {
	restoreDiscoveryProbes(t)
	icmpAlive, tcpAlive := discoverLiveHosts(nil, Config{}, []string{"192.0.2.10", "192.0.2.11"}, nil)
	if len(icmpAlive) != 0 || len(tcpAlive) != 0 {
		t.Fatalf("empty probes must not shrink targets: icmp=%v tcp=%v", icmpAlive, tcpAlive)
	}
}

func TestDiscoverLiveHostsNoICMPUsesTCPAfterARP(t *testing.T) {
	restoreDiscoveryProbes(t)
	localLinkNets = func() []discovery.LinkNet {
		_, ipnet, _ := net.ParseCIDR("10.0.0.0/24")
		return []discovery.LinkNet{{
			Iface: net.Interface{Name: "eth0", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 1}},
			SrcIP: net.ParseIP("10.0.0.8").To4(),
			Net:   ipnet,
		}}
	}
	probeARP = func(onLink []string, _ func(ddout.OutputMessage)) ([]string, bool) {
		return []string{"10.0.0.1"}, true
	}
	probeICMP = func(ips []string, _ bool, _ func(ddout.OutputMessage)) []string {
		t.Fatalf("ICMP ran with -nip on %v", ips)
		return nil
	}
	var tcp []string
	probeTCP = func(ips []string, _, _, _ int, _ func(ddout.OutputMessage)) []string {
		tcp = append([]string(nil), ips...)
		return []string{"192.0.2.10"}
	}
	icmpAlive, tcpAlive := discoverLiveHosts(nil, Config{NoICMPPing: true, TCPPing: true}, []string{"10.0.0.1", "192.0.2.10"}, nil)
	if !reflect.DeepEqual(icmpAlive, []string{"10.0.0.1"}) {
		t.Fatalf("ARP alive = %v", icmpAlive)
	}
	if !reflect.DeepEqual(tcp, []string{"192.0.2.10"}) || !reflect.DeepEqual(tcpAlive, []string{"192.0.2.10"}) {
		t.Fatalf("TCP = %v alive=%v", tcp, tcpAlive)
	}
}

func TestDiscoverLiveHostsUDPPingProbesICMPAndTCPMisses(t *testing.T) {
	restoreDiscoveryProbes(t)
	localLinkNets = func() []discovery.LinkNet { return nil }
	probeICMP = func(ips []string, _ bool, _ func(ddout.OutputMessage)) []string {
		return []string{"192.0.2.10"}
	}
	probeTCP = func(ips []string, _, _, _ int, _ func(ddout.OutputMessage)) []string {
		return nil
	}
	var udp []string
	probeUDP = func(ips []string, _ time.Duration, _ int, _ func(ddout.OutputMessage)) []string {
		udp = append([]string(nil), ips...)
		return []string{"192.0.2.12"}
	}
	icmpAlive, extraAlive := discoverLiveHosts(nil, Config{UDPPing: true}, []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"}, nil)
	if !reflect.DeepEqual(icmpAlive, []string{"192.0.2.10"}) {
		t.Fatalf("icmp=%v", icmpAlive)
	}
	if !reflect.DeepEqual(udp, []string{"192.0.2.11", "192.0.2.12"}) {
		t.Fatalf("UDP remaining = %v", udp)
	}
	if !reflect.DeepEqual(extraAlive, []string{"192.0.2.12"}) {
		t.Fatalf("extra=%v", extraAlive)
	}
}

func TestDiscoverLiveHostsUDPPingOnlySkipsICMPAndTCP(t *testing.T) {
	restoreDiscoveryProbes(t)
	localLinkNets = func() []discovery.LinkNet { return nil }
	probeICMP = func(ips []string, _ bool, _ func(ddout.OutputMessage)) []string {
		t.Fatalf("ICMP ran when only UDP ping was selected: %v", ips)
		return nil
	}
	probeTCP = func(ips []string, _, _, _ int, _ func(ddout.OutputMessage)) []string {
		t.Fatalf("TCP ran when only UDP ping was selected: %v", ips)
		return nil
	}
	var udp []string
	probeUDP = func(ips []string, _ time.Duration, _ int, _ func(ddout.OutputMessage)) []string {
		udp = append([]string(nil), ips...)
		return []string{"192.0.2.10"}
	}
	_, extraAlive := discoverLiveHosts(nil, Config{NoICMPPing: true, UDPPing: true}, []string{"192.0.2.10", "192.0.2.11"}, nil)
	if !reflect.DeepEqual(udp, []string{"192.0.2.10", "192.0.2.11"}) {
		t.Fatalf("UDP targets = %v", udp)
	}
	if !reflect.DeepEqual(extraAlive, []string{"192.0.2.10"}) {
		t.Fatalf("extra=%v", extraAlive)
	}
}

func TestProtocolPhaseUDPHostsRequiresConfirmedAlive(t *testing.T) {
	if got := protocolPhaseUDPHosts(nil); len(got) != 0 {
		t.Fatalf("empty confirmed-alive set expanded into UDP hosts: %v", got)
	}
	if got := protocolPhaseUDPHosts([]string{"192.0.2.10"}); !reflect.DeepEqual(got, []string{"192.0.2.10"}) {
		t.Fatalf("alive host should still allow UDP identify: %v", got)
	}
}

func restoreDiscoveryProbes(t *testing.T) {
	t.Helper()
	origARP, origICMP, origTCP, origUDP, origNets := probeARP, probeICMP, probeTCP, probeUDP, localLinkNets
	t.Cleanup(func() {
		probeARP, probeICMP, probeTCP, probeUDP, localLinkNets = origARP, origICMP, origTCP, origUDP, origNets
	})
	probeARP = func([]string, func(ddout.OutputMessage)) ([]string, bool) { return nil, false }
	probeICMP = func([]string, bool, func(ddout.OutputMessage)) []string { return nil }
	probeTCP = func([]string, int, int, int, func(ddout.OutputMessage)) []string { return nil }
	probeUDP = func([]string, time.Duration, int, func(ddout.OutputMessage)) []string { return nil }
	localLinkNets = func() []discovery.LinkNet { return nil }
}

func TestPipelineTraceOnlyDoesNotBindKnowledgeOrScan(t *testing.T) {
	orig := mapIntranet
	t.Cleanup(func() { mapIntranet = orig })
	var hosts []string
	mapIntranet = func(alive []string, emit func(ddout.OutputMessage)) []discovery.Route {
		hosts = append([]string(nil), alive...)
		if emit != nil && len(alive) > 0 {
			emit(ddout.OutputMessage{Type: "Path", IP: alive[0], IPs: []string{"10.0.0.1", alive[0]}, AdditionalMsg: "hops=2"})
		}
		return nil
	}

	var msgs []ddout.OutputMessage
	ctx := &ScanContext{
		Config: Config{TraceOnly: true, Targets: []string{"10.0.2.20", "10.0.2.20:445", "http://10.0.2.21/"}},
		Ctx:    context.Background(),
	}
	ctx.OutputObserver = func(msg ddout.OutputMessage) {
		msgs = append(msgs, msg)
	}
	if err := (&Pipeline{}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hosts, []string{"10.0.2.20", "10.0.2.21"}) {
		t.Fatalf("trace hosts = %v", hosts)
	}
	if len(msgs) == 0 || msgs[0].Type != "Path" || msgs[0].IP != "10.0.2.20" {
		t.Fatalf("path output = %#v", msgs)
	}
}
