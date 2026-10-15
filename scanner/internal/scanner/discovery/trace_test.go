package discovery

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/ddout"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var errICMPDenied = errors.New("icmp listen denied")

func TestHostsFromTraceTargetsExpandsIPPortAndURL(t *testing.T) {
	got := HostsFromTraceTargets([]string{
		"10.0.2.20",
		"10.0.2.21:445",
		"http://10.0.2.22:8080/login",
		"example.test",
		"256.1.1.1",
	})
	if !reflect.DeepEqual(got, []string{"10.0.2.20", "10.0.2.21", "10.0.2.22"}) {
		t.Fatalf("hosts = %v", got)
	}
}

func TestHostsFromTraceTargetsSamplesLargeCIDRWithoutExpanding(t *testing.T) {
	got := HostsFromTraceTargets([]string{"10.0.0.0/8"})
	if len(got) == 0 || len(got) > maxTraceSamples {
		t.Fatalf("sampled = %v", got)
	}
	for _, host := range got {
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() == nil || ip.To4()[0] != 10 {
			t.Fatalf("out of range: %s", host)
		}
	}
}

func TestHostsFromTraceTargetsExpandsSmallCIDR(t *testing.T) {
	got := HostsFromTraceTargets([]string{"10.0.2.0/30"})
	if !reflect.DeepEqual(got, []string{"10.0.2.0", "10.0.2.1", "10.0.2.2", "10.0.2.3"}) {
		t.Fatalf("small cidr = %v", got)
	}
}

func TestTraceInputHostsPrefersDiscoveryThenPorts(t *testing.T) {
	if got := TraceInputHosts([]string{"10.0.0.2"}, []string{"10.0.0.2", "10.0.0.3"}, nil); !reflect.DeepEqual(got, []string{"10.0.0.2"}) {
		t.Fatalf("confirmed = %v", got)
	}
	if got := TraceInputHosts(nil, []string{"10.1.0.1"}, []string{"10.0.0.8:445", "10.0.0.9:22"}); !reflect.DeepEqual(got, []string{"10.0.0.8", "10.0.0.9"}) {
		t.Fatalf("ports = %v", got)
	}
	if got := TraceInputHosts(nil, []string{"10.0.0.1", "10.0.0.2"}, nil); len(got) != 2 {
		t.Fatalf("small explicit list = %v", got)
	}
	huge := make([]string, 300)
	for i := range huge {
		huge[i] = "10.1.0.1"
	}
	if got := TraceInputHosts(nil, huge, nil); got != nil {
		t.Fatalf("large leftover CIDR should not be traced: %v", got)
	}
}

func TestSampleTraceHostsCapsPerNet(t *testing.T) {
	alive := []string{"10.0.0.3", "10.0.0.1", "10.0.0.2", "10.0.1.9", "127.0.0.1"}
	got := SampleTraceHosts(alive, 2, 32)
	if !reflect.DeepEqual(got, []string{"10.0.0.1", "10.0.0.2", "10.0.1.9", "127.0.0.1"}) {
		t.Fatalf("sample = %v", got)
	}
}

func TestCollapseBlueprintMergesDestNets(t *testing.T) {
	lines := CollapseBlueprint([]Route{
		{Dest: "10.0.2.20", Hops: []string{"10.0.0.1", "10.0.2.1", "10.0.2.20"}},
		{Dest: "10.0.2.21", Hops: []string{"10.0.0.1", "10.0.2.1", "10.0.2.21"}},
		{Dest: "10.0.1.10", Hops: []string{"10.0.0.1", "10.0.1.10"}},
		{Dest: "10.0.9.9", Hops: []string{"", ""}},
	})
	want := []string{
		"10.0.0.1 -> 10.0.1.0/24",
		"10.0.0.1 -> 10.0.2.1 -> 10.0.2.0/24",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("blueprint = %#v", lines)
	}
}

func TestParseTraceICMPTimeExceeded(t *testing.T) {
	inner := make([]byte, 20)
	inner[0] = 0x45
	copy(inner[16:20], net.ParseIP("10.0.2.20").To4())
	msg := icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Code: 0, Body: &icmp.TimeExceeded{Data: inner}}
	payload, err := msg.Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	from, dest, reached, ttl, ok := parseTraceICMP("10.0.0.1", payload)
	if !ok || reached || ttl != 0 || from.String() != "10.0.0.1" || dest.String() != "10.0.2.20" {
		t.Fatalf("from=%v dest=%v reached=%v ttl=%d ok=%v", from, dest, reached, ttl, ok)
	}
}

func TestInnerProbeTTLFromUDPPort(t *testing.T) {
	inner := make([]byte, 28)
	inner[0] = 0x45
	inner[9] = 17
	copy(inner[16:20], net.ParseIP("10.0.2.20").To4())
	port := traceUDPBase + 3
	inner[22] = byte(port >> 8)
	inner[23] = byte(port)
	if got := innerProbeTTL(inner); got != 3 {
		t.Fatalf("ttl = %d", got)
	}
}

func TestWaitHopIgnoresLatePreviousHop(t *testing.T) {
	replies := make(chan hopReply, 2)
	dest := net.ParseIP("10.0.2.20").To4()
	replies <- hopReply{from: net.ParseIP("10.0.0.1").To4(), dest: dest, ttl: 1}
	replies <- hopReply{from: net.ParseIP("10.0.0.8").To4(), dest: dest, ttl: 2}
	hop, reached := waitHop(replies, dest, 2, time.Second)
	if reached || hop != "10.0.0.8" {
		t.Fatalf("hop=%q reached=%v", hop, reached)
	}
}

func TestHopCountAndTopoKeepSilentMiddle(t *testing.T) {
	route := Route{Dest: "10.0.2.20", Hops: []string{"10.0.0.1", "", "10.0.2.20"}}
	if hopCount(route) != 3 {
		t.Fatalf("hops = %d", hopCount(route))
	}
	lines := CollapseBlueprint([]Route{route})
	if !reflect.DeepEqual(lines, []string{"10.0.0.1 -> * -> 10.0.2.0/24"}) {
		t.Fatalf("topo = %#v", lines)
	}
}

func TestSendTraceICMPDoesNotPanicOnPacketConn(t *testing.T) {
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	}
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("sendTraceICMP panicked: %v", r)
		}
	}()
	if err := sendTraceICMP(conn, net.ParseIP("127.0.0.1").To4(), 1); err != nil {
		t.Logf("send returned %v", err)
	}
}

func TestTraceHostsSkipsWhenICMPUnavailable(t *testing.T) {
	orig := openTraceICMP
	t.Cleanup(func() { openTraceICMP = orig })
	openTraceICMP = func() (*icmp.PacketConn, error) {
		return nil, errICMPDenied
	}
	if got := traceHostsImpl([]string{"10.0.2.20"}, 3, time.Millisecond); len(got) != 0 {
		t.Fatalf("expected skip without system traceroute, got %#v", got)
	}
}

func TestMapIntranetEmitsPathAndTopo(t *testing.T) {
	orig := traceHosts
	t.Cleanup(func() { traceHosts = orig })
	traceHosts = func(hosts []string, _ int, _ time.Duration) []Route {
		return []Route{{Dest: "10.0.2.20", Hops: []string{"10.0.0.1", "10.0.2.20"}}}
	}
	var msgs []ddout.OutputMessage
	MapIntranet([]string{"10.0.2.20"}, func(msg ddout.OutputMessage) { msgs = append(msgs, msg) })
	if len(msgs) != 2 || msgs[0].Type != "Path" || msgs[1].Type != "Topo" {
		t.Fatalf("messages = %#v", msgs)
	}
	if msgs[0].IP != "10.0.2.20" || msgs[0].AdditionalMsg != "hops=2" {
		t.Fatalf("path = %#v", msgs[0])
	}
	if msgs[1].AdditionalMsg != "10.0.0.1 -> 10.0.2.0/24" {
		t.Fatalf("topo = %q", msgs[1].AdditionalMsg)
	}
}
