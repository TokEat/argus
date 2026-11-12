package discovery

import (
	"bytes"
	"net"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/TokEat/argus/scanner/ddout"
)

func TestEncodeDecodeARPReply(t *testing.T) {
	srcMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	srcIP := net.ParseIP("10.0.0.8").To4()
	dstIP := net.ParseIP("10.0.0.9").To4()
	req := encodeARPRequest(srcMAC, srcIP, dstIP)
	if req == nil || len(req) != arpFrameLen {
		t.Fatalf("request = %v", req)
	}
	if !bytes.Equal(req[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Fatalf("dst mac = %x", req[0:6])
	}

	reply := append([]byte(nil), req...)
	copy(reply[0:6], srcMAC)
	copy(reply[6:12], net.HardwareAddr{0x02, 0, 0, 0, 0, 2})
	reply[21] = arpOperRep
	copy(reply[22:28], net.HardwareAddr{0x02, 0, 0, 0, 0, 2})
	copy(reply[28:32], dstIP)
	copy(reply[32:38], srcMAC)
	copy(reply[38:42], srcIP)

	sha, spa, ok := decodeARPReply(reply)
	if !ok || spa.String() != "10.0.0.9" || !bytes.Equal(sha, net.HardwareAddr{0x02, 0, 0, 0, 0, 2}) {
		t.Fatalf("decode = %v %v %v", sha, spa, ok)
	}
	if _, _, ok := decodeARPReply(req); ok {
		t.Fatal("request decoded as reply")
	}
	if _, _, ok := decodeARPReply(reply[:20]); ok {
		t.Fatal("short frame decoded")
	}
}

func TestParseProcNetARPAndARPAN(t *testing.T) {
	proc := `IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x2         02:00:00:00:00:aa     *        eth0
10.0.0.2         0x1         0x0         00:00:00:00:00:00     *        eth0
10.0.0.3         0x1         0x2         *                     *        eth0
`
	path := t.TempDir() + "/arp"
	if err := os.WriteFile(path, []byte(proc), 0o644); err != nil {
		t.Fatal(err)
	}
	got, ok := parseProcNetARP(path)
	if !ok || !reflect.DeepEqual(sortedKeys(got), []string{"10.0.0.1"}) {
		t.Fatalf("proc arp = %v ok=%v", got, ok)
	}

	an := `? (10.0.0.1) at 02:00:00:00:00:aa on en0 ifscope [ethernet]
? (10.0.0.2) at (incomplete) on en0 ifscope [ethernet]
10.0.0.3           ether   02:00:00:00:00:bb   C                     eth0
`
	parsed := parseARPAN(an)
	if _, ok := parsed["10.0.0.1"]; !ok {
		t.Fatalf("missing darwin entry: %v", parsed)
	}
	if _, ok := parsed["10.0.0.2"]; ok {
		t.Fatalf("incomplete entry kept: %v", parsed)
	}
	if _, ok := parsed["10.0.0.3"]; !ok {
		t.Fatalf("missing linux arp -a entry: %v", parsed)
	}
}

func TestProbeARPFallsBackToNeighborAndEmits(t *testing.T) {
	t.Cleanup(func() {
		rawARPProbe = probeRawARP
		neighborARPProbe = probeNeighborARP
	})
	var rawCalls, neighCalls int
	rawARPProbe = func(link LinkNet, ips []string, _ time.Duration) ([]string, bool) {
		rawCalls++
		return nil, false
	}
	neighborARPProbe = func(link LinkNet, ips []string, _ time.Duration) ([]string, bool) {
		neighCalls++
		return []string{"10.0.0.1"}, true
	}

	var msgs []ddout.OutputMessage
	alive, attempted := probeARPOnNets(
		[]string{"10.0.0.1", "10.0.0.2"},
		[]LinkNet{testLinkNet("10.0.0.0/24", "10.0.0.8")},
		func(msg ddout.OutputMessage) { msgs = append(msgs, msg) },
	)
	if !attempted || !reflect.DeepEqual(alive, []string{"10.0.0.1"}) {
		t.Fatalf("alive=%v attempted=%v", alive, attempted)
	}
	if rawCalls != 1 || neighCalls != 1 {
		t.Fatalf("raw=%d neighbor=%d", rawCalls, neighCalls)
	}
	if len(msgs) != 1 || msgs[0].AdditionalMsg != "ARP" || msgs[0].IP != "10.0.0.1" {
		t.Fatalf("emit = %#v", msgs)
	}
}

func TestProbeARPUnavailable(t *testing.T) {
	t.Cleanup(func() {
		rawARPProbe = probeRawARP
		neighborARPProbe = probeNeighborARP
	})
	rawARPProbe = func(LinkNet, []string, time.Duration) ([]string, bool) { return nil, false }
	neighborARPProbe = func(LinkNet, []string, time.Duration) ([]string, bool) { return nil, false }
	alive, attempted := probeARPOnNets([]string{"10.0.0.1"}, []LinkNet{testLinkNet("10.0.0.0/24", "10.0.0.8")}, nil)
	if attempted || len(alive) != 0 {
		t.Fatalf("alive=%v attempted=%v", alive, attempted)
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
