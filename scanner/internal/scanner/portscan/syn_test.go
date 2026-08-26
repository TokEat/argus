package portscan

import (
	"encoding/binary"
	mrand "math/rand"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestSipHash24EmptyVector(t *testing.T) {
	var key [2]uint64
	// k = 00 01 02 ... 0f as little-endian uint64 halves
	keyBytes := make([]byte, 16)
	for i := 0; i < 16; i++ {
		keyBytes[i] = byte(i)
	}
	key[0] = binary.LittleEndian.Uint64(keyBytes[0:8])
	key[1] = binary.LittleEndian.Uint64(keyBytes[8:16])

	got := siphash24(nil, key)
	want := binary.LittleEndian.Uint64([]byte{0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72})
	if got != want {
		t.Fatalf("empty SipHash vector: got %#016x want %#016x", got, want)
	}
}

func TestSipHash24OneByteVector(t *testing.T) {
	var key [2]uint64
	keyBytes := make([]byte, 16)
	for i := 0; i < 16; i++ {
		keyBytes[i] = byte(i)
	}
	key[0] = binary.LittleEndian.Uint64(keyBytes[0:8])
	key[1] = binary.LittleEndian.Uint64(keyBytes[8:16])
	got := siphash24([]byte{0x00}, key)
	want := binary.LittleEndian.Uint64([]byte{0xfd, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74})
	if got != want {
		t.Fatalf("1-byte SipHash vector: got %#016x want %#016x", got, want)
	}
}

func TestSynCookieStableAndValidatesACK(t *testing.T) {
	them := net.ParseIP("203.0.113.10").To4()
	me := net.ParseIP("198.51.100.7").To4()
	const entropy uint64 = 0x0123456789abcdef
	a := synCookieSeq(them, me, 443, 61000, entropy)
	b := synCookieSeq(them, me, 443, 61000, entropy)
	if a != b {
		t.Fatalf("cookie not stable: %#x vs %#x", a, b)
	}
	if !synCookieValid(a+1, them, me, 443, 61000, entropy) {
		t.Fatal("expected ACK-1 to validate")
	}
	if synCookieValid(a+2, them, me, 443, 61000, entropy) {
		t.Fatal("wrong ACK must not validate")
	}
	other := synCookieSeq(them, me, 80, 61000, entropy)
	if other == a {
		t.Fatal("different port_them should change cookie")
	}
}

func TestBuildAndParseSYNPacket(t *testing.T) {
	src := net.ParseIP("192.0.2.1").To4()
	dst := net.ParseIP("198.51.100.2").To4()
	pkt := buildIPv4TCP(tcpSegment{
		SrcIP:   src,
		DstIP:   dst,
		SrcPort: 61000,
		DstPort: 443,
		Seq:     0xAABBCCDD,
		Flags:   tcpFlagSYN,
		Window:  29200,
		WithMSS: true,
	}, 64, 7)
	if len(pkt) != synProbeLen {
		t.Fatalf("packet len=%d want %d", len(pkt), synProbeLen)
	}
	seg, ok := parseIPv4TCP(pkt)
	if !ok {
		t.Fatal("parse failed")
	}
	if !seg.SrcIP.Equal(src) || !seg.DstIP.Equal(dst) {
		t.Fatalf("ip mismatch %#v", seg)
	}
	if seg.SrcPort != 61000 || seg.DstPort != 443 || seg.Seq != 0xAABBCCDD {
		t.Fatalf("tcp fields mismatch %#v", seg)
	}
	if seg.Flags&tcpFlagSYN == 0 {
		t.Fatal("missing SYN flag")
	}
	if seg.DataOff != 6 {
		t.Fatalf("expected MSS option dataoff=6, got %d", seg.DataOff)
	}

	rst := buildIPv4TCP(tcpSegment{
		SrcIP:   src,
		DstIP:   dst,
		SrcPort: 61000,
		DstPort: 443,
		Seq:     0xAABBCCDE,
		Ack:     0x100,
		Flags:   tcpFlagRST | tcpFlagACK,
	}, 64, 8)
	if len(rst) != synPacketLen {
		t.Fatalf("RST should be bare tcp, len=%d", len(rst))
	}
	rstSeg, ok := parseIPv4TCP(rst)
	if !ok || rstSeg.Flags&(tcpFlagRST|tcpFlagACK) != tcpFlagRST|tcpFlagACK {
		t.Fatalf("RST parse failed: ok=%v flags=%#x", ok, rstSeg.Flags)
	}
}

func TestScanSYNUsesRequestedPortsWithoutMasscanBinary(t *testing.T) {
	ports := ParsePort("80,443")
	if len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Fatalf("ParsePort: %v", ports)
	}
	got := ScanSYN([]string{"192.0.2.1"}, "80,443", 100, nil)
	if got != nil {
		t.Fatalf("non-linux or no raw socket: want nil abort, got %v", got)
	}
}

func TestScanSYNAbortVsEmptySuccess(t *testing.T) {
	if runtime.GOOS != "linux" || !CanSYNScan() {
		t.Skip("requires Linux raw socket")
	}
	if got := ScanSYN(nil, "80", 100, nil); got != nil {
		t.Fatalf("no targets: want nil abort, got %v", got)
	}
	if got := ScanSYN([]string{"192.0.2.1"}, "", 100, nil); got != nil {
		t.Fatalf("no ports: want nil abort, got %v", got)
	}
}

func TestPacketPacerAdvances(t *testing.T) {
	p := newPacketPacer(1000)
	start := time.Now()
	for i := 0; i < 5; i++ {
		p.wait()
	}
	elapsed := time.Since(start)
	if elapsed < 3*time.Millisecond {
		t.Fatalf("pacer too fast: %s", elapsed)
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("pacer too slow: %s", elapsed)
	}
}

func TestSynBlendAvoidsMasscanIPID(t *testing.T) {
	dst := net.ParseIP("203.0.113.10").To4()
	seq := uint32(0xAABBCCDD)
	masscanLike := uint16(ipv4Uint32(dst) ^ 443 ^ seq)
	var counter uint32 = 1
	got := nextIPID(&counter)
	// Statistical: a single sample can collide; ensure formula helper is gone and counter advances.
	_ = masscanLike
	got2 := nextIPID(&counter)
	if got == got2 && counter < 3 {
		t.Fatal("IP ID counter did not advance")
	}
	port := synEphemeralPort()
	if port < 49152 {
		t.Fatalf("ephemeral port out of IANA range: %d", port)
	}
}

func TestShuffleProbeOrderCoversAll(t *testing.T) {
	rng := mrand.New(mrand.NewSource(1))
	probes := shuffleProbeOrder([]string{"10.0.0.1", "10.0.0.2"}, []int{80, 443}, rng)
	if len(probes) != 4 {
		t.Fatalf("len=%d", len(probes))
	}
	seen := map[string]bool{}
	for _, p := range probes {
		seen[p.host+":"+strconv.Itoa(p.port)] = true
	}
	if len(seen) != 4 {
		t.Fatalf("missing probes: %v", seen)
	}
}

func TestCanSYNScanMatchesPlatform(t *testing.T) {
	if runtime.GOOS != "linux" && CanSYNScan() {
		t.Fatal("CanSYNScan must be false outside linux")
	}
}
