package portscan

import (
	"net"
	"testing"
	"time"

	"github.com/TokEat/argus/scanner/ddout"
	"github.com/TokEat/argus/scanner/internal/scanner/protocol/intranet"
)

func TestScanUDPEmitsOpenPortOnReply(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:5060")
	if err != nil {
		t.Skipf("cannot bind 5060/udp: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 4096)
		_ = pc.SetDeadline(time.Now().Add(3 * time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil || n == 0 {
			return
		}
		_, _ = pc.WriteTo([]byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), addr)
	}()

	var ports []ddout.OutputMessage
	recs := ScanUDP([]string{"127.0.0.1"}, 2, 9, func(msg ddout.OutputMessage) {
		ports = append(ports, msg)
	})
	found := false
	for _, rec := range recs {
		if rec.Protocol == "sip" && rec.Transport == "udp" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing sip record: %+v", recs)
	}
	emitted := false
	for _, msg := range ports {
		if msg.Type == "PortScan" && msg.Port == "5060" && msg.Transport == "udp" {
			emitted = true
			break
		}
	}
	if !emitted {
		t.Fatalf("missing port emit: %+v", ports)
	}
}

func TestProbeHostsTimeoutIsNotOpen(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	recs := intranet.ProbeHosts([]string{"127.0.0.1"}, []intranet.UDPProbe{{
		Name:     "dns",
		Port:     port,
		Payloads: [][]byte{{0x00, 0x06, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}}, 200*time.Millisecond, 1)
	if len(recs) != 0 {
		t.Fatalf("closed udp port reported open: %+v", recs)
	}
}
