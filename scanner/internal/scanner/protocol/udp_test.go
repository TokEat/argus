package protocol

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func TestUDPIdentifyHostsUsesAliveAndOpenPortsOnly(t *testing.T) {
	got := UDPIdentifyHosts(
		[]string{"10.0.0.8", "10.0.0.8", " "},
		[]string{"10.0.0.9:445", "10.0.0.8:22", "not-a-hostport", "[2001:db8::1]:53"},
	)
	want := []string{"10.0.0.8", "10.0.0.9", "2001:db8::1"}
	if len(got) != len(want) {
		t.Fatalf("hosts = %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("hosts = %v want %v", got, want)
		}
	}
}

func TestUDPIdentifyHostsEmpty(t *testing.T) {
	if got := UDPIdentifyHosts(nil, nil); len(got) != 0 {
		t.Fatalf("empty input = %v", got)
	}
}

func TestIdentifyUDPStoresServiceMapNotIPPortMap(t *testing.T) {
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

	var mu sync.Mutex
	var emitted []structs.OutputMessage
	rt := NewRuntime(map[string]string{}, &sync.Mutex{}, nil, func(message structs.OutputMessage) {
		mu.Lock()
		emitted = append(emitted, message)
		mu.Unlock()
	}, map[string]structs.ServiceRecord{})
	rt.IdentifyUDP([]string{"127.0.0.1"}, 9, 2)

	if len(rt.IPPortMap) != 0 {
		t.Fatalf("IPPortMap = %#v", rt.IPPortMap)
	}
	got := rt.ServiceMap["127.0.0.1:5060/udp"]
	if got.Protocol != "sip" || got.Transport != "udp" {
		t.Fatalf("ServiceMap sip = %+v map=%#v", got, rt.ServiceMap)
	}
	found := false
	mu.Lock()
	for _, msg := range emitted {
		if msg.Protocol == "sip" && msg.Transport == "udp" && msg.Port == "5060" {
			found = true
			break
		}
	}
	mu.Unlock()
	if !found {
		t.Fatalf("missing sip emit: %+v", emitted)
	}
}
