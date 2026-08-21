package discovery

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/ddout"
)

func TestIsPortUnreachable(t *testing.T) {
	if !isPortUnreachable(syscall.ECONNREFUSED) {
		t.Fatal("ECONNREFUSED should mean host up")
	}
	if !isPortUnreachable(&net.OpError{Op: "read", Err: syscall.ECONNREFUSED}) {
		t.Fatal("wrapped ECONNREFUSED should mean host up")
	}
	if isPortUnreachable(nil) || isPortUnreachable(errors.New("i/o timeout")) {
		t.Fatal("timeout must not count as alive")
	}
}

func TestProbeUDPReplyIsAlive(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 32)
		_, addr, err := pc.ReadFromUDP(buf)
		if err != nil || addr == nil {
			return
		}
		_, _ = pc.WriteToUDP([]byte("ok"), addr)
	}()

	if !udpHostAlive("127.0.0.1", port, time.Second) {
		t.Fatal("UDP reply should count as alive")
	}
}

func TestProbeUDPClosedLocalhost(t *testing.T) {
	// Closed UDP on loopback usually comes back as ICMP port unreachable.
	if !udpHostAlive("127.0.0.1", UDPProbePort, time.Second) {
		t.Skip("this OS did not surface ICMP port unreachable on loopback")
	}
	var msgs []ddout.OutputMessage
	alive := ProbeUDP([]string{"127.0.0.1"}, time.Second, 1, func(msg ddout.OutputMessage) {
		msgs = append(msgs, msg)
	})
	if len(alive) != 1 || alive[0] != "127.0.0.1" {
		t.Fatalf("alive = %v", alive)
	}
	if len(msgs) != 1 || msgs[0].AdditionalMsg != "UDP" {
		t.Fatalf("emit = %#v", msgs)
	}
}

func TestProbeUDPTimeoutIsNotAlive(t *testing.T) {
	if udpHostAlive("192.0.2.1", UDPProbePort, 80*time.Millisecond) {
		t.Fatal("TEST-NET timeout must not count as alive")
	}
}
