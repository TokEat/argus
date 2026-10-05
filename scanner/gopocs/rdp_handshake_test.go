package gopocs

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/tomatome/grdp/emission"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/sec"
	"github.com/tomatome/grdp/protocol/t125"
	"github.com/tomatome/grdp/protocol/t125/gcc"
)

type rdpEmitterTransport struct {
	emission.Emitter
}

func newRDPEmitterTransport() *rdpEmitterTransport {
	return &rdpEmitterTransport{Emitter: *emission.NewEmitter()}
}

func (t *rdpEmitterTransport) Read([]byte) (int, error) { return 0, io.EOF }
func (t *rdpEmitterTransport) Write(b []byte) (int, error) {
	return len(b), nil
}
func (t *rdpEmitterTransport) Close() error { return nil }

// emitStandardRDPConnect reproduces the grdp "connect" callback that panics
// when standard RDP is selected and the server security block is missing or
// has no server random. The callback runs on an emitter goroutine.
func emitStandardRDPConnect(t *testing.T, serverSecurity *gcc.ServerSecurityData) error {
	t.Helper()
	transport := newRDPEmitterTransport()
	sec.NewClient(transport)
	got := make(chan error, 1)
	installRDPHandshakeGuard(func(err error) {
		got <- err
	}, transport)

	var security interface{} = serverSecurity
	transport.Emit("connect",
		[]interface{}{&gcc.ClientCoreData{}},
		[]interface{}{(*gcc.ServerCoreData)(nil), security},
		uint16(1002),
		[]t125.MCSChannelInfo{{ID: 1003, Name: "global"}},
	)
	select {
	case err := <-got:
		return err
	default:
		t.Fatal("standard RDP connect returned without containing a listener failure")
	}
	return nil
}

func TestStandardRDPMissingSecurityDataDoesNotPanic(t *testing.T) {
	err := emitStandardRDPConnect(t, nil)
	if !isRDPHandshakePanic(err) {
		t.Fatalf("error = %v, want handshake panic", err)
	}
}

func TestStandardRDPEmptyServerRandomDoesNotPanic(t *testing.T) {
	err := emitStandardRDPConnect(t, &gcc.ServerSecurityData{})
	if !isRDPHandshakePanic(err) {
		t.Fatalf("error = %v, want handshake panic", err)
	}
}

func TestRDPScanStopsAfterHandshakePanic(t *testing.T) {
	var calls atomic.Int32
	info := &structs.HostInfo{Host: "127.0.0.1", Ports: "13389", CredentialPairLimit: 2}
	err := rdpScanWithConnector(info, func(string, string, string, string, int, int64) (bool, []structs.GoPocExchange, error) {
		calls.Add(1)
		return false, nil, fmt.Errorf("%w on connect: nil pointer", errRDPHandshakePanic)
	})
	if !isRDPHandshakePanic(err) {
		t.Fatalf("error = %v, want handshake panic", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want the remaining pairs to be skipped", calls.Load())
	}
}

func TestRDPScanContinuesWhenErrorOnlyLooksLikeHandshakePanic(t *testing.T) {
	var calls atomic.Int32
	info := &structs.HostInfo{Host: "127.0.0.1", Ports: "13389", CredentialPairLimit: 2}
	err := rdpScanWithConnector(info, func(string, string, string, string, int, int64) (bool, []structs.GoPocExchange, error) {
		calls.Add(1)
		return false, nil, errors.New("rdp handshake panic on connect: nil pointer")
	})
	if err != nil {
		t.Fatalf("an ordinary login error must not abort the scan: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
}

func TestRDPLoginTimeoutReturns(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{})
	var once sync.Once
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		once.Do(func() { close(accepted) })
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
	}()

	client := newClientWithDialer(listener.Addr().String(), glog.NONE, func(network, address string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(network, address, timeout)
	})
	started := time.Now()
	_, err = client.loginWithEvidence("", "user", "pass", 1, 1024)
	if err == nil {
		t.Fatal("expected the incomplete handshake to fail")
	}
	if time.Since(started) > 5*time.Second {
		t.Fatalf("login blocked for %s", time.Since(started))
	}
	select {
	case <-accepted:
	default:
		t.Fatal("server did not accept the RDP connection")
	}
}
