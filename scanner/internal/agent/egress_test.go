package agent

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
)

func TestForbiddenAgentEgressIP(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "169.254.169.254", "100.100.100.200", "224.0.0.1", "fe80::1"} {
		if !forbiddenAgentEgressIP(net.ParseIP(raw)) {
			t.Fatalf("%s was not forbidden", raw)
		}
	}
	for _, raw := range []string{"10.20.30.40", "172.16.1.2", "1.1.1.1"} {
		if forbiddenAgentEgressIP(net.ParseIP(raw)) {
			t.Fatalf("%s was unexpectedly forbidden", raw)
		}
	}
}

type orderedWriteConn struct {
	mu        sync.Mutex
	writes    []string
	halfClose bool
	closed    chan struct{}
}

func (c *orderedWriteConn) Read([]byte) (int, error) { <-c.closed; return 0, io.EOF }
func (c *orderedWriteConn) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.halfClose {
		return 0, io.ErrClosedPipe
	}
	c.writes = append(c.writes, string(data))
	return len(data), nil
}
func (c *orderedWriteConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *orderedWriteConn) CloseWrite() error {
	c.mu.Lock()
	c.halfClose = true
	c.mu.Unlock()
	return nil
}
func (c *orderedWriteConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *orderedWriteConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *orderedWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *orderedWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *orderedWriteConn) SetWriteDeadline(time.Time) error { return nil }

func TestWriteAgentEgressPreservesDataBeforeHalfClose(t *testing.T) {
	conn := &orderedWriteConn{closed: make(chan struct{})}
	item := &agentEgressConnection{conn: conn, writes: make(chan agentEgressWrite, 2), done: make(chan struct{})}
	item.writes <- agentEgressWrite{payload: []byte("tail")}
	item.writes <- agentEgressWrite{halfClose: true}
	done := make(chan struct{})
	go writeAgentEgress("r", "c", item, make(chan *pb.EgressFrame, 1), func() { close(done) })
	deadline := time.After(time.Second)
	for {
		conn.mu.Lock()
		ready := len(conn.writes) == 1 && conn.halfClose
		conn.mu.Unlock()
		if ready {
			break
		}
		select {
		case <-deadline:
			t.Fatal("writer did not flush DATA before HALF_CLOSE")
		case <-time.After(time.Millisecond):
		}
	}
	item.close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("writer did not exit after connection close")
	}
}

func TestAgentEgressConnectionKeyIncludesRoute(t *testing.T) {
	first, ok := agentEgressKey(&pb.EgressFrame{RouteId: "route-a", ConnectionId: "c-1"})
	if !ok {
		t.Fatal("first key was rejected")
	}
	second, ok := agentEgressKey(&pb.EgressFrame{RouteId: "route-b", ConnectionId: "c-1"})
	if !ok || first == second {
		t.Fatalf("route-scoped keys collided: first=%+v second=%+v", first, second)
	}
	if _, ok := agentEgressKey(&pb.EgressFrame{ConnectionId: "c-1"}); ok {
		t.Fatal("connection without route_id was accepted")
	}
}
