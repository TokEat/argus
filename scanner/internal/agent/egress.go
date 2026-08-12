package agent

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

const (
	agentEgressMaxFrame = 64 << 10
	agentEgressQueue    = 128
)

type agentEgressConnection struct {
	conn      net.Conn
	seq       atomic.Uint64
	writes    chan agentEgressWrite
	done      chan struct{}
	closeOnce sync.Once
}

type agentEgressWrite struct {
	payload   []byte
	halfClose bool
}

func (c *agentEgressConnection) close() {
	if c != nil {
		c.closeOnce.Do(func() { close(c.done); _ = c.conn.Close() })
	}
}

type agentEgressConnectionKey struct {
	routeID      string
	connectionID string
}

type agentEgressPending struct{ cancel context.CancelFunc }

func agentEgressKey(frame *pb.EgressFrame) (agentEgressConnectionKey, bool) {
	if frame == nil || strings.TrimSpace(frame.GetRouteId()) == "" || strings.TrimSpace(frame.GetConnectionId()) == "" {
		return agentEgressConnectionKey{}, false
	}
	return agentEgressConnectionKey{routeID: frame.GetRouteId(), connectionID: frame.GetConnectionId()}, true
}

func (w *Worker) runEgressTunnel() {
	defer w.wg.Done()
	client := pb.NewAgentEgressServiceClient(w.conn)
	for {
		select {
		case <-w.stopCh:
			return
		default:
		}
		baseCtx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-w.stopCh:
				cancel()
			case <-baseCtx.Done():
			}
		}()
		ctx := metadata.AppendToOutgoingContext(baseCtx, "x-agent-token", w.sessionToken)
		stream, err := client.EgressTunnel(ctx)
		if err == nil {
			err = w.serveEgressTunnel(stream)
		}
		cancel()
		if err != nil && err != io.EOF {
			log.Printf("[Egress] tunnel disconnected: %v", err)
		}
		select {
		case <-w.stopCh:
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (w *Worker) serveEgressTunnel(stream pb.AgentEgressService_EgressTunnelClient) error {
	if err := stream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_HELLO, AgentId: w.agentID}); err != nil {
		return err
	}
	ack, err := stream.Recv()
	if err != nil {
		return err
	}
	if ack.GetKind() != pb.EgressFrameKind_EGRESS_FRAME_HELLO_ACK || ack.GetAgentId() != w.agentID {
		return fmt.Errorf("server rejected Agent egress tunnel")
	}
	log.Printf("[Egress] native tunnel established")

	send := make(chan *pb.EgressFrame, agentEgressQueue)
	sendErr := make(chan error, 1)
	go func() {
		for {
			select {
			case frame := <-send:
				if err := stream.Send(frame); err != nil {
					sendErr <- err
					return
				}
			case <-stream.Context().Done():
				return
			}
		}
	}()
	connections := map[agentEgressConnectionKey]*agentEgressConnection{}
	pending := map[agentEgressConnectionKey]*agentEgressPending{}
	var connectionsMu sync.Mutex
	closeAll := func() {
		connectionsMu.Lock()
		defer connectionsMu.Unlock()
		for id, item := range connections {
			item.close()
			delete(connections, id)
		}
		for id, item := range pending {
			item.cancel()
			delete(pending, id)
		}
	}
	defer closeAll()

	for {
		frame, err := stream.Recv()
		if err != nil {
			return err
		}
		if len(frame.GetPayload()) > agentEgressMaxFrame {
			return fmt.Errorf("egress frame exceeds %d bytes", agentEgressMaxFrame)
		}
		switch frame.GetKind() {
		case pb.EgressFrameKind_EGRESS_FRAME_OPEN:
			key, valid := agentEgressKey(frame)
			if !valid {
				enqueueEgress(send, &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_ERROR, RouteId: frame.GetRouteId(), ConnectionId: frame.GetConnectionId(), ErrorCode: "invalid_connection", ErrorMessage: "route_id and connection_id are required"})
				continue
			}
			openCtx, cancel := context.WithCancel(stream.Context())
			pendingOpen := &agentEgressPending{cancel: cancel}
			connectionsMu.Lock()
			if old := pending[key]; old != nil {
				old.cancel()
			}
			pending[key] = pendingOpen
			connectionsMu.Unlock()
			frameCopy := proto.Clone(frame).(*pb.EgressFrame)
			go func(frame *pb.EgressFrame) {
				defer cancel()
				connection, metadata, openErr := openAgentEgress(openCtx, frame.GetHost(), frame.GetPort())
				connectionsMu.Lock()
				if pending[key] != pendingOpen {
					connectionsMu.Unlock()
					if connection != nil {
						_ = connection.Close()
					}
					return
				}
				delete(pending, key)
				if openErr != nil {
					connectionsMu.Unlock()
					enqueueEgress(send, &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_ERROR, RouteId: frame.GetRouteId(), ConnectionId: frame.GetConnectionId(), ErrorCode: "open_failed", ErrorMessage: openErr.Error()})
					return
				}
				item := &agentEgressConnection{conn: connection, writes: make(chan agentEgressWrite, 16), done: make(chan struct{})}
				connections[key] = item
				connectionsMu.Unlock()
				enqueueEgress(send, &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_OPEN_RESULT, RouteId: frame.GetRouteId(), ConnectionId: frame.GetConnectionId(), ResolvedIp: metadata.resolvedIP, RemoteAddress: metadata.remoteAddress})
				remove := func() {
					connectionsMu.Lock()
					if connections[key] == item {
						delete(connections, key)
					}
					connectionsMu.Unlock()
				}
				go writeAgentEgress(frame.GetRouteId(), frame.GetConnectionId(), item, send, remove)
				go readAgentEgress(frame.GetRouteId(), frame.GetConnectionId(), item, send, remove)
			}(frameCopy)
		case pb.EgressFrameKind_EGRESS_FRAME_DATA:
			key, valid := agentEgressKey(frame)
			if !valid {
				enqueueEgress(send, &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_ERROR, RouteId: frame.GetRouteId(), ConnectionId: frame.GetConnectionId(), ErrorCode: "invalid_connection", ErrorMessage: "route_id and connection_id are required"})
				continue
			}
			connectionsMu.Lock()
			item := connections[key]
			connectionsMu.Unlock()
			if item == nil {
				enqueueEgress(send, &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_ERROR, RouteId: frame.GetRouteId(), ConnectionId: frame.GetConnectionId(), ErrorCode: "connection_not_found", ErrorMessage: "egress connection is not open"})
				continue
			}
			select {
			case item.writes <- agentEgressWrite{payload: append([]byte(nil), frame.GetPayload()...)}:
			case <-item.done:
			default:
				item.close()
				enqueueEgress(send, &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_ERROR, RouteId: frame.GetRouteId(), ConnectionId: frame.GetConnectionId(), ErrorCode: "write_backpressure", ErrorMessage: "connection write queue is full"})
			}
		case pb.EgressFrameKind_EGRESS_FRAME_HALF_CLOSE:
			key, valid := agentEgressKey(frame)
			if !valid {
				continue
			}
			connectionsMu.Lock()
			item := connections[key]
			connectionsMu.Unlock()
			if item == nil {
				continue
			}
			select {
			case item.writes <- agentEgressWrite{halfClose: true}:
			case <-item.done:
			default:
				item.close()
				enqueueEgress(send, &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_ERROR, RouteId: frame.GetRouteId(), ConnectionId: frame.GetConnectionId(), ErrorCode: "write_backpressure", ErrorMessage: "connection write queue is full"})
			}
		case pb.EgressFrameKind_EGRESS_FRAME_CLOSE:
			key, valid := agentEgressKey(frame)
			if !valid {
				continue
			}
			connectionsMu.Lock()
			item := connections[key]
			delete(connections, key)
			pendingOpen := pending[key]
			delete(pending, key)
			connectionsMu.Unlock()
			if pendingOpen != nil {
				pendingOpen.cancel()
			}
			item.close()
			enqueueEgress(send, &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_CLOSE, RouteId: frame.GetRouteId(), ConnectionId: frame.GetConnectionId()})
		case pb.EgressFrameKind_EGRESS_FRAME_ERROR:
			key, valid := agentEgressKey(frame)
			if !valid {
				continue
			}
			connectionsMu.Lock()
			item := connections[key]
			delete(connections, key)
			pendingOpen := pending[key]
			delete(pending, key)
			connectionsMu.Unlock()
			if pendingOpen != nil {
				pendingOpen.cancel()
			}
			item.close()
		case pb.EgressFrameKind_EGRESS_FRAME_PING:
			enqueueEgress(send, &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_PONG})
		}
		select {
		case err := <-sendErr:
			return err
		default:
		}
	}
}

type agentOpenMetadata struct{ resolvedIP, remoteAddress string }

func writeAgentEgress(routeID, connectionID string, item *agentEgressConnection, send chan<- *pb.EgressFrame, done func()) {
	defer done()
	defer item.close()
	for {
		select {
		case write := <-item.writes:
			if write.halfClose {
				if halfCloser, ok := item.conn.(interface{ CloseWrite() error }); ok {
					_ = halfCloser.CloseWrite()
				}
				continue
			}
			_ = item.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := item.conn.Write(write.payload)
			_ = item.conn.SetWriteDeadline(time.Time{})
			if err != nil {
				enqueueEgress(send, &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_ERROR, RouteId: routeID, ConnectionId: connectionID, ErrorCode: "write_failed", ErrorMessage: err.Error()})
				return
			}
		case <-item.done:
			return
		}
	}
}

func openAgentEgress(ctx context.Context, host string, port uint32) (net.Conn, agentOpenMetadata, error) {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if host == "" || port < 1 || port > 65535 {
		return nil, agentOpenMetadata{}, fmt.Errorf("invalid egress target")
	}
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	if err != nil {
		return nil, agentOpenMetadata{}, fmt.Errorf("resolve target: %w", err)
	}
	var lastErr error
	allowed := false
	for _, address := range addresses {
		if forbiddenAgentEgressIP(address.IP) {
			continue
		}
		allowed = true
		connection, dialErr := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(resolveCtx, "tcp", net.JoinHostPort(address.IP.String(), strconv.Itoa(int(port))))
		if dialErr != nil {
			lastErr = dialErr
			continue
		}
		return connection, agentOpenMetadata{resolvedIP: address.IP.String(), remoteAddress: connection.RemoteAddr().String()}, nil
	}
	if !allowed {
		return nil, agentOpenMetadata{}, fmt.Errorf("target resolves only to forbidden addresses")
	}
	if lastErr != nil {
		return nil, agentOpenMetadata{}, lastErr
	}
	return nil, agentOpenMetadata{}, fmt.Errorf("target has no usable address")
}

func readAgentEgress(routeID, connectionID string, item *agentEgressConnection, send chan<- *pb.EgressFrame, done func()) {
	buffer := make([]byte, agentEgressMaxFrame)
	for {
		count, err := item.conn.Read(buffer)
		if count > 0 {
			if !enqueueEgress(send, &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_DATA, RouteId: routeID, ConnectionId: connectionID, Sequence: item.seq.Add(1), Payload: append([]byte(nil), buffer[:count]...)}) {
				done()
				item.close()
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				enqueueEgress(send, &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_HALF_CLOSE, RouteId: routeID, ConnectionId: connectionID})
				return
			}
			done()
			item.close()
			enqueueEgress(send, &pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_ERROR, RouteId: routeID, ConnectionId: connectionID, ErrorCode: "read_failed", ErrorMessage: err.Error()})
			return
		}
	}
}

func enqueueEgress(send chan<- *pb.EgressFrame, frame *pb.EgressFrame) bool {
	select {
	case send <- frame:
		return true
	case <-time.After(5 * time.Second):
		return false
	}
}

func forbiddenAgentEgressIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, raw := range []string{"169.254.169.254", "100.100.100.200", "192.0.0.192", "fd00:ec2::254"} {
		if ip.Equal(net.ParseIP(raw)) {
			return true
		}
	}
	return false
}
