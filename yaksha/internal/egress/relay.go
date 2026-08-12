package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const relayMaxFrame = 64 << 10

type RelayConnector struct {
	ctx     context.Context
	cancel  context.CancelFunc
	conn    *grpc.ClientConn
	stream  pb.YakshaEgressGateway_RelayClient
	routeID string
	sendMu  sync.Mutex
	mu      sync.Mutex
	items   map[string]*relayConnection
	nextID  atomic.Uint64
	closed  atomic.Bool
}

type relayConnection struct {
	public   *relayConn
	readCh   chan relayReadEvent
	readEOF  atomic.Bool
	opened   chan *pb.EgressFrame
	done     chan struct{}
	once     sync.Once
	metadata OpenMetadata
}

type relayConn struct {
	connector     *RelayConnector
	item          *relayConnection
	id            string
	readMu        sync.Mutex
	writeMu       sync.Mutex
	readBuffer    []byte
	readEnded     bool
	deadlineWake  chan struct{}
	writeWake     chan struct{}
	sequence      atomic.Uint64
	closed        atomic.Bool
	writeClosed   atomic.Bool
	readDeadline  atomic.Int64
	writeDeadline atomic.Int64
}

type relayReadEvent struct {
	data []byte
	eof  bool
}

type relayAddr string

func (a relayAddr) Network() string { return "tcp" }
func (a relayAddr) String() string  { return string(a) }

func NewRelayClient(ctx context.Context, address, token, routeID string) (Client, error) {
	connector, err := NewRelayConnector(ctx, address, token, routeID)
	if err != nil {
		return nil, err
	}
	return NetworkClient{Connector: connector}, nil
}

func NewRelayConnector(parent context.Context, address, token, routeID string) (*RelayConnector, error) {
	return newRelayConnector(parent, address, token, routeID)
}

func newRelayConnector(parent context.Context, address, token, routeID string, extraOptions ...grpc.DialOption) (*RelayConnector, error) {
	address, token, routeID = strings.TrimSpace(address), strings.TrimSpace(token), strings.TrimSpace(routeID)
	if address == "" || token == "" {
		return nil, fmt.Errorf("Agent Egress Unavailable: relay provider is not configured")
	}
	if routeID == "" {
		return nil, fmt.Errorf("Agent Egress Unavailable: route_id is required")
	}
	ctx, cancel := context.WithCancel(parent)
	options := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(relayMaxFrame+4096), grpc.MaxCallSendMsgSize(relayMaxFrame+4096))}
	options = append(options, extraOptions...)
	conn, err := grpc.NewClient(address, options...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("Agent Egress Unavailable: %w", err)
	}
	streamCtx := metadata.AppendToOutgoingContext(ctx, "x-yaksha-egress-token", token)
	stream, err := pb.NewYakshaEgressGatewayClient(conn).Relay(streamCtx)
	if err != nil {
		conn.Close()
		cancel()
		return nil, fmt.Errorf("Agent Egress Unavailable: %w", err)
	}
	connector := &RelayConnector{ctx: ctx, cancel: cancel, conn: conn, stream: stream, routeID: routeID, items: map[string]*relayConnection{}}
	if err := connector.send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_HELLO, RouteId: routeID}); err != nil {
		connector.Close()
		return nil, err
	}
	ack, err := stream.Recv()
	if err != nil {
		connector.Close()
		return nil, fmt.Errorf("Agent Egress Unavailable: %w", err)
	}
	if ack.GetKind() != pb.EgressFrameKind_EGRESS_FRAME_HELLO_ACK || ack.GetRouteId() != routeID {
		connector.Close()
		return nil, fmt.Errorf("Agent Egress Unavailable: route was not acknowledged")
	}
	go connector.receive()
	return connector, nil
}

func (c *RelayConnector) Open(ctx context.Context, request OpenRequest) (OpenResult, error) {
	if c == nil || c.closed.Load() {
		return OpenResult{}, fmt.Errorf("Agent Egress Unavailable: relay is closed")
	}
	port, err := strconv.Atoi(request.Port)
	if err != nil || port < 1 || port > 65535 {
		return OpenResult{}, fmt.Errorf("invalid relay target port")
	}
	id := fmt.Sprintf("c-%d", c.nextID.Add(1))
	item := &relayConnection{readCh: make(chan relayReadEvent, 16), opened: make(chan *pb.EgressFrame, 1), done: make(chan struct{})}
	public := &relayConn{connector: c, item: item, id: id, deadlineWake: make(chan struct{}, 1), writeWake: make(chan struct{}, 1)}
	item.public = public
	c.mu.Lock()
	c.items[id] = item
	c.mu.Unlock()
	cleanup := func() { c.remove(id); item.close() }
	if err := c.send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_OPEN, RouteId: c.routeID, ConnectionId: id, Host: request.Host, Port: uint32(port), Protocol: request.Protocol}); err != nil {
		cleanup()
		return OpenResult{}, err
	}
	select {
	case response := <-item.opened:
		if response.GetKind() == pb.EgressFrameKind_EGRESS_FRAME_ERROR {
			cleanup()
			return OpenResult{}, errors.New(response.GetErrorMessage())
		}
		item.metadata = OpenMetadata{Mode: "relay", ResolvedIP: response.GetResolvedIp(), RemoteAddress: response.GetRemoteAddress()}
		return OpenResult{Conn: public, Metadata: item.metadata}, nil
	case <-ctx.Done():
		cleanup()
		return OpenResult{}, ctx.Err()
	case <-c.ctx.Done():
		cleanup()
		return OpenResult{}, fmt.Errorf("Agent Egress Unavailable: relay disconnected")
	}
}

func (c *RelayConnector) receive() {
	defer c.Close()
	for {
		frame, err := c.stream.Recv()
		if err != nil {
			return
		}
		if frame.GetRouteId() != c.routeID || len(frame.GetPayload()) > relayMaxFrame {
			continue
		}
		c.mu.Lock()
		item := c.items[frame.GetConnectionId()]
		c.mu.Unlock()
		if item == nil {
			continue
		}
		switch frame.GetKind() {
		case pb.EgressFrameKind_EGRESS_FRAME_OPEN_RESULT, pb.EgressFrameKind_EGRESS_FRAME_ERROR:
			select {
			case item.opened <- frame:
			default:
			}
			if frame.GetKind() == pb.EgressFrameKind_EGRESS_FRAME_ERROR {
				item.close()
				c.remove(frame.GetConnectionId())
			}
		case pb.EgressFrameKind_EGRESS_FRAME_DATA:
			select {
			case item.readCh <- relayReadEvent{data: append([]byte(nil), frame.GetPayload()...)}:
			case <-item.done:
			case <-c.ctx.Done():
				return
			default:
				item.close()
				c.remove(frame.GetConnectionId())
				go func(connectionID string) {
					_ = c.send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_CLOSE, RouteId: c.routeID, ConnectionId: connectionID})
				}(frame.GetConnectionId())
			}
		case pb.EgressFrameKind_EGRESS_FRAME_HALF_CLOSE:
			if item.readEOF.CompareAndSwap(false, true) {
				select {
				case item.readCh <- relayReadEvent{eof: true}:
				case <-item.done:
				case <-c.ctx.Done():
					return
				default:
					item.close()
					c.remove(frame.GetConnectionId())
					go func(connectionID string) {
						_ = c.send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_CLOSE, RouteId: c.routeID, ConnectionId: connectionID})
					}(frame.GetConnectionId())
				}
			}
		case pb.EgressFrameKind_EGRESS_FRAME_CLOSE:
			item.close()
			c.remove(frame.GetConnectionId())
		}
	}
}

func (c *RelayConnector) send(frame *pb.EgressFrame) error {
	if c.closed.Load() {
		return fmt.Errorf("Agent Egress Unavailable: relay is closed")
	}
	if len(frame.GetPayload()) > relayMaxFrame {
		return fmt.Errorf("relay frame exceeds %d bytes", relayMaxFrame)
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if err := c.stream.Send(frame); err != nil {
		return fmt.Errorf("Agent Egress Unavailable: %w", err)
	}
	return nil
}

func (c *RelayConnector) remove(id string) { c.mu.Lock(); delete(c.items, id); c.mu.Unlock() }

func (c *RelayConnector) Close() error {
	if c == nil || !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	c.cancel()
	c.mu.Lock()
	for id, item := range c.items {
		item.close()
		delete(c.items, id)
	}
	c.mu.Unlock()
	_ = c.stream.CloseSend()
	return c.conn.Close()
}

func (c *relayConnection) close() {
	c.once.Do(func() {
		close(c.done)
		c.public.closed.Store(true)
	})
}

func (c *relayConn) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readEnded {
		return 0, io.EOF
	}
	for len(c.readBuffer) == 0 {
		var timer <-chan time.Time
		var deadlineTimer *time.Timer
		if deadline := c.readDeadline.Load(); deadline > 0 {
			wait := time.Until(time.Unix(0, deadline))
			if wait <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			deadlineTimer = time.NewTimer(wait)
			timer = deadlineTimer.C
		}
		select {
		case event := <-c.item.readCh:
			if event.eof {
				c.readEnded = true
				if deadlineTimer != nil {
					deadlineTimer.Stop()
				}
				return 0, io.EOF
			}
			c.readBuffer = event.data
		case <-c.item.done:
			if deadlineTimer != nil {
				deadlineTimer.Stop()
			}
			return 0, net.ErrClosed
		case <-timer:
			return 0, os.ErrDeadlineExceeded
		case <-c.deadlineWake:
		}
		if deadlineTimer != nil {
			deadlineTimer.Stop()
		}
	}
	count := copy(buffer, c.readBuffer)
	c.readBuffer = c.readBuffer[count:]
	return count, nil
}

func (c *relayConn) Write(buffer []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() || c.writeClosed.Load() {
		return 0, net.ErrClosed
	}
	written := 0
	for len(buffer) > 0 {
		if deadline := c.writeDeadline.Load(); deadline > 0 && time.Now().UnixNano() >= deadline {
			return written, os.ErrDeadlineExceeded
		}
		count := min(len(buffer), relayMaxFrame)
		payload := append([]byte(nil), buffer[:count]...)
		if err := c.sendWithDeadline(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_DATA, RouteId: c.connector.routeID, ConnectionId: c.id, Sequence: c.sequence.Add(1), Payload: payload}); err != nil {
			return written, err
		}
		written += count
		buffer = buffer[count:]
	}
	return written, nil
}

func (c *relayConn) sendWithDeadline(frame *pb.EgressFrame) error {
	result := make(chan error, 1)
	go func() { result <- c.connector.send(frame) }()
	for {
		var timer *time.Timer
		var timerCh <-chan time.Time
		if deadline := c.writeDeadline.Load(); deadline > 0 {
			wait := time.Until(time.Unix(0, deadline))
			if wait <= 0 {
				_ = c.connector.Close()
				return os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(wait)
			timerCh = timer.C
		}
		select {
		case err := <-result:
			if timer != nil {
				timer.Stop()
			}
			return err
		case <-timerCh:
			_ = c.connector.Close()
			return os.ErrDeadlineExceeded
		case <-c.writeWake:
			if timer != nil {
				timer.Stop()
			}
		}
	}
}

func (c *relayConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() || !c.writeClosed.CompareAndSwap(false, true) {
		return nil
	}
	return c.connector.send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_HALF_CLOSE, RouteId: c.connector.routeID, ConnectionId: c.id})
}

func (c *relayConn) Close() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	err := c.connector.send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_CLOSE, RouteId: c.connector.routeID, ConnectionId: c.id})
	c.item.close()
	c.connector.remove(c.id)
	return err
}

func (c *relayConn) LocalAddr() net.Addr  { return relayAddr("yaksha-relay") }
func (c *relayConn) RemoteAddr() net.Addr { return relayAddr(c.item.metadata.RemoteAddress) }

func (c *relayConn) SetDeadline(deadline time.Time) error {
	if err := c.SetReadDeadline(deadline); err != nil {
		return err
	}
	return c.SetWriteDeadline(deadline)
}

func (c *relayConn) SetReadDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		c.readDeadline.Store(0)
	} else {
		c.readDeadline.Store(deadline.UnixNano())
	}
	select {
	case c.deadlineWake <- struct{}{}:
	default:
	}
	return nil
}

func (c *relayConn) SetWriteDeadline(deadline time.Time) error {
	if deadline.IsZero() {
		c.writeDeadline.Store(0)
	} else {
		c.writeDeadline.Store(deadline.UnixNano())
	}
	select {
	case c.writeWake <- struct{}{}:
	default:
	}
	return nil
}

var _ Connector = (*RelayConnector)(nil)
var _ io.Closer = (*RelayConnector)(nil)
