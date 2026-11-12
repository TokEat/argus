package egress

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	pb "github.com/TokEat/argus/shared/proto/go/scan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

type relayTestGateway struct {
	pb.UnimplementedYakshaEgressGatewayServer
}

func (relayTestGateway) Relay(stream pb.YakshaEgressGateway_RelayServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	if values := md.Get("x-yaksha-egress-token"); len(values) != 1 || values[0] != "secret" {
		return io.ErrUnexpectedEOF
	}
	hello, err := stream.Recv()
	if err != nil {
		return err
	}
	if err := stream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_HELLO_ACK, RouteId: hello.GetRouteId()}); err != nil {
		return err
	}
	opened, err := stream.Recv()
	if err != nil {
		return err
	}
	if err := stream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_OPEN_RESULT, RouteId: opened.GetRouteId(), ConnectionId: opened.GetConnectionId(), ResolvedIp: "10.0.0.8", RemoteAddress: "10.0.0.8:443"}); err != nil {
		return err
	}
	data, err := stream.Recv()
	if err != nil {
		return err
	}
	if err := stream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_DATA, RouteId: data.GetRouteId(), ConnectionId: data.GetConnectionId(), Payload: []byte("pong")}); err != nil {
		return err
	}
	if err := stream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_DATA, RouteId: data.GetRouteId(), ConnectionId: data.GetConnectionId(), Payload: []byte("tail")}); err != nil {
		return err
	}
	if err := stream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_HALF_CLOSE, RouteId: data.GetRouteId(), ConnectionId: data.GetConnectionId()}); err != nil {
		return err
	}
	afterHalfClose, err := stream.Recv()
	if err != nil {
		return err
	}
	if afterHalfClose.GetKind() != pb.EgressFrameKind_EGRESS_FRAME_DATA || string(afterHalfClose.GetPayload()) != "still-writable" {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func TestRelayConnectorCarriesRawConnectionOverGateway(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	pb.RegisterYakshaEgressGatewayServer(server, relayTestGateway{})
	go server.Serve(listener)
	defer server.Stop()
	dialer := func(context.Context, string) (net.Conn, error) { return listener.Dial() }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connector, err := newRelayConnector(ctx, "passthrough:///gateway", "secret", "route-1", grpc.WithContextDialer(dialer))
	if err != nil {
		t.Fatal(err)
	}
	defer connector.Close()
	opened, err := connector.Open(ctx, OpenRequest{Host: "example.test", Port: "443", Protocol: "tcp", Deadline: time.Now().Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if opened.Metadata.ResolvedIP != "10.0.0.8" {
		t.Fatalf("metadata=%+v", opened.Metadata)
	}
	if _, err := opened.Conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(opened.Conn, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "pong" {
		t.Fatalf("response=%q", buffer)
	}
	tail := make([]byte, 4)
	if _, err := io.ReadFull(opened.Conn, tail); err != nil || string(tail) != "tail" {
		t.Fatalf("queued data before remote half-close = %q, %v", tail, err)
	}
	if _, err := opened.Conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read after remote half-close error = %v, want EOF", err)
	}
	if _, err := opened.Conn.Write([]byte("still-writable")); err != nil {
		t.Fatalf("write after remote half-close: %v", err)
	}
}

func TestRelayReadDeadlineAppliesToPendingRead(t *testing.T) {
	item := &relayConnection{readCh: make(chan relayReadEvent, 1), done: make(chan struct{})}
	conn := &relayConn{item: item, deadlineWake: make(chan struct{}, 1), writeWake: make(chan struct{}, 1)}
	item.public = conn
	result := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		result <- err
	}()
	time.Sleep(10 * time.Millisecond)
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !os.IsTimeout(err) {
			t.Fatalf("pending Read error = %v, want deadline", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending Read was not woken by SetReadDeadline")
	}
}
