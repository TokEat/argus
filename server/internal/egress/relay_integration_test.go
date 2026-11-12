package egress

import (
	"context"
	"net"
	"testing"
	"time"

	pb "github.com/TokEat/argus/shared/proto/go/scan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type testAgentEgressService struct {
	pb.UnimplementedAgentEgressServiceServer
	broker *Broker
}

func (s testAgentEgressService) EgressTunnel(stream pb.AgentEgressService_EgressTunnelServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	return s.broker.AttachAgent(first.GetAgentId(), stream)
}

func bufDialer(listener *bufconn.Listener) func(context.Context, string) (net.Conn, error) {
	return func(context.Context, string) (net.Conn, error) { return listener.Dial() }
}

func TestBrokerRelaysMultiplexedFramesBetweenYakshaAndAgent(t *testing.T) {
	broker := NewBroker()
	agentListener := bufconn.Listen(1 << 20)
	agentServer := grpc.NewServer()
	pb.RegisterAgentEgressServiceServer(agentServer, testAgentEgressService{broker: broker})
	go agentServer.Serve(agentListener)
	defer agentServer.Stop()
	agentConn, err := grpc.NewClient("passthrough:///agent", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(bufDialer(agentListener)))
	if err != nil {
		t.Fatal(err)
	}
	defer agentConn.Close()
	agentStream, err := pb.NewAgentEgressServiceClient(agentConn).EgressTunnel(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := agentStream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_HELLO, AgentId: "agent-a"}); err != nil {
		t.Fatal(err)
	}
	if ack, err := agentStream.Recv(); err != nil || ack.GetKind() != pb.EgressFrameKind_EGRESS_FRAME_HELLO_ACK {
		t.Fatalf("agent ack=%v err=%v", ack, err)
	}
	closed := make(chan string, 1)
	go func() {
		for {
			frame, recvErr := agentStream.Recv()
			if recvErr != nil {
				return
			}
			switch frame.GetKind() {
			case pb.EgressFrameKind_EGRESS_FRAME_OPEN:
				_ = agentStream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_OPEN_RESULT, RouteId: frame.GetRouteId(), ConnectionId: frame.GetConnectionId(), ResolvedIp: "10.0.0.8", RemoteAddress: "10.0.0.8:443"})
			case pb.EgressFrameKind_EGRESS_FRAME_DATA:
				_ = agentStream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_DATA, RouteId: frame.GetRouteId(), ConnectionId: frame.GetConnectionId(), Sequence: frame.GetSequence(), Payload: append([]byte("echo:"), frame.GetPayload()...)})
			case pb.EgressFrameKind_EGRESS_FRAME_CLOSE:
				closed <- frame.GetConnectionId()
				_ = agentStream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_CLOSE, RouteId: frame.GetRouteId(), ConnectionId: frame.GetConnectionId()})
			}
		}
	}()

	route, err := broker.CreateRoute(context.Background(), RouteRequest{TenantID: "tenant-a", OperatorID: "7", AgentID: "agent-a", NetworkTargets: []string{"tcp://example.test:443"}, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	gatewayListener := bufconn.Listen(1 << 20)
	gatewayServer := grpc.NewServer()
	pb.RegisterYakshaEgressGatewayServer(gatewayServer, &Gateway{Broker: broker})
	go gatewayServer.Serve(gatewayListener)
	defer gatewayServer.Stop()
	gatewayConn, err := grpc.NewClient("passthrough:///gateway", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(bufDialer(gatewayListener)))
	if err != nil {
		t.Fatal(err)
	}
	defer gatewayConn.Close()
	relayContext, relayCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer relayCancel()
	stream, err := pb.NewYakshaEgressGatewayClient(gatewayConn).Relay(relayContext)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_HELLO, RouteId: route.RouteID}); err != nil {
		t.Fatal(err)
	}
	if ack, err := stream.Recv(); err != nil || ack.GetKind() != pb.EgressFrameKind_EGRESS_FRAME_HELLO_ACK {
		t.Fatalf("gateway ack=%v err=%v", ack, err)
	}
	if err := stream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_OPEN, RouteId: route.RouteID, ConnectionId: "c-1", Host: "example.test", Port: 443, Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	opened, err := stream.Recv()
	if err != nil || opened.GetKind() != pb.EgressFrameKind_EGRESS_FRAME_OPEN_RESULT || opened.GetResolvedIp() != "10.0.0.8" {
		t.Fatalf("open=%v err=%v", opened, err)
	}
	if err := stream.Send(&pb.EgressFrame{Kind: pb.EgressFrameKind_EGRESS_FRAME_DATA, RouteId: route.RouteID, ConnectionId: "c-1", Sequence: 1, Payload: []byte("hello")}); err != nil {
		t.Fatal(err)
	}
	echo, err := stream.Recv()
	if err != nil || string(echo.GetPayload()) != "echo:hello" {
		t.Fatalf("echo=%v err=%v", echo, err)
	}
	if _, err := broker.Revoke("tenant-a", route.RouteID, "test_cancel"); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err == nil {
		t.Fatal("relay remained open after route revocation")
	}
	select {
	case connectionID := <-closed:
		if connectionID != "c-1" {
			t.Fatalf("closed connection=%q", connectionID)
		}
	case <-time.After(time.Second):
		t.Fatal("Agent did not receive CLOSE after route revocation")
	}
}
