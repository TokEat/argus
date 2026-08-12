package egress

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"strings"

	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const gatewayTokenHeader = "x-yaksha-egress-token"

type Gateway struct {
	pb.UnimplementedYakshaEgressGatewayServer
	Broker *Broker
	Token  string
}

func (g *Gateway) Relay(stream pb.YakshaEgressGateway_RelayServer) error {
	if g == nil || g.Broker == nil {
		return status.Error(codes.Unavailable, "Agent Egress Unavailable")
	}
	return g.Broker.Relay(stream)
}

func (g *Gateway) Serve(address string) error {
	address = strings.TrimSpace(address)
	token := strings.TrimSpace(g.Token)
	if address == "" || token == "" {
		return fmt.Errorf("ARGUS_EGRESS_GATEWAY_LISTEN and ARGUS_EGRESS_GATEWAY_TOKEN are required together")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen Yaksha egress gateway: %w", err)
	}
	interceptor := func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := validateGatewayToken(stream.Context(), token); err != nil {
			return err
		}
		return handler(srv, stream)
	}
	server := grpc.NewServer(grpc.StreamInterceptor(interceptor), grpc.MaxRecvMsgSize(MaxFrameBytes+4096), grpc.MaxSendMsgSize(MaxFrameBytes+4096))
	pb.RegisterYakshaEgressGatewayServer(server, g)
	return server.Serve(listener)
}

func validateGatewayToken(ctx context.Context, expected string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing Yaksha gateway metadata")
	}
	values := md.Get(gatewayTokenHeader)
	if len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), []byte(expected)) != 1 {
		return status.Error(codes.Unauthenticated, "invalid Yaksha gateway token")
	}
	return nil
}
