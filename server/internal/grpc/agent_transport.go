package grpc

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	pb "github.com/TokEat/argus/shared/proto/go/scan"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func agentSupportsRiskValidation(version string) bool {
	return agentSupportsVersion(version, 2, 4, 0)
}

func agentSupportsCheckpointResume(version string) bool {
	return agentSupportsVersion(version, 2, 6, 0)
}

func agentSupportsVersion(version string, requiredMajor, requiredMinor, requiredPatch int) bool {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	patch, patchErr := strconv.Atoi(parts[2])
	if majorErr != nil || minorErr != nil || patchErr != nil || major < 0 || minor < 0 || patch < 0 {
		return false
	}
	if major != requiredMajor {
		return major > requiredMajor
	}
	if minor != requiredMinor {
		return minor > requiredMinor
	}
	return patch >= requiredPatch
}

// Serve starts the legacy Agent listener. Credential-validation work is never
// claimable on this plaintext transport.
func (s *Server) Serve() error {
	return s.serve(s.port, nil)
}

// ServeTLS starts the authenticated transport used by credential-validation Agents.
func (s *Server) ServeTLS(port int, certFile, keyFile string) error {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load Agent gRPC TLS certificate: %w", err)
	}
	transport := credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
	})
	return s.serve(port, transport)
}

func (s *Server) serve(port int, transport credentials.TransportCredentials) error {
	if s.agentPSKMissing() {
		return fmt.Errorf("agent PSK is required; set ARGUS_AGENT_PSK or pass --dev")
	}
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute, MaxConnectionAge: 2 * time.Hour,
			MaxConnectionAgeGrace: 30 * time.Second, Time: 30 * time.Second, Timeout: 10 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	}
	if transport != nil {
		opts = append(opts, grpc.Creds(transport))
	}
	if s.psk != "" {
		opts = append(opts, grpc.UnaryInterceptor(s.unaryPSKInterceptor), grpc.StreamInterceptor(s.streamPSKInterceptor))
		log.Printf("[Auth] Agent PSK authentication enabled")
	} else {
		log.Printf("[Auth] WARNING: Agent PSK not set, running in open mode (dev only)")
	}
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterAgentServiceServer(grpcServer, s)
	pb.RegisterAgentEgressServiceServer(grpcServer, s)
	log.Printf("gRPC server listening at %v (tls=%t)", lis.Addr(), transport != nil)
	return grpcServer.Serve(lis)
}

func (s *Server) unaryPSKInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if err := s.validatePSK(ctx); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (s *Server) streamPSKInterceptor(srv interface{}, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := s.validatePSK(stream.Context()); err != nil {
		return err
	}
	return handler(srv, stream)
}

func (s *Server) validatePSK(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	tokens := md.Get("x-agent-psk")
	presented := ""
	if len(tokens) > 0 {
		presented = tokens[0]
	}
	if subtle.ConstantTimeCompare([]byte(presented), []byte(s.psk)) != 1 {
		return status.Error(codes.Unauthenticated, "invalid agent pre-shared key")
	}
	return nil
}

func agentTransportTLS(ctx context.Context) bool {
	remote, ok := peer.FromContext(ctx)
	if !ok || remote.AuthInfo == nil {
		return false
	}
	switch remote.AuthInfo.(type) {
	case credentials.TLSInfo, *credentials.TLSInfo:
		return true
	default:
		return false
	}
}

func attestedAgentTags(ctx context.Context, supplied map[string]string) map[string]string {
	tags := make(map[string]string, len(supplied)+1)
	for key, value := range supplied {
		if key != "transport_tls" {
			tags[key] = value
		}
	}
	if agentTransportTLS(ctx) {
		tags["transport_tls"] = "verified"
	}
	return tags
}
