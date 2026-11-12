package grpc

import (
	"strings"

	pb "github.com/TokEat/argus/shared/proto/go/scan"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// EgressTunnel is deliberately independent from Subscribe. The first frame
// binds the authenticated registration session to one multiplexed tunnel.
func (s *Server) EgressTunnel(stream pb.AgentEgressService_EgressTunnelServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	agentID := strings.TrimSpace(first.GetAgentId())
	if first.GetKind() != pb.EgressFrameKind_EGRESS_FRAME_HELLO || agentID == "" {
		return status.Error(codes.InvalidArgument, "first egress frame must be HELLO with agent_id")
	}
	node, err := validateEmergencyAgentSession(stream.Context(), agentID)
	if err != nil {
		return err
	}
	if strings.TrimSpace(node.TenantID) == "" {
		return status.Error(codes.PermissionDenied, "agent tenant is unavailable")
	}
	if !strings.EqualFold(node.Status, "Alive") && !strings.EqualFold(node.Status, "Draining") {
		return status.Error(codes.FailedPrecondition, "agent is not online for egress")
	}
	if s.Egress == nil {
		return status.Error(codes.Unavailable, "Agent Egress Unavailable")
	}
	return s.Egress.AttachAgentWithExpiry(agentID, node.TokenExpiresAt, stream)
}
