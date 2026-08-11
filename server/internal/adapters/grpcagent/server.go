package grpcagent

import (
	"context"

	"github.com/P0lar1ght/argus/server/internal/adapters/ws"
	"github.com/P0lar1ght/argus/server/internal/core/usecase"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server 预留给 Agent gRPC 传输层，后续逐步替换当前 internal/grpc 包中的直接实现。
type Server struct {
	pb.UnimplementedAgentServiceServer
	usecases *usecase.Set
	hub      *ws.Hub
}

func NewServer(usecases *usecase.Set, hub *ws.Hub) *Server {
	return &Server{
		usecases: usecases,
		hub:      hub,
	}
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterReq) (*pb.RegisterResp, error) {
	return nil, status.Error(codes.Unimplemented, "grpc adapter scaffold created, register is not implemented")
}

func (s *Server) Heartbeat(ctx context.Context, req *pb.HeartbeatReq) (*pb.HeartbeatResp, error) {
	return nil, status.Error(codes.Unimplemented, "grpc adapter scaffold created, heartbeat is not implemented")
}

func (s *Server) FetchTask(ctx context.Context, req *pb.FetchTaskReq) (*pb.Task, error) {
	return nil, status.Error(codes.Unimplemented, "grpc adapter scaffold created, fetch task is not implemented")
}

func (s *Server) StreamResult(stream pb.AgentService_StreamResultServer) error {
	return status.Error(codes.Unimplemented, "grpc adapter scaffold created, stream result is not implemented")
}

func (s *Server) TaskComplete(ctx context.Context, req *pb.TaskCompleteReq) (*pb.Ack, error) {
	return nil, status.Error(codes.Unimplemented, "grpc adapter scaffold created, task complete is not implemented")
}

func (s *Server) EmergencyDump(ctx context.Context, req *pb.EmergencyReq) (*pb.Ack, error) {
	return nil, status.Error(codes.Unimplemented, "grpc adapter scaffold created, emergency dump is not implemented")
}
