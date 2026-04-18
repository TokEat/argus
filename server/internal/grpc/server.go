package grpc

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-server/internal/api"
	"github.com/user/dddd-server/internal/db"
	"google.golang.org/grpc"
)

// Server 封装了对 Agent 通信的 gRPC 服务端
type Server struct {
	pb.UnimplementedAgentServiceServer
	port int
	// queue 负责从 redis 等调度队列获取任务，当前暂用回调解耦
	fetchTaskHook func(agentID string) (*pb.Task, error)
}

// NewServer 初始化 gRPC Server
func NewServer(port int) *Server {
	return &Server{
		port: port,
	}
}

// SetFetchTaskHook 注入从队列拉取任务的钩子
func (s *Server) SetFetchTaskHook(fn func(agentID string) (*pb.Task, error)) {
	s.fetchTaskHook = fn
}

// Serve 启动 gRPC 监听
func (s *Server) Serve() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAgentServiceServer(grpcServer, s)

	log.Printf("gRPC server listening at %v", lis.Addr())
	return grpcServer.Serve(lis)
}

// Register 节点上线注册
func (s *Server) Register(ctx context.Context, req *pb.RegisterReq) (*pb.RegisterResp, error) {
	log.Printf("[Register] Agent %s connected, version: %s", req.AgentId, req.Version)

	// 持久化落地
	db.DB.Save(&db.Node{
		AgentID:  req.AgentId,
		Status:   "Alive",
		LastBeat: time.Now().UnixMilli(),
	})

	return &pb.RegisterResp{
		Success: true,
		Token:   "dummy_token_" + req.AgentId,
	}, nil
}

func (s *Server) Heartbeat(ctx context.Context, req *pb.HeartbeatReq) (*pb.HeartbeatResp, error) {
	_ = db.DB.Model(&db.Node{}).Where("agent_id = ?", req.AgentId).
		Updates(map[string]interface{}{
			"status":    "Alive",
			"last_beat": time.Now().UnixMilli(),
		}).Error
	return &pb.HeartbeatResp{Ack: true, ShouldTerminate: false}, nil
}

func (s *Server) FetchTask(ctx context.Context, req *pb.FetchTaskReq) (*pb.Task, error) {
	var task *pb.Task
	var err error
	if s.fetchTaskHook != nil {
		task, err = s.fetchTaskHook(req.AgentId)
	}
	if task != nil && task.TaskId != "" {
		// 记录流转：状态变为执行中，挂载关联代理人
		db.DB.Model(&db.Task{}).Where("id = ?", task.TaskId).
			Updates(map[string]interface{}{
				"status":   "Running",
				"agent_id": req.AgentId,
			})
	} else if task == nil {
		task = &pb.Task{}
	}
	return task, err
}

// StreamResult 流式接收客户端回传的结果
func (s *Server) StreamResult(stream pb.AgentService_StreamResultServer) error {
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.Ack{Success: true, Message: "EOF"})
		}
		if err != nil {
			return err
		}
		log.Printf("[Result Hook] Task %s => Found %s: payload_size=%d", res.TaskId, res.PayloadType, len(res.Payload))

		// 1. 落库持久化
		_ = db.AddVuln(res.TaskId, res.PayloadType, string(res.Payload))

		// 2. 将此高价值资产/漏洞直接投送给所有订阅了大屏 WebSocket 的前端用户
		api.Hub.Broadcast(map[string]interface{}{
			"type":      "scan_result",
			"task_id":   res.TaskId,
			"vuln_type": res.PayloadType,
			"payload":   string(res.Payload),
			"timestamp": res.Timestamp,
		})
	}
}

// TaskComplete 任务完成通知
func (s *Server) TaskComplete(ctx context.Context, req *pb.TaskCompleteReq) (*pb.Ack, error) {
	log.Printf("[TaskComplete] Task %s by Agent %s => Status: %s", req.TaskId, req.AgentId, req.Status)
	db.DB.Model(&db.Task{}).Where("id = ?", req.TaskId).Update("status", req.Status)
	return &pb.Ack{Success: true}, nil
}

// EmergencyDump 紧急数据下刷（处理 Spot 回收）
func (s *Server) EmergencyDump(ctx context.Context, req *pb.EmergencyReq) (*pb.Ack, error) {
	log.Printf("[EmergencyDump] Agent %s is flushing all local states due to Spot termination signal!", req.AgentId)
	return &pb.Ack{Success: true, Message: "Safe drop signal received"}, nil
}
