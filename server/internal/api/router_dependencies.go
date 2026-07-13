package api

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/user/dddd-server/internal/db"
	grpcpkg "github.com/user/dddd-server/internal/grpc"
	"github.com/user/dddd-server/internal/scheduler"
)

// RouterDependencies groups runtime collaborators that were previously
// configured through independent package globals and setters.
type RouterDependencies struct {
	TaskQueue         *scheduler.TaskQueue
	NotifyHub         *grpcpkg.NotifyHub
	AgentPSK          string
	Build             *BuildService
	TaskRecovery      *TaskRecoveryService
	AgentLogRetention *AgentLogRetentionService
	Cloud             *CloudHandler
	ObjectStorageRoot string
}

// BuildService owns mutable build execution and cancellation state.
type BuildService struct {
	mu       sync.Mutex
	cancelMu sync.Mutex
	cancels  map[uint]context.CancelFunc
	runner   func(uint)
}

func newBuildService(runner func(uint)) *BuildService {
	return &BuildService{cancels: map[uint]context.CancelFunc{}, runner: runner}
}

func (s *BuildService) start(jobID uint) {
	runner := s.runner
	if runner == nil {
		runner = runBuildJob
	}
	go runner(jobID)
}

var errBuildAlreadyQueued = errors.New("another build job is already queued or running")

var activeRouterDependencies = &RouterDependencies{
	Build:             newBuildService(nil),
	ObjectStorageRoot: "./data/objects",
}

func normalizeRouterDependencies(deps RouterDependencies) *RouterDependencies {
	deps.AgentPSK = strings.TrimSpace(deps.AgentPSK)
	if deps.Build == nil {
		deps.Build = newBuildService(nil)
	}
	if deps.ObjectStorageRoot == "" {
		deps.ObjectStorageRoot = "./data/objects"
	}
	if deps.TaskRecovery == nil {
		deps.TaskRecovery = NewTaskRecoveryService(deps.TaskQueue)
	}
	if deps.AgentLogRetention == nil {
		deps.AgentLogRetention = NewAgentLogRetentionService()
	}
	deps.Cloud = deps.Cloud.normalize()
	return &deps
}

func NewRouterDependencies(queue *scheduler.TaskQueue, hub *grpcpkg.NotifyHub, agentPSK string) RouterDependencies {
	return *normalizeRouterDependencies(RouterDependencies{TaskQueue: queue, NotifyHub: hub, AgentPSK: agentPSK})
}

func routerRuntime() *RouterDependencies {
	return activeRouterDependencies
}

// ConfigureRouterDependencies installs one coherent runtime dependency set.
func ConfigureRouterDependencies(deps RouterDependencies) {
	activeRouterDependencies = normalizeRouterDependencies(deps)
	db.DebugEventHook = handleAgentDebugEvent
	db.ExploitCleanupDispatchHook = func(run db.ExploitRun) error {
		return dispatchExploitCleanup(run, run.TenantID)
	}
}
