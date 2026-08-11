package api

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/P0lar1ght/argus/server/internal/assetdiscovery"
	"github.com/P0lar1ght/argus/server/internal/db"
	grpcpkg "github.com/P0lar1ght/argus/server/internal/grpc"
	"github.com/P0lar1ght/argus/server/internal/scheduler"
)

// FOFAQueryProvider is the bounded Server-side provider used by the project
// discovery API. Keeping it injectable prevents API tests from making real
// provider calls and keeps credentials inside the Server process.
type FOFAQueryProvider interface {
	Search(context.Context, assetdiscovery.FOFACredential, assetdiscovery.FOFAQuery) (assetdiscovery.Result, error)
}

// HunterQueryProvider is the bounded Server-side Hunter provider. It remains
// injectable so API tests never need a real tenant credential or network call.
type HunterQueryProvider interface {
	Search(context.Context, assetdiscovery.HunterCredential, assetdiscovery.HunterQuery) (assetdiscovery.Result, error)
}

// QuakeQueryProvider is the bounded Server-side Quake provider. It remains
// injectable so API tests never need a real tenant credential or network call.
type QuakeQueryProvider interface {
	Search(context.Context, assetdiscovery.QuakeCredential, assetdiscovery.QuakeQuery) (assetdiscovery.Result, error)
}

// RouterDependencies groups runtime collaborators that were previously
// configured through independent package globals and setters.
type RouterDependencies struct {
	TaskQueue            *scheduler.TaskQueue
	NotifyHub            *grpcpkg.NotifyHub
	AgentPSK             string
	Build                *BuildService
	TaskRecovery         *TaskRecoveryService
	AgentLogRetention    *AgentLogRetentionService
	AssetDiscoveryFOFA   FOFAQueryProvider
	AssetDiscoveryHunter HunterQueryProvider
	AssetDiscoveryQuake  QuakeQueryProvider
	Cloud                *CloudHandler
	ObjectStorageRoot    string
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
	Build:                newBuildService(nil),
	AssetDiscoveryFOFA:   assetdiscovery.NewFOFAClient(nil),
	AssetDiscoveryHunter: assetdiscovery.NewHunterClient(nil),
	AssetDiscoveryQuake:  assetdiscovery.NewQuakeClient(nil),
	ObjectStorageRoot:    "./data/objects",
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
	if deps.AssetDiscoveryFOFA == nil {
		deps.AssetDiscoveryFOFA = assetdiscovery.NewFOFAClient(nil)
	}
	if deps.AssetDiscoveryHunter == nil {
		deps.AssetDiscoveryHunter = assetdiscovery.NewHunterClient(nil)
	}
	if deps.AssetDiscoveryQuake == nil {
		deps.AssetDiscoveryQuake = assetdiscovery.NewQuakeClient(nil)
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
