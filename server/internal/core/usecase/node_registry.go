package usecase

import (
	"context"
	"time"

	"github.com/P0lar1ght/argus/server/internal/core/domain/node"
	"github.com/P0lar1ght/argus/server/internal/shared/apperr"
)

type RegisterNodeCommand struct {
	AgentID     string
	Version     string
	Tags        map[string]string
	Capacity    int
	RuleVersion string
}

type HeartbeatCommand struct {
	AgentID string
	Status  node.Status
	At      time.Time
}

type NodeRegistry struct {
	repo node.Repository
}

func NewNodeRegistry(repo node.Repository) *NodeRegistry {
	return &NodeRegistry{repo: repo}
}

func (uc *NodeRegistry) Register(ctx context.Context, cmd RegisterNodeCommand) (*node.Node, error) {
	return nil, apperr.ErrNotImplemented
}

func (uc *NodeRegistry) Heartbeat(ctx context.Context, cmd HeartbeatCommand) error {
	return apperr.ErrNotImplemented
}

func (uc *NodeRegistry) SweepExpiredNodes(ctx context.Context, cutoff time.Time) ([]node.Node, error) {
	return nil, apperr.ErrNotImplemented
}
