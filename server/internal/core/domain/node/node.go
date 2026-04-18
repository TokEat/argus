package node

import (
	"context"
	"time"

	"github.com/user/dddd-server/internal/core/domain/common"
)

type Status string

const (
	StatusOnline   Status = "Online"
	StatusIdle     Status = "Idle"
	StatusRunning  Status = "Running"
	StatusOffline  Status = "Offline"
	StatusDraining Status = "Draining"
)

type Node struct {
	AgentID       string
	Version       string
	Status        Status
	Tags          map[string]string
	Capacity      int
	RunningTasks  int
	RuleVersion   string
	LastHeartbeat time.Time
	CreatedAt     time.Time
}

type Filter struct {
	Statuses []Status
	Page     common.Page
}

type Repository interface {
	Upsert(ctx context.Context, node *Node) error
	Get(ctx context.Context, agentID string) (*Node, error)
	List(ctx context.Context, filter Filter) ([]Node, error)
	MarkHeartbeat(ctx context.Context, agentID string, status Status, at time.Time) error
	ListExpired(ctx context.Context, cutoff time.Time) ([]Node, error)
}
