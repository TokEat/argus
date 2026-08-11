package usecase

import (
	"context"

	"github.com/P0lar1ght/argus/server/internal/core/domain/node"
	"github.com/P0lar1ght/argus/server/internal/core/domain/result"
	"github.com/P0lar1ght/argus/server/internal/core/domain/task"
	"github.com/P0lar1ght/argus/server/internal/shared/apperr"
)

type DashboardOverview struct {
	RootTaskCount      int64
	OnlineNodeCount    int64
	VulnerabilityCount int64
}

type DashboardQuery struct {
	tasks   task.Repository
	nodes   node.Repository
	results result.Repository
}

func NewDashboardQuery(tasks task.Repository, nodes node.Repository, results result.Repository) *DashboardQuery {
	return &DashboardQuery{
		tasks:   tasks,
		nodes:   nodes,
		results: results,
	}
}

func (uc *DashboardQuery) Overview(ctx context.Context) (*DashboardOverview, error) {
	return nil, apperr.ErrNotImplemented
}
