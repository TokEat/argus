package usecase

import (
	"context"

	"github.com/user/dddd-server/internal/core/domain/node"
	"github.com/user/dddd-server/internal/core/domain/task"
	"github.com/user/dddd-server/internal/shared/apperr"
)

type TaskScheduler struct {
	tasks task.Repository
	queue task.Queue
	nodes node.Repository
}

func NewTaskScheduler(tasks task.Repository, queue task.Queue, nodes node.Repository) *TaskScheduler {
	return &TaskScheduler{
		tasks: tasks,
		queue: queue,
		nodes: nodes,
	}
}

func (uc *TaskScheduler) LeaseNextSubTask(ctx context.Context, agentID string) (*task.SubTask, error) {
	return nil, apperr.ErrNotImplemented
}

func (uc *TaskScheduler) RecoverAgentTasks(ctx context.Context, agentID string) error {
	return apperr.ErrNotImplemented
}
