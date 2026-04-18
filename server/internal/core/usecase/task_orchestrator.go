package usecase

import (
	"context"

	"github.com/user/dddd-server/internal/core/domain/task"
	"github.com/user/dddd-server/internal/shared/apperr"
)

type CreateTaskCommand struct {
	TenantID       string
	Name           string
	Targets        []string
	ConfigJSON     string
	RuleVersion    string
	Priority       int
	ChunkSize      int
	TimeoutSeconds int
}

type TaskOrchestrator struct {
	repo  task.Repository
	queue task.Queue
}

func NewTaskOrchestrator(repo task.Repository, queue task.Queue) *TaskOrchestrator {
	return &TaskOrchestrator{repo: repo, queue: queue}
}

func (uc *TaskOrchestrator) CreateRootTask(ctx context.Context, cmd CreateTaskCommand) (*task.RootTask, []task.SubTask, error) {
	return nil, nil, apperr.ErrNotImplemented
}

func (uc *TaskOrchestrator) CancelRootTask(ctx context.Context, rootTaskID string) error {
	return apperr.ErrNotImplemented
}
