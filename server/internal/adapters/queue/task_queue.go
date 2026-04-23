package queue

import (
	"context"

	"github.com/user/dddd-server/internal/core/domain/task"
	"github.com/user/dddd-server/internal/shared/apperr"
)

// TaskQueueAdapter 预留给 RabbitMQ / 其他 MQ 适配实现。
type TaskQueueAdapter struct {
	name string
}

func NewTaskQueueAdapter(name string) *TaskQueueAdapter {
	return &TaskQueueAdapter{name: name}
}

func (a *TaskQueueAdapter) Enqueue(ctx context.Context, subtask *task.SubTask) error {
	return apperr.ErrNotImplemented
}

func (a *TaskQueueAdapter) EnqueueBatch(ctx context.Context, subtasks []*task.SubTask) error {
	return apperr.ErrNotImplemented
}

func (a *TaskQueueAdapter) EnqueueFront(ctx context.Context, subtask *task.SubTask) error {
	return apperr.ErrNotImplemented
}

func (a *TaskQueueAdapter) Dequeue(ctx context.Context, agentID string) (*task.SubTask, error) {
	return nil, apperr.ErrNotImplemented
}
