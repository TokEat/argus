package task

import (
	"context"
	"time"

	"github.com/P0lar1ght/argus/server/internal/core/domain/common"
)

type RootTaskStatus string
type SubTaskStatus string

const (
	RootTaskStatusCreated  RootTaskStatus = "Created"
	RootTaskStatusQueued   RootTaskStatus = "Queued"
	RootTaskStatusRunning  RootTaskStatus = "Running"
	RootTaskStatusDone     RootTaskStatus = "Done"
	RootTaskStatusFailed   RootTaskStatus = "Failed"
	RootTaskStatusTimeout  RootTaskStatus = "Timeout"
	RootTaskStatusCanceled RootTaskStatus = "Cancelled"
)

const (
	SubTaskStatusPending   SubTaskStatus = "Pending"
	SubTaskStatusRunning   SubTaskStatus = "Running"
	SubTaskStatusDone      SubTaskStatus = "Done"
	SubTaskStatusFailed    SubTaskStatus = "Failed"
	SubTaskStatusTimeout   SubTaskStatus = "Timeout"
	SubTaskStatusCanceled  SubTaskStatus = "Cancelled"
	SubTaskStatusRecovered SubTaskStatus = "Recovered"
)

type RootTask struct {
	ID               string
	TenantID         string
	Name             string
	Status           RootTaskStatus
	OriginalTargets  []string
	ConfigJSON       string
	RuleVersion      string
	Priority         int
	TimeoutSeconds   int
	TotalChunks      int
	CompletedChunks  int
	TotalTargets     int // 原始目标总数
	CompletedTargets int // 已完成目标数
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type SubTask struct {
	ID             string
	RootTaskID     string
	Status         SubTaskStatus
	ChunkTargets   []string
	ConfigJSON     string
	RuleVersion    string
	AssignedAgent  string
	RetryCount     int
	MaxRetryCount  int
	TimeoutSeconds int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type RootTaskFilter struct {
	TenantID string
	Statuses []RootTaskStatus
	Page     common.Page
}

type Splitter interface {
	Split(targets []string, chunkSize int) [][]string
}

type Repository interface {
	CreateRootTask(ctx context.Context, root *RootTask) error
	CreateSubTasks(ctx context.Context, subtasks []*SubTask) error
	GetRootTask(ctx context.Context, id string) (*RootTask, error)
	GetSubTask(ctx context.Context, id string) (*SubTask, error)
	ListRootTasks(ctx context.Context, filter RootTaskFilter) ([]RootTask, error)
	UpdateRootTaskStatus(ctx context.Context, id string, status RootTaskStatus) error
	UpdateSubTaskStatus(ctx context.Context, id string, status SubTaskStatus) error
	ListRecoverableSubTasks(ctx context.Context, agentID string) ([]SubTask, error)
	IncrementCompletedChunks(ctx context.Context, rootTaskID string, delta int) error
}

type Queue interface {
	Enqueue(ctx context.Context, subtask *SubTask) error
	EnqueueBatch(ctx context.Context, subtasks []*SubTask) error
	EnqueueFront(ctx context.Context, subtask *SubTask) error
	Dequeue(ctx context.Context, agentID string) (*SubTask, error)
}
