package gormrepo

import (
	"context"
	"time"

	"github.com/P0lar1ght/argus/server/internal/core/domain/node"
	"github.com/P0lar1ght/argus/server/internal/core/domain/result"
	"github.com/P0lar1ght/argus/server/internal/core/domain/rule"
	"github.com/P0lar1ght/argus/server/internal/core/domain/task"
	"github.com/P0lar1ght/argus/server/internal/shared/apperr"
	"gorm.io/gorm"
)

type RepositorySet struct {
	Tasks   task.Repository
	Nodes   node.Repository
	Rules   rule.Repository
	Results result.Repository
}

func NewRepositorySet(db *gorm.DB) *RepositorySet {
	return &RepositorySet{
		Tasks:   &TaskRepository{db: db},
		Nodes:   &NodeRepository{db: db},
		Rules:   &RuleRepository{db: db},
		Results: &ResultRepository{db: db},
	}
}

type TaskRepository struct {
	db *gorm.DB
}

func (r *TaskRepository) CreateRootTask(ctx context.Context, root *task.RootTask) error {
	return apperr.ErrNotImplemented
}

func (r *TaskRepository) CreateSubTasks(ctx context.Context, subtasks []*task.SubTask) error {
	return apperr.ErrNotImplemented
}

func (r *TaskRepository) GetRootTask(ctx context.Context, id string) (*task.RootTask, error) {
	return nil, apperr.ErrNotImplemented
}

func (r *TaskRepository) GetSubTask(ctx context.Context, id string) (*task.SubTask, error) {
	return nil, apperr.ErrNotImplemented
}

func (r *TaskRepository) ListRootTasks(ctx context.Context, filter task.RootTaskFilter) ([]task.RootTask, error) {
	return nil, apperr.ErrNotImplemented
}

func (r *TaskRepository) UpdateRootTaskStatus(ctx context.Context, id string, status task.RootTaskStatus) error {
	return apperr.ErrNotImplemented
}

func (r *TaskRepository) UpdateSubTaskStatus(ctx context.Context, id string, status task.SubTaskStatus) error {
	return apperr.ErrNotImplemented
}

func (r *TaskRepository) ListRecoverableSubTasks(ctx context.Context, agentID string) ([]task.SubTask, error) {
	return nil, apperr.ErrNotImplemented
}

func (r *TaskRepository) IncrementCompletedChunks(ctx context.Context, rootTaskID string, delta int) error {
	return apperr.ErrNotImplemented
}

type NodeRepository struct {
	db *gorm.DB
}

func (r *NodeRepository) Upsert(ctx context.Context, n *node.Node) error {
	return apperr.ErrNotImplemented
}

func (r *NodeRepository) Get(ctx context.Context, agentID string) (*node.Node, error) {
	return nil, apperr.ErrNotImplemented
}

func (r *NodeRepository) List(ctx context.Context, filter node.Filter) ([]node.Node, error) {
	return nil, apperr.ErrNotImplemented
}

func (r *NodeRepository) MarkHeartbeat(ctx context.Context, agentID string, status node.Status, at time.Time) error {
	return apperr.ErrNotImplemented
}

func (r *NodeRepository) ListExpired(ctx context.Context, cutoff time.Time) ([]node.Node, error) {
	return nil, apperr.ErrNotImplemented
}

type RuleRepository struct {
	db *gorm.DB
}

func (r *RuleRepository) SaveBundle(ctx context.Context, bundle *rule.Bundle) error {
	return apperr.ErrNotImplemented
}

func (r *RuleRepository) GetBundle(ctx context.Context, version string) (*rule.Bundle, error) {
	return nil, apperr.ErrNotImplemented
}

func (r *RuleRepository) GetActiveBundle(ctx context.Context) (*rule.Bundle, error) {
	return nil, apperr.ErrNotImplemented
}

func (r *RuleRepository) ListArtifacts(ctx context.Context, filter rule.ArtifactFilter) ([]rule.Artifact, error) {
	return nil, apperr.ErrNotImplemented
}

type ResultRepository struct {
	db *gorm.DB
}

func (r *ResultRepository) SaveAsset(ctx context.Context, asset *result.Asset) error {
	return apperr.ErrNotImplemented
}

func (r *ResultRepository) SaveFingerprintHit(ctx context.Context, hit *result.FingerprintHit) error {
	return apperr.ErrNotImplemented
}

func (r *ResultRepository) SaveVulnerability(ctx context.Context, vuln *result.Vulnerability) error {
	return apperr.ErrNotImplemented
}

func (r *ResultRepository) SaveBatch(ctx context.Context, batch *result.Batch) error {
	return apperr.ErrNotImplemented
}

func (r *ResultRepository) GetSummary(ctx context.Context, taskID string) (*result.Summary, error) {
	return nil, apperr.ErrNotImplemented
}

func (r *ResultRepository) ListVulnerabilities(ctx context.Context, filter result.VulnerabilityFilter) ([]result.Vulnerability, error) {
	return nil, apperr.ErrNotImplemented
}
