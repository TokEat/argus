package usecase

import (
	"context"

	"github.com/P0lar1ght/argus/server/internal/core/domain/result"
	"github.com/P0lar1ght/argus/server/internal/shared/apperr"
)

type ResultAggregator struct {
	repo result.Repository
}

func NewResultAggregator(repo result.Repository) *ResultAggregator {
	return &ResultAggregator{repo: repo}
}

func (uc *ResultAggregator) IngestBatch(ctx context.Context, batch *result.Batch) error {
	return apperr.ErrNotImplemented
}

func (uc *ResultAggregator) SummarizeTask(ctx context.Context, taskID string) (*result.Summary, error) {
	return nil, apperr.ErrNotImplemented
}
