package usecase

import (
	"context"

	"github.com/user/dddd-server/internal/core/domain/rule"
	"github.com/user/dddd-server/internal/shared/apperr"
)

type RuleCenter struct {
	repo rule.Repository
}

func NewRuleCenter(repo rule.Repository) *RuleCenter {
	return &RuleCenter{repo: repo}
}

func (uc *RuleCenter) PublishBundle(ctx context.Context, bundle *rule.Bundle) error {
	return apperr.ErrNotImplemented
}

func (uc *RuleCenter) FetchActiveBundle(ctx context.Context) (*rule.Bundle, error) {
	return nil, apperr.ErrNotImplemented
}
