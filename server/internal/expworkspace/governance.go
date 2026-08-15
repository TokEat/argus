package expworkspace

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type RiskWaiverInput struct {
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

var ErrRiskConfirmationRequired = errors.New("high-risk EXP execution requires risk_confirmed=true or an active risk waiver")

func (s *Service) CheckExecutionAllowed(ctx context.Context, tenantID, expID string, revision int, action string, riskConfirmed bool) (bool, error) {
	root, err := s.GetExp(ctx, tenantID, expID)
	if err != nil {
		return false, err
	}
	action = strings.ToLower(strings.TrimSpace(action))
	type executionNode struct {
		expID    string
		revision int
	}
	queue := []executionNode{{expID: expID, revision: revision}}
	seen := map[string]bool{}
	waiverUsed := false
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		currentID := current.expID
		currentRevision := current.revision
		key := currentID + ":" + fmt.Sprint(currentRevision)
		if seen[key] {
			continue
		}
		seen[key] = true
		var currentExp db.Exp
		if currentID == expID {
			currentExp = root
		} else if err := s.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, currentID).First(&currentExp).Error; err != nil {
			return false, err
		}
		if currentExp.Status == db.ExpStatusDeprecated {
			return false, fmt.Errorf("deprecated EXP %s cannot be executed", currentID)
		}
		if action != "test" && (currentExp.RiskLevel == "high" || currentExp.RiskLevel == "critical") && !riskConfirmed {
			active, err := s.HasActiveRiskWaiver(ctx, tenantID, currentID)
			if err != nil {
				return false, err
			}
			if !active {
				return false, ErrRiskConfirmationRequired
			}
			waiverUsed = true
		}
		if currentRevision > 0 {
			var dependencies []db.ExpDependency
			if err := s.db.WithContext(ctx).Where("tenant_id = ? AND parent_exp_id = ? AND parent_revision = ?", tenantID, currentID, currentRevision).Find(&dependencies).Error; err != nil {
				return false, err
			}
			for _, dependency := range dependencies {
				queue = append(queue, executionNode{expID: dependency.DependencyExpID, revision: dependency.DependencyRevision})
			}
		}
	}
	return waiverUsed, nil
}

func (s *Service) HasActiveRiskWaiver(ctx context.Context, tenantID, expID string) (bool, error) {
	var count int64
	err := s.db.WithContext(ctx).Model(&db.ExpRiskWaiver{}).
		Where("tenant_id = ? AND exp_id = ? AND (expires_at IS NULL OR expires_at > ?)", tenantID, expID, time.Now().UTC()).
		Count(&count).Error
	return count > 0, err
}

func (s *Service) ListAudits(ctx context.Context, tenantID, expID string, offset, limit int) ([]db.ExpAudit, int64, error) {
	if _, err := s.GetExp(ctx, tenantID, expID); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	query := s.db.WithContext(ctx).Model(&db.ExpAudit{}).Where("tenant_id = ? AND exp_id = ?", tenantID, expID)
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var items []db.ExpAudit
	err := query.Order("created_at DESC, id DESC").Offset(offset).Limit(limit).Find(&items).Error
	return items, total, err
}

func (s *Service) GetRiskWaiver(ctx context.Context, tenantID, expID string) (db.ExpRiskWaiver, error) {
	if _, err := s.GetExp(ctx, tenantID, expID); err != nil {
		return db.ExpRiskWaiver{}, err
	}
	var waiver db.ExpRiskWaiver
	err := s.db.WithContext(ctx).Where("tenant_id = ? AND exp_id = ?", tenantID, expID).First(&waiver).Error
	return waiver, err
}

func (s *Service) UpsertRiskWaiver(ctx context.Context, tenantID, actorID, expID string, input RiskWaiverInput) (db.ExpRiskWaiver, error) {
	reason := strings.TrimSpace(input.Reason)
	if reason == "" {
		return db.ExpRiskWaiver{}, errors.New("risk waiver reason is required")
	}
	if input.ExpiresAt != nil && !input.ExpiresAt.After(time.Now().UTC()) {
		return db.ExpRiskWaiver{}, errors.New("risk waiver expires_at must be in the future")
	}
	var waiver db.ExpRiskWaiver
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var root db.Exp
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ? AND id = ?", tenantID, expID).First(&root).Error; err != nil {
			return err
		}
		if err := tx.Where("tenant_id = ? AND exp_id = ?", tenantID, expID).First(&waiver).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			waiver = db.ExpRiskWaiver{TenantID: tenantID, ExpID: expID, Reason: reason, GrantedBy: actorID, ExpiresAt: input.ExpiresAt}
			if err := tx.Create(&waiver).Error; err != nil {
				return err
			}
		} else {
			if err := tx.Model(&waiver).Updates(map[string]any{"reason": reason, "granted_by": actorID, "expires_at": input.ExpiresAt}).Error; err != nil {
				return err
			}
			if err := tx.Where("tenant_id = ? AND exp_id = ?", tenantID, expID).First(&waiver).Error; err != nil {
				return err
			}
		}
		return createAudit(tx, tenantID, expID, 0, actorID, "risk_waiver_upsert", map[string]any{"expires_at": input.ExpiresAt})
	})
	return waiver, err
}

func (s *Service) DeleteRiskWaiver(ctx context.Context, tenantID, actorID, expID string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("tenant_id = ? AND id = ?", tenantID, expID).First(&db.Exp{}).Error; err != nil {
			return err
		}
		result := tx.Where("tenant_id = ? AND exp_id = ?", tenantID, expID).Delete(&db.ExpRiskWaiver{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		return createAudit(tx, tenantID, expID, 0, actorID, "risk_waiver_delete", map[string]any{})
	})
}
