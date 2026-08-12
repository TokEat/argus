package expworkspace

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
)

func (s *Service) StartMaintenance(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().UTC()
			if _, err := s.ExpireRunArtifacts(ctx, now); err != nil {
				log.Printf("[EXP] run artifact retention failed; retrying next cycle: %v", err)
			}
			if _, err := s.CleanupOrphanObjects(ctx, 24*time.Hour, now); err != nil {
				log.Printf("[EXP] orphan object cleanup failed; retrying next cycle: %v", err)
			}
		}
	}
}

func (s *Service) ExpireRunArtifacts(ctx context.Context, now time.Time) (int, error) {
	var runs []db.ExpRun
	if err := s.db.WithContext(ctx).Where("artifact_object_key <> '' AND artifact_expires_at IS NOT NULL AND artifact_expires_at <= ?", now).Find(&runs).Error; err != nil {
		return 0, err
	}
	deleted := 0
	for _, run := range runs {
		result := s.db.WithContext(ctx).Model(&db.ExpRun{}).Where("tenant_id = ? AND id = ? AND artifact_object_key = ?", run.TenantID, run.ID, run.ArtifactObjectKey).Updates(map[string]any{"artifact_object_key": "", "artifact_sha256": "", "artifact_expires_at": nil})
		if result.Error != nil {
			return deleted, result.Error
		}
		if result.RowsAffected == 0 {
			continue
		}
		// Clear the database reference first. If object deletion then fails, the
		// body is merely an orphan and the independent 24h cleanup can retry it;
		// the inverse order could leave a live row pointing at a missing object.
		if err := s.objects.Delete(ctx, run.ArtifactObjectKey); err != nil && !isMissingObjectError(err) {
			return deleted, fmt.Errorf("delete expired run artifact: %w", err)
		}
		deleted++
	}
	return deleted, nil
}

func (s *Service) CleanupOrphanObjects(ctx context.Context, minimumAge time.Duration, now time.Time) (int, error) {
	if minimumAge < 24*time.Hour {
		return 0, errors.New("orphan object minimum age cannot be less than 24h")
	}
	references := map[string]struct{}{}
	var revisionKeys, assetKeys, runKeys []string
	if err := s.db.WithContext(ctx).Model(&db.ExpRevision{}).Where("source_object_key <> ''").Pluck("source_object_key", &revisionKeys).Error; err != nil {
		return 0, err
	}
	if err := s.db.WithContext(ctx).Model(&db.ExpAsset{}).Where("object_key <> ''").Pluck("object_key", &assetKeys).Error; err != nil {
		return 0, err
	}
	if err := s.db.WithContext(ctx).Model(&db.ExpRun{}).Where("artifact_object_key <> ''").Pluck("artifact_object_key", &runKeys).Error; err != nil {
		return 0, err
	}
	for _, keys := range [][]string{revisionKeys, assetKeys, runKeys} {
		for _, key := range keys {
			references[key] = struct{}{}
		}
	}
	objects, err := s.objects.List(ctx, "tenants/")
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, object := range objects {
		if _, referenced := references[object.Key]; referenced || object.ModTime.IsZero() || now.Sub(object.ModTime) < minimumAge {
			continue
		}
		if err := s.objects.Delete(ctx, object.Key); err != nil && !isMissingObjectError(err) {
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
}

func isMissingObjectError(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "not found") || strings.Contains(text, "no such file") || strings.Contains(text, "nosuchkey")
}
