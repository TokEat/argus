package expworkspace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/storage"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var logicalIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Service struct {
	db        *gorm.DB
	objects   storage.Store
	runtime   *RuntimeClient
	retention time.Duration
	mu        sync.Mutex
	runs      map[string]context.CancelFunc
}

func NewService(database *gorm.DB, objects storage.Store, runtime *RuntimeClient, retention time.Duration) (*Service, error) {
	if database == nil || objects == nil {
		return nil, errors.New("EXP database and MinIO object store are required")
	}
	if retention <= 0 {
		retention = 7 * 24 * time.Hour
	}
	return &Service{db: database, objects: objects, runtime: runtime, retention: retention, runs: map[string]context.CancelFunc{}}, nil
}

func (s *Service) CreateExp(ctx context.Context, tenantID, actorID, name, description, riskLevel string) (db.Exp, error) {
	tenantID, actorID, name = strings.TrimSpace(tenantID), strings.TrimSpace(actorID), strings.TrimSpace(name)
	riskLevel = strings.ToLower(strings.TrimSpace(riskLevel))
	if tenantID == "" || actorID == "" || name == "" {
		return db.Exp{}, errors.New("tenant, actor and name are required")
	}
	switch riskLevel {
	case "low", "medium", "high", "critical":
	default:
		return db.Exp{}, errors.New("risk_level must be low, medium, high or critical")
	}
	item := db.Exp{ID: uuid.NewString(), TenantID: tenantID, Name: name, Description: strings.TrimSpace(description), RiskLevel: riskLevel, Status: db.ExpStatusDraft, CreatedBy: actorID}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&item).Error; err != nil {
			return err
		}
		return createAudit(tx, tenantID, item.ID, 0, actorID, "create", map[string]any{"risk_level": riskLevel})
	}); err != nil {
		return db.Exp{}, fmt.Errorf("create EXP: %w", err)
	}
	return item, nil
}

func (s *Service) ListExps(ctx context.Context, tenantID string, offset, limit int) ([]db.Exp, int64, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	query := s.db.WithContext(ctx).Model(&db.Exp{}).Where("tenant_id = ?", tenantID)
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var items []db.Exp
	err := query.Order("updated_at DESC").Offset(offset).Limit(limit).Find(&items).Error
	return items, total, err
}

func (s *Service) GetExp(ctx context.Context, tenantID, expID string) (db.Exp, error) {
	var item db.Exp
	err := s.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, expID).First(&item).Error
	return item, err
}

func (s *Service) UpdateExp(ctx context.Context, tenantID, actorID, expID, name, description, riskLevel string, allowRiskDecrease bool) (db.Exp, error) {
	item, err := s.GetExp(ctx, tenantID, expID)
	if err != nil {
		return db.Exp{}, err
	}
	if item.Status == db.ExpStatusDeprecated {
		return db.Exp{}, errors.New("deprecated EXP metadata is immutable")
	}
	updates := map[string]any{}
	if strings.TrimSpace(name) != "" {
		updates["name"] = strings.TrimSpace(name)
	}
	updates["description"] = strings.TrimSpace(description)
	if riskLevel != "" {
		riskLevel = strings.ToLower(strings.TrimSpace(riskLevel))
		switch riskLevel {
		case "low", "medium", "high", "critical":
			updates["risk_level"] = riskLevel
		default:
			return db.Exp{}, errors.New("risk_level must be low, medium, high or critical")
		}
		if riskLevelRank(riskLevel) < riskLevelRank(item.RiskLevel) && !allowRiskDecrease {
			return db.Exp{}, errors.New("only Admin can lower EXP risk_level")
		}
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&db.Exp{}).Where("tenant_id = ? AND id = ?", tenantID, expID).Updates(updates).Error; err != nil {
			return err
		}
		return createAudit(tx, tenantID, expID, 0, actorID, "update_metadata", updates)
	})
	if err != nil {
		return db.Exp{}, err
	}
	return s.GetExp(ctx, tenantID, expID)
}

func riskLevelRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func (s *Service) DeprecateExp(ctx context.Context, tenantID, actorID, expID string) error {
	now := time.Now().UTC()
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&db.Exp{}).Where("tenant_id = ? AND id = ? AND status <> ?", tenantID, expID, db.ExpStatusDeprecated).Updates(map[string]any{"status": db.ExpStatusDeprecated, "deprecated_at": now})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		return createAudit(tx, tenantID, expID, 0, actorID, "deprecate", map[string]any{})
	})
}

func (s *Service) CreateRevision(ctx context.Context, tenantID, actorID, expID string, input CreateRevisionInput) (db.ExpRevision, error) {
	if err := validateDraftSource(input.Source); err != nil {
		return db.ExpRevision{}, err
	}
	if len(input.Dependencies) > MaxDependencies || len(input.Assets) > MaxAssets {
		return db.ExpRevision{}, errors.New("revision resolver limits exceeded")
	}
	hash := contentHash([]byte(input.Source))
	key := sourceObjectKey(tenantID, hash)
	if err := s.putImmutable(ctx, key, []byte(input.Source), hash); err != nil {
		return db.ExpRevision{}, fmt.Errorf("store revision source: %w", err)
	}

	var created db.ExpRevision
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		created, err = s.createRevisionRecord(tx, tenantID, actorID, expID, input, key, hash)
		return err
	})
	if err != nil {
		return db.ExpRevision{}, err
	}
	return created, nil
}

func (s *Service) createRevisionRecord(tx *gorm.DB, tenantID, actorID, expID string, input CreateRevisionInput, key, hash string) (db.ExpRevision, error) {
	var root db.Exp
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ? AND id = ?", tenantID, expID).First(&root).Error; err != nil {
		return db.ExpRevision{}, err
	}
	if root.Status == db.ExpStatusDeprecated {
		return db.ExpRevision{}, errors.New("deprecated EXP cannot accept revisions")
	}
	var last int
	if err := tx.Model(&db.ExpRevision{}).Where("tenant_id = ? AND exp_id = ?", tenantID, expID).Select("COALESCE(MAX(revision), 0)").Scan(&last).Error; err != nil {
		return db.ExpRevision{}, err
	}
	created := db.ExpRevision{ExpID: expID, TenantID: tenantID, Revision: last + 1, Status: db.ExpStatusDraft, SourceObjectKey: key, SourceSHA256: hash, SourceSize: int64(len(input.Source)), CLISchema: "{}", InspectSummary: "{}", ValidateSummary: "{}", CreatedBy: actorID}
	if err := tx.Create(&created).Error; err != nil {
		return db.ExpRevision{}, err
	}
	if err := s.createDependencyRows(tx, tenantID, created, input.Dependencies); err != nil {
		return db.ExpRevision{}, err
	}
	if err := s.createAssetRefRows(tx, tenantID, created, input.Assets); err != nil {
		return db.ExpRevision{}, err
	}
	if err := s.rejectDependencyCycle(tx, tenantID, expID, created.Revision); err != nil {
		return db.ExpRevision{}, err
	}
	if err := createAudit(tx, tenantID, expID, created.Revision, actorID, "create_revision", map[string]any{"source_sha256": hash}); err != nil {
		return db.ExpRevision{}, err
	}
	return created, nil
}

func (s *Service) GetRevision(ctx context.Context, tenantID, expID string, revision int) (db.ExpRevision, error) {
	var item db.ExpRevision
	err := s.db.WithContext(ctx).Where("tenant_id = ? AND exp_id = ? AND revision = ?", tenantID, expID, revision).First(&item).Error
	return item, err
}

func (s *Service) ListRevisions(ctx context.Context, tenantID, expID string) ([]db.ExpRevision, error) {
	var items []db.ExpRevision
	err := s.db.WithContext(ctx).Where("tenant_id = ? AND exp_id = ?", tenantID, expID).Order("revision DESC").Find(&items).Error
	return items, err
}

func (s *Service) PutAsset(ctx context.Context, tenantID, actorID, assetID, mediaType string, content []byte) (db.ExpAsset, error) {
	assetID = strings.TrimSpace(assetID)
	if !logicalIDPattern.MatchString(assetID) {
		return db.ExpAsset{}, errors.New("asset_id is invalid")
	}
	if len(content) == 0 || len(content) > MaxAssetBytes {
		return db.ExpAsset{}, fmt.Errorf("asset must contain 1 to %d bytes", MaxAssetBytes)
	}
	hash := contentHash(content)
	key := assetObjectKey(tenantID, hash)
	if err := s.putImmutable(ctx, key, content, hash); err != nil {
		return db.ExpAsset{}, err
	}
	var item db.ExpAsset
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var last int
		if err := tx.Model(&db.ExpAsset{}).Where("tenant_id = ? AND asset_id = ?", tenantID, assetID).Select("COALESCE(MAX(version), 0)").Scan(&last).Error; err != nil {
			return err
		}
		item = db.ExpAsset{TenantID: tenantID, AssetID: assetID, Version: last + 1, ObjectKey: key, SHA256: hash, Size: int64(len(content)), MediaType: strings.TrimSpace(mediaType), CreatedBy: actorID}
		if item.MediaType == "" {
			item.MediaType = "application/octet-stream"
		}
		return tx.Create(&item).Error
	})
	return item, err
}

func (s *Service) ListAssets(ctx context.Context, tenantID string) ([]db.ExpAsset, error) {
	var items []db.ExpAsset
	err := s.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Order("asset_id ASC, version DESC").Find(&items).Error
	return items, err
}

func (s *Service) GetAssetContent(ctx context.Context, tenantID, assetID string, version int) (db.ExpAsset, SealedAsset, error) {
	var item db.ExpAsset
	if err := s.db.WithContext(ctx).Where("tenant_id = ? AND asset_id = ? AND version = ?", tenantID, assetID, version).First(&item).Error; err != nil {
		return item, SealedAsset{}, err
	}
	content, err := s.readVerifiedObject(ctx, item.ObjectKey, item.SHA256, item.Size)
	if err != nil {
		return item, SealedAsset{}, err
	}
	sealed := sealedAssetFromContent(item.AssetID, item.SHA256, content)
	return item, sealed, nil
}

func (s *Service) DeleteAsset(ctx context.Context, tenantID, assetID string, version int) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&db.ExpAssetRef{}).Where("tenant_id = ? AND asset_id = ? AND asset_version = ?", tenantID, assetID, version).Count(&count).Error; err != nil {
			return err
		}
		if count > 0 {
			return errors.New("asset is referenced by an EXP revision")
		}
		result := tx.Where("tenant_id = ? AND asset_id = ? AND version = ?", tenantID, assetID, version).Delete(&db.ExpAsset{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
}

func (s *Service) putImmutable(ctx context.Context, key string, content []byte, expectedHash string) error {
	if object, exists, err := s.objects.Exists(ctx, key); err != nil {
		return err
	} else if exists {
		if object.Size != int64(len(content)) {
			return errors.New("immutable object key collision")
		}
		stored, err := s.readVerifiedObject(ctx, key, expectedHash, int64(len(content)))
		if err != nil || !bytes.Equal(stored, content) {
			return errors.New("immutable object integrity check failed")
		}
		return nil
	}
	object, err := s.objects.Put(ctx, key, bytes.NewReader(content))
	if err != nil {
		return err
	}
	if object.Size != int64(len(content)) {
		return errors.New("stored object size mismatch")
	}
	reader, _, err := s.objects.Open(ctx, key)
	if err != nil {
		return err
	}
	defer reader.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, io.LimitReader(reader, int64(len(content))+1)); err != nil {
		return err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != expectedHash {
		return errors.New("stored object hash mismatch")
	}
	return nil
}

func contentHash(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func tenantObjectPrefix(tenantID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(tenantID)))
	return "tenants/" + hex.EncodeToString(sum[:])
}

func sourceObjectKey(tenantID, hash string) string {
	return tenantObjectPrefix(tenantID) + "/exp/sources/" + hash + "/main.yak"
}

func assetObjectKey(tenantID, hash string) string {
	return tenantObjectPrefix(tenantID) + "/exp/assets/" + hash
}

func artifactObjectKey(tenantID, runID, hash string) string {
	return tenantObjectPrefix(tenantID) + "/exp/runs/" + runID + "/" + hash + ".json"
}

func createAudit(tx *gorm.DB, tenantID, expID string, revision int, actorID, action string, details any) error {
	raw, err := json.Marshal(details)
	if err != nil {
		return err
	}
	return tx.Create(&db.ExpAudit{TenantID: tenantID, ExpID: expID, Revision: revision, ActorID: actorID, Action: action, Details: string(raw)}).Error
}
