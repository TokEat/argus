package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/assetdiscovery"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

const (
	assetDiscoverySnapshotTimeout   = 10 * time.Second
	assetDiscoverySnapshotBatchSize = 500
	assetDiscoverySnapshotItemLimit = 10000
)

var errInvalidAssetDiscoverySnapshot = errors.New("invalid asset discovery snapshot")

func completeProjectDiscoveryPreview(c *gin.Context, projectID string, request projectDiscoveryQueryRequest, result assetdiscovery.Result, audit *db.AssetDiscoveryAudit) {
	if result.Assets == nil {
		result.Assets = []assetdiscovery.Asset{}
	}
	audit.Status = "success"
	audit.ProviderTotal = result.ProviderTotal
	audit.ReturnedCount = len(result.Assets)
	audit.SkippedRows = result.SkippedRows
	audit.Truncated = result.Truncated

	if err := persistAssetDiscoverySnapshot(audit, request, result); err != nil {
		// The successful audit belongs to the rolled-back transaction. Record a
		// separate stable failure audit when possible, but never expose results
		// if either the snapshot or audit path is unavailable.
		audit.ID = 0
		audit.Status = "failed"
		audit.ReturnedCount = 0
		if errors.Is(err, errInvalidAssetDiscoverySnapshot) {
			audit.ErrorCode = "snapshot_validation_failed"
		} else {
			audit.ErrorCode = "snapshot_persistence_failed"
		}
		_ = saveAssetDiscoveryAudit(audit)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist asset discovery result"})
		return
	}

	c.JSON(http.StatusOK, projectDiscoveryQueryResponse{
		SchemaVersion: assetDiscoveryPreviewSchema,
		ProjectID:     projectID,
		AuditID:       audit.ID,
		Provider:      result.Provider,
		ProviderTotal: result.ProviderTotal,
		SkippedRows:   result.SkippedRows,
		Truncated:     result.Truncated,
		Assets:        result.Assets,
	})
}

func persistAssetDiscoverySnapshot(audit *db.AssetDiscoveryAudit, request projectDiscoveryQueryRequest, result assetdiscovery.Result) error {
	if db.DB == nil || audit == nil {
		return errors.New("asset discovery database is unavailable")
	}
	snapshot, items, err := buildAssetDiscoverySnapshot(audit, request, result, time.Now().UTC())
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), assetDiscoverySnapshotTimeout)
	defer cancel()
	return db.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(audit).Error; err != nil {
			return fmt.Errorf("create asset discovery audit: %w", err)
		}
		snapshot.AuditID = audit.ID
		if err := tx.Create(&snapshot).Error; err != nil {
			return fmt.Errorf("create asset discovery snapshot: %w", err)
		}
		for index := range items {
			items[index].SnapshotID = snapshot.ID
		}
		if len(items) > 0 {
			if err := tx.CreateInBatches(&items, assetDiscoverySnapshotBatchSize).Error; err != nil {
				return fmt.Errorf("create asset discovery snapshot items: %w", err)
			}
		}
		return nil
	})
}

func buildAssetDiscoverySnapshot(audit *db.AssetDiscoveryAudit, request projectDiscoveryQueryRequest, result assetdiscovery.Result, observedAt time.Time) (db.AssetDiscoverySnapshot, []db.AssetDiscoverySnapshotItem, error) {
	var snapshot db.AssetDiscoverySnapshot
	provider := strings.ToLower(strings.TrimSpace(audit.Provider))
	if audit.TenantID == "" || audit.ProjectID == "" || audit.OperatorID == "" || provider == "" ||
		provider != strings.ToLower(strings.TrimSpace(result.Provider)) || len(provider) > 32 ||
		request.Expression == "" || len(request.Expression) > assetdiscovery.MaxFOFAQueryBytes ||
		!validSnapshotText(request.Expression, assetdiscovery.MaxFOFAQueryBytes, true) || strings.ContainsAny(request.Expression, "\r\n\x00") ||
		request.Limit < 1 || result.ProviderTotal < 0 || result.SkippedRows < 0 || len(result.Assets) > assetDiscoverySnapshotItemLimit {
		return snapshot, nil, errInvalidAssetDiscoverySnapshot
	}
	if !validSHA256Hex(audit.QueryHash) || !validSHA256Hex(audit.ConfigHash) {
		return snapshot, nil, errInvalidAssetDiscoverySnapshot
	}

	snapshot = db.AssetDiscoverySnapshot{
		SchemaVersion:  db.AssetDiscoverySnapshotSchemaVersion,
		TenantID:       audit.TenantID,
		ProjectID:      audit.ProjectID,
		Provider:       provider,
		Expression:     request.Expression,
		QueryHash:      audit.QueryHash,
		ConfigVersion:  audit.ConfigVersion,
		ConfigHash:     audit.ConfigHash,
		RequestedLimit: request.Limit,
		ProviderTotal:  result.ProviderTotal,
		ReturnedCount:  len(result.Assets),
		SkippedRows:    result.SkippedRows,
		Truncated:      result.Truncated,
		CreatedBy:      audit.OperatorID,
		CreatedAt:      observedAt,
	}
	items := make([]db.AssetDiscoverySnapshotItem, 0, len(result.Assets))
	targetsByHash := make(map[string]string, len(result.Assets))
	for position, asset := range result.Assets {
		item, err := buildAssetDiscoverySnapshotItem(audit, provider, asset, position, observedAt)
		if err != nil {
			return db.AssetDiscoverySnapshot{}, nil, err
		}
		if _, exists := targetsByHash[item.TargetHash]; exists {
			return db.AssetDiscoverySnapshot{}, nil, errInvalidAssetDiscoverySnapshot
		}
		targetsByHash[item.TargetHash] = item.NormalizedTarget
		items = append(items, item)
	}
	return snapshot, items, nil
}

func buildAssetDiscoverySnapshotItem(audit *db.AssetDiscoveryAudit, provider string, asset assetdiscovery.Asset, position int, observedAt time.Time) (db.AssetDiscoverySnapshotItem, error) {
	target := strings.TrimSpace(asset.Target)
	source := strings.ToLower(strings.TrimSpace(asset.Source))
	if !validStructuredSnapshotText(target, 8192, false) || source != provider || !validStructuredSnapshotText(source, 32, false) ||
		!validStructuredSnapshotText(asset.IP, 64, true) || !validStructuredSnapshotText(asset.Domain, 255, true) ||
		!validStructuredSnapshotText(asset.Protocol, 32, true) || !validSnapshotText(asset.Title, 1024, true) ||
		!validSnapshotText(asset.ICP, 1024, true) || !validSnapshotText(asset.Country, 128, true) ||
		!validSnapshotText(asset.City, 128, true) || !validSnapshotText(asset.Company, 1024, true) ||
		asset.Port < 0 || asset.Port > 65535 || asset.StatusCode < 0 || asset.StatusCode > 999 {
		return db.AssetDiscoverySnapshotItem{}, errInvalidAssetDiscoverySnapshot
	}
	digest := sha256.Sum256([]byte(target))
	return db.AssetDiscoverySnapshotItem{
		TenantID:         audit.TenantID,
		ProjectID:        audit.ProjectID,
		Position:         position,
		NormalizedTarget: target,
		TargetHash:       hex.EncodeToString(digest[:]),
		IP:               asset.IP,
		Port:             asset.Port,
		Domain:           asset.Domain,
		Protocol:         asset.Protocol,
		Title:            asset.Title,
		ICP:              asset.ICP,
		Country:          asset.Country,
		City:             asset.City,
		Company:          asset.Company,
		StatusCode:       asset.StatusCode,
		Source:           source,
		ObservedAt:       observedAt,
		CreatedAt:        observedAt,
	}, nil
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validStructuredSnapshotText(value string, maxBytes int, allowEmpty bool) bool {
	return validSnapshotText(value, maxBytes, allowEmpty) && !hasControlCharacters(value)
}

func validSnapshotText(value string, maxBytes int, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > maxBytes || !utf8.ValidString(value) || strings.ContainsRune(value, '\x00') {
		return false
	}
	return true
}
