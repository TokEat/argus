package expworkspace

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/P0lar1ght/argus/server/internal/db"
	"gorm.io/gorm"
)

func (s *Service) createDependencyRows(tx *gorm.DB, tenantID string, parent db.ExpRevision, inputs []DependencyInput) error {
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		input.ExpID = strings.TrimSpace(input.ExpID)
		input.SourceSHA256 = strings.ToLower(strings.TrimSpace(input.SourceSHA256))
		key := fmt.Sprintf("%s:%d", input.ExpID, input.Revision)
		if input.ExpID == "" || input.Revision < 1 || len(input.SourceSHA256) != 64 {
			return errors.New("dependency requires exp_id, positive revision and source_sha256")
		}
		if _, exists := seen[key]; exists {
			return errors.New("duplicate dependency revision")
		}
		seen[key] = struct{}{}
		var child db.ExpRevision
		if err := tx.Where("tenant_id = ? AND exp_id = ? AND revision = ?", tenantID, input.ExpID, input.Revision).First(&child).Error; err != nil {
			return fmt.Errorf("dependency %s not found in tenant", key)
		}
		if child.SourceSHA256 != input.SourceSHA256 {
			return fmt.Errorf("dependency %s source hash mismatch", key)
		}
		var childExp db.Exp
		if err := tx.Where("tenant_id = ? AND id = ?", tenantID, input.ExpID).First(&childExp).Error; err != nil {
			return err
		}
		if childExp.Status == db.ExpStatusDeprecated {
			return fmt.Errorf("dependency %s is deprecated", input.ExpID)
		}
		row := db.ExpDependency{TenantID: tenantID, ParentExpID: parent.ExpID, ParentRevision: parent.Revision, DependencyExpID: child.ExpID, DependencyRevision: child.Revision, SourceSHA256: child.SourceSHA256}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) createAssetRefRows(tx *gorm.DB, tenantID string, parent db.ExpRevision, inputs []AssetRefInput) error {
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		input.AssetID = strings.TrimSpace(input.AssetID)
		input.SHA256 = strings.ToLower(strings.TrimSpace(input.SHA256))
		if !logicalIDPattern.MatchString(input.AssetID) || input.Version < 1 || len(input.SHA256) != 64 {
			return errors.New("asset reference requires valid asset_id, positive version and sha256")
		}
		if _, exists := seen[input.AssetID]; exists {
			return errors.New("duplicate asset reference")
		}
		seen[input.AssetID] = struct{}{}
		var asset db.ExpAsset
		if err := tx.Where("tenant_id = ? AND asset_id = ? AND version = ?", tenantID, input.AssetID, input.Version).First(&asset).Error; err != nil {
			return fmt.Errorf("asset %s version %d not found in tenant", input.AssetID, input.Version)
		}
		if asset.SHA256 != input.SHA256 {
			return fmt.Errorf("asset %s source hash mismatch", input.AssetID)
		}
		row := db.ExpAssetRef{TenantID: tenantID, ExpID: parent.ExpID, Revision: parent.Revision, AssetID: asset.AssetID, AssetVersion: asset.Version, SHA256: asset.SHA256}
		if err := tx.Create(&row).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) rejectDependencyCycle(tx *gorm.DB, tenantID, rootExpID string, rootRevision int) error {
	type node struct {
		expID    string
		revision int
		depth    int
	}
	queue := []node{{expID: rootExpID, revision: rootRevision}}
	seen := map[string]bool{}
	count := 0
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		key := fmt.Sprintf("%s:%d", current.expID, current.revision)
		if seen[key] {
			continue
		}
		seen[key] = true
		if current.depth > 8 {
			return errors.New("dependency call depth exceeds 8")
		}
		var rows []db.ExpDependency
		if err := tx.Where("tenant_id = ? AND parent_exp_id = ? AND parent_revision = ?", tenantID, current.expID, current.revision).Find(&rows).Error; err != nil {
			return err
		}
		for _, row := range rows {
			if row.DependencyExpID == rootExpID && row.DependencyRevision == rootRevision {
				return errors.New("dependency cycle detected")
			}
			count++
			if count > MaxDependencies {
				return fmt.Errorf("dependency closure exceeds %d", MaxDependencies)
			}
			queue = append(queue, node{expID: row.DependencyExpID, revision: row.DependencyRevision, depth: current.depth + 1})
		}
	}
	return nil
}

func (s *Service) BuildSealedPackage(ctx context.Context, tenantID, expID string, revision int, includeTests bool) (SealedPackage, error) {
	exp, err := s.GetExp(ctx, tenantID, expID)
	if err != nil {
		return SealedPackage{}, err
	}
	waiverActive, err := s.HasActiveRiskWaiver(ctx, tenantID, expID)
	if err != nil {
		return SealedPackage{}, err
	}
	root, err := s.GetRevision(ctx, tenantID, expID, revision)
	if err != nil {
		return SealedPackage{}, err
	}
	script, err := s.readVerifiedObject(ctx, root.SourceObjectKey, root.SourceSHA256, MaxSourceBytes)
	if err != nil {
		return SealedPackage{}, fmt.Errorf("read EXP revision: %w", err)
	}
	sealed := SealedPackage{ExpID: root.ExpID, ExpStatus: exp.Status, RiskLevel: exp.RiskLevel, RiskWaiverActive: waiverActive, Revision: root.Revision, SourceSHA256: root.SourceSHA256, Script: string(script), Dependencies: []SealedDependency{}, Assets: []SealedAsset{}}
	if err := s.collectDependencies(ctx, tenantID, root, &sealed); err != nil {
		return SealedPackage{}, err
	}
	governed := append([]SealedDependency{{ExpID: root.ExpID, Revision: root.Revision}}, sealed.Dependencies...)
	for _, dependency := range governed {
		var dependencyExp db.Exp
		if err := s.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, dependency.ExpID).First(&dependencyExp).Error; err != nil {
			return SealedPackage{}, err
		}
		if dependencyExp.Status == db.ExpStatusDeprecated {
			sealed.DeprecatedDependency = dependencyExp.ID
		}
		if dependencyExp.RiskLevel == "high" || dependencyExp.RiskLevel == "critical" {
			active, err := s.HasActiveRiskWaiver(ctx, tenantID, dependencyExp.ID)
			if err != nil {
				return SealedPackage{}, err
			}
			if !active {
				sealed.RequiresRiskConfirmation = true
			}
		}
	}
	if err := s.collectAssets(ctx, tenantID, governed, &sealed); err != nil {
		return SealedPackage{}, err
	}
	if includeTests {
		sealed.TestCases, sealed.TestCasesSHA256, err = s.sealedTestCasesWithDB(ctx, s.db, tenantID, expID, revision)
		if err != nil {
			return SealedPackage{}, err
		}
	}
	return sealed, nil
}

func (s *Service) collectDependencies(ctx context.Context, tenantID string, root db.ExpRevision, sealed *SealedPackage) error {
	type node struct {
		expID    string
		revision int
		depth    int
	}
	queue := []node{{expID: root.ExpID, revision: root.Revision}}
	seen := map[string]bool{fmt.Sprintf("%s:%d", root.ExpID, root.Revision): true}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.depth >= 8 {
			return errors.New("dependency call depth exceeds 8")
		}
		var rows []db.ExpDependency
		if err := s.db.WithContext(ctx).Where("tenant_id = ? AND parent_exp_id = ? AND parent_revision = ?", tenantID, current.expID, current.revision).Order("dependency_exp_id, dependency_revision").Find(&rows).Error; err != nil {
			return err
		}
		for _, row := range rows {
			key := fmt.Sprintf("%s:%d", row.DependencyExpID, row.DependencyRevision)
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(sealed.Dependencies) >= MaxDependencies {
				return fmt.Errorf("dependency closure exceeds %d", MaxDependencies)
			}
			var revision db.ExpRevision
			if err := s.db.WithContext(ctx).Where("tenant_id = ? AND exp_id = ? AND revision = ?", tenantID, row.DependencyExpID, row.DependencyRevision).First(&revision).Error; err != nil {
				return fmt.Errorf("sealed dependency %s is missing", key)
			}
			if revision.SourceSHA256 != row.SourceSHA256 {
				return fmt.Errorf("sealed dependency %s hash mismatch", key)
			}
			source, err := s.readVerifiedObject(ctx, revision.SourceObjectKey, revision.SourceSHA256, MaxSourceBytes)
			if err != nil {
				return err
			}
			sealed.Dependencies = append(sealed.Dependencies, SealedDependency{ExpID: revision.ExpID, Revision: revision.Revision, SourceSHA256: revision.SourceSHA256, Script: string(source)})
			queue = append(queue, node{expID: revision.ExpID, revision: revision.Revision, depth: current.depth + 1})
		}
	}
	sort.Slice(sealed.Dependencies, func(i, j int) bool {
		if sealed.Dependencies[i].ExpID == sealed.Dependencies[j].ExpID {
			return sealed.Dependencies[i].Revision < sealed.Dependencies[j].Revision
		}
		return sealed.Dependencies[i].ExpID < sealed.Dependencies[j].ExpID
	})
	return nil
}

func (s *Service) collectAssets(ctx context.Context, tenantID string, revisions []SealedDependency, sealed *SealedPackage) error {
	seen := map[string]string{}
	for _, revision := range revisions {
		var refs []db.ExpAssetRef
		if err := s.db.WithContext(ctx).Where("tenant_id = ? AND exp_id = ? AND revision = ?", tenantID, revision.ExpID, revision.Revision).Order("asset_id").Find(&refs).Error; err != nil {
			return err
		}
		for _, ref := range refs {
			if hash, exists := seen[ref.AssetID]; exists {
				if hash != ref.SHA256 {
					return fmt.Errorf("asset %s resolves to conflicting hashes", ref.AssetID)
				}
				continue
			}
			if len(sealed.Assets) >= MaxAssets {
				return fmt.Errorf("asset closure exceeds %d", MaxAssets)
			}
			var asset db.ExpAsset
			if err := s.db.WithContext(ctx).Where("tenant_id = ? AND asset_id = ? AND version = ?", tenantID, ref.AssetID, ref.AssetVersion).First(&asset).Error; err != nil {
				return err
			}
			if asset.SHA256 != ref.SHA256 {
				return fmt.Errorf("asset %s hash mismatch", ref.AssetID)
			}
			content, err := s.readVerifiedObject(ctx, asset.ObjectKey, asset.SHA256, MaxAssetBytes)
			if err != nil {
				return err
			}
			seen[ref.AssetID] = ref.SHA256
			sealed.Assets = append(sealed.Assets, sealedAssetFromContent(ref.AssetID, ref.SHA256, content))
		}
	}
	sort.Slice(sealed.Assets, func(i, j int) bool { return sealed.Assets[i].AssetID < sealed.Assets[j].AssetID })
	return nil
}

func sealedAssetFromContent(assetID, hash string, content []byte) SealedAsset {
	encoding, value := "base64", base64.StdEncoding.EncodeToString(content)
	if isTextAsset(content) {
		encoding, value = "utf8", string(content)
	}
	return SealedAsset{AssetID: assetID, SHA256: hash, Encoding: encoding, Content: value}
}

func isTextAsset(content []byte) bool {
	if !utf8.Valid(content) {
		return false
	}
	for _, r := range string(content) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

func (s *Service) readVerifiedObject(ctx context.Context, key, expectedHash string, max int64) ([]byte, error) {
	reader, object, err := s.objects.Open(ctx, key)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	if object.Size < 0 || object.Size > max {
		return nil, errors.New("object size exceeds resolver limit")
	}
	content, err := io.ReadAll(io.LimitReader(reader, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > max || contentHash(content) != expectedHash {
		return nil, errors.New("object content failed integrity verification")
	}
	return content, nil
}

func (s *Service) sealedTestCasesWithDB(ctx context.Context, database *gorm.DB, tenantID, expID string, revision int) ([]json.RawMessage, string, error) {
	var rows []db.ExpTestCase
	if err := database.WithContext(ctx).Where("tenant_id = ? AND exp_id = ? AND revision = ? AND enabled = ?", tenantID, expID, revision, true).Order("created_at, id").Find(&rows).Error; err != nil {
		return nil, "", err
	}
	result := make([]json.RawMessage, 0, len(rows))
	for _, row := range rows {
		var params, fixture, expect any
		if err := json.Unmarshal([]byte(row.Params), &params); err != nil {
			return nil, "", fmt.Errorf("test case %s params are invalid", row.ID)
		}
		if err := json.Unmarshal([]byte(row.Fixtures), &fixture); err != nil {
			return nil, "", fmt.Errorf("test case %s fixture is invalid", row.ID)
		}
		if err := json.Unmarshal([]byte(row.Assertions), &expect); err != nil {
			return nil, "", fmt.Errorf("test case %s assertions are invalid", row.ID)
		}
		item := map[string]any{"id": row.ID, "params": params, "fixture": fixture, "expect": expect}
		raw, err := json.Marshal(item)
		if err != nil {
			return nil, "", err
		}
		result = append(result, raw)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, "", err
	}
	return result, contentHash(raw), nil
}
