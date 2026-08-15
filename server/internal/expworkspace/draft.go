package expworkspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const draftTestReceiptTTL = 15 * time.Minute

type normalizedDraftCase struct {
	Name    string          `json:"name"`
	Params  json.RawMessage `json:"params"`
	Fixture json.RawMessage `json:"fixture"`
	Expect  json.RawMessage `json:"expect"`
	Enabled bool            `json:"enabled"`
}

func (s *Service) InspectDraft(ctx context.Context, tenantID, expID, source string) (RuntimeResponse, error) {
	if s.runtime == nil {
		return nil, errors.New("Yaksha Runtime Unavailable")
	}
	if err := validateDraftSource(source); err != nil {
		return nil, err
	}
	var root db.Exp
	if err := s.db.WithContext(ctx).Where("tenant_id = ? AND id = ? AND status <> ?", tenantID, expID, db.ExpStatusDeprecated).First(&root).Error; err != nil {
		return nil, err
	}
	// A live draft is deliberately unbound: sending only source_sha256 would make
	// Yaksha treat it as a persisted EXP context and require a positive Revision.
	return s.runtime.Execute(ctx, RuntimeRequest{ID: uuid.NewString(), Action: "inspect", Script: source})
}

func (s *Service) ValidateDraft(ctx context.Context, tenantID, expID string, input DraftPackageInput) (RuntimeResponse, error) {
	if s.runtime == nil {
		return nil, errors.New("Yaksha Runtime Unavailable")
	}
	sealed, _, _, err := s.buildDraftPackage(ctx, tenantID, expID, input)
	if err != nil {
		return nil, err
	}
	return s.runtime.Execute(ctx, RuntimeRequest{
		ID: uuid.NewString(), Action: "validate", Script: sealed.Script,
		Dependencies: sealed.Dependencies, Assets: sealed.Assets, ValidationMode: "contract",
	})
}

func (s *Service) TestDraft(ctx context.Context, tenantID, actorID, expID string, input DraftPackageInput) (DraftTestResult, error) {
	if s.runtime == nil {
		return DraftTestResult{}, errors.New("Yaksha Runtime Unavailable")
	}
	sealed, normalizedCases, packageHash, err := s.buildDraftPackage(ctx, tenantID, expID, input)
	if err != nil {
		return DraftTestResult{}, err
	}
	if len(sealed.TestCases) == 0 {
		return DraftTestResult{}, errors.New("at least one enabled Fixture is required before saving")
	}
	contract, err := s.runtime.Execute(ctx, RuntimeRequest{
		ID: uuid.NewString(), Action: "validate", Script: sealed.Script,
		Dependencies: sealed.Dependencies, Assets: sealed.Assets, ValidationMode: "contract",
	})
	if err != nil {
		return DraftTestResult{}, err
	}
	if !contractPassed(contract) {
		return DraftTestResult{RuntimeResponse: contract}, errors.New("EXP contract validation did not pass; draft cannot be tested or saved")
	}
	response, err := s.runtime.Execute(ctx, RuntimeRequest{
		ID: uuid.NewString(), Action: "test", Script: sealed.Script,
		Dependencies: sealed.Dependencies, Assets: sealed.Assets, TestCases: sealed.TestCases,
		Egress: map[string]any{"mode": "disabled"},
	})
	if err != nil {
		return DraftTestResult{}, err
	}
	if !testPassed(response) {
		return DraftTestResult{RuntimeResponse: response}, errors.New("Fixture test did not pass; draft cannot be saved")
	}
	response["inspection"] = contract["inspection"]
	response["validation"] = contract["validation"]
	receipt := uuid.NewString() + uuid.NewString()
	expiresAt := time.Now().UTC().Add(draftTestReceiptTTL)
	details := map[string]any{
		"receipt_sha256": contentHash([]byte(receipt)), "package_sha256": packageHash,
		"source_sha256": sealed.SourceSHA256, "test_cases_sha256": sealed.TestCasesSHA256,
		"expires_at": expiresAt, "inspection": mapValue(response, "inspection"),
		"validation": mapValue(response, "validation"), "case_count": len(normalizedCases),
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var item db.Exp
		if err := tx.Where("tenant_id = ? AND id = ? AND status <> ?", tenantID, expID, db.ExpStatusDeprecated).First(&item).Error; err != nil {
			return err
		}
		return createAudit(tx, tenantID, expID, 0, actorID, "draft_test_passed", details)
	}); err != nil {
		return DraftTestResult{}, err
	}
	return DraftTestResult{RuntimeResponse: response, TestReceipt: receipt, ExpiresAt: expiresAt}, nil
}

func contractPassed(response RuntimeResponse) bool {
	if stringValue(response, "status") != "Succeeded" {
		return false
	}
	inspection, _ := response["inspection"].(map[string]any)
	validation, _ := response["validation"].(map[string]any)
	inspectionValid, _ := inspection["valid"].(bool)
	validationValid, _ := validation["valid"].(bool)
	return inspectionValid && validationValid
}

func (s *Service) CreateTestedRevision(ctx context.Context, tenantID, actorID, expID string, input CreateTestedRevisionInput) (db.ExpRevision, error) {
	input.TestReceipt = strings.TrimSpace(input.TestReceipt)
	if input.TestReceipt == "" {
		return db.ExpRevision{}, errors.New("a successful draft Fixture test receipt is required")
	}
	sealed, normalizedCases, packageHash, err := s.buildDraftPackage(ctx, tenantID, expID, input.DraftPackageInput)
	if err != nil {
		return db.ExpRevision{}, err
	}
	hash := sealed.SourceSHA256
	key := sourceObjectKey(tenantID, hash)
	if err := s.putImmutable(ctx, key, []byte(input.Source), hash); err != nil {
		return db.ExpRevision{}, fmt.Errorf("store revision source: %w", err)
	}
	receiptHash := contentHash([]byte(input.TestReceipt))
	var created db.ExpRevision
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		acceptance, err := findDraftAcceptance(tx, tenantID, actorID, expID, receiptHash, packageHash)
		if err != nil {
			return err
		}
		created, err = s.createRevisionRecord(tx, tenantID, actorID, expID, CreateRevisionInput{
			Source: input.Source, Dependencies: input.Dependencies, Assets: input.Assets,
		}, key, hash)
		if err != nil {
			return err
		}
		for _, testCase := range normalizedCases {
			item := db.ExpTestCase{
				ID: uuid.NewString(), TenantID: tenantID, ExpID: expID, Revision: created.Revision,
				Name: testCase.Name, Params: string(testCase.Params), Fixtures: string(testCase.Fixture), Assertions: string(testCase.Expect),
				Enabled: testCase.Enabled, CreatedBy: actorID,
			}
			if err := tx.Create(&item).Error; err != nil {
				return err
			}
		}
		cliSchema, _ := json.Marshal(acceptance.Inspection["parameters"])
		inspectSummary, _ := json.Marshal(map[string]any{"status": "Succeeded", "inspection": acceptance.Inspection})
		validateSummary, _ := json.Marshal(map[string]any{"status": "Succeeded", "validation": acceptance.Validation})
		testedAt := acceptance.CreatedAt
		if err := tx.Model(&created).Updates(map[string]any{
			"cli_schema": string(cliSchema), "inspect_summary": string(inspectSummary), "validate_summary": string(validateSummary),
			"tests_passed_at": testedAt, "test_cases_sha256": acceptance.TestCasesSHA256,
		}).Error; err != nil {
			return err
		}
		return createAudit(tx, tenantID, expID, created.Revision, actorID, "draft_test_consumed", map[string]any{"receipt_sha256": receiptHash, "source_sha256": hash})
	})
	if err != nil {
		return db.ExpRevision{}, err
	}
	return s.GetRevision(ctx, tenantID, expID, created.Revision)
}

type draftAcceptance struct {
	ReceiptSHA256   string         `json:"receipt_sha256"`
	PackageSHA256   string         `json:"package_sha256"`
	SourceSHA256    string         `json:"source_sha256"`
	TestCasesSHA256 string         `json:"test_cases_sha256"`
	ExpiresAt       time.Time      `json:"expires_at"`
	Inspection      map[string]any `json:"inspection"`
	Validation      map[string]any `json:"validation"`
	CreatedAt       time.Time      `json:"-"`
}

func findDraftAcceptance(tx *gorm.DB, tenantID, actorID, expID, receiptHash, packageHash string) (draftAcceptance, error) {
	var rows []db.ExpAudit
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where(
		"tenant_id = ? AND exp_id = ? AND actor_id = ? AND action = ? AND created_at >= ?",
		tenantID, expID, actorID, "draft_test_passed", time.Now().UTC().Add(-draftTestReceiptTTL),
	).Order("created_at DESC").Limit(50).Find(&rows).Error; err != nil {
		return draftAcceptance{}, err
	}
	var matched draftAcceptance
	for _, row := range rows {
		var candidate draftAcceptance
		if json.Unmarshal([]byte(row.Details), &candidate) == nil && candidate.ReceiptSHA256 == receiptHash && candidate.PackageSHA256 == packageHash {
			candidate.CreatedAt = row.CreatedAt
			matched = candidate
			break
		}
	}
	if matched.ReceiptSHA256 == "" || !matched.ExpiresAt.After(time.Now().UTC()) {
		return draftAcceptance{}, errors.New("draft Fixture test receipt is invalid, expired, or does not match the current source package")
	}
	var consumed []db.ExpAudit
	if err := tx.Where("tenant_id = ? AND exp_id = ? AND actor_id = ? AND action = ?", tenantID, expID, actorID, "draft_test_consumed").Order("created_at DESC").Limit(100).Find(&consumed).Error; err != nil {
		return draftAcceptance{}, err
	}
	for _, row := range consumed {
		var details map[string]any
		if json.Unmarshal([]byte(row.Details), &details) == nil && details["receipt_sha256"] == receiptHash {
			return draftAcceptance{}, errors.New("draft Fixture test receipt has already been used")
		}
	}
	return matched, nil
}

func (s *Service) buildDraftPackage(ctx context.Context, tenantID, expID string, input DraftPackageInput) (SealedPackage, []normalizedDraftCase, string, error) {
	if err := validateDraftSource(input.Source); err != nil {
		return SealedPackage{}, nil, "", err
	}
	if len(input.Dependencies) > MaxDependencies || len(input.Assets) > MaxAssets {
		return SealedPackage{}, nil, "", errors.New("draft resolver limits exceeded")
	}
	var root db.Exp
	if err := s.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, expID).First(&root).Error; err != nil {
		return SealedPackage{}, nil, "", err
	}
	if root.Status == db.ExpStatusDeprecated {
		return SealedPackage{}, nil, "", errors.New("deprecated EXP cannot accept drafts")
	}
	sealed := SealedPackage{
		ExpID: expID, ExpStatus: root.Status, RiskLevel: root.RiskLevel, SourceSHA256: contentHash([]byte(input.Source)), Script: input.Source,
		DependencyRefs: append([]DependencyInput(nil), input.Dependencies...), AssetRefs: append([]AssetRefInput(nil), input.Assets...),
		Dependencies: []SealedDependency{}, Assets: []SealedAsset{},
	}
	if err := s.collectDraftDependencies(ctx, tenantID, expID, input.Dependencies, &sealed); err != nil {
		return SealedPackage{}, nil, "", err
	}
	if err := s.collectDraftAssets(ctx, tenantID, input.Assets, sealed.Dependencies, &sealed); err != nil {
		return SealedPackage{}, nil, "", err
	}
	normalizedCases, runtimeCases, casesHash, err := normalizeDraftTestCases(input.TestCases)
	if err != nil {
		return SealedPackage{}, nil, "", err
	}
	sealed.TestCases, sealed.TestCasesSHA256 = runtimeCases, casesHash
	canonical := struct {
		Source       string                `json:"source"`
		Dependencies []DependencyInput     `json:"dependencies"`
		Assets       []AssetRefInput       `json:"assets"`
		TestCases    []normalizedDraftCase `json:"test_cases"`
	}{input.Source, input.Dependencies, input.Assets, normalizedCases}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return SealedPackage{}, nil, "", err
	}
	return sealed, normalizedCases, contentHash(raw), nil
}

func (s *Service) collectDraftDependencies(ctx context.Context, tenantID, rootExpID string, refs []DependencyInput, sealed *SealedPackage) error {
	type node struct {
		expID           string
		revision, depth int
		hash            string
	}
	queue := make([]node, 0, len(refs))
	for _, ref := range refs {
		queue = append(queue, node{strings.TrimSpace(ref.ExpID), ref.Revision, 1, strings.ToLower(strings.TrimSpace(ref.SourceSHA256))})
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.expID == "" || current.revision < 1 || len(current.hash) != 64 {
			return errors.New("dependency requires exp_id, positive revision and source_sha256")
		}
		if current.expID == rootExpID {
			return errors.New("draft dependency cycle detected")
		}
		if current.depth > 8 {
			return errors.New("dependency call depth exceeds 8")
		}
		key := fmt.Sprintf("%s:%d", current.expID, current.revision)
		if seen[key] {
			continue
		}
		seen[key] = true
		if len(sealed.Dependencies) >= MaxDependencies {
			return fmt.Errorf("dependency closure exceeds %d", MaxDependencies)
		}
		var revision db.ExpRevision
		if err := s.db.WithContext(ctx).Where("tenant_id = ? AND exp_id = ? AND revision = ?", tenantID, current.expID, current.revision).First(&revision).Error; err != nil {
			return fmt.Errorf("dependency %s not found in tenant", key)
		}
		if revision.SourceSHA256 != current.hash {
			return fmt.Errorf("dependency %s source hash mismatch", key)
		}
		var dependencyExp db.Exp
		if err := s.db.WithContext(ctx).Where("tenant_id = ? AND id = ? AND status <> ?", tenantID, current.expID, db.ExpStatusDeprecated).First(&dependencyExp).Error; err != nil {
			return fmt.Errorf("dependency %s is unavailable", key)
		}
		source, err := s.readVerifiedObject(ctx, revision.SourceObjectKey, revision.SourceSHA256, MaxSourceBytes)
		if err != nil {
			return err
		}
		sealed.Dependencies = append(sealed.Dependencies, SealedDependency{ExpID: revision.ExpID, Revision: revision.Revision, SourceSHA256: revision.SourceSHA256, Script: string(source)})
		var children []db.ExpDependency
		if err := s.db.WithContext(ctx).Where("tenant_id = ? AND parent_exp_id = ? AND parent_revision = ?", tenantID, current.expID, current.revision).Find(&children).Error; err != nil {
			return err
		}
		for _, child := range children {
			queue = append(queue, node{child.DependencyExpID, child.DependencyRevision, current.depth + 1, child.SourceSHA256})
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

func (s *Service) collectDraftAssets(ctx context.Context, tenantID string, rootRefs []AssetRefInput, dependencies []SealedDependency, sealed *SealedPackage) error {
	seen := map[string]string{}
	add := func(assetID string, version int, expectedHash string) error {
		assetID, expectedHash = strings.TrimSpace(assetID), strings.ToLower(strings.TrimSpace(expectedHash))
		if !logicalIDPattern.MatchString(assetID) || version < 1 || len(expectedHash) != 64 {
			return errors.New("asset reference requires valid asset_id, positive version and sha256")
		}
		if hash, exists := seen[assetID]; exists {
			if hash != expectedHash {
				return fmt.Errorf("asset %s resolves to conflicting hashes", assetID)
			}
			return nil
		}
		if len(sealed.Assets) >= MaxAssets {
			return fmt.Errorf("asset closure exceeds %d", MaxAssets)
		}
		var asset db.ExpAsset
		if err := s.db.WithContext(ctx).Where("tenant_id = ? AND asset_id = ? AND version = ?", tenantID, assetID, version).First(&asset).Error; err != nil {
			return err
		}
		if asset.SHA256 != expectedHash {
			return fmt.Errorf("asset %s hash mismatch", assetID)
		}
		content, err := s.readVerifiedObject(ctx, asset.ObjectKey, asset.SHA256, MaxAssetBytes)
		if err != nil {
			return err
		}
		seen[assetID] = expectedHash
		sealed.Assets = append(sealed.Assets, sealedAssetFromContent(assetID, expectedHash, content))
		return nil
	}
	for _, ref := range rootRefs {
		if err := add(ref.AssetID, ref.Version, ref.SHA256); err != nil {
			return err
		}
	}
	for _, dependency := range dependencies {
		var refs []db.ExpAssetRef
		if err := s.db.WithContext(ctx).Where("tenant_id = ? AND exp_id = ? AND revision = ?", tenantID, dependency.ExpID, dependency.Revision).Find(&refs).Error; err != nil {
			return err
		}
		for _, ref := range refs {
			if err := add(ref.AssetID, ref.AssetVersion, ref.SHA256); err != nil {
				return err
			}
		}
	}
	sort.Slice(sealed.Assets, func(i, j int) bool { return sealed.Assets[i].AssetID < sealed.Assets[j].AssetID })
	return nil
}

func normalizeDraftTestCases(inputs []TestCaseInput) ([]normalizedDraftCase, []json.RawMessage, string, error) {
	normalized := make([]normalizedDraftCase, 0, len(inputs))
	runtimeCases := make([]json.RawMessage, 0, len(inputs))
	for index, input := range inputs {
		params, err := normalizeJSONObject(input.Params, "params")
		if err != nil {
			return nil, nil, "", err
		}
		fixture, err := normalizeJSONObject(input.Fixture, "fixture")
		if err != nil {
			return nil, nil, "", err
		}
		expect, err := normalizeJSONObject(input.Expect, "expect")
		if err != nil {
			return nil, nil, "", err
		}
		enabled := input.Enabled == nil || *input.Enabled
		item := normalizedDraftCase{Name: strings.TrimSpace(input.Name), Params: params, Fixture: fixture, Expect: expect, Enabled: enabled}
		if item.Name == "" {
			return nil, nil, "", errors.New("test case name is required")
		}
		normalized = append(normalized, item)
		if enabled {
			raw, err := json.Marshal(map[string]any{"id": fmt.Sprintf("draft-%d", index+1), "params": json.RawMessage(params), "fixture": json.RawMessage(fixture), "expect": json.RawMessage(expect)})
			if err != nil {
				return nil, nil, "", err
			}
			runtimeCases = append(runtimeCases, raw)
		}
	}
	raw, err := json.Marshal(runtimeCases)
	if err != nil {
		return nil, nil, "", err
	}
	return normalized, runtimeCases, contentHash(raw), nil
}

func validateDraftSource(source string) error {
	if len(source) == 0 || len(source) > MaxSourceBytes || !utf8.ValidString(source) {
		return fmt.Errorf("source must be valid UTF-8 and contain 1 to %d bytes", MaxSourceBytes)
	}
	return nil
}
