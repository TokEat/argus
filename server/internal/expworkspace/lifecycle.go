package expworkspace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type TestCaseInput struct {
	Name    string          `json:"name"`
	Params  json.RawMessage `json:"params"`
	Fixture json.RawMessage `json:"fixture"`
	Expect  json.RawMessage `json:"expect"`
	Enabled *bool           `json:"enabled,omitempty"`
}

func (s *Service) CreateTestCase(ctx context.Context, tenantID, actorID, expID string, revision int, input TestCaseInput) (db.ExpTestCase, error) {
	params, err := normalizeJSONObject(input.Params, "params")
	if err != nil {
		return db.ExpTestCase{}, err
	}
	fixture, err := normalizeJSONObject(input.Fixture, "fixture")
	if err != nil {
		return db.ExpTestCase{}, err
	}
	expect, err := normalizeJSONObject(input.Expect, "expect")
	if err != nil {
		return db.ExpTestCase{}, err
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}
	item := db.ExpTestCase{ID: uuid.NewString(), TenantID: tenantID, ExpID: expID, Revision: revision, Name: strings.TrimSpace(input.Name), Params: string(params), Fixtures: string(fixture), Assertions: string(expect), Enabled: enabled, CreatedBy: actorID}
	if item.Name == "" {
		return db.ExpTestCase{}, errors.New("test case name is required")
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var revisionRow db.ExpRevision
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ? AND exp_id = ? AND revision = ? AND status = ?", tenantID, expID, revision, db.ExpStatusDraft).First(&revisionRow).Error; err != nil {
			return errors.New("only draft revision test cases can be changed")
		}
		if err := tx.Create(&item).Error; err != nil {
			return err
		}
		return tx.Model(&revisionRow).Updates(map[string]any{"tests_passed_at": nil, "test_cases_sha256": ""}).Error
	}); err != nil {
		return db.ExpTestCase{}, err
	}
	return item, nil
}

func (s *Service) UpdateTestCase(ctx context.Context, tenantID, expID, caseID string, input TestCaseInput) (db.ExpTestCase, error) {
	var item db.ExpTestCase
	if err := s.db.WithContext(ctx).Where("tenant_id = ? AND exp_id = ? AND id = ?", tenantID, expID, caseID).First(&item).Error; err != nil {
		return item, err
	}
	updates := map[string]any{}
	if name := strings.TrimSpace(input.Name); name != "" {
		updates["name"] = name
	}
	if len(input.Params) > 0 {
		raw, err := normalizeJSONObject(input.Params, "params")
		if err != nil {
			return item, err
		}
		updates["params"] = string(raw)
	}
	if len(input.Fixture) > 0 {
		raw, err := normalizeJSONObject(input.Fixture, "fixture")
		if err != nil {
			return item, err
		}
		updates["fixtures"] = string(raw)
	}
	if len(input.Expect) > 0 {
		raw, err := normalizeJSONObject(input.Expect, "expect")
		if err != nil {
			return item, err
		}
		updates["assertions"] = string(raw)
	}
	if input.Enabled != nil {
		updates["enabled"] = *input.Enabled
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var revision db.ExpRevision
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ? AND exp_id = ? AND revision = ? AND status = ?", tenantID, expID, item.Revision, db.ExpStatusDraft).First(&revision).Error; err != nil {
			return errors.New("only draft revision test cases can be changed")
		}
		result := tx.Model(&db.ExpTestCase{}).Where("tenant_id = ? AND exp_id = ? AND id = ? AND revision = ?", tenantID, expID, caseID, item.Revision).Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		if err := tx.Model(&revision).Updates(map[string]any{"tests_passed_at": nil, "test_cases_sha256": ""}).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		return item, err
	}
	return s.GetTestCase(ctx, tenantID, expID, caseID)
}

func (s *Service) GetTestCase(ctx context.Context, tenantID, expID, caseID string) (db.ExpTestCase, error) {
	var item db.ExpTestCase
	err := s.db.WithContext(ctx).Where("tenant_id = ? AND exp_id = ? AND id = ?", tenantID, expID, caseID).First(&item).Error
	return item, err
}

func (s *Service) ListTestCases(ctx context.Context, tenantID, expID string, revision int) ([]db.ExpTestCase, error) {
	var items []db.ExpTestCase
	err := s.db.WithContext(ctx).Where("tenant_id = ? AND exp_id = ? AND revision = ?", tenantID, expID, revision).Order("created_at, id").Find(&items).Error
	return items, err
}

func (s *Service) DeleteTestCase(ctx context.Context, tenantID, expID, caseID string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var item db.ExpTestCase
		if err := tx.Where("tenant_id = ? AND exp_id = ? AND id = ?", tenantID, expID, caseID).First(&item).Error; err != nil {
			return err
		}
		var revision db.ExpRevision
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ? AND exp_id = ? AND revision = ? AND status = ?", tenantID, expID, item.Revision, db.ExpStatusDraft).First(&revision).Error; err != nil {
			return errors.New("only draft revision test cases can be changed")
		}
		if err := tx.Delete(&item).Error; err != nil {
			return err
		}
		return tx.Model(&revision).Updates(map[string]any{"tests_passed_at": nil, "test_cases_sha256": ""}).Error
	})
}

func (s *Service) Inspect(ctx context.Context, tenantID, actorID, expID string, revision int) (RuntimeResponse, error) {
	if s.runtime == nil {
		return nil, errors.New("Yaksha Runtime Unavailable")
	}
	sealed, err := s.BuildSealedPackage(ctx, tenantID, expID, revision, false)
	if err != nil {
		return nil, err
	}
	response, err := s.runtime.Execute(ctx, RuntimeRequest{ID: uuid.NewString(), Action: "inspect", Script: sealed.Script, ExpID: expID, Revision: revision, SourceSHA256: sealed.SourceSHA256})
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(response)
	inspection := mapValue(response, "inspection")
	cliSchema, _ := json.Marshal(inspection["parameters"])
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&db.ExpRevision{}).Where("tenant_id = ? AND exp_id = ? AND revision = ? AND status = ?", tenantID, expID, revision, db.ExpStatusDraft).Updates(map[string]any{"inspect_summary": string(raw), "cli_schema": string(cliSchema)})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errors.New("only draft revisions can be inspected and updated")
		}
		return createAudit(tx, tenantID, expID, revision, actorID, "inspect", statusDetails(response))
	})
	return response, err
}

func (s *Service) Validate(ctx context.Context, tenantID, actorID, expID string, revision int) (RuntimeResponse, error) {
	if s.runtime == nil {
		return nil, errors.New("Yaksha Runtime Unavailable")
	}
	sealed, err := s.BuildSealedPackage(ctx, tenantID, expID, revision, false)
	if err != nil {
		return nil, err
	}
	response, err := s.runtime.Execute(ctx, runtimeRequestFromSealed(sealed, "validate"))
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(response)
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&db.ExpRevision{}).Where("tenant_id = ? AND exp_id = ? AND revision = ? AND status = ?", tenantID, expID, revision, db.ExpStatusDraft).Update("validate_summary", string(raw))
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errors.New("only draft revisions can be validated and updated")
		}
		return createAudit(tx, tenantID, expID, revision, actorID, "validate", statusDetails(response))
	})
	return response, err
}

func (s *Service) Execute(ctx context.Context, tenantID, actorID, expID string, revision int, input RunInput, internalEgress map[string]any) (RunResult, error) {
	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action != "test" && action != "debug" && action != "run" {
		return RunResult{}, errors.New("action must be test, debug or run")
	}
	waiverUsed, err := s.CheckExecutionAllowed(ctx, tenantID, expID, revision, action, input.RiskConfirmed)
	if err != nil {
		return RunResult{}, err
	}
	sealed, err := s.BuildSealedPackage(ctx, tenantID, expID, revision, action == "test")
	if err != nil {
		return RunResult{}, err
	}
	if expectedHash := strings.TrimSpace(input.SourceSHA256); expectedHash == "" || expectedHash != sealed.SourceSHA256 {
		return RunResult{}, errors.New("source_sha256 confirmation does not match the Server Revision")
	}
	if s.runtime == nil {
		return RunResult{}, errors.New("Yaksha Runtime Unavailable")
	}
	if action == "test" && len(sealed.TestCases) == 0 {
		return RunResult{}, errors.New("at least one enabled Fixture test case is required")
	}
	request := runtimeRequestFromSealed(sealed, action)
	request.Params = input.Params
	request.TimeoutMS = input.TimeoutMS
	request.NetworkTargets = input.NetworkTargets
	request.Egress = internalEgress
	if action == "test" {
		request.Params, request.NetworkTargets = nil, nil
		request.Egress = map[string]any{"mode": "disabled"}
	}

	started := time.Now().UTC()
	run := db.ExpRun{ID: uuid.NewString(), TenantID: tenantID, ExpID: expID, Revision: revision, SourceSHA256: sealed.SourceSHA256, Action: action, OperatorID: actorID, EgressMode: stringValue(internalEgress, "mode"), AgentID: strings.TrimSpace(input.Egress.AgentID), Status: "running", Provenance: "server", Attested: true, ResultSummary: "{}", StartedAt: started}
	if run.EgressMode == "" {
		run.EgressMode = "disabled"
	}
	if err := s.db.WithContext(ctx).Create(&run).Error; err != nil {
		return RunResult{}, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.runs[run.ID] = cancel
	s.mu.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		delete(s.runs, run.ID)
		s.mu.Unlock()
	}()
	response, executeErr := s.runtime.Execute(runCtx, request)
	finished := time.Now().UTC()
	if executeErr != nil {
		_ = s.finishFailedRun(context.WithoutCancel(ctx), run, finished, executeErr)
		return RunResult{}, executeErr
	}
	raw, err := json.Marshal(response)
	if err != nil {
		_ = s.finishFailedRun(context.WithoutCancel(ctx), run, finished, err)
		return RunResult{}, err
	}
	artifactHash := contentHash(raw)
	artifactKey := artifactObjectKey(tenantID, run.ID, artifactHash)
	if err := s.putImmutable(context.WithoutCancel(ctx), artifactKey, raw, artifactHash); err != nil {
		_ = s.finishFailedRun(context.WithoutCancel(ctx), run, finished, err)
		return RunResult{}, fmt.Errorf("persist EXP run artifact: %w", err)
	}
	expires := finished.Add(s.retention)
	summary, _ := json.Marshal(statusDetails(response))
	status := stringValue(response, "status")
	var acceptanceErr error
	err = s.db.WithContext(context.WithoutCancel(ctx)).Transaction(func(tx *gorm.DB) error {
		runUpdates := map[string]any{"status": status, "result_summary": string(summary), "artifact_object_key": artifactKey, "artifact_sha256": artifactHash, "artifact_expires_at": expires, "finished_at": finished}
		if err := tx.Model(&db.ExpRun{}).Where("tenant_id = ? AND id = ?", tenantID, run.ID).Updates(runUpdates).Error; err != nil {
			return err
		}
		if action == "test" && testPassed(response) {
			var revisionRow db.ExpRevision
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ? AND exp_id = ? AND revision = ? AND status = ?", tenantID, expID, revision, db.ExpStatusDraft).First(&revisionRow).Error; err != nil {
				acceptanceErr = errors.New("Fixture acceptance cannot update a non-draft revision")
			} else {
				currentCases, currentHash, err := s.sealedTestCasesWithDB(context.WithoutCancel(ctx), tx, tenantID, expID, revision)
				if err != nil {
					return err
				}
				if len(currentCases) == 0 || currentHash != sealed.TestCasesSHA256 {
					acceptanceErr = errors.New("Fixture test cases changed during execution; acceptance was not recorded")
				} else if err := tx.Model(&revisionRow).Updates(map[string]any{"tests_passed_at": finished, "test_cases_sha256": currentHash}).Error; err != nil {
					return err
				}
			}
			if acceptanceErr != nil {
				if err := tx.Model(&db.ExpRun{}).Where("tenant_id = ? AND id = ?", tenantID, run.ID).Updates(map[string]any{"status": "Rejected", "error_code": "fixture_snapshot_changed"}).Error; err != nil {
					return err
				}
				status = "Rejected"
			}
		}
		details := statusDetails(response)
		details["status"] = status
		if acceptanceErr != nil {
			details["acceptance_error"] = "fixture_snapshot_changed"
		}
		details["risk_confirmed"] = input.RiskConfirmed
		details["risk_waiver_used"] = waiverUsed
		return createAudit(tx, tenantID, expID, revision, actorID, action, details)
	})
	if err != nil {
		return RunResult{}, err
	}
	if acceptanceErr != nil {
		return RunResult{}, acceptanceErr
	}
	return RunResult{RunID: run.ID, Response: response, StartedAt: started, FinishedAt: finished}, nil
}

func (s *Service) Publish(ctx context.Context, tenantID, actorID, expID string, revision int, expectedHash string) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var root db.Exp
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ? AND id = ?", tenantID, expID).First(&root).Error; err != nil {
			return err
		}
		if root.Status == db.ExpStatusDeprecated {
			return errors.New("deprecated EXP cannot be published")
		}
		var item db.ExpRevision
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("tenant_id = ? AND exp_id = ? AND revision = ?", tenantID, expID, revision).First(&item).Error; err != nil {
			return err
		}
		if item.Status != db.ExpStatusDraft || item.SourceSHA256 != strings.ToLower(strings.TrimSpace(expectedHash)) {
			return errors.New("draft revision and exact expected source hash are required")
		}
		if !summaryPassed(item.InspectSummary, "inspection") || !summaryPassed(item.ValidateSummary, "validation") || item.TestsPassedAt == nil || item.TestCasesSHA256 == "" {
			return errors.New("publish requires successful inspect, validate and Fixture test")
		}
		cases, currentCasesHash, err := s.sealedTestCasesWithDB(ctx, tx, tenantID, expID, revision)
		if err != nil {
			return err
		}
		if len(cases) == 0 || currentCasesHash != item.TestCasesSHA256 {
			return errors.New("publish requires Fixture acceptance for the current test case snapshot")
		}
		var dependencies []db.ExpDependency
		if err := tx.Where("tenant_id = ? AND parent_exp_id = ? AND parent_revision = ?", tenantID, expID, revision).Find(&dependencies).Error; err != nil {
			return err
		}
		for _, dependency := range dependencies {
			var childExp db.Exp
			if err := tx.Where("tenant_id = ? AND id = ? AND status <> ?", tenantID, dependency.DependencyExpID, db.ExpStatusDeprecated).First(&childExp).Error; err != nil {
				return fmt.Errorf("dependency %s is deprecated or unavailable", dependency.DependencyExpID)
			}
			var child db.ExpRevision
			if err := tx.Where("tenant_id = ? AND exp_id = ? AND revision = ? AND status = ?", tenantID, dependency.DependencyExpID, dependency.DependencyRevision, db.ExpStatusPublished).First(&child).Error; err != nil {
				return fmt.Errorf("dependency %s revision %d is not published", dependency.DependencyExpID, dependency.DependencyRevision)
			}
		}
		now := time.Now().UTC()
		if err := tx.Model(&item).Updates(map[string]any{"status": db.ExpStatusPublished, "published_by": actorID, "published_at": now}).Error; err != nil {
			return err
		}
		if err := tx.Model(&root).Updates(map[string]any{"status": db.ExpStatusPublished, "active_revision": revision}).Error; err != nil {
			return err
		}
		return createAudit(tx, tenantID, expID, revision, actorID, "publish", map[string]any{"source_sha256": item.SourceSHA256})
	})
}

func (s *Service) SetActiveRevision(ctx context.Context, tenantID, actorID, expID string, revision int) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var target db.ExpRevision
		if err := tx.Where("tenant_id = ? AND exp_id = ? AND revision = ? AND status = ?", tenantID, expID, revision, db.ExpStatusPublished).First(&target).Error; err != nil {
			return errors.New("active revision must be a published revision in the same tenant")
		}
		result := tx.Model(&db.Exp{}).Where("tenant_id = ? AND id = ? AND status <> ?", tenantID, expID, db.ExpStatusDeprecated).Update("active_revision", revision)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		return createAudit(tx, tenantID, expID, revision, actorID, "set_active_revision", map[string]any{})
	})
}

func (s *Service) ListRuns(ctx context.Context, tenantID, expID string, offset, limit int) ([]db.ExpRun, int64, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := s.db.WithContext(ctx).Model(&db.ExpRun{}).Where("tenant_id = ?", tenantID)
	if expID != "" {
		query = query.Where("exp_id = ?", expID)
	}
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var items []db.ExpRun
	err := query.Order("created_at DESC").Offset(offset).Limit(limit).Find(&items).Error
	return items, total, err
}

func (s *Service) GetRun(ctx context.Context, tenantID, runID string, includeArtifact bool) (db.ExpRun, RuntimeResponse, error) {
	var run db.ExpRun
	if err := s.db.WithContext(ctx).Where("tenant_id = ? AND id = ?", tenantID, runID).First(&run).Error; err != nil {
		return run, nil, err
	}
	if !includeArtifact || run.ArtifactObjectKey == "" {
		return run, nil, nil
	}
	raw, err := s.readVerifiedObject(ctx, run.ArtifactObjectKey, run.ArtifactSHA256, maxRuntimeResponse)
	if err != nil {
		return run, nil, err
	}
	var response RuntimeResponse
	err = json.Unmarshal(raw, &response)
	return run, response, err
}

func (s *Service) CancelRun(ctx context.Context, tenantID, runID string) error {
	var run db.ExpRun
	if err := s.db.WithContext(ctx).Select("id", "tenant_id", "status").Where("tenant_id = ? AND id = ?", tenantID, runID).First(&run).Error; err != nil {
		return err
	}
	if run.Status != "running" {
		return errors.New("only a running EXP run can be canceled")
	}
	s.mu.Lock()
	cancel := s.runs[runID]
	s.mu.Unlock()
	if cancel == nil {
		return errors.New("running EXP request is not owned by this Server process")
	}
	cancel()
	return nil
}

func (s *Service) finishFailedRun(ctx context.Context, run db.ExpRun, finished time.Time, runErr error) error {
	status := "InternalError"
	if errors.Is(runErr, context.Canceled) {
		status = "Canceled"
	} else if errors.Is(runErr, context.DeadlineExceeded) {
		status = "Timeout"
	}
	summary, _ := json.Marshal(map[string]any{"status": status})
	return s.db.WithContext(ctx).Model(&db.ExpRun{}).Where("tenant_id = ? AND id = ?", run.TenantID, run.ID).Updates(map[string]any{"status": status, "result_summary": string(summary), "error_code": stableErrorCode(runErr), "finished_at": finished}).Error
}

func runtimeRequestFromSealed(sealed SealedPackage, action string) RuntimeRequest {
	return RuntimeRequest{ID: uuid.NewString(), Action: action, Script: sealed.Script, ExpID: sealed.ExpID, Revision: sealed.Revision, SourceSHA256: sealed.SourceSHA256, Dependencies: sealed.Dependencies, Assets: sealed.Assets, TestCases: sealed.TestCases, Egress: map[string]any{"mode": "disabled"}}
}

func normalizeJSONObject(raw json.RawMessage, field string) ([]byte, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []byte("{}"), nil
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil || value == nil {
		return nil, fmt.Errorf("%s must be a JSON object", field)
	}
	return json.Marshal(value)
}

func mapValue(value map[string]any, key string) map[string]any {
	nested, _ := value[key].(map[string]any)
	return nested
}

func statusDetails(response RuntimeResponse) map[string]any {
	return map[string]any{"status": stringValue(response, "status"), "has_error": stringValue(response, "error") != ""}
}

func summaryPassed(raw, section string) bool {
	var value RuntimeResponse
	if json.Unmarshal([]byte(raw), &value) != nil || fmt.Sprint(value["status"]) != "Succeeded" {
		return false
	}
	part, _ := value[section].(map[string]any)
	valid, _ := part["valid"].(bool)
	return valid
}

func testPassed(response RuntimeResponse) bool {
	if fmt.Sprint(response["status"]) != "Succeeded" {
		return false
	}
	report, _ := response["test"].(map[string]any)
	failed, ok := report["failed"].(json.Number)
	if ok {
		return failed.String() == "0"
	}
	return fmt.Sprint(report["failed"]) == "0"
}

func stringValue(value map[string]any, key string) string {
	raw, exists := value[key]
	if !exists || raw == nil {
		return ""
	}
	text, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func stableErrorCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	return "runtime_error"
}
