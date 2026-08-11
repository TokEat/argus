package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const riskValidationExecutionIdempotencyOperation = "execute_risk_validation_v1"

var errInvalidRiskValidationExecutionIdempotencyKey = errors.New("Idempotency-Key must contain 1-128 visible ASCII characters")
var errRiskValidationIdempotencyRace = errors.New("risk validation idempotency record was committed concurrently")

type canonicalRiskValidationExecutionRequest struct {
	SchemaVersion      string                    `json:"schema_version"`
	TenantID           string                    `json:"tenant_id"`
	ProjectID          string                    `json:"project_id"`
	RootTaskID         string                    `json:"root_task_id"`
	OperatorID         string                    `json:"operator_id"`
	Operation          string                    `json:"operation"`
	PlanHash           string                    `json:"plan_hash"`
	SpecifiedPOCs      []string                  `json:"specified_pocs"`
	Selected           []riskValidationSelection `json:"selected"`
	Confirmed          bool                      `json:"confirmed"`
	SecondConfirmation bool                      `json:"second_confirmation"`
}

func parseRiskValidationExecutionIdempotencyKey(header http.Header) (string, bool, error) {
	values := header.Values("Idempotency-Key")
	if len(values) == 0 {
		return "", false, nil
	}
	if len(values) != 1 || !validTaskCreateIdempotencyKey(values[0]) {
		return "", true, errInvalidRiskValidationExecutionIdempotencyKey
	}
	return values[0], true, nil
}

func buildRiskValidationExecutionRequestHash(input canonicalRiskValidationExecutionRequest) (string, error) {
	input.SchemaVersion = db.RiskValidationExecutionIdempotencySchemaVersion
	input.Operation = riskValidationExecutionIdempotencyOperation
	input.PlanHash = strings.TrimSpace(input.PlanHash)
	input.SpecifiedPOCs = append([]string(nil), input.SpecifiedPOCs...)
	sort.Strings(input.SpecifiedPOCs)
	seen := make(map[string]struct{}, len(input.Selected))
	selected := make([]riskValidationSelection, 0, len(input.Selected))
	for _, item := range input.Selected {
		item.Endpoint, item.PocFile, item.PocContentHash = strings.TrimSpace(item.Endpoint), strings.TrimSpace(item.PocFile), strings.TrimSpace(item.PocContentHash)
		key := riskValidationCandidateKey(item.Endpoint, item.PocFile, item.PocContentHash)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		selected = append(selected, item)
	}
	sort.Slice(selected, func(i, j int) bool {
		return riskValidationCandidateKey(selected[i].Endpoint, selected[i].PocFile, selected[i].PocContentHash) < riskValidationCandidateKey(selected[j].Endpoint, selected[j].PocFile, selected[j].PocContentHash)
	})
	input.Selected = selected
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func riskValidationExecutionConfigHash(config string) string {
	sum := sha256.Sum256([]byte(config))
	return hex.EncodeToString(sum[:])
}

func riskValidationExecutionPOCSetHash(selected []riskValidationCandidate) string {
	values := make([]string, 0, len(selected))
	for _, candidate := range selected {
		values = append(values, strings.TrimSpace(candidate.PocFile)+"\x00"+strings.ToLower(strings.TrimSpace(candidate.PocContentHash)))
	}
	sort.Strings(values)
	encoded, _ := json.Marshal(values)
	return riskValidationExecutionConfigHash(string(encoded))
}

func riskValidationExecutionReplay(tx *gorm.DB, record db.RiskValidationExecutionIdempotency) (riskValidationExecutionResult, int, error) {
	var batch db.TaskBatch
	if err := tx.Where("id = ? AND tenant_id = ? AND project_id = ? AND root_task_id = ?", record.BatchID, record.TenantID, record.ProjectID, record.RootTaskID).First(&batch).Error; err != nil {
		return riskValidationExecutionResult{}, 0, err
	}
	var attempt db.SubTask
	if err := tx.Where("id = ? AND tenant_id = ? AND project_id = ? AND root_task_id = ? AND batch_id = ?", record.AttemptID, record.TenantID, record.ProjectID, record.RootTaskID, record.BatchID).First(&attempt).Error; err != nil {
		return riskValidationExecutionResult{}, 0, err
	}
	pending := 0
	if strings.EqualFold(strings.TrimSpace(attempt.Status), subTaskStatusDispatching) {
		pending = 1
	}
	return riskValidationExecutionResult{Batch: batch, Attempt: attempt, CandidateCount: record.CandidateCount, PocCount: record.POCCount, Estimated: record.EstimatedRequests}, pending, nil
}

var (
	errRiskValidationConfirmation     = errors.New("risk validation requires explicit authorization confirmation")
	errRiskValidationSecondCheck      = errors.New("high-risk or unclassified POCs require second confirmation")
	errRiskValidationStalePlan        = errors.New("risk validation preview is stale; generate a new preview")
	errRiskValidationTaskState        = errors.New("risk validation can only be added to a terminal task")
	errRiskValidationEmptyPlan        = errors.New("risk validation has no executable candidates")
	errRiskValidationSelection        = errors.New("risk validation selection is not part of the current preview")
	errRiskValidationQueueUnavailable = errors.New("task queue not initialized")
)

type riskValidationSelection struct {
	Endpoint       string `json:"endpoint"`
	PocFile        string `json:"poc_file"`
	PocContentHash string `json:"poc_content_hash"`
}

type executeRiskValidationRequest struct {
	PlanHash           string                    `json:"plan_hash"`
	SpecifiedPocs      []string                  `json:"specified_pocs"`
	Selected           []riskValidationSelection `json:"selected"`
	Confirmed          bool                      `json:"confirmed"`
	SecondConfirmation bool                      `json:"second_confirmation"`
}

type riskValidationExecutionResult struct {
	Batch           db.TaskBatch
	Attempt         db.SubTask
	CandidateCount  int
	PocCount        int
	Estimated       int64
	SecondConfirmed bool
}

func riskValidationCandidateKey(endpoint, pocFile, contentHash string) string {
	return strings.TrimSpace(endpoint) + "\x00" + strings.TrimSpace(pocFile) + "\x00" + strings.TrimSpace(contentHash)
}

func selectRiskValidationCandidates(preview riskValidationPreview, requested []riskValidationSelection) ([]riskValidationCandidate, error) {
	if len(preview.Candidates) == 0 {
		return nil, errRiskValidationEmptyPlan
	}
	if len(requested) == 0 {
		return append([]riskValidationCandidate(nil), preview.Candidates...), nil
	}
	available := make(map[string]riskValidationCandidate, len(preview.Candidates))
	for _, candidate := range preview.Candidates {
		available[riskValidationCandidateKey(candidate.Endpoint, candidate.PocFile, candidate.PocContentHash)] = candidate
	}
	selected := make([]riskValidationCandidate, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, item := range requested {
		key := riskValidationCandidateKey(item.Endpoint, item.PocFile, item.PocContentHash)
		candidate, exists := available[key]
		if !exists {
			return nil, errRiskValidationSelection
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		selected = append(selected, candidate)
	}
	if len(selected) == 0 {
		return nil, errRiskValidationEmptyPlan
	}
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].Endpoint != selected[j].Endpoint {
			return selected[i].Endpoint < selected[j].Endpoint
		}
		return selected[i].PocFile < selected[j].PocFile
	})
	return selected, nil
}

func buildRiskValidationAttemptConfig(revision db.TaskConfigRevision, ruleVersion string, selected []riskValidationCandidate) (string, []string, int64, bool, error) {
	targetPocs := make(map[string][]string)
	pocHashes := make(map[string]string)
	pocSet := make(map[string]struct{})
	var estimated int64
	secondConfirmation := false
	for _, candidate := range selected {
		endpoint := strings.TrimSpace(candidate.Endpoint)
		pocFile := strings.TrimSpace(candidate.PocFile)
		contentHash := strings.ToLower(strings.TrimSpace(candidate.PocContentHash))
		if endpoint == "" || !isSafeRiskValidationPocFile(pocFile) || contentHash == "" {
			return "", nil, 0, false, errRiskValidationSelection
		}
		if existing, exists := pocHashes[pocFile]; exists && existing != contentHash {
			return "", nil, 0, false, errRiskValidationSelection
		}
		pocHashes[pocFile] = contentHash
		duplicate := false
		for _, existing := range targetPocs[endpoint] {
			if existing == pocFile {
				duplicate = true
				break
			}
		}
		if !duplicate {
			targetPocs[endpoint] = append(targetPocs[endpoint], pocFile)
		}
		pocSet[pocFile] = struct{}{}
		estimated = saturatingAdd(estimated, candidate.EstimatedRequests)
		secondConfirmation = secondConfirmation || candidate.RequiresSecondConfirmation
	}
	targets := make([]string, 0, len(targetPocs))
	for target := range targetPocs {
		sort.Strings(targetPocs[target])
		targets = append(targets, target)
	}
	sort.Strings(targets)
	if len(targets) == 0 {
		return "", nil, 0, false, errRiskValidationEmptyPlan
	}

	config := make(map[string]interface{})
	if strings.TrimSpace(revision.Config) != "" {
		if err := json.Unmarshal([]byte(revision.Config), &config); err != nil {
			return "", nil, 0, false, fmt.Errorf("decode current task config: %w", err)
		}
	}
	config["ExecutionMode"] = "risk_validation"
	config["RequiredRuleVersion"] = strings.TrimSpace(ruleVersion)
	config["RiskValidationTargets"] = targetPocs
	config["RiskValidationPocHashes"] = pocHashes
	// These flags are redundant with the dedicated Scanner branch but make
	// the safety intent explicit in the immutable Attempt snapshot.
	config["NoPoc"] = false
	config["GolangPoc"] = false
	config["PocNameForSearch"] = ""
	config["Hunter"] = false
	config["Fofa"] = false
	config["Quake"] = false
	encoded, err := json.Marshal(config)
	if err != nil {
		return "", nil, 0, false, err
	}
	return string(encoded), targets, estimated, secondConfirmation, nil
}

func currentRuleVersionTx(tx *gorm.DB) string {
	var config db.SystemConfig
	if err := tx.Where("key = ?", "rule_version").First(&config).Error; err == nil {
		if version := strings.TrimSpace(config.Value); version != "" {
			return version
		}
	}
	return "unknown"
}

func executeTaskRiskValidation(c *gin.Context) {
	tenantID := currentTenantID(c)
	var task db.RootTask
	if err := db.DB.WithContext(c.Request.Context()).Where("id = ? AND tenant_id = ?", c.Param("id"), tenantID).First(&task).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, task.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}
	idempotencyKey, idempotencyRequested, idempotencyErr := parseRiskValidationExecutionIdempotencyKey(c.Request.Header)
	if idempotencyErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_idempotency_key", "error": idempotencyErr.Error()})
		return
	}

	var request executeRiskValidationRequest
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid risk validation request: " + err.Error()})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid risk validation request: expected one JSON object"})
		return
	}
	if !idempotencyRequested && !request.Confirmed {
		c.JSON(http.StatusBadRequest, gin.H{"error": errRiskValidationConfirmation.Error()})
		return
	}
	specified, err := normalizeSpecifiedPocReferences(request.SpecifiedPocs)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	requestHash := ""
	if idempotencyRequested {
		requestHash, err = buildRiskValidationExecutionRequestHash(canonicalRiskValidationExecutionRequest{TenantID: tenantID, ProjectID: task.ProjectID, RootTaskID: task.ID, OperatorID: taskOperatorID(c), PlanHash: request.PlanHash, SpecifiedPOCs: specified, Selected: request.Selected, Confirmed: request.Confirmed, SecondConfirmation: request.SecondConfirmation})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	var preview riskValidationPreview
	var selected []riskValidationCandidate
	if !idempotencyRequested {
		preview, err = buildTaskRiskValidationPreview(c.Request.Context(), tenantID, task, riskValidationPreviewOptions{SpecifiedPocs: specified})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if len(strings.TrimSpace(request.PlanHash)) != len(preview.PlanHash) || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(request.PlanHash)), []byte(preview.PlanHash)) != 1 {
			c.JSON(http.StatusConflict, gin.H{"error": errRiskValidationStalePlan.Error()})
			return
		}
		selected, err = selectRiskValidationCandidates(preview, request.Selected)
		if err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
	}

	var result riskValidationExecutionResult
	replayed, replayDispatchPending := false, 0
	err = db.DB.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		var current db.RootTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ?", task.ID, tenantID).First(&current).Error; err != nil {
			return err
		}
		if current.ArchivedAt != nil {
			return errRiskValidationTaskState
		}
		var project db.Project
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ?", current.ProjectID, tenantID).First(&project).Error; err != nil {
			return err
		}
		if !strings.EqualFold(strings.TrimSpace(project.Status), "active") {
			return errProjectInactive
		}
		if idempotencyRequested {
			lookup, err := db.LookupRiskValidationExecutionIdempotencyTx(tx, tenantID, current.ProjectID, current.ID, taskOperatorID(c), riskValidationExecutionIdempotencyOperation, idempotencyKey, requestHash)
			if err != nil {
				return err
			}
			if lookup.Replayed {
				result, replayDispatchPending, err = riskValidationExecutionReplay(tx, lookup.Record)
				replayed = err == nil
				return err
			}
		}
		if !db.IsTerminalTaskStatus(current.Status) {
			return errRiskValidationTaskState
		}
		if !request.Confirmed {
			return errRiskValidationConfirmation
		}
		if routerRuntime().TaskQueue == nil {
			return errRiskValidationQueueUnavailable
		}
		currentConfigVersion := current.CurrentConfigVersion
		if currentConfigVersion < 1 {
			currentConfigVersion = 1
		}
		if idempotencyRequested {
			var previewErr error
			preview, previewErr = buildTaskRiskValidationPreview(c.Request.Context(), tenantID, current, riskValidationPreviewOptions{SpecifiedPocs: specified})
			if previewErr != nil {
				return previewErr
			}
			if len(strings.TrimSpace(request.PlanHash)) != len(preview.PlanHash) || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(request.PlanHash)), []byte(preview.PlanHash)) != 1 {
				return errRiskValidationStalePlan
			}
			selected, previewErr = selectRiskValidationCandidates(preview, request.Selected)
			if previewErr != nil {
				return previewErr
			}
		}
		if currentConfigVersion != preview.ConfigVersion || currentRuleVersionTx(tx) != preview.RuleVersion {
			return errRiskValidationStalePlan
		}
		revision, err := db.CurrentTaskConfigRevision(tx, current)
		if err != nil {
			return err
		}
		if revision.Version != preview.ConfigVersion {
			return errRiskValidationStalePlan
		}
		attemptConfig, targets, estimated, needsSecondConfirmation, err := buildRiskValidationAttemptConfig(revision, preview.RuleVersion, selected)
		if err != nil {
			return err
		}
		if needsSecondConfirmation && !request.SecondConfirmation {
			return errRiskValidationSecondCheck
		}

		var sequence int
		if err := tx.Model(&db.TaskBatch{}).Select("COALESCE(MAX(sequence), -1) + 1").
			Where("tenant_id = ? AND root_task_id = ?", tenantID, current.ID).Scan(&sequence).Error; err != nil {
			return err
		}
		batchID := current.ID + "-risk-" + uuid.NewString()
		attemptID := batchID + "-attempt-1"
		targetJSON, _ := json.Marshal(targets)
		result.Batch = db.TaskBatch{
			ID: batchID, TenantID: tenantID, ProjectID: current.ProjectID, RootTaskID: current.ID,
			Sequence: sequence, Kind: "risk_validation", TargetType: "risk_validation",
			Targets: string(targetJSON), TargetCount: len(targets), Status: subTaskStatusDispatching,
			ControlState: string(db.BatchControlActive), ConfigVersion: revision.Version, RuleVersion: preview.RuleVersion,
			Priority: revision.Priority, TimeoutSec: revision.TimeoutSec,
			AgentSelector: revision.AgentSelector, AgentSelectorRules: revision.AgentSelectorRules,
			CurrentAttemptNo: 1, AttemptCount: 1, LatestAttemptID: attemptID, CreatedBy: taskOperatorID(c),
		}
		result.Attempt = db.SubTask{
			ID: attemptID, TenantID: tenantID, ProjectID: current.ProjectID, RootTaskID: current.ID,
			BatchID: batchID, AttemptNo: 1, Trigger: db.AttemptTriggerInitial,
			ChunkTargets: string(targetJSON), Status: subTaskStatusDispatching, Config: attemptConfig,
			Priority: revision.Priority, TimeoutSec: revision.TimeoutSec, MaxRetry: 0,
			ConfigVersion: revision.Version, RuleVersion: preview.RuleVersion,
			AgentSelector: revision.AgentSelector, AgentSelectorRules: revision.AgentSelectorRules,
		}
		if err := tx.Create(&result.Batch).Error; err != nil {
			return err
		}
		if err := tx.Create(&result.Attempt).Error; err != nil {
			return err
		}
		// SubTask has a legacy GORM default of three retries. Risk validation
		// must never inherit that automatic retry budget.
		if err := tx.Model(&db.SubTask{}).Where("id = ? AND tenant_id = ?", result.Attempt.ID, tenantID).
			Update("max_retry", 0).Error; err != nil {
			return err
		}
		result.Attempt.MaxRetry = 0
		rootUpdate := tx.Model(&db.RootTask{}).
			Where("id = ? AND tenant_id = ? AND status = ? AND archived_at IS NULL", current.ID, tenantID, current.Status).
			Updates(map[string]interface{}{
				"status": "Running", "total_chunks": current.TotalChunks + 1,
				"total_targets": current.TotalTargets + len(targets), "rule_version": preview.RuleVersion,
			})
		if rootUpdate.Error != nil {
			return rootUpdate.Error
		}
		if rootUpdate.RowsAffected != 1 {
			return errTaskStateChanged
		}
		pocSet := make(map[string]struct{})
		for _, candidate := range selected {
			pocSet[candidate.PocFile] = struct{}{}
		}
		result.CandidateCount = len(selected)
		result.PocCount = len(pocSet)
		result.Estimated = estimated
		result.SecondConfirmed = needsSecondConfirmation
		if err := recordBatchAudit(tx, current, result.Batch, result.Attempt.ID, "risk_validation_execute", current.Status, "Running", taskOperatorID(c), map[string]interface{}{
			"plan_hash": preview.PlanHash, "candidate_count": len(selected), "poc_count": len(pocSet),
			"estimated_requests": estimated, "config_version": revision.Version, "rule_version": preview.RuleVersion,
			"authorization_confirmed":      request.Confirmed,
			"second_confirmation_required": needsSecondConfirmation, "second_confirmation_confirmed": request.SecondConfirmation,
			"specified_poc_count": len(specified), "automatic_retry": false,
		}); err != nil {
			return err
		}
		if idempotencyRequested {
			ledger, err := db.RecordRiskValidationExecutionIdempotencyTx(tx, db.RiskValidationExecutionIdempotencyDraft{TenantID: tenantID, ProjectID: current.ProjectID, RootTaskID: current.ID, OperatorID: taskOperatorID(c), Operation: riskValidationExecutionIdempotencyOperation, IdempotencyKey: idempotencyKey, RequestHash: requestHash, PlanHash: preview.PlanHash, POCSetHash: riskValidationExecutionPOCSetHash(selected), ConfigVersion: result.Attempt.ConfigVersion, ConfigHash: riskValidationExecutionConfigHash(result.Attempt.Config), RuleVersion: result.Attempt.RuleVersion, BatchID: result.Batch.ID, BatchSequence: result.Batch.Sequence, AttemptID: result.Attempt.ID, AttemptNo: result.Attempt.AttemptNo, CandidateCount: result.CandidateCount, TargetCount: result.Batch.TargetCount, POCCount: result.PocCount, EstimatedRequests: result.Estimated, SecondConfirmationRequired: result.SecondConfirmed, BeforeStatus: current.Status, AfterStatus: "Running"})
			if err != nil {
				return err
			}
			if ledger.Replayed {
				return errRiskValidationIdempotencyRace
			}
			return nil
		}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, errRiskValidationSecondCheck), errors.Is(err, errRiskValidationConfirmation), errors.Is(err, errRiskValidationEmptyPlan):
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case errors.Is(err, db.ErrRiskValidationExecutionIdempotencyConflict):
			c.JSON(http.StatusConflict, gin.H{"code": "idempotency_conflict", "error": "Idempotency-Key was already used for a different risk validation request"})
		case errors.Is(err, errRiskValidationIdempotencyRace):
			c.JSON(http.StatusConflict, gin.H{"code": "idempotency_conflict", "error": "Idempotency-Key was committed concurrently; retry the same request"})
		case errors.Is(err, errRiskValidationQueueUnavailable):
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		case errors.Is(err, errRiskValidationStalePlan), errors.Is(err, errRiskValidationTaskState), errors.Is(err, errRiskValidationSelection), errors.Is(err, errProjectInactive), errors.Is(err, errTaskStateChanged):
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return
	}

	if replayed {
		c.JSON(http.StatusAccepted, gin.H{"status": "scheduled", "task_id": task.ID, "batch_id": result.Batch.ID, "attempt_id": result.Attempt.ID, "candidate_count": result.CandidateCount, "target_count": result.Batch.TargetCount, "poc_count": result.PocCount, "estimated_requests": result.Estimated, "config_version": result.Attempt.ConfigVersion, "rule_version": result.Attempt.RuleVersion, "dispatch_pending": replayDispatchPending, "replayed": true})
		return
	}
	pushed, dispatchPending := dispatchSubTasks(context.Background(), routerRuntime().TaskQueue, []db.SubTask{result.Attempt})
	if totalDispatchedTasks(pushed) > 0 {
		broadcastDispatchedTasks(pushed)
	}
	db.RefreshRootTaskStatus(task.ID)
	c.JSON(http.StatusAccepted, gin.H{
		"status": "scheduled", "task_id": task.ID, "batch_id": result.Batch.ID,
		"attempt_id": result.Attempt.ID, "candidate_count": result.CandidateCount,
		"target_count": result.Batch.TargetCount, "poc_count": result.PocCount,
		"estimated_requests": result.Estimated, "config_version": result.Attempt.ConfigVersion,
		"rule_version": result.Attempt.RuleVersion, "dispatch_pending": dispatchPending, "replayed": false,
	})
}
