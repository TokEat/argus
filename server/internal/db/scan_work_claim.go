package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/user/dddd-proto/go/scanplan"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	scanWorkClaimStatusActive     = "active"
	scanWorkClaimStatusComplete   = "completed"
	scanWorkClaimStatusFailed     = "failed"
	scanWorkClaimMarkerPrefix     = "workclaim:"
	taskCoverageLinkExecuted      = "executed"
	taskCoverageLinkInFlight      = "in_flight"
	taskCoverageLinkStatusActive  = "active"
	taskCoverageLinkStatusWaiting = "waiting"
)

// ScanWorkClaimPlan is an immutable candidate calculated before quota checks.
// AcquireScanWorkClaimsAtLease rebuilds it under the final Agent lease
// transaction, so lifecycle, scope, configuration, and network-zone changes
// cannot leak a stale claim.
type ScanWorkClaimPlan struct {
	Enabled     bool
	AttemptID   string
	TenantID    string
	ProjectID   string
	RootTaskID  string
	BatchID     string
	AgentID     string
	NetworkZone string
	Targets     []string
	Claims      []ScanWorkClaim
}

type ScanWorkClaimAcquireResult struct {
	Claims   []ScanWorkClaim
	Links    []TaskCoverageLink
	Conflict bool
}

// PlanScanWorkClaimsAtClaim calculates one whole-target execution mutex per
// target. The Scanner currently runs a target as one pipeline, so the stable
// fingerprint WorkKey represents that pipeline until stage-level dispatch is
// introduced. This does not imply fingerprint-only coverage.
func PlanScanWorkClaimsAtClaim(store *gorm.DB, attemptID, tenantID, agentID string, targets []string) (ScanWorkClaimPlan, error) {
	plan := ScanWorkClaimPlan{}
	if store == nil {
		return plan, errors.New("scan work claim store is unavailable")
	}
	err := store.Transaction(func(tx *gorm.DB) error {
		var err error
		plan, err = buildScanWorkClaimPlan(tx, attemptID, tenantID, agentID, targets)
		return err
	})
	return plan, err
}

func buildScanWorkClaimPlan(store *gorm.DB, attemptID, tenantID, agentID string, requestedTargets []string) (ScanWorkClaimPlan, error) {
	plan := ScanWorkClaimPlan{
		AttemptID: strings.TrimSpace(attemptID),
		TenantID:  strings.TrimSpace(tenantID),
		AgentID:   strings.TrimSpace(agentID),
	}
	if plan.AttemptID == "" || plan.TenantID == "" || plan.AgentID == "" {
		return plan, errors.New("scan work claim requires attempt, tenant, and agent identities")
	}

	attempt, batch, _, eligible, err := lockReusableAttemptContext(store, plan.AttemptID, plan.TenantID)
	if err != nil {
		return plan, fmt.Errorf("load scan work claim attempt: %w", err)
	}
	plan.ProjectID = attempt.ProjectID
	plan.RootTaskID = attempt.RootTaskID
	plan.BatchID = attempt.BatchID
	if !eligible || strings.EqualFold(strings.TrimSpace(batch.Kind), "risk_validation") ||
		normalizeAttemptTrigger(attempt.Trigger) == AttemptTriggerManualRetry {
		return plan, nil
	}

	var allTargets []string
	if err := json.Unmarshal([]byte(attempt.ChunkTargets), &allTargets); err != nil || len(allTargets) == 0 {
		return plan, nil
	}
	targets, ok := claimTargetSubset(allTargets, requestedTargets)
	if !ok {
		return plan, errors.New("scan work claim targets are not a subset of the current attempt")
	}
	if len(targets) == 0 {
		return plan, nil
	}

	var node Node
	if err := store.Select("agent_id", "tenant_id", "status", "tags").
		Where("agent_id = ? AND tenant_id = ? AND UPPER(status) = ?", plan.AgentID, attempt.TenantID, "ALIVE").
		First(&node).Error; err != nil {
		return plan, nil
	}
	if _, valid := decodeReusableScanConfig(attempt.Config); !valid {
		return plan, nil
	}
	ruleVersion := strings.TrimSpace(attempt.RuleVersion)
	if strings.TrimSpace(attempt.ProjectID) == "" || strings.TrimSpace(attempt.RootTaskID) == "" ||
		ruleVersion == "" || strings.EqualFold(ruleVersion, "unknown") || strings.EqualFold(ruleVersion, "_unknown") {
		return plan, nil
	}

	var project Project
	if err := store.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ? AND tenant_id = ? AND status = ?", attempt.ProjectID, attempt.TenantID, "active").
		First(&project).Error; err != nil {
		return plan, nil
	}
	scopeHash, scopeValid := canonicalJSONHash(project.Scope)
	if !scopeValid {
		return plan, nil
	}
	configHash := observationConfigHash(store, attempt)

	claims := make([]ScanWorkClaim, 0, len(targets))
	for _, target := range targets {
		if reusableTargetKind(target) == "" {
			return plan, nil
		}
		networkZone := scanNetworkZoneForTarget(plan.AgentID, node.Tags, target)
		workKey := scanplan.WorkKey{
			TenantID:         attempt.TenantID,
			ProjectID:        attempt.ProjectID,
			NetworkZone:      networkZone,
			NormalizedTarget: target,
			Stage:            scanplan.StageFingerprint,
			ScopeHash:        scopeHash,
			ConfigHash:       configHash,
			RuleVersion:      attempt.RuleVersion,
		}
		digest, err := workKey.Digest()
		if err != nil {
			return plan, fmt.Errorf("build scan work claim WorkKey: %w", err)
		}
		claims = append(claims, ScanWorkClaim{
			SchemaVersion:    scanplan.SchemaVersion,
			TenantID:         attempt.TenantID,
			ProjectID:        attempt.ProjectID,
			NetworkZone:      networkZone,
			NormalizedTarget: target,
			TargetHash:       stableScanClaimHash(target),
			Stage:            string(scanplan.StageFingerprint),
			WorkKeyHash:      digest,
			ScopeHash:        scopeHash,
			ConfigHash:       configHash,
			RuleVersion:      attempt.RuleVersion,
		})
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i].WorkKeyHash < claims[j].WorkKeyHash })
	plan.Enabled = len(claims) > 0
	plan.NetworkZone = scanWorkClaimPlanZone(claims)
	plan.Targets = append([]string(nil), targets...)
	plan.Claims = claims
	return plan, nil
}

func claimTargetSubset(allTargets, requestedTargets []string) ([]string, bool) {
	available := make(map[string]struct{}, len(allTargets))
	ordered := make([]string, 0, len(allTargets))
	for _, target := range allTargets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, exists := available[target]; exists {
			continue
		}
		available[target] = struct{}{}
		ordered = append(ordered, target)
	}
	if requestedTargets == nil {
		return ordered, len(ordered) > 0
	}
	seen := make(map[string]struct{}, len(requestedTargets))
	result := make([]string, 0, len(requestedTargets))
	for _, target := range requestedTargets {
		target = strings.TrimSpace(target)
		if _, exists := available[target]; !exists || target == "" {
			return nil, false
		}
		if _, exists := seen[target]; exists {
			continue
		}
		seen[target] = struct{}{}
		result = append(result, target)
	}
	return result, len(result) > 0
}

// AttachAttemptToActiveWorkClaims parks a whole destination Attempt when any
// target is already executing. The queue message can then be ACKed without
// consuming Agent capacity; terminal claim resolution moves it back to
// Dispatching for a fresh coverage/reuse decision.
func AttachAttemptToActiveWorkClaims(store *gorm.DB, plan ScanWorkClaimPlan) (bool, int, error) {
	if store == nil || !plan.Enabled {
		return false, 0, nil
	}
	attached := false
	attachedCount := 0
	err := store.Transaction(func(tx *gorm.DB) error {
		current, err := buildScanWorkClaimPlan(tx, plan.AttemptID, plan.TenantID, plan.AgentID, plan.Targets)
		if err != nil {
			return err
		}
		if !current.Enabled {
			return nil
		}
		hashes := scanWorkClaimHashes(current.Claims)
		var claims []ScanWorkClaim
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where(
			"tenant_id = ? AND project_id = ? AND work_key_hash IN ? AND status = ?",
			current.TenantID, current.ProjectID, hashes, scanWorkClaimStatusActive,
		).Order("work_key_hash asc").Find(&claims).Error; err != nil {
			return fmt.Errorf("load active scan work claims: %w", err)
		}
		active := make([]ScanWorkClaim, 0, len(claims))
		for _, claim := range claims {
			if claim.OwnerAttemptID == current.AttemptID {
				continue
			}
			ownerActive, err := scanWorkClaimOwnerActive(tx, claim)
			if err != nil {
				return err
			}
			if ownerActive {
				active = append(active, claim)
			}
		}
		if len(active) == 0 {
			return nil
		}

		for _, claim := range active {
			link := TaskCoverageLink{
				SchemaVersion: scanplan.SchemaVersion,
				TenantID:      current.TenantID, ProjectID: current.ProjectID, RootTaskID: current.RootTaskID,
				BatchID: current.BatchID, AttemptID: current.AttemptID, WorkKeyHash: claim.WorkKeyHash,
				LinkType: taskCoverageLinkInFlight, Status: taskCoverageLinkStatusWaiting, ClaimID: claim.ID,
				SourceTaskID: claim.OwnerTaskID, SourceBatchID: claim.OwnerBatchID,
				SourceAttemptID: claim.OwnerAttemptID, Reason: "active_work_claim",
			}
			if err := tx.Clauses(clause.OnConflict{
				Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "project_id"}, {Name: "root_task_id"}, {Name: "batch_id"}, {Name: "attempt_id"}, {Name: "work_key_hash"}, {Name: "link_type"}},
				DoUpdates: clause.AssignmentColumns([]string{"status", "claim_id", "source_task_id", "source_batch_id", "source_attempt_id", "reason", "updated_at"}),
			}).Create(&link).Error; err != nil {
				return fmt.Errorf("attach destination to active scan work claim: %w", err)
			}
		}
		marker := scanWorkClaimMarker(active)
		updated := tx.Model(&SubTask{}).Where(
			"id = ? AND tenant_id = ? AND project_id = ? AND status IN ? AND agent_id = ?",
			current.AttemptID, current.TenantID, current.ProjectID, []string{"Pending", "Recovered", "Dispatching"}, "",
		).Updates(map[string]interface{}{"status": "Pending", "stream_msg_id": marker})
		if updated.Error != nil {
			return fmt.Errorf("park destination on active scan work claim: %w", updated.Error)
		}
		if updated.RowsAffected != 1 {
			return ErrScanReuseAttemptNotClaimable
		}
		if current.BatchID != "" {
			if err := tx.Model(&TaskBatch{}).Where(
				"id = ? AND tenant_id = ? AND latest_attempt_id = ?", current.BatchID, current.TenantID, current.AttemptID,
			).Update("status", "Pending").Error; err != nil {
				return fmt.Errorf("park scan work claim batch: %w", err)
			}
		}
		attached = true
		attachedCount = len(active)
		return nil
	})
	return attached, attachedCount, err
}

// AcquireScanWorkClaimsAtLease atomically owns every whole-target claim inside
// the caller's Agent lease transaction. A conflict must cause the caller to
// roll back the entire transaction and attach in a separate transaction.
func AcquireScanWorkClaimsAtLease(store *gorm.DB, plan ScanWorkClaimPlan) (ScanWorkClaimAcquireResult, error) {
	result := ScanWorkClaimAcquireResult{}
	if store == nil || !plan.Enabled {
		return result, nil
	}
	current, err := buildScanWorkClaimPlan(store, plan.AttemptID, plan.TenantID, plan.AgentID, plan.Targets)
	if err != nil {
		return result, err
	}
	if !current.Enabled || !scanWorkClaimPlansEqual(plan, current) {
		return result, ErrReusableCoverageChanged
	}

	now := time.Now().UTC()
	leaseDuration := time.Duration(60) * time.Second
	var attempt SubTask
	if err := store.Select("id", "timeout_sec").Where(
		"id = ? AND tenant_id = ? AND project_id = ?", current.AttemptID, current.TenantID, current.ProjectID,
	).First(&attempt).Error; err != nil {
		return result, fmt.Errorf("load scan work claim lease timeout: %w", err)
	}
	if timeout := time.Duration(attempt.TimeoutSec) * time.Second; timeout > leaseDuration {
		leaseDuration = timeout
	}
	leaseExpires := now.Add(leaseDuration)

	for _, candidate := range current.Claims {
		claim, exists, err := loadScanWorkClaimForUpdate(store, current.TenantID, current.ProjectID, candidate.WorkKeyHash)
		if err != nil {
			return result, err
		}
		if !exists {
			candidate.Status = scanWorkClaimStatusActive
			candidate.OwnerTaskID = current.RootTaskID
			candidate.OwnerBatchID = current.BatchID
			candidate.OwnerAttemptID = current.AttemptID
			candidate.OwnerAgentID = current.AgentID
			candidate.ClaimedAt = now
			candidate.LeaseExpiresAt = &leaseExpires
			candidate.Revision = 1
			candidate.LeaseTokenHash = scanWorkClaimLeaseHash(candidate, current.AttemptID, current.AgentID, candidate.Revision)
			created := store.Clauses(clause.OnConflict{DoNothing: true}).Create(&candidate)
			if created.Error != nil {
				return result, fmt.Errorf("create scan work claim: %w", created.Error)
			}
			if created.RowsAffected == 1 {
				claim = candidate
				exists = true
			} else {
				claim, exists, err = loadScanWorkClaimForUpdate(store, current.TenantID, current.ProjectID, candidate.WorkKeyHash)
				if err != nil {
					return result, err
				}
			}
		}
		if !exists {
			return result, errors.New("scan work claim disappeared after conflict")
		}

		if claim.Status == scanWorkClaimStatusActive && claim.OwnerAttemptID != current.AttemptID {
			ownerActive, err := scanWorkClaimOwnerActive(store, claim)
			if err != nil {
				return result, err
			}
			if ownerActive {
				result.Conflict = true
				return result, nil
			}
		}

		if claim.OwnerAttemptID != current.AttemptID || claim.Status != scanWorkClaimStatusActive {
			claimID := claim.ID
			revision := claim.Revision + 1
			if revision < 1 {
				revision = 1
			}
			updates := map[string]interface{}{
				"schema_version": candidate.SchemaVersion, "network_zone": candidate.NetworkZone,
				"normalized_target": candidate.NormalizedTarget, "target_hash": candidate.TargetHash,
				"stage": candidate.Stage, "scope_hash": candidate.ScopeHash, "config_hash": candidate.ConfigHash,
				"rule_version": candidate.RuleVersion, "poc_set_hash": "", "endpoint_content_hash": "",
				"status": scanWorkClaimStatusActive, "owner_task_id": current.RootTaskID,
				"owner_batch_id": current.BatchID, "owner_attempt_id": current.AttemptID,
				"owner_agent_id": current.AgentID, "lease_expires_at": leaseExpires,
				"claimed_at": now, "released_at": nil, "revision": revision, "last_error": "",
				"lease_token_hash": scanWorkClaimLeaseHash(candidate, current.AttemptID, current.AgentID, revision),
			}
			if err := store.Model(&ScanWorkClaim{}).Where(
				"id = ? AND tenant_id = ? AND project_id = ?", claim.ID, current.TenantID, current.ProjectID,
			).Updates(updates).Error; err != nil {
				return result, fmt.Errorf("recycle scan work claim: %w", err)
			}
			if err := store.Model(&TaskCoverageLink{}).Where(
				"tenant_id = ? AND project_id = ? AND claim_id = ? AND link_type = ? AND status = ?",
				current.TenantID, current.ProjectID, claim.ID, taskCoverageLinkInFlight, taskCoverageLinkStatusWaiting,
			).Updates(map[string]interface{}{
				"source_task_id": current.RootTaskID, "source_batch_id": current.BatchID,
				"source_attempt_id": current.AttemptID, "reason": "source_replanned",
			}).Error; err != nil {
				return result, fmt.Errorf("repoint scan work claim waiters: %w", err)
			}
			claim = candidate
			claim.ID = claimID
			claim.Status = scanWorkClaimStatusActive
			claim.OwnerTaskID = current.RootTaskID
			claim.OwnerBatchID = current.BatchID
			claim.OwnerAttemptID = current.AttemptID
			claim.OwnerAgentID = current.AgentID
			claim.LeaseExpiresAt = &leaseExpires
			claim.ClaimedAt = now
			claim.ReleasedAt = nil
			claim.Revision = revision
			claim.LastError = ""
			claim.LeaseTokenHash = scanWorkClaimLeaseHash(candidate, current.AttemptID, current.AgentID, revision)
		}

		result.Claims = append(result.Claims, claim)
		result.Links = append(result.Links, TaskCoverageLink{
			SchemaVersion: scanplan.SchemaVersion,
			TenantID:      current.TenantID, ProjectID: current.ProjectID, RootTaskID: current.RootTaskID,
			BatchID: current.BatchID, AttemptID: current.AttemptID, WorkKeyHash: claim.WorkKeyHash,
			LinkType: taskCoverageLinkExecuted, Status: taskCoverageLinkStatusActive, ClaimID: claim.ID,
			SourceTaskID: current.RootTaskID, SourceBatchID: current.BatchID,
			SourceAttemptID: current.AttemptID, Reason: "claimed_for_execution",
		})
	}
	return result, nil
}

func loadScanWorkClaimForUpdate(store *gorm.DB, tenantID, projectID, workKeyHash string) (ScanWorkClaim, bool, error) {
	var claim ScanWorkClaim
	err := store.Clauses(clause.Locking{Strength: "UPDATE"}).Where(
		"tenant_id = ? AND project_id = ? AND work_key_hash = ?", tenantID, projectID, workKeyHash,
	).First(&claim).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return claim, false, nil
	}
	if err != nil {
		return claim, false, fmt.Errorf("load scan work claim: %w", err)
	}
	return claim, true, nil
}

func scanWorkClaimOwnerActive(store *gorm.DB, claim ScanWorkClaim) (bool, error) {
	if strings.TrimSpace(claim.OwnerAttemptID) == "" {
		return false, nil
	}
	var owner SubTask
	if err := store.Select("id", "status", "tenant_id", "project_id").Where(
		"id = ? AND tenant_id = ? AND project_id = ?", claim.OwnerAttemptID, claim.TenantID, claim.ProjectID,
	).First(&owner).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("load scan work claim owner: %w", err)
	}
	state := CanonicalAttemptState(owner.Status)
	return state == AttemptStateRunning || state == AttemptStateStopping, nil
}

// ResolveScanWorkClaimsForAttempt atomically releases a terminal source, then
// promotes waiters whose every in-flight dependency has resolved through a
// per-Attempt CAS. Claim and destination locks are intentionally not held in
// the same transaction, avoiding a claim/lease deadlock with ClaimTask.
func ResolveScanWorkClaimsForAttempt(store *gorm.DB, sourceAttemptID string) ([]SubTask, error) {
	ready := []SubTask{}
	if store == nil || strings.TrimSpace(sourceAttemptID) == "" {
		return ready, nil
	}
	destinationIDs := []string{}
	tenantID := ""
	projectID := ""
	err := store.Transaction(func(tx *gorm.DB) error {
		var source SubTask
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", strings.TrimSpace(sourceAttemptID)).First(&source).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return fmt.Errorf("load terminal scan work claim source: %w", err)
		}
		state := CanonicalAttemptState(source.Status)
		if !IsTerminalAttemptStatus(source.Status) {
			return nil
		}
		tenantID = source.TenantID
		projectID = source.ProjectID
		var claims []ScanWorkClaim
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where(
			"tenant_id = ? AND project_id = ? AND owner_attempt_id = ? AND status = ?",
			source.TenantID, source.ProjectID, source.ID, scanWorkClaimStatusActive,
		).Order("work_key_hash asc").Find(&claims).Error; err != nil {
			return fmt.Errorf("load terminal scan work claims: %w", err)
		}
		if len(claims) == 0 {
			return nil
		}
		claimIDs := make([]uint64, 0, len(claims))
		for _, claim := range claims {
			claimIDs = append(claimIDs, claim.ID)
		}
		now := time.Now().UTC()
		claimStatus := scanWorkClaimStatusFailed
		linkStatus := scanWorkClaimStatusFailed
		waiterStatus := "source_failed"
		lastError := NormalizeAttemptFailureReason(source.FailureReason)
		if state == AttemptStateCompleted {
			claimStatus = scanWorkClaimStatusComplete
			linkStatus = scanWorkClaimStatusComplete
			waiterStatus = "resolved"
			lastError = ""
		}
		if err := tx.Model(&ScanWorkClaim{}).Where(
			"tenant_id = ? AND project_id = ? AND owner_attempt_id = ? AND id IN ? AND status = ?",
			source.TenantID, source.ProjectID, source.ID, claimIDs, scanWorkClaimStatusActive,
		).Updates(map[string]interface{}{
			"status": claimStatus, "released_at": now, "lease_expires_at": nil, "last_error": lastError,
		}).Error; err != nil {
			return fmt.Errorf("release terminal scan work claims: %w", err)
		}
		if err := tx.Model(&TaskCoverageLink{}).Where(
			"tenant_id = ? AND project_id = ? AND source_attempt_id = ? AND claim_id IN ? AND link_type = ?",
			source.TenantID, source.ProjectID, source.ID, claimIDs, taskCoverageLinkExecuted,
		).Update("status", linkStatus).Error; err != nil {
			return fmt.Errorf("settle executed scan work links: %w", err)
		}

		var waiting []TaskCoverageLink
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where(
			"tenant_id = ? AND project_id = ? AND claim_id IN ? AND link_type = ? AND status = ?",
			source.TenantID, source.ProjectID, claimIDs, taskCoverageLinkInFlight, taskCoverageLinkStatusWaiting,
		).Order("attempt_id asc, work_key_hash asc").Find(&waiting).Error; err != nil {
			return fmt.Errorf("load scan work claim waiters: %w", err)
		}
		if len(waiting) == 0 {
			return nil
		}
		if err := tx.Model(&TaskCoverageLink{}).Where(
			"tenant_id = ? AND project_id = ? AND claim_id IN ? AND link_type = ? AND status = ?",
			source.TenantID, source.ProjectID, claimIDs, taskCoverageLinkInFlight, taskCoverageLinkStatusWaiting,
		).Updates(map[string]interface{}{"status": waiterStatus}).Error; err != nil {
			return fmt.Errorf("settle scan work claim waiters: %w", err)
		}

		seen := make(map[string]struct{}, len(waiting))
		for _, link := range waiting {
			if _, exists := seen[link.AttemptID]; exists || strings.TrimSpace(link.AttemptID) == "" {
				continue
			}
			seen[link.AttemptID] = struct{}{}
			destinationIDs = append(destinationIDs, link.AttemptID)
		}
		return nil
	})
	if err != nil {
		return ready, err
	}
	sort.Strings(destinationIDs)
	for _, attemptID := range destinationIDs {
		destination, promoted, err := promoteResolvedWorkClaimDestination(store, tenantID, projectID, attemptID)
		if err != nil {
			return ready, err
		}
		if promoted {
			ready = append(ready, destination)
		}
	}
	return ready, nil
}

func promoteResolvedWorkClaimDestination(store *gorm.DB, tenantID, projectID, attemptID string) (SubTask, bool, error) {
	destination := SubTask{}
	promoted := false
	err := store.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where(
			"id = ? AND tenant_id = ? AND project_id = ?", attemptID, tenantID, projectID,
		).First(&destination).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return fmt.Errorf("load scan work claim destination: %w", err)
		}
		var remaining int64
		if err := tx.Model(&TaskCoverageLink{}).Where(
			"tenant_id = ? AND project_id = ? AND attempt_id = ? AND link_type = ? AND status = ?",
			tenantID, projectID, attemptID, taskCoverageLinkInFlight, taskCoverageLinkStatusWaiting,
		).Count(&remaining).Error; err != nil {
			return fmt.Errorf("count remaining scan work dependencies: %w", err)
		}
		if remaining > 0 {
			return nil
		}
		updated := tx.Model(&SubTask{}).Where(
			"id = ? AND tenant_id = ? AND project_id = ? AND status = ? AND agent_id = ? AND stream_msg_id LIKE ?",
			destination.ID, destination.TenantID, destination.ProjectID, "Pending", "", scanWorkClaimMarkerPrefix+"%",
		).Updates(map[string]interface{}{"status": "Dispatching", "stream_msg_id": ""})
		if updated.Error != nil {
			return fmt.Errorf("replan scan work claim destination: %w", updated.Error)
		}
		if updated.RowsAffected != 1 {
			return nil
		}
		destination.Status = "Dispatching"
		destination.StreamMsgID = ""
		if destination.BatchID != "" {
			if err := tx.Model(&TaskBatch{}).Where(
				"id = ? AND tenant_id = ? AND latest_attempt_id = ?", destination.BatchID, destination.TenantID, destination.ID,
			).Update("status", "Dispatching").Error; err != nil {
				return fmt.Errorf("replan scan work claim batch: %w", err)
			}
		}
		promoted = true
		return nil
	})
	return destination, promoted, err
}

// ResolveTerminalScanWorkClaimWaiters reconciles terminal owners reached by
// timeout, stop, or recovery paths that do not call the Agent completion RPC.
func ResolveTerminalScanWorkClaimWaiters(store *gorm.DB, limit int) ([]SubTask, error) {
	if store == nil {
		return nil, nil
	}
	query := store.Model(&ScanWorkClaim{}).Select("owner_attempt_id").Where(
		"status = ? AND owner_attempt_id <> ?", scanWorkClaimStatusActive, "",
	).Group("owner_attempt_id").Order("MIN(updated_at) asc")
	if limit > 0 {
		query = query.Limit(limit)
	}
	var ownerIDs []string
	if err := query.Pluck("owner_attempt_id", &ownerIDs).Error; err != nil {
		return nil, fmt.Errorf("list active scan work claim owners: %w", err)
	}
	readyByID := make(map[string]SubTask)
	for _, ownerID := range ownerIDs {
		var owner SubTask
		if err := store.Select("id", "status").Where("id = ?", ownerID).First(&owner).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				continue
			}
			return nil, err
		}
		if !IsTerminalAttemptStatus(owner.Status) {
			continue
		}
		ready, err := ResolveScanWorkClaimsForAttempt(store, ownerID)
		if err != nil {
			return nil, err
		}
		for _, attempt := range ready {
			readyByID[attempt.ID] = attempt
		}
	}
	ready := make([]SubTask, 0, len(readyByID))
	for _, attempt := range readyByID {
		ready = append(ready, attempt)
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i].ID < ready[j].ID })
	return ready, nil
}

func scanWorkClaimPlansEqual(expected, actual ScanWorkClaimPlan) bool {
	if !expected.Enabled || !actual.Enabled || expected.AttemptID != actual.AttemptID || expected.TenantID != actual.TenantID ||
		expected.ProjectID != actual.ProjectID || expected.RootTaskID != actual.RootTaskID || expected.BatchID != actual.BatchID ||
		expected.AgentID != actual.AgentID || expected.NetworkZone != actual.NetworkZone || len(expected.Claims) != len(actual.Claims) {
		return false
	}
	for index := range expected.Claims {
		if expected.Claims[index].WorkKeyHash != actual.Claims[index].WorkKeyHash {
			return false
		}
	}
	return true
}

func scanWorkClaimPlanZone(claims []ScanWorkClaim) string {
	if len(claims) == 0 {
		return ""
	}
	zone := claims[0].NetworkZone
	for _, claim := range claims[1:] {
		if claim.NetworkZone != zone {
			return "_mixed"
		}
	}
	return zone
}

func scanWorkClaimHashes(claims []ScanWorkClaim) []string {
	hashes := make([]string, 0, len(claims))
	for _, claim := range claims {
		hashes = append(hashes, claim.WorkKeyHash)
	}
	return hashes
}

func scanWorkClaimMarker(claims []ScanWorkClaim) string {
	hashes := scanWorkClaimHashes(claims)
	sort.Strings(hashes)
	return scanWorkClaimMarkerPrefix + stableScanClaimHash(strings.Join(hashes, "\n"))
}

func scanWorkClaimLeaseHash(claim ScanWorkClaim, attemptID, agentID string, revision int) string {
	return stableScanClaimHash(strings.Join([]string{
		claim.TenantID, claim.ProjectID, claim.WorkKeyHash, attemptID, agentID, fmt.Sprintf("%d", revision),
	}, "\n"))
}

func stableScanClaimHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
