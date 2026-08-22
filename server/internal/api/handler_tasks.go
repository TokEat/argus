package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/subdomainpassive"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func getTasks(c *gin.Context) {
	var tasks []db.RootTask
	tenantID := c.GetString("tenant")
	page, pageSize := parsePagination(c, 20, 100)
	query := db.DB.Where("tenant_id = ?", tenantID)
	query, _ = applyProjectScope(c, query, "project_id")
	switch strings.ToLower(strings.TrimSpace(c.Query("archived"))) {
	case "", "active":
		query = query.Where("archived_at IS NULL")
	case "only":
		query = query.Where("archived_at IS NOT NULL")
	case "include":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "archived must be active, only, or include"})
		return
	}

	var total int64
	if err := query.Model(&db.RootTask{}).Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := query.Order("created_at desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&tasks).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 增强返回：包含目标维度进度
	type TaskResponse struct {
		db.RootTask
	}
	resp := make([]TaskResponse, 0, len(tasks))
	for _, t := range tasks {
		resp = append(resp, TaskResponse{RootTask: t})
	}
	c.JSON(http.StatusOK, pagedResponse(resp, total, page, pageSize, ""))
}

type taskReasonStat struct {
	Status      string `json:"status"`
	Reason      string `json:"reason"`
	Count       int    `json:"count"`
	TargetCount int    `json:"target_count"`
}

func subTaskTargetCount(st db.SubTask) int {
	var targets []string
	if json.Unmarshal([]byte(st.ChunkTargets), &targets) == nil {
		return len(targets)
	}
	return 0
}

func buildTaskReasonStats(subTasks []db.SubTask) []taskReasonStat {
	type acc struct {
		status      string
		reason      string
		count       int
		targetCount int
	}
	statsByKey := make(map[string]*acc)
	order := make([]string, 0)
	add := func(status, reason string, targetCount int) {
		if reason == "" {
			return
		}
		key := status + "\x00" + reason
		if _, ok := statsByKey[key]; !ok {
			statsByKey[key] = &acc{status: status, reason: reason}
			order = append(order, key)
		}
		statsByKey[key].count++
		statsByKey[key].targetCount += targetCount
	}

	for _, st := range subTasks {
		targetCount := subTaskTargetCount(st)
		switch db.CanonicalAttemptState(st.Status) {
		case db.AttemptStateFailed:
			reason := strings.TrimSpace(st.FailureReason)
			if reason == "" {
				reason = "批次失败或重试耗尽"
			}
			add(st.Status, reason, targetCount)
		case db.AttemptStateTimeout:
			if strings.TrimSpace(st.FailureReason) != "" {
				add(st.Status, st.FailureReason, targetCount)
			} else if st.TimeoutSec > 0 {
				add(st.Status, fmt.Sprintf("超过 %d 秒未完成或重试耗尽", st.TimeoutSec), targetCount)
			} else {
				add(st.Status, "批次超时或重试耗尽", targetCount)
			}
		case db.AttemptStateStopped:
			add(st.Status, "用户取消后已终止", targetCount)
		case db.AttemptStateStopping:
			add(st.Status, "取消请求已下发，等待 Agent 确认", targetCount)
		case db.AttemptStateQueued, db.AttemptStateDispatching, db.AttemptStateRecovered:
			if strings.TrimSpace(st.AgentID) == "" {
				if db.CanonicalAttemptState(st.Status) == db.AttemptStateQueued && subdomainPassiveJobActive(db.DB, st.TenantID, st.ID) {
					add(st.Status, "Server 被动子域收集中，完成后派发", targetCount)
				} else {
					add(st.Status, "等待可匹配节点认领", targetCount)
				}
			}
		}
	}

	stats := make([]taskReasonStat, 0, len(order))
	for _, key := range order {
		item := statsByKey[key]
		stats = append(stats, taskReasonStat{
			Status:      item.status,
			Reason:      item.reason,
			Count:       item.count,
			TargetCount: item.targetCount,
		})
	}
	return stats
}

// getTaskDetail 返回单个任务的详细信息，包括子任务列表和结果统计
func getTaskDetail(c *gin.Context) {
	taskID := c.Param("id")
	tenantID := currentTenantID(c)

	// 查询 RootTask
	var rootTask db.RootTask
	if err := db.DB.Where("id = ? AND tenant_id = ?", taskID, tenantID).First(&rootTask).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	if !canAccessProject(c, rootTask.ProjectID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "project not accessible"})
		return
	}

	// 查询全部 Attempt，并按 TaskBatch.latest_attempt_id 生成当前批次视图。
	var subTasks []db.SubTask
	db.DB.Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).
		Order("batch_id asc, attempt_no asc, created_at asc").Find(&subTasks)
	var taskBatches []db.TaskBatch
	db.DB.Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).
		Order("sequence asc").Find(&taskBatches)
	attemptByID := make(map[string]db.SubTask, len(subTasks))
	for _, attempt := range subTasks {
		attemptByID[attempt.ID] = attempt
	}
	latestSubTasks := make([]db.SubTask, 0, len(taskBatches))
	for _, batch := range taskBatches {
		if batch.ArchivedAt != nil {
			continue
		}
		if attempt, exists := attemptByID[batch.LatestAttemptID]; exists {
			latestSubTasks = append(latestSubTasks, attempt)
		}
	}
	if len(taskBatches) == 0 {
		latestSubTasks = subTasks
	}

	// 子任务状态分布统计
	statusDistribution := make(map[string]int)
	for _, st := range latestSubTasks {
		statusDistribution[st.Status]++
	}

	// 构建子任务摘要（不暴露完整 Config 和 ChunkTargets 原文）
	type SubTaskSummary struct {
		ID              string     `json:"id"`
		BatchID         string     `json:"batch_id"`
		AttemptNo       int        `json:"attempt_no"`
		ParentAttemptID string     `json:"parent_attempt_id"`
		Trigger         string     `json:"trigger"`
		Status          string     `json:"status"`
		AgentID         string     `json:"agent_id"`
		FailureReason   string     `json:"failure_reason"`
		TargetCount     int        `json:"target_count"`
		RetryCount      int        `json:"retry_count"`
		MaxRetry        int        `json:"max_retry"`
		Priority        int        `json:"priority"`
		TimeoutSec      int        `json:"timeout_sec"`
		ConfigVersion   int        `json:"config_version"`
		RuleVersion     string     `json:"rule_version"`
		StartedAt       *time.Time `json:"started_at"`
		FinishedAt      *time.Time `json:"finished_at"`
		CreatedAt       time.Time  `json:"created_at"`
		UpdatedAt       time.Time  `json:"updated_at"`
	}
	buildSubSummaries := func(items []db.SubTask) []SubTaskSummary {
		summaries := make([]SubTaskSummary, 0, len(items))
		for _, st := range items {
			summaries = append(summaries, SubTaskSummary{
				ID:              st.ID,
				BatchID:         st.BatchID,
				AttemptNo:       st.AttemptNo,
				ParentAttemptID: st.ParentAttemptID,
				Trigger:         st.Trigger,
				Status:          st.Status,
				AgentID:         st.AgentID,
				FailureReason:   st.FailureReason,
				TargetCount:     subTaskTargetCount(st),
				RetryCount:      st.RetryCount,
				MaxRetry:        st.MaxRetry,
				Priority:        st.Priority,
				TimeoutSec:      st.TimeoutSec,
				ConfigVersion:   st.ConfigVersion,
				RuleVersion:     st.RuleVersion,
				StartedAt:       st.StartedAt,
				FinishedAt:      st.FinishedAt,
				CreatedAt:       st.CreatedAt,
				UpdatedAt:       st.UpdatedAt,
			})
		}
		return summaries
	}
	subSummaries := buildSubSummaries(latestSubTasks)
	attemptSummaries := buildSubSummaries(subTasks)
	coverageExplanation, err := buildTaskCoverageExplanation(db.DB, rootTask)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	timingProjection, err := db.BuildTaskTimingProjection(db.DB, rootTask, subTasks)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load task timing"})
		return
	}

	resultStats := loadTaskResultStats(taskID, tenantID, subTasks)

	// 解析原始配置为 JSON 对象返回
	var configObj interface{}
	if json.Unmarshal([]byte(rootTask.Config), &configObj) != nil {
		configObj = rootTask.Config
	}

	// This projection contains immutable references and hashes, never dictionary contents.
	scanPolicy, stageDerivations := loadTaskScanPolicyView(tenantID, taskID)

	type TaskAuditResponse struct {
		ID           uint            `json:"id"`
		BatchID      string          `json:"batch_id"`
		AttemptID    string          `json:"attempt_id"`
		OperatorID   string          `json:"operator_id"`
		Action       string          `json:"action"`
		BeforeStatus string          `json:"before_status"`
		AfterStatus  string          `json:"after_status"`
		Details      json.RawMessage `json:"details"`
		CreatedAt    time.Time       `json:"created_at"`
	}
	var auditRows []db.TaskAudit
	if err := db.DB.Where("root_task_id = ? AND tenant_id = ?", taskID, tenantID).
		Order("created_at desc, id desc").
		Limit(100).
		Find(&auditRows).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	audits := make([]TaskAuditResponse, 0, len(auditRows))
	for _, row := range auditRows {
		details := json.RawMessage(row.Details)
		if !json.Valid(details) {
			details = json.RawMessage(`{}`)
		}
		audits = append(audits, TaskAuditResponse{
			ID:           row.ID,
			BatchID:      row.BatchID,
			AttemptID:    row.AttemptID,
			OperatorID:   row.OperatorID,
			Action:       row.Action,
			BeforeStatus: row.BeforeStatus,
			AfterStatus:  row.AfterStatus,
			Details:      details,
			CreatedAt:    row.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"task": gin.H{
			"id":                     rootTask.ID,
			"name":                   rootTask.Name,
			"status":                 rootTask.Status,
			"priority":               rootTask.Priority,
			"total_chunks":           rootTask.TotalChunks,
			"completed_chunks":       rootTask.CompletedChunks,
			"total_targets":          rootTask.TotalTargets,
			"completed_targets":      rootTask.CompletedTargets,
			"timeout_sec":            rootTask.TimeoutSec,
			"original_targets":       rootTask.OriginalTargets,
			"config":                 configObj,
			"rule_version":           rootTask.RuleVersion,
			"current_config_version": rootTask.CurrentConfigVersion,
			"created_at":             rootTask.CreatedAt,
			"updated_at":             rootTask.UpdatedAt,
			"archived_at":            rootTask.ArchivedAt,
		},
		"sub_tasks":            subSummaries,
		"batches":              buildTaskBatchSummaries(taskBatches, attemptByID),
		"attempts":             attemptSummaries,
		"status_distribution":  statusDistribution,
		"passive_collection":   subdomainpassive.CollectionProgressForTask(db.DB, tenantID, taskID),
		"reason_stats":         buildTaskReasonStats(latestSubTasks),
		"audits":               audits,
		"coverage_explanation": coverageExplanation,
		"timing":               timingProjection,
		"scan_policy":          scanPolicy,
		"stage_derivations":    stageDerivations,
		"result_stats": gin.H{
			"assets":       resultStats.AssetCount,
			"fingerprints": resultStats.FingerprintCount,
			"vulns":        resultStats.VulnerabilityCount,
			"severity":     resultStats.Severity,
		},
	})
}

// subdomainPassiveJobActive reports whether the attempt is currently held by
// an in-flight Server-side passive collection job.
func subdomainPassiveJobActive(store *gorm.DB, tenantID, attemptID string) bool {
	if store == nil || attemptID == "" {
		return false
	}
	var count int64
	store.Model(&db.SubdomainPassiveJob{}).
		Where("tenant_id = ? AND attempt_id = ? AND state IN ?", tenantID, attemptID, []string{subdomainpassive.JobStatePending, subdomainpassive.JobStateRunning}).
		Count(&count)
	return count > 0
}

func createTask(c *gin.Context) {
	var req taskCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.ProjectID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project_id is required"})
		return
	}
	project, ok := requireProjectAccess(c, req.ProjectID)
	if !ok {
		return
	}
	if project.Status != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project is not active"})
		return
	}
	idempotencyKey, idempotencyRequested, idempotencyErr := parseTaskCreateIdempotencyKey(c.Request.Header)
	if idempotencyErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "invalid_idempotency_key", "error": idempotencyErr.Error()})
		return
	}

	priority, timeoutSec, err := normalizeTaskScheduling(req.Priority, req.TimeoutSec)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Policy != nil && (len(req.Config) > 0 || len(req.AgentSelector) > 0 || len(req.AgentSelectorRules) > 0) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy cannot be combined with raw config or legacy agent selectors"})
		return
	}
	userSelector, err := parseAgentSelector(req.AgentSelector)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	userRules, err := parseAgentSelectorRules(req.AgentSelectorRules)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	configJSON := ""
	targetMode := taskTargetModeDirect
	var effectiveConfig taskScanConfig
	var semanticPlan *scanPolicyPlan
	if req.Policy == nil {
		configJSON, targetMode, err = normalizeTaskConfigPayload(req.Config)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := json.Unmarshal([]byte(configJSON), &effectiveConfig); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	targetSource := "request"
	if len(strings.TrimSpace(string(req.Targets))) == 0 || strings.TrimSpace(string(req.Targets)) == "null" || strings.TrimSpace(string(req.Targets)) == `""` {
		if targetMode != taskTargetModeDirect {
			c.JSON(http.StatusBadRequest, gin.H{"error": "targets is required for network search modes"})
			return
		}
		projectTargets, projectErr := projectDefaultTargets(project)
		if projectErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": projectErr.Error()})
			return
		}
		if len(projectTargets) > 0 {
			req.Targets, err = json.Marshal(projectTargets)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			targetSource = "project_scope"
		}
	}
	if req.Policy != nil {
		plan, compileErr := compileTaskScanPolicy(c, scanPolicyPlanRequest{ProjectID: req.ProjectID, Targets: req.Targets, Policy: *req.Policy, Priority: req.Priority, TimeoutSec: req.TimeoutSec, SkipUnsupported: req.SkipUnsupported})
		if compileErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": compileErr.Error()})
			return
		}
		if strings.TrimSpace(req.PlanHash) == "" || !strings.EqualFold(strings.TrimSpace(req.PlanHash), plan.PlanHash) {
			c.JSON(http.StatusConflict, gin.H{"code": "scan_plan_changed", "error": "plan_hash does not match the current normalized plan", "current_plan_hash": plan.PlanHash})
			return
		}
		semanticPlan = &plan
		configJSON = plan.ScannerConfig
		if err := json.Unmarshal([]byte(configJSON), &effectiveConfig); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "compiled scanner configuration is invalid"})
			return
		}
		userRules = db.ParseSelectorRulesJSON(plan.SelectorRules)
	}

	var skippedTargets []invalidTarget
	var targets []string
	var targetSummary taskTargetSummary
	if req.SkipUnsupported {
		rawTargets, parseErr := parseTargets(req.Targets)
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": parseErr.Error()})
			return
		}
		rawTargets = normalizeTargetsForMode(rawTargets, targetMode)
		targets, skippedTargets, _ = classifyTargets(rawTargets, targetMode)
		if len(targets) > 0 {
			targets, targetSummary, err = validateTargetsByMode(targets, targetMode)
		}
	} else {
		targets, targetSummary, err = parseAndValidateTargetsForMode(req.Targets, targetMode)
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(targets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "targets is empty"})
		return
	}

	targetsJSON, err := json.Marshal(targets)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	rootTaskID := fmt.Sprintf("task-%d", time.Now().UnixNano())
	requestedName := strings.TrimSpace(req.Name)
	name := requestedName
	if name == "" {
		name = targets[0]
	}

	// 多租户隔离下钻
	tenantID := c.GetString("tenant")

	// ================================================================
	// 批次聚合入队（激进档）
	//
	// 替代原有"每目标一个SubTask"的原子拆分：
	//   1. 按 target_type 分组
	//   2. 每组按激进档批大小切片生成聚合 SubTask
	//   3. 聚合后 TotalChunks = 批次数（不再等于目标数）
	//   4. TotalTargets 记录原始目标总数用于进度展示
	// ================================================================

	batches := groupAndBatchTargets(targets, targetMode)
	ruleVersion := currentRuleVersionValue()
	operatorID := currentUserID(c)
	selectorJSON := mergeAgentSelector("{}", userSelector)
	selectorRulesJSON := db.SelectorRulesToJSON(userRules)
	requestHash := ""
	if idempotencyRequested {
		// The ledger deliberately does not persist rejected raw inputs. Sort the
		// bounded, sanitized projection so equivalent retries return the same
		// response while legacy requests retain their existing presentation.
		skippedTargets = canonicalTaskCreateSkippedTargets(skippedTargets)
		requestHash, err = buildTaskCreateRequestHash(canonicalTaskCreateRequest{
			TenantID:           tenantID,
			ProjectID:          req.ProjectID,
			OperatorID:         operatorID,
			Name:               requestedName,
			Targets:            targets,
			SkippedTargets:     skippedTargets,
			Config:             configJSON,
			TargetMode:         string(targetMode),
			Priority:           priority,
			TimeoutSec:         timeoutSec,
			AgentSelector:      selectorJSON,
			AgentSelectorRules: canonicalTaskCreateSelectorRules(userRules),
			SkipUnsupported:    req.SkipUnsupported,
			TargetSource:       targetSource,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to canonicalize task creation request"})
			return
		}
	}

	var taskBatches []db.TaskBatch
	var subTasks []db.SubTask
	var passiveJobs []db.SubdomainPassiveJob
	heldAttempts := make(map[string]struct{})
	// Server 端被动收集持有：策略开启被动子域发现且存在满足批次选择器的
	// 能力 Agent 时，域名批次先停留 Queued，收集完成（或超时兜底）后再入队。
	passiveHoldEnabled := subdomainpassive.Enabled() &&
		effectiveConfig.Subdomain && !effectiveConfig.NoSubFinder
	aliveNodes := subdomainpassive.AliveNodes(db.DB)
	profile := batchProfile{
		TotalTargets:  len(targets),
		TotalBatches:  len(batches),
		BatchesByType: make(map[string]int),
		BatchSize:     make(map[string]int),
	}

	for idx, batch := range batches {
		chunkJSON, _ := json.Marshal(batch.Targets)

		batchLegacySelector, batchRules, rulesJSON := effectiveSelectorRules(batch.SelectorJSON, userSelector, userRules)
		batchID := fmt.Sprintf("%s-batch-%d-%s", rootTaskID, idx, batch.TargetType)
		attemptID := fmt.Sprintf("%s-attempt-1", batchID)
		holdPassive := passiveHoldEnabled && subdomainpassive.HoldApplies(
			effectiveConfig.Subdomain, effectiveConfig.NoSubFinder, batch.TargetType,
			subdomainpassive.CapableAgentMatchesSelector(aliveNodes, batchLegacySelector, batchRules))
		initialStatus := subTaskStatusDispatching
		if holdPassive {
			initialStatus = subdomainpassive.HoldStatus
			heldAttempts[attemptID] = struct{}{}
		}
		effectiveSelector := mergeAgentSelector(batch.SelectorJSON, userSelector)
		taskBatches = append(taskBatches, db.TaskBatch{
			ID:                 batchID,
			TenantID:           tenantID,
			ProjectID:          req.ProjectID,
			RootTaskID:         rootTaskID,
			Sequence:           idx,
			Kind:               "asset_scan",
			TargetType:         batch.TargetType,
			Targets:            string(chunkJSON),
			TargetCount:        len(batch.Targets),
			Status:             initialStatus,
			ConfigVersion:      1,
			RuleVersion:        ruleVersion,
			Priority:           priority,
			TimeoutSec:         timeoutSec,
			AgentSelector:      effectiveSelector,
			AgentSelectorRules: rulesJSON,
			CurrentAttemptNo:   1,
			AttemptCount:       1,
			LatestAttemptID:    attemptID,
			CreatedBy:          operatorID,
		})
		subTasks = append(subTasks, db.SubTask{
			ID:                 attemptID,
			TenantID:           tenantID,
			ProjectID:          req.ProjectID,
			RootTaskID:         rootTaskID,
			BatchID:            batchID,
			AttemptNo:          1,
			Trigger:            db.AttemptTriggerInitial,
			ChunkTargets:       string(chunkJSON),
			Status:             initialStatus,
			Config:             configJSON,
			Priority:           priority,
			TimeoutSec:         timeoutSec,
			MaxRetry:           3,
			ConfigVersion:      1,
			RuleVersion:        ruleVersion,
			AgentSelector:      effectiveSelector,
			AgentSelectorRules: rulesJSON,
		})
		if holdPassive {
			domainsJSON, _ := json.Marshal(batch.Targets)
			passiveJobs = append(passiveJobs, db.SubdomainPassiveJob{
				ID:         subdomainpassive.PassiveJobID(attemptID),
				TenantID:   tenantID,
				ProjectID:  req.ProjectID,
				RootTaskID: rootTaskID,
				BatchID:    batchID,
				AttemptID:  attemptID,
				Domains:    string(domainsJSON),
				State:      subdomainpassive.JobStatePending,
			})
		}

		profile.BatchesByType[batch.TargetType]++
		if _, ok := profile.BatchSize[batch.TargetType]; !ok {
			profile.BatchSize[batch.TargetType] = batchSizeForTargetType(batch.TargetType)
		}
	}

	rootTask := db.RootTask{
		ID:                   rootTaskID,
		TenantID:             tenantID,
		ProjectID:            req.ProjectID,
		UserID:               operatorID,
		Name:                 name,
		Status:               "Queued",
		OriginalTargets:      string(targetsJSON),
		Config:               configJSON,
		TotalChunks:          len(subTasks),
		CompletedChunks:      0,
		TotalTargets:         len(targets),
		CompletedTargets:     0,
		Priority:             priority,
		TimeoutSec:           timeoutSec,
		RuleVersion:          ruleVersion,
		CurrentConfigVersion: 1,
	}
	configRevision := db.NewTaskConfigRevision(rootTask, 1, selectorJSON, selectorRulesJSON, operatorID, "initial configuration")
	var policyIntent *db.ScanPolicyIntent
	if semanticPlan != nil {
		policyIntent, err = newScanPolicyIntent(*semanticPlan, tenantID, req.ProjectID, rootTaskID, operatorID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist normalized scan policy"})
			return
		}
	}

	// 2. Transaction for Root and SubTasks
	var projectScopeAdded, projectSeedsAdded int
	var replayed bool
	var replayDispatched, replayPending int
	var replayTargetSummary taskTargetSummary
	var replayProfile batchProfile
	attemptIDs := make([]string, 0, len(subTasks))
	for _, attempt := range subTasks {
		attemptIDs = append(attemptIDs, attempt.ID)
	}
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		var currentProject db.Project
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND tenant_id = ? AND status = ?", project.ID, tenantID, "active").
			First(&currentProject).Error; err != nil {
			return err
		}
		scopeExpansionTargets := targets
		if targetMode != taskTargetModeDirect {
			scopeExpansionTargets = nil
		}
		seedTargets, seedAdded, _, err := mergeStoredTargetList(currentProject.SeedTargets, scopeExpansionTargets, false)
		if err != nil {
			return err
		}
		scopeTargets, scopeAdded, scopeTotal, err := mergeStoredTargetList(currentProject.Scope, scopeExpansionTargets, false)
		if err != nil {
			return err
		}
		projectSeedsAdded = len(seedAdded)
		projectScopeAdded = len(scopeAdded)
		if idempotencyRequested {
			idempotencyResult, err := db.RecordTaskCreationIdempotencyTx(tx, db.TaskCreationIdempotencyDraft{
				TenantID:          tenantID,
				ProjectID:         req.ProjectID,
				OperatorID:        operatorID,
				Operation:         taskCreateIdempotencyOperation,
				IdempotencyKey:    idempotencyKey,
				RequestHash:       requestHash,
				RootTaskID:        rootTask.ID,
				AttemptIDs:        attemptIDs,
				ProjectScopeAdded: projectScopeAdded,
				ProjectSeedsAdded: projectSeedsAdded,
			})
			if err != nil {
				return err
			}
			if idempotencyResult.Replayed {
				var existingRoot db.RootTask
				if err := tx.Where("id = ? AND tenant_id = ? AND project_id = ?", idempotencyResult.Record.RootTaskID, tenantID, req.ProjectID).First(&existingRoot).Error; err != nil {
					return err
				}
				replayDispatched, replayPending, err = taskCreationReplayDispatchCounts(tx, idempotencyResult.Record)
				if err != nil {
					return err
				}
				replayTargetSummary, replayProfile, err = taskCreationReplayScanSummary(tx, idempotencyResult.Record)
				if err != nil {
					return err
				}
				rootTask.ID = existingRoot.ID
				// A replay returns the immutable creation result. Later task
				// configuration revisions must not rewrite that response.
				rootTask.CurrentConfigVersion = 1
				projectScopeAdded = idempotencyResult.Record.ProjectScopeAdded
				projectSeedsAdded = idempotencyResult.Record.ProjectSeedsAdded
				replayed = true
				return nil
			}
		}
		if routerRuntime().TaskQueue == nil {
			return errTaskCreateQueueUnavailable
		}
		if err := db.CheckTenantTaskCreationQuota(tx, tenantID, time.Now()); err != nil {
			return err
		}
		if err := tx.Model(&db.Project{}).
			Where("id = ? AND tenant_id = ? AND status = ?", currentProject.ID, tenantID, "active").
			Updates(map[string]interface{}{
				"seed_targets": seedTargets,
				"scope":        scopeTargets,
				"updated_at":   time.Now(),
			}).Error; err != nil {
			return err
		}
		if err := tx.Create(&rootTask).Error; err != nil {
			return err
		}
		if err := tx.Create(&configRevision).Error; err != nil {
			return err
		}
		if policyIntent != nil {
			if err := tx.Create(policyIntent).Error; err != nil {
				return err
			}
		}
		if len(taskBatches) > 0 {
			if err := tx.CreateInBatches(taskBatches, 100).Error; err != nil {
				return err
			}
		}
		if len(subTasks) > 0 {
			if err := tx.CreateInBatches(subTasks, 100).Error; err != nil {
				return err
			}
		}
		if len(passiveJobs) > 0 {
			if err := tx.CreateInBatches(passiveJobs, 100).Error; err != nil {
				return err
			}
		}
		return recordTaskAudit(tx, rootTask, "create", "", rootTask.Status, operatorID, map[string]interface{}{
			"profile":                   scanplan.ScenarioExternalMap,
			"target_source":             targetSource,
			"target_count":              len(targets),
			"batch_count":               len(taskBatches),
			"project_scope_added_count": len(scopeAdded),
			"project_scope_after_count": scopeTotal,
			"project_seeds_added_count": len(seedAdded),
			"poc_enabled":               !effectiveConfig.NoPoc,
			"scan_policy_hash": func() string {
				if semanticPlan != nil {
					return semanticPlan.PolicyHash
				}
				return ""
			}(),
			"scan_plan_hash": func() string {
				if semanticPlan != nil {
					return semanticPlan.PlanHash
				}
				return ""
			}(),
		})
	})

	if err != nil {
		if errors.Is(err, db.ErrTaskCreationIdempotencyConflict) {
			c.JSON(http.StatusConflict, gin.H{"code": "idempotency_conflict", "error": "Idempotency-Key was already used for a different task creation request"})
			return
		}
		if errors.Is(err, errTaskCreateQueueUnavailable) {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "task queue not initialized"})
			return
		}
		if writeTenantQuotaError(c, err) {
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if replayed {
		response := buildTaskCreateResponse(taskCreateResponseInput{
			TaskID:            rootTask.ID,
			ConfigVersion:     rootTask.CurrentConfigVersion,
			TargetSummary:     replayTargetSummary,
			Dispatched:        replayDispatched,
			DispatchPending:   replayPending,
			Profile:           replayProfile,
			TargetSource:      targetSource,
			ProjectScopeAdded: projectScopeAdded,
			ProjectSeedsAdded: projectSeedsAdded,
			SkippedTargets:    skippedTargets,
			Replayed:          true,
		})
		decorateTaskCreateResponse(response, semanticPlan)
		c.JSON(http.StatusOK, response)
		return
	}

	// 3. Dispatch to Queue（闭环保证：失败任务保留 Dispatching，守护协程会继续补投）
	// 被动收集持有的域名批次跳过立即入队，由 collector 完成收集（或超时兜底）后释放。
	dispatchableSubTasks := make([]db.SubTask, 0, len(subTasks))
	for _, st := range subTasks {
		if _, held := heldAttempts[st.ID]; !held {
			dispatchableSubTasks = append(dispatchableSubTasks, st)
		}
	}
	pushedByPriority, dispatchPending := dispatchSubTasks(context.Background(), routerRuntime().TaskQueue, dispatchableSubTasks)
	pushedCount := totalDispatchedTasks(pushedByPriority)
	broadcastDispatchedTasks(pushedByPriority)
	if dispatchPending > 0 {
		log.Printf("[CreateTask] RootTask %s has %d batches pending dispatch recovery", rootTask.ID, dispatchPending)
	}

	log.Printf("[CreateTask] RootTask %s: %d targets → %d batches (profile: %v)",
		rootTask.ID, len(targets), len(subTasks), profile.BatchesByType)

	response := buildTaskCreateResponse(taskCreateResponseInput{
		TaskID:            rootTask.ID,
		ConfigVersion:     rootTask.CurrentConfigVersion,
		TargetSummary:     targetSummary,
		Dispatched:        pushedCount,
		DispatchPending:   dispatchPending,
		Profile:           profile,
		TargetSource:      targetSource,
		ProjectScopeAdded: projectScopeAdded,
		ProjectSeedsAdded: projectSeedsAdded,
		SkippedTargets:    skippedTargets,
	})
	decorateTaskCreateResponse(response, semanticPlan)
	c.JSON(http.StatusOK, response)
}
