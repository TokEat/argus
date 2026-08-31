package api

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

const (
	copilotActionCreatePocDraft    = "create_poc_draft"
	copilotActionUpsertWorkflow    = "upsert_workflow_draft"
	copilotActionCreateTaskDraft   = "create_task_draft"
	copilotActionUpsertDirDraft    = "upsert_dir_draft"
	copilotActionCreateExpDraft    = "create_exp_draft"
	maxCopilotDraftContentSizeByte = 512 * 1024
)

var errEXPUserAuthorization = errors.New("EXP access requires user-level authorization")

type CopilotPendingAction struct {
	ActionType   string                 `json:"action_type"`
	Title        string                 `json:"title"`
	Summary      string                 `json:"summary"`
	RiskLevel    string                 `json:"risk_level"`
	Params       map[string]interface{} `json:"params"`
	Preview      string                 `json:"preview"`
	RequiredRole string                 `json:"required_role"`
	ConfirmLabel string                 `json:"confirm_label"`
}

type confirmCopilotActionRequest struct {
	Action      CopilotPendingAction   `json:"action"`
	PageContext map[string]interface{} `json:"page_context"`
}

type copilotActionResult struct {
	Status     string                 `json:"status"`
	Message    string                 `json:"message"`
	ActionType string                 `json:"action_type"`
	Object     map[string]interface{} `json:"object,omitempty"`
}

func confirmCopilotAction(c *gin.Context) {
	var req confirmCopilotActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actionType := strings.TrimSpace(req.Action.ActionType)
	if actionType == "" {
		actionType = strings.TrimSpace(stringParam(req.Action.Params, "action_type"))
	}

	result, err := executeCopilotAction(c, actionType, req.Action)
	if err != nil {
		statusCode := http.StatusBadRequest
		if errors.Is(err, errEXPUserAuthorization) {
			statusCode = http.StatusForbidden
		}
		c.JSON(statusCode, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func executeCopilotAction(c *gin.Context, actionType string, action CopilotPendingAction) (copilotActionResult, error) {
	requiredRole := strings.TrimSpace(action.RequiredRole)
	if requiredRole == "" {
		requiredRole = "operator"
	}
	if !roleAtLeast(currentTenantID(c), c.GetString("role"), requiredRole) {
		return copilotActionResult{}, fmt.Errorf("insufficient permissions: required role %s", requiredRole)
	}

	switch actionType {
	case copilotActionCreatePocDraft:
		return executeCreatePOCDraft(currentTenantID(c), action.Params)
	case copilotActionUpsertWorkflow:
		return executeUpsertWorkflowDraft(currentTenantID(c), action.Params)
	case copilotActionCreateTaskDraft:
		return executeCreateTaskDraft(c, action.Params)
	case copilotActionUpsertDirDraft:
		return executeUpsertDirDraft(currentTenantID(c), action.Params)
	case copilotActionCreateExpDraft:
		if !currentUserHasEXPAuthorization(c) {
			return copilotActionResult{}, errEXPUserAuthorization
		}
		return executeCreateExpDraft(c, action.Params)
	default:
		return copilotActionResult{}, fmt.Errorf("unsupported copilot action_type %q", actionType)
	}
}

func executeCreatePOCDraft(tenantID string, params map[string]interface{}) (copilotActionResult, error) {
	fileName := strings.TrimSpace(stringParam(params, "file_name"))
	content := stringParam(params, "content")
	if fileName == "" || content == "" {
		return copilotActionResult{}, fmt.Errorf("file_name and content are required")
	}
	if err := validateDraftFileName(fileName, true); err != nil {
		return copilotActionResult{}, err
	}
	if len(content) > maxCopilotDraftContentSizeByte {
		return copilotActionResult{}, fmt.Errorf("content is too large")
	}
	if err := yaml.Unmarshal([]byte(content), &struct{}{}); err != nil {
		return copilotActionResult{}, fmt.Errorf("content is not valid YAML: %w", err)
	}

	hash := fmt.Sprintf("%x", md5.Sum([]byte(content)))
	var existing db.Arsenal
	previousHash := ""
	previousContent := ""
	version := 1
	if err := db.DB.Where("tenant_id = ? AND type = ? AND file_name = ?", tenantID, "poc", fileName).First(&existing).Error; err == nil {
		previousHash = existing.Hash
		previousContent = existing.Content
		version = existing.Version + 1
	}
	arsenal := db.Arsenal{
		ID:              db.BuildTenantArsenalID(tenantID, "poc", fileName),
		TenantID:        tenantID,
		Type:            "poc",
		FileName:        fileName,
		Content:         content,
		Hash:            hash,
		PreviousHash:    previousHash,
		PreviousContent: previousContent,
		Version:         version,
		State:           "Draft",
	}
	if err := db.DB.Save(&arsenal).Error; err != nil {
		return copilotActionResult{}, err
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		return copilotActionResult{}, err
	}
	return copilotActionResult{
		Status:     "saved",
		Message:    "POC draft saved. Approval still requires the existing arsenal review flow.",
		ActionType: copilotActionCreatePocDraft,
		Object: map[string]interface{}{
			"type":      "poc",
			"file_name": fileName,
			"state":     "Draft",
			"hash":      hash,
			"version":   version,
		},
	}, nil
}

func executeCreateTaskDraft(c *gin.Context, params map[string]interface{}) (copilotActionResult, error) {
	projectID := strings.TrimSpace(stringParam(params, "project_id"))
	if projectID == "" {
		return copilotActionResult{}, fmt.Errorf("project_id is required")
	}
	var project db.Project
	if err := scopedProjectsQuery(c).Where("id = ?", projectID).First(&project).Error; err != nil {
		return copilotActionResult{}, fmt.Errorf("project access denied")
	}
	if project.Status != "active" {
		return copilotActionResult{}, fmt.Errorf("project is not active")
	}

	targetsRaw, err := rawJSONParam(params, "targets")
	if err != nil {
		return copilotActionResult{}, err
	}
	policyRaw, err := rawJSONParam(params, "policy")
	if err != nil {
		return copilotActionResult{}, fmt.Errorf("policy is required: %w", err)
	}
	var policy scanpolicy.Policy
	if err := json.Unmarshal(policyRaw, &policy); err != nil {
		return copilotActionResult{}, fmt.Errorf("policy is invalid: %w", err)
	}

	priority := intParam(params, "priority", 1)
	timeoutSec := intParam(params, "timeout_sec", 3600)
	plan, err := compileTaskScanPolicy(c, scanPolicyPlanRequest{
		ProjectID: projectID, Targets: targetsRaw, Policy: policy,
		Priority: &priority, TimeoutSec: &timeoutSec,
	})
	if err != nil {
		return copilotActionResult{}, fmt.Errorf("compile Server scan policy: %w", err)
	}
	targetsJSON, err := json.Marshal(plan.TargetsNormalized)
	if err != nil {
		return copilotActionResult{}, err
	}
	name := strings.TrimSpace(stringParam(params, "name"))
	if name == "" {
		name = plan.TargetsNormalized[0]
	}

	taskID := fmt.Sprintf("task-draft-%d", time.Now().UnixNano())
	rootTask := db.RootTask{
		ID:                   taskID,
		TenantID:             currentTenantID(c),
		ProjectID:            projectID,
		UserID:               currentUserID(c),
		Name:                 name,
		Status:               "Draft",
		OriginalTargets:      string(targetsJSON),
		Config:               plan.ScannerConfig,
		TotalChunks:          0,
		CompletedChunks:      0,
		TotalTargets:         len(plan.TargetsNormalized),
		CompletedTargets:     0,
		Priority:             priority,
		TimeoutSec:           timeoutSec,
		CurrentConfigVersion: 1,
	}
	revision := db.NewTaskConfigRevision(rootTask, 1, "{}", plan.SelectorRules, currentUserID(c), "initial semantic scan policy draft")
	policyIntent, err := newScanPolicyIntent(plan, currentTenantID(c), projectID, taskID, currentUserID(c))
	if err != nil {
		return copilotActionResult{}, err
	}
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&rootTask).Error; err != nil {
			return err
		}
		if err := tx.Create(&revision).Error; err != nil {
			return err
		}
		return tx.Create(policyIntent).Error
	}); err != nil {
		return copilotActionResult{}, err
	}
	return copilotActionResult{
		Status:     "saved",
		Message:    "Task draft saved. It has not been dispatched; start it through the normal task flow after review.",
		ActionType: copilotActionCreateTaskDraft,
		Object: map[string]interface{}{
			"type":           "task",
			"task_id":        taskID,
			"project_id":     projectID,
			"state":          "Draft",
			"config_version": 1,
			"target_summary": plan.TargetSummary,
			"policy_hash":    plan.PolicyHash,
			"plan_hash":      plan.PlanHash,
			"stages":         plan.Stages,
		},
	}, nil
}

func executeUpsertDirDraft(tenantID string, params map[string]interface{}) (copilotActionResult, error) {
	product := strings.TrimSpace(stringParam(params, "product"))
	paths := stringSliceParam(params, "paths")
	if product == "" {
		return copilotActionResult{}, fmt.Errorf("product is required")
	}
	if len(paths) == 0 {
		return copilotActionResult{}, fmt.Errorf("paths must contain at least one entry")
	}
	for _, p := range paths {
		if err := validateDirPath(p); err != nil {
			return copilotActionResult{}, err
		}
	}
	data, arsenal, err := fetchAndParseDir(tenantID)
	if err != nil {
		return copilotActionResult{}, err
	}
	data[product] = paths
	content, hash, err := saveDirDraft(data, arsenal)
	if err != nil {
		return copilotActionResult{}, err
	}
	return copilotActionResult{
		Status:     "saved",
		Message:    "Dir dictionary draft saved. Publishing still follows the existing rule review flow.",
		ActionType: copilotActionUpsertDirDraft,
		Object: map[string]interface{}{
			"type":           "dir",
			"file_name":      "dir.yaml",
			"product":        product,
			"state":          "Draft",
			"hash":           hash,
			"content_length": len(content),
		},
	}, nil
}

func executeCreateExpDraft(c *gin.Context, params map[string]interface{}) (copilotActionResult, error) {
	content := strings.TrimSpace(stringParam(params, "content"))
	if content == "" {
		return copilotActionResult{}, fmt.Errorf("content is required")
	}
	if len(content) > maxCopilotDraftContentSizeByte {
		return copilotActionResult{}, fmt.Errorf("content is too large")
	}
	service := routerRuntime().EXPWorkspace
	if service == nil {
		return copilotActionResult{}, fmt.Errorf("EXP Workspace Unavailable")
	}
	tenantID, actorID := currentTenantID(c), currentUserID(c)
	expID := strings.TrimSpace(stringParam(params, "exp_id"))
	name := strings.TrimSpace(stringParam(params, "name"))
	if name == "" {
		name = strings.TrimSuffix(strings.TrimSpace(stringParam(params, "file_name")), ".yak")
	}
	if expID == "" {
		if name == "" {
			return copilotActionResult{}, fmt.Errorf("name is required when creating a new EXP")
		}
		riskLevel := strings.ToLower(strings.TrimSpace(stringParam(params, "risk_level")))
		if riskLevel == "" {
			riskLevel = "high"
		}
		created, err := service.CreateExp(c.Request.Context(), tenantID, actorID, name, stringParam(params, "description"), riskLevel)
		if err != nil {
			return copilotActionResult{}, err
		}
		expID = created.ID
	} else if _, err := service.GetExp(c.Request.Context(), tenantID, expID); err != nil {
		return copilotActionResult{}, err
	}
	sourceHash := sha256.Sum256([]byte(content))
	return copilotActionResult{
		Status:     "prepared",
		Message:    "EXP metadata is ready. The generated Yak source remains an in-memory draft and must pass a trusted offline Fixture test before it can be saved as a Revision.",
		ActionType: copilotActionCreateExpDraft,
		Object: map[string]interface{}{
			"exp_id":        expID,
			"state":         "in_memory",
			"source":        content,
			"source_sha256": hex.EncodeToString(sourceHash[:]),
		},
	}, nil
}

func executeUpsertWorkflowDraft(tenantID string, params map[string]interface{}) (copilotActionResult, error) {
	product := strings.TrimSpace(stringParam(params, "product"))
	if product == "" {
		return copilotActionResult{}, fmt.Errorf("product is required")
	}
	types := stringSliceParam(params, "type")
	pocs := stringSliceParam(params, "pocs")
	if len(types) == 0 {
		return copilotActionResult{}, fmt.Errorf("type must contain at least one trigger stage")
	}
	for _, trigger := range types {
		if !allowedWorkflowTrigger(trigger) {
			return copilotActionResult{}, fmt.Errorf("unsupported workflow trigger stage %q", trigger)
		}
	}
	for _, poc := range pocs {
		if err := validateDraftFileName(poc, false); err != nil {
			return copilotActionResult{}, fmt.Errorf("invalid poc reference %q: %w", poc, err)
		}
	}

	data, arsenal, err := fetchAndParseWorkflow(tenantID)
	if err != nil {
		return copilotActionResult{}, err
	}
	data[product] = WorkflowEntry{Type: types, Pocs: pocs}
	content, hash, err := saveWorkflowDraft(data, arsenal)
	if err != nil {
		return copilotActionResult{}, err
	}
	return copilotActionResult{
		Status:     "saved",
		Message:    "Workflow draft saved. Rule publishing still requires the existing review or approval flow.",
		ActionType: copilotActionUpsertWorkflow,
		Object: map[string]interface{}{
			"type":           "workflow",
			"file_name":      "workflow.yaml",
			"product":        product,
			"state":          "Draft",
			"hash":           hash,
			"content_length": len(content),
		},
	}, nil
}

func saveDirDraft(data map[string][]string, arsenal *db.Arsenal) (string, string, error) {
	out, err := yaml.Marshal(data)
	if err != nil {
		return "", "", err
	}
	content := string(out)
	hash := fmt.Sprintf("%x", md5.Sum(out))
	arsenal.PreviousContent = arsenal.Content
	arsenal.PreviousHash = arsenal.Hash
	arsenal.Content = content
	arsenal.Hash = hash
	arsenal.State = "Draft"
	arsenal.Version++
	if err := db.DB.Save(arsenal).Error; err != nil {
		return "", "", err
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		return "", "", err
	}
	return content, hash, nil
}

func saveWorkflowDraft(data map[string]WorkflowEntry, arsenal *db.Arsenal) (string, string, error) {
	out, err := yaml.Marshal(data)
	if err != nil {
		return "", "", err
	}
	content := string(out)
	hash := fmt.Sprintf("%x", md5.Sum(out))
	arsenal.PreviousContent = arsenal.Content
	arsenal.PreviousHash = arsenal.Hash
	arsenal.Content = content
	arsenal.Hash = hash
	arsenal.State = "Draft"
	arsenal.Version++
	if err := db.DB.Save(arsenal).Error; err != nil {
		return "", "", err
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		return "", "", err
	}
	return content, hash, nil
}

func extractPendingActions(content string) []CopilotPendingAction {
	actions := make([]CopilotPendingAction, 0)
	fencePattern := regexp.MustCompile("(?is)```pending_action\\s*\\n(.*?)```")
	for _, match := range fencePattern.FindAllStringSubmatch(content, -1) {
		raw := strings.TrimSpace(match[1])
		if raw == "" || !strings.Contains(raw, "action_type") {
			continue
		}
		var action CopilotPendingAction
		if err := json.Unmarshal([]byte(raw), &action); err != nil {
			continue
		}
		if normalizePendingAction(&action) {
			actions = append(actions, action)
		}
	}
	return actions
}

func normalizePendingAction(action *CopilotPendingAction) bool {
	action.ActionType = strings.TrimSpace(action.ActionType)
	if action.ActionType == "" || action.Params == nil {
		return false
	}
	switch action.ActionType {
	case copilotActionCreatePocDraft:
		if action.Title == "" {
			action.Title = "保存 POC 草稿"
		}
		if action.RequiredRole == "" {
			action.RequiredRole = "operator"
		}
		if action.ConfirmLabel == "" {
			action.ConfirmLabel = "保存草稿"
		}
		if action.RiskLevel == "" {
			action.RiskLevel = "low"
		}
	case copilotActionUpsertWorkflow:
		if action.Title == "" {
			action.Title = "保存 Workflow 草稿"
		}
		if action.RequiredRole == "" {
			action.RequiredRole = "operator"
		}
		if action.ConfirmLabel == "" {
			action.ConfirmLabel = "保存草稿"
		}
		if action.RiskLevel == "" {
			action.RiskLevel = "medium"
		}
	case copilotActionCreateTaskDraft:
		if action.Title == "" {
			action.Title = "创建扫描任务草稿"
		}
		if action.RequiredRole == "" {
			action.RequiredRole = "operator"
		}
		if action.ConfirmLabel == "" {
			action.ConfirmLabel = "保存任务草稿"
		}
		if action.RiskLevel == "" {
			action.RiskLevel = "medium"
		}
	case copilotActionUpsertDirDraft:
		if action.Title == "" {
			action.Title = "保存 Dir 字典草稿"
		}
		if action.RequiredRole == "" {
			action.RequiredRole = "operator"
		}
		if action.ConfirmLabel == "" {
			action.ConfirmLabel = "保存草稿"
		}
		if action.RiskLevel == "" {
			action.RiskLevel = "low"
		}
	case copilotActionCreateExpDraft:
		if action.Title == "" {
			action.Title = "保存 EXP 草稿"
		}
		if action.RequiredRole == "" {
			action.RequiredRole = "operator"
		}
		if action.ConfirmLabel == "" {
			action.ConfirmLabel = "保存草稿"
		}
		if action.RiskLevel == "" {
			action.RiskLevel = "low"
		}
	default:
		return false
	}
	return true
}

func roleAtLeast(tenantID, role, required string) bool {
	if role == "" {
		role = "viewer"
	}
	userLevel := roleLevelForTenant(tenantID, role)
	requiredLevel := roleHierarchy[required]
	// If required role is not in hierarchy, default to "operator"
	if requiredLevel == 0 {
		requiredLevel = roleHierarchy["operator"]
	}
	return userLevel >= requiredLevel
}

func stringParam(params map[string]interface{}, key string) string {
	if params == nil {
		return ""
	}
	if value, ok := params[key].(string); ok {
		return value
	}
	return ""
}

func stringSliceParam(params map[string]interface{}, key string) []string {
	if params == nil {
		return nil
	}
	raw, ok := params[key]
	if !ok {
		return nil
	}
	switch values := raw.(type) {
	case []string:
		return values
	case []interface{}:
		out := make([]string, 0, len(values))
		for _, item := range values {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				out = append(out, strings.TrimSpace(text))
			}
		}
		return out
	default:
		return nil
	}
}

func rawJSONParam(params map[string]interface{}, key string) (json.RawMessage, error) {
	if params == nil {
		return []byte("{}"), nil
	}
	value, ok := params[key]
	if !ok || value == nil {
		if key == "config" {
			return []byte("{}"), nil
		}
		return nil, fmt.Errorf("%s is required", key)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func intParam(params map[string]interface{}, key string, fallback int) int {
	if params == nil {
		return fallback
	}
	switch value := params[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			return parsed
		}
	}
	return fallback
}

func validateDraftFileName(fileName string, requireYAML bool) error {
	clean := strings.TrimSpace(fileName)
	if clean == "" {
		return fmt.Errorf("file name is required")
	}
	if clean != filepath.Base(clean) || strings.ContainsAny(clean, `/\`) {
		return fmt.Errorf("file name must not contain path separators")
	}
	if strings.Contains(clean, "..") {
		return fmt.Errorf("file name must not contain traversal segments")
	}
	if requireYAML && !regexp.MustCompile(`(?i)\.ya?ml$`).MatchString(clean) {
		return fmt.Errorf("file name must end with .yaml or .yml")
	}
	return nil
}

func validateDirPath(value string) error {
	pathValue := strings.TrimSpace(value)
	if pathValue == "" {
		return fmt.Errorf("dir path must not be empty")
	}
	if len(pathValue) > 300 {
		return fmt.Errorf("dir path is too long")
	}
	if strings.ContainsAny(pathValue, "\r\n\t") {
		return fmt.Errorf("dir path must be a single path segment or URL path")
	}
	if strings.Contains(pathValue, "..") {
		return fmt.Errorf("dir path must not contain traversal segments")
	}
	return nil
}

func allowedWorkflowTrigger(value string) bool {
	switch value {
	case "root", "base", "dir", "dir-fallback":
		return true
	default:
		return false
	}
}

func clampQueryInt(raw string, fallback, min, max int) int {
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	if parsed < min {
		return min
	}
	if parsed > max {
		return max
	}
	return parsed
}
