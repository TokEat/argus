package api

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/db"
	"gopkg.in/yaml.v3"
)

const (
	copilotActionCreatePocDraft    = "create_poc_draft"
	copilotActionUpsertWorkflow    = "upsert_workflow_draft"
	maxCopilotDraftContentSizeByte = 512 * 1024
)

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

	module := resolveCopilotModule(compactPageContext(req.PageContext))
	audit := AIToolAuditContext{TenantID: currentTenantID(c), UserID: c.GetString("user_id"), Module: module}
	startedAt := time.Now()
	actionType := strings.TrimSpace(req.Action.ActionType)
	if actionType == "" {
		actionType = strings.TrimSpace(stringParam(req.Action.Params, "action_type"))
	}

	result, err := executeCopilotAction(c, actionType, req.Action)
	status := "success"
	errorSummary := ""
	if err != nil {
		status = "error"
		errorSummary = err.Error()
	}
	recordAIToolInvocation(audit, "CopilotAction:"+actionType, summarizeCopilotAction(req.Action), "", "", time.Since(startedAt), status, truncateString(errorSummary, 1000))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func executeCopilotAction(c *gin.Context, actionType string, action CopilotPendingAction) (copilotActionResult, error) {
	requiredRole := strings.TrimSpace(action.RequiredRole)
	if requiredRole == "" {
		requiredRole = "operator"
	}
	if !roleAtLeast(c.GetString("role"), requiredRole) {
		return copilotActionResult{}, fmt.Errorf("insufficient permissions: required role %s", requiredRole)
	}

	switch actionType {
	case copilotActionCreatePocDraft:
		return executeCreatePOCDraft(currentTenantID(c), action.Params)
	case copilotActionUpsertWorkflow:
		return executeUpsertWorkflowDraft(currentTenantID(c), action.Params)
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
	default:
		return false
	}
	return true
}

func roleAtLeast(role, required string) bool {
	if role == "" {
		role = "viewer"
	}
	userLevel := roleHierarchy[role]
	requiredLevel := roleHierarchy[required]
	return requiredLevel > 0 && userLevel >= requiredLevel
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

func allowedWorkflowTrigger(value string) bool {
	switch value {
	case "root", "base", "dir", "dir-fallback":
		return true
	default:
		return false
	}
}

func summarizeCopilotAction(action CopilotPendingAction) string {
	params := compactAuditValue(action.Params, 0)
	if paramMap, ok := params.(map[string]interface{}); ok {
		if content := stringParam(action.Params, "content"); content != "" {
			sum := sha256.Sum256([]byte(content))
			paramMap["content"] = map[string]interface{}{
				"sha256": hex.EncodeToString(sum[:]),
				"length": len(content),
			}
		}
	}
	summary := map[string]interface{}{
		"action_type":   action.ActionType,
		"title":         truncateString(action.Title, 200),
		"risk_level":    action.RiskLevel,
		"required_role": action.RequiredRole,
		"params":        params,
	}
	data, err := json.Marshal(summary)
	if err != nil {
		return "{}"
	}
	return truncateString(string(data), 4096)
}
