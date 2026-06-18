package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-proto/pyexp"
	"github.com/user/dddd-server/internal/db"
	"gopkg.in/yaml.v3"
)

const (
	defaultMCPSyncTimeoutSec = 60
	maxMCPSyncTimeoutSec     = 300
)

var mcpPythonScratchpadCommands = map[string]bool{
	"python_version": true,
	"py_compile":     true,
	"script_help":    true,
	"import_probe":   true,
	"pip_version":    true,
	"pip_list":       true,
	"pip_show":       true,
	"pip_check":      true,
}

type mcpResourceResponse struct {
	URI      string `json:"uri"`
	MIMEType string `json:"mime_type"`
	Text     string `json:"text"`
}

type mcpResourceDoc struct {
	URI         string
	Name        string
	Description string
	MIMEType    string
	Text        string
}

var mcpResourceDocs = []mcpResourceDoc{
	{URI: "argus://argus-mcp/quickstart", Name: "Argus MCP Quickstart", Description: "How a source-less MCP client should read specs, debug, save, publish, and verify rules.", MIMEType: "text/markdown", Text: argusMCPQuickstartText},
	{URI: "argus://argus-mcp/tool-guide", Name: "Argus MCP Tool Guide", Description: "Field combinations and expected sequencing for the four aggregate MCP tools.", MIMEType: "text/markdown", Text: argusMCPToolGuideText},
	{URI: "argus://fingerprint/spec", Name: "Argus Fingerprint Spec", Description: "Fingerprint dictionary format and expression examples.", MIMEType: "text/markdown", Text: fingerprintSpecText},
	{URI: "argus://fingerprint/template", Name: "Argus Fingerprint Template", Description: "Minimal fingerprint YAML snippet.", MIMEType: "text/yaml", Text: fingerprintTemplateText},
	{URI: "argus://poc/spec", Name: "Argus POC Spec", Description: "POC YAML format accepted by Argus debug and draft flows.", MIMEType: "text/markdown", Text: pocSpecText},
	{URI: "argus://poc/template", Name: "Argus POC Template", Description: "Minimal POC YAML template.", MIMEType: "text/yaml", Text: pocTemplateText},
	{URI: "argus://workflow/spec", Name: "Argus Workflow Spec", Description: "Workflow rule format linking products to POC files.", MIMEType: "text/markdown", Text: workflowSpecText},
	{URI: "argus://workflow/template", Name: "Argus Workflow Template", Description: "Minimal workflow YAML snippet.", MIMEType: "text/yaml", Text: workflowTemplateText},
	{URI: "argus://examples/fingerprint-poc-workflow", Name: "Argus Full Chain Example", Description: "End-to-end fingerprint, POC, workflow, debug/save/publish example.", MIMEType: "text/markdown", Text: fullChainExampleText},
	{URI: "argus://pyexp/spec", Name: "Argus Python EXP Spec", Description: "Python EXP source format, dependency policy, migration guidance, and debug flow.", MIMEType: "text/markdown", Text: pyexpSpecText},
	{URI: "argus://pyexp/template", Name: "Argus Python EXP Template", Description: "Minimal Python EXP template.", MIMEType: "text/x-python", Text: pyexpTemplateText},
}

func mcpResourceByURI(uri string) (mcpResourceDoc, bool) {
	uri = strings.TrimSpace(uri)
	for _, resource := range mcpResourceDocs {
		if resource.URI == uri {
			return resource, true
		}
	}
	return mcpResourceDoc{}, false
}

type mcpPyexpSourceRequest struct {
	Source string `json:"source"`
}

type mcpPyexpDryRunRequest struct {
	Source string                 `json:"source"`
	Target string                 `json:"target"`
	Params map[string]interface{} `json:"params"`
}

type mcpSaveDraftRequest struct {
	FileName string `json:"file_name"`
	Content  string `json:"content"`
}

type mcpDebugExploitRequest struct {
	ExploitRuleID uint                   `json:"exploit_rule_id"`
	AgentID       string                 `json:"agent_id"`
	TargetURL     string                 `json:"target_url"`
	Source        string                 `json:"source"`
	Params        map[string]interface{} `json:"params"`
	Proxy         string                 `json:"proxy"`
	TimeoutSec    int32                  `json:"timeout_sec"`
	Action        string                 `json:"action"`
}

type mcpPOCDebugRequest struct {
	AgentID    string `json:"agent_id"`
	TargetURL  string `json:"target_url"`
	PocContent string `json:"poc_content"`
	Proxy      string `json:"proxy"`
	TimeoutSec int32  `json:"timeout_sec"`
}

type mcpAgentPythonRunRequest struct {
	AgentID    string          `json:"agent_id"`
	Command    string          `json:"command"`
	Params     json.RawMessage `json:"params"`
	TimeoutSec int32           `json:"timeout_sec"`
}

type mcpDebugWaitResult struct {
	Status          string                   `json:"status"`
	Matched         bool                     `json:"matched"`
	Error           string                   `json:"error,omitempty"`
	ExecutionResult map[string]interface{}   `json:"execution_result,omitempty"`
	Logs            []map[string]interface{} `json:"logs,omitempty"`
	Result          map[string]interface{}   `json:"result,omitempty"`
	Complete        map[string]interface{}   `json:"complete,omitempty"`
}

func mcpPyexpSpec(c *gin.Context) {
	writeMCPResource(c, "argus://pyexp/spec")
}

func mcpPyexpTemplate(c *gin.Context) {
	writeMCPResource(c, "argus://pyexp/template")
}

func mcpPOCTemplate(c *gin.Context) {
	writeMCPResource(c, "argus://poc/template")
}

func mcpArgusMCPQuickstart(c *gin.Context) {
	writeMCPResource(c, "argus://argus-mcp/quickstart")
}

func mcpArgusMCPToolGuide(c *gin.Context) {
	writeMCPResource(c, "argus://argus-mcp/tool-guide")
}

func mcpFingerprintSpec(c *gin.Context) {
	writeMCPResource(c, "argus://fingerprint/spec")
}

func mcpFingerprintTemplate(c *gin.Context) {
	writeMCPResource(c, "argus://fingerprint/template")
}

func mcpPOCSpec(c *gin.Context) {
	writeMCPResource(c, "argus://poc/spec")
}

func mcpWorkflowSpec(c *gin.Context) {
	writeMCPResource(c, "argus://workflow/spec")
}

func mcpWorkflowTemplate(c *gin.Context) {
	writeMCPResource(c, "argus://workflow/template")
}

func mcpFullChainExample(c *gin.Context) {
	writeMCPResource(c, "argus://examples/fingerprint-poc-workflow")
}

func writeMCPResource(c *gin.Context, uri string) {
	resource, ok := mcpResourceByURI(uri)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "resource not found"})
		return
	}
	c.JSON(http.StatusOK, mcpResourceResponse{URI: resource.URI, MIMEType: resource.MIMEType, Text: resource.Text})
}

func mcpPyexpValidate(c *gin.Context) {
	var req mcpPyexpSourceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	tmpl, err := parseMCPPyexpSource(req.Source, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"valid": false, "error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"valid":             true,
		"id":                tmpl.ID,
		"name":              tmpl.Name,
		"risk_level":        tmpl.RiskLevel,
		"params_schema":     pyexp.ParamSchema(tmpl.Params),
		"requirements":      tmpl.Requirements,
		"requirements_hash": tmpl.RequirementsHash,
		"has_run":           tmpl.HasRun,
		"has_main":          tmpl.HasMain,
		"has_cleanup":       tmpl.HasCleanup,
		"policy":            tmpl.Policy,
	})
}

func mcpPyexpDryRun(c *gin.Context) {
	var req mcpPyexpDryRunRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target is required"})
		return
	}
	tmpl, err := parseMCPPyexpSource(req.Source, false)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	paramsSchema := pyexp.ParamSchema(tmpl.Params)
	normalizedParams, paramErrors := normalizeExpParamsForTarget(paramsSchema, req.Params, req.Target)
	paramsValid := len(paramErrors) == 0
	executionPlan := map[string]interface{}{
		"mode":              "python",
		"engine":            pyexp.RuntimeEngine,
		"entry":             "run(ctx)",
		"cleanup_entry":     "cleanup(ctx)",
		"cleanup_defined":   tmpl.HasCleanup,
		"requirements":      tmpl.Requirements,
		"requirements_hash": tmpl.RequirementsHash,
		"sandbox_profile":   "local-python",
	}
	c.JSON(http.StatusOK, dryRunExploitResponse{
		ExploitID:        tmpl.ID,
		Target:           req.Target,
		RiskLevel:        tmpl.RiskLevel,
		RequiresAuth:     tmpl.Policy.RequiresAuth,
		SideEffects:      tmpl.Policy.SideEffects,
		CleanupSupported: tmpl.Policy.CleanupSupported,
		CleanupRequired:  tmpl.Policy.CleanupRequired,
		TimeoutSec:       tmpl.Policy.TimeoutSec,
		Capabilities:     tmpl.Policy.Capabilities,
		ExecutionPlan:    executionPlan,
		ParamsValid:      paramsValid,
		ParamsErrors:     paramErrors,
		NormalizedParams: normalizedParams,
	})
}

func mcpPyexpSaveDraft(c *gin.Context) {
	var req mcpSaveDraftRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	result, err := executeCreateExpDraft(currentTenantID(c), map[string]interface{}{"file_name": req.FileName, "content": req.Content})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	resp, err := mcpSavedExpDraftResponse(currentTenantID(c), req.FileName, result)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func mcpPOCSaveDraft(c *gin.Context) {
	var req mcpSaveDraftRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	result, err := executeCreatePOCDraft(currentTenantID(c), map[string]interface{}{"file_name": req.FileName, "content": req.Content})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result.Object)
}

func mcpPyexpDebug(c *gin.Context) {
	tenantID := currentTenantID(c)
	var req mcpDebugExploitRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.AgentID = strings.TrimSpace(req.AgentID)
	req.TargetURL = strings.TrimSpace(req.TargetURL)
	req.Proxy = strings.TrimSpace(req.Proxy)
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	if req.Action == "" {
		req.Action = "run"
	}
	source := strings.TrimSpace(req.Source)
	if req.Action == "dry_run" {
		req.TargetURL = strings.TrimSpace(req.TargetURL)
		if req.TargetURL == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "target_url is required"})
			return
		}
		tmpl, err := parseMCPPyexpSource(source, false)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		normalizedParams, paramErrors := normalizeExpParamsForTarget(pyexp.ParamSchema(tmpl.Params), req.Params, req.TargetURL)
		resp := sourceLevelPyexpDryRunResponse(tmpl, req.TargetURL, normalizedParams, paramErrors)
		resp["mcp_guidance"] = mcpPyexpSourceDebugGuidance("dry_run")
		c.JSON(http.StatusOK, resp)
		return
	}
	if notifyHub == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent notify hub is not ready"})
		return
	}
	if req.AgentID == "" || req.TargetURL == "" || (req.ExploitRuleID == 0 && source == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id, target_url and either exploit_rule_id or source are required"})
		return
	}
	if req.Action != "run" && req.Action != "cleanup" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be run, cleanup or dry_run"})
		return
	}
	if err := validateDebugTargetURL(req.TargetURL); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateDebugProxy(req.Proxy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var expContent string
	var paramsSchema map[string]interface{}
	sourceLevel := source != ""
	var ruleID string
	if sourceLevel {
		tmpl, err := parseMCPPyexpSource(source, false)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("EXP validation failed: %v", err)})
			return
		}
		if req.Action == "cleanup" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cleanup requires a saved pyexp rule; source-level debug only supports run and dry_run"})
			return
		}
		expContent = source
		paramsSchema = pyexp.ParamSchema(tmpl.Params)
		ruleID = tmpl.ID
	} else {
		rule, arsenal, ok := loadDebuggableMCPExpRule(c, tenantID, req.ExploitRuleID)
		if !ok {
			return
		}
		expContent = arsenal.Content
		paramsSchema = decodeJSONMap(rule.ParamsSchema)
		ruleID = rule.RuleID
	}
	normalizedParams, paramErrors := normalizeExpParamsForTarget(paramsSchema, req.Params, req.TargetURL)
	if len(paramErrors) > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": strings.Join(paramErrors, "; "), "params_errors": paramErrors})
		return
	}
	if !mcpValidateDebugAgent(c, tenantID, req.AgentID, true) {
		return
	}

	timeoutSec := normalizeMCPSyncTimeout(req.TimeoutSec)
	resultChan := make(chan map[string]interface{}, 10)
	session, ok := pocDebugSessions.start(tenantID, req.AgentID, time.Duration(timeoutSec)*time.Second, resultChan)
	if !ok {
		c.JSON(http.StatusConflict, gin.H{"error": "tenant already has a running debug session"})
		return
	}
	paramsJSON, _ := json.Marshal(normalizedParams)
	action := "start_exp_debug"
	if req.Action == "cleanup" {
		action = "cleanup_exp_debug"
	}
	cmd := &pb.DebugCommand{
		Action:     action,
		SessionId:  session.SessionID,
		TenantId:   tenantID,
		PocContent: expContent,
		TargetUrl:  req.TargetURL,
		Proxy:      req.Proxy,
		TimeoutSec: timeoutSec,
		Params:     string(paramsJSON),
	}
	if err := notifyHub.SendDebugCommand(req.AgentID, cmd); err != nil {
		pocDebugSessions.finish(session.SessionID)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to send EXP debug command to agent"})
		return
	}
	go expireDebugSession(session)
	waited, err := waitMCPDebugResult(resultChan, time.Duration(timeoutSec+15)*time.Second)
	if err != nil {
		pocDebugSessions.finish(session.SessionID)
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": err.Error()})
		return
	}
	waited.Result = enrichMCPPyexpDebugResult(waited.Result, sourceLevel, ruleID)
	if waited.Result == nil {
		waited.Result = map[string]interface{}{"source_level": sourceLevel, "rule_id": ruleID}
	}
	waited.Result["mcp_guidance"] = mcpPyexpSourceDebugGuidance(req.Action)
	if waited.ExecutionResult != nil {
		waited.ExecutionResult["rule_type"] = "pyexp"
		waited.ExecutionResult["source_level"] = sourceLevel
		if ruleID != "" {
			waited.ExecutionResult["rule_id"] = ruleID
		}
	}
	c.JSON(http.StatusOK, waited)
}

func mcpPOCDebug(c *gin.Context) {
	if notifyHub == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent notify hub is not ready"})
		return
	}
	tenantID := currentTenantID(c)
	var req mcpPOCDebugRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.AgentID = strings.TrimSpace(req.AgentID)
	req.TargetURL = strings.TrimSpace(req.TargetURL)
	req.PocContent = strings.TrimSpace(req.PocContent)
	req.Proxy = strings.TrimSpace(req.Proxy)
	if req.AgentID == "" || req.TargetURL == "" || req.PocContent == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id, poc_content and target_url are required"})
		return
	}
	if len(req.PocContent) > 256*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "poc_content is too large"})
		return
	}
	if err := yaml.Unmarshal([]byte(req.PocContent), &struct{}{}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("poc_content is not valid YAML: %v", err)})
		return
	}
	if err := validateDebugTargetURL(req.TargetURL); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateDebugProxy(req.Proxy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !mcpValidateDebugAgent(c, tenantID, req.AgentID, false) {
		return
	}
	timeoutSec := normalizeMCPSyncTimeout(req.TimeoutSec)
	resultChan := make(chan map[string]interface{}, 10)
	session, ok := pocDebugSessions.start(tenantID, req.AgentID, time.Duration(timeoutSec)*time.Second, resultChan)
	if !ok {
		c.JSON(http.StatusConflict, gin.H{"error": "tenant already has a running debug session"})
		return
	}
	cmd := &pb.DebugCommand{
		Action:     "start_debug",
		SessionId:  session.SessionID,
		TenantId:   tenantID,
		PocContent: req.PocContent,
		TargetUrl:  req.TargetURL,
		Proxy:      req.Proxy,
		TimeoutSec: timeoutSec,
	}
	if err := notifyHub.SendDebugCommand(req.AgentID, cmd); err != nil {
		pocDebugSessions.finish(session.SessionID)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to send debug command to agent"})
		return
	}
	go expireDebugSession(session)
	waited, err := waitMCPDebugResult(resultChan, time.Duration(timeoutSec+15)*time.Second)
	if err != nil {
		pocDebugSessions.finish(session.SessionID)
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, waited)
}

func mcpAgentPythonRun(c *gin.Context) {
	if notifyHub == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent notify hub is not ready"})
		return
	}
	tenantID := currentTenantID(c)
	var req mcpAgentPythonRunRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.AgentID = strings.TrimSpace(req.AgentID)
	req.Command = strings.ToLower(strings.TrimSpace(req.Command))
	if req.AgentID == "" || req.Command == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id and command are required"})
		return
	}
	if !mcpPythonScratchpadCommands[req.Command] {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unsupported python scratchpad command %q", req.Command)})
		return
	}
	if !mcpValidateDebugAgent(c, tenantID, req.AgentID, true) {
		return
	}
	timeoutSec := normalizeMCPSyncTimeout(req.TimeoutSec)
	params, err := mcpScratchpadParams(req.Command, req.Params, timeoutSec)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	resultChan := make(chan map[string]interface{}, 10)
	session, ok := pocDebugSessions.start(tenantID, req.AgentID, time.Duration(timeoutSec)*time.Second, resultChan)
	if !ok {
		c.JSON(http.StatusConflict, gin.H{"error": "tenant already has a running debug session"})
		return
	}
	cmd := &pb.DebugCommand{
		Action:     "python_scratchpad_run",
		SessionId:  session.SessionID,
		TenantId:   tenantID,
		TimeoutSec: timeoutSec,
		Params:     params,
	}
	if err := notifyHub.SendDebugCommand(req.AgentID, cmd); err != nil {
		pocDebugSessions.finish(session.SessionID)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to send Python scratchpad command to agent"})
		return
	}
	go expireDebugSession(session)
	waited, err := waitMCPDebugResult(resultChan, time.Duration(timeoutSec+15)*time.Second)
	if err != nil {
		pocDebugSessions.finish(session.SessionID)
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, waited)
}

func parseMCPPyexpSource(source string, strict bool) (*pyexp.Template, error) {
	source = strings.TrimSpace(source)
	if source == "" {
		return nil, fmt.Errorf("source is required")
	}
	if len(source) > maxCopilotDraftContentSizeByte {
		return nil, fmt.Errorf("source is too large")
	}
	tmpl, err := pyexp.ParseTemplate([]byte(source))
	if err != nil {
		return nil, err
	}
	if err := pyexp.Validate([]byte(source), strict); err != nil {
		return nil, err
	}
	return tmpl, nil
}

func mcpSavedExpDraftResponse(tenantID, fileName string, result copilotActionResult) (gin.H, error) {
	fileName = strings.TrimSpace(fileName)
	var arsenal db.Arsenal
	if err := db.DB.Where("tenant_id = ? AND type = ? AND file_name = ?", tenantID, "exp", fileName).First(&arsenal).Error; err != nil {
		return nil, fmt.Errorf("load saved EXP draft: %w", err)
	}
	var rule db.ExploitRule
	if err := db.DB.Where("tenant_id = ? AND artifact_id = ?", tenantID, arsenal.ID).First(&rule).Error; err != nil {
		return nil, fmt.Errorf("load synced EXP rule: %w", err)
	}
	tmpl, err := pyexp.ParseTemplate([]byte(arsenal.Content))
	if err != nil {
		return nil, err
	}
	resp := gin.H{
		"status":            result.Status,
		"message":           result.Message,
		"artifact_id":       arsenal.ID,
		"exploit_rule_id":   rule.ID,
		"rule_id":           rule.RuleID,
		"file_name":         arsenal.FileName,
		"state":             arsenal.State,
		"hash":              arsenal.Hash,
		"version":           arsenal.Version,
		"requirements":      tmpl.Requirements,
		"requirements_hash": tmpl.RequirementsHash,
	}
	return resp, nil
}

func loadDebuggableMCPExpRule(c *gin.Context, tenantID string, ruleID uint) (db.ExploitRule, db.Arsenal, bool) {
	var rule db.ExploitRule
	if err := db.DB.Where("id = ? AND tenant_id = ?", ruleID, tenantID).First(&rule).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Exploit rule not found"})
		return db.ExploitRule{}, db.Arsenal{}, false
	}
	if rule.State == "Deprecated" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Deprecated EXP rule cannot be debugged"})
		return db.ExploitRule{}, db.Arsenal{}, false
	}
	var arsenal db.Arsenal
	if err := db.DB.Where("id = ? AND tenant_id = ?", rule.ArtifactID, tenantID).First(&arsenal).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "EXP source package not found"})
		return db.ExploitRule{}, db.Arsenal{}, false
	}
	if err := validateExpPackage(arsenal.Content, false); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("EXP validation failed: %v", err)})
		return db.ExploitRule{}, db.Arsenal{}, false
	}
	return rule, arsenal, true
}

func mcpValidateDebugAgent(c *gin.Context, tenantID, agentID string, requirePython bool) bool {
	var node db.Node
	if err := scopedNodeQuery(tenantID).Where("agent_id = ? AND status = ?", agentID, "Alive").First(&node).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent is not alive in this tenant"})
		return false
	}
	if requirePython && !agentSupportsPythonEXP(node) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent does not support local Python execution"})
		return false
	}
	if !isDebugCapableAgent(node.Version) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent does not support debug; please upgrade agent"})
		return false
	}
	if !notifyHub.IsAgentOnline(agentID) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent subscribe stream is offline"})
		return false
	}
	return true
}

func mcpScratchpadParams(command string, paramsRaw json.RawMessage, timeoutSec int32) (string, error) {
	params := map[string]interface{}{}
	if len(paramsRaw) > 0 && string(paramsRaw) != "null" {
		if err := json.Unmarshal(paramsRaw, &params); err != nil {
			return "", fmt.Errorf("params must be an object")
		}
	}
	params["command"] = command
	params["timeout_sec"] = timeoutSec
	data, _ := json.Marshal(params)
	return string(data), nil
}

func normalizeMCPSyncTimeout(timeoutSec int32) int32 {
	if timeoutSec <= 0 {
		return defaultMCPSyncTimeoutSec
	}
	if timeoutSec > maxMCPSyncTimeoutSec {
		return maxMCPSyncTimeoutSec
	}
	return timeoutSec
}

func waitMCPDebugResult(resultChan <-chan map[string]interface{}, timeout time.Duration) (mcpDebugWaitResult, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var latestResult map[string]interface{}
	var logs []map[string]interface{}
	var errorMessages []string
	for {
		select {
		case msg := <-resultChan:
			msg = sanitizeMCPDebugEvent(msg)
			switch msg["type"] {
			case "debug_log":
				logs = append(logs, msg)
				if isMCPDebugErrorLog(msg) {
					if text := strings.TrimSpace(fmt.Sprint(msg["message"])); text != "" {
						errorMessages = append(errorMessages, text)
					}
				}
			case "debug_result":
				latestResult = msg
			case "debug_complete":
				status := "completed"
				errText := ""
				if rawErr, ok := msg["error"]; ok && rawErr != nil {
					errText = strings.TrimSpace(fmt.Sprint(rawErr))
				}
				if errText != "" {
					errorMessages = append(errorMessages, errText)
				}
				if latestResult == nil && len(errorMessages) > 0 {
					status = "failed"
				}
				if errText == "" && len(errorMessages) > 0 {
					errText = strings.Join(errorMessages, "; ")
				}
				executionResult := buildMCPExecutionResult(status, errText, logs, latestResult, msg)
				return mcpDebugWaitResult{
					Status:          status,
					Matched:         boolFromMCPMap(executionResult, "matched"),
					Error:           errText,
					ExecutionResult: executionResult,
					Logs:            logs,
					Result:          latestResult,
					Complete:        msg,
				}, nil
			}
		case <-timer.C:
			return mcpDebugWaitResult{}, fmt.Errorf("debug execution timeout after %s", timeout)
		}
	}
}

var (
	mcpANSIControlPattern   = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
	mcpDebugTempPathPattern = regexp.MustCompile(`(?:(?:/private)?/var/folders|(?:/private)?/tmp)[^\s"']*argus-poc-debug-[^\s"']*/debug-poc\.ya?ml`)
	mcpRepeatedSpacePattern = regexp.MustCompile(`[ \t]{2,}`)
)

func sanitizeMCPDebugEvent(msg map[string]interface{}) map[string]interface{} {
	if msg == nil {
		return nil
	}
	out := make(map[string]interface{}, len(msg))
	for key, value := range msg {
		out[key] = sanitizeMCPDebugValue(value)
	}
	return out
}

func sanitizeMCPDebugValue(value interface{}) interface{} {
	switch v := value.(type) {
	case string:
		return sanitizeMCPDebugText(v)
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, sanitizeMCPDebugText(item))
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(v))
		for _, item := range v {
			out = append(out, sanitizeMCPDebugValue(item))
		}
		return out
	case map[string]interface{}:
		return sanitizeMCPDebugEvent(v)
	default:
		return value
	}
}

func sanitizeMCPDebugText(text string) string {
	text = mcpANSIControlPattern.ReplaceAllString(text, "")
	text = mcpDebugTempPathPattern.ReplaceAllString(text, "debug-poc.yaml")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(mcpRepeatedSpacePattern.ReplaceAllString(line, " "))
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func buildMCPExecutionResult(status, errText string, logs []map[string]interface{}, result, complete map[string]interface{}) map[string]interface{} {
	parsed := parseMCPDebugResultMessage(result)
	matched := boolFromMCPMap(result, "matched")
	completeMatched := boolFromMCPMap(complete, "matched")
	if !matched {
		matched = completeMatched
	}
	resultStatus := firstMCPString(parsed, "status")
	if resultStatus == "" {
		resultStatus = firstMCPString(result, "severity", "status")
	}
	success := matched || strings.EqualFold(resultStatus, "Succeeded") || strings.EqualFold(resultStatus, "success")
	if status == "failed" || errText != "" {
		success = false
	}
	message := firstMCPString(parsed, "message")
	if message == "" {
		message = firstMCPString(result, "message")
	}
	if message == "" && errText != "" {
		message = errText
	}
	errorMessage := errText
	if errorMessage == "" {
		errorMessage = firstMCPString(parsed, "error", "error_message")
	}
	if errorMessage == "" {
		errorMessage = firstMCPString(result, "error", "error_message")
	}
	request := firstMCPString(result, "request")
	response := firstMCPString(result, "response")
	warnings := []string{}
	if result != nil && boolValuePresent(result, "matched") && boolValuePresent(complete, "matched") && boolFromMCPMap(result, "matched") != boolFromMCPMap(complete, "matched") {
		warnings = append(warnings, "complete.matched differed from result.matched; result.matched was used")
		matched = boolFromMCPMap(result, "matched")
		success = success || matched
	}
	if status == "failed" || errText != "" {
		success = false
	}
	errorLogs := []string{}
	for _, logItem := range logs {
		if isMCPDebugErrorLog(logItem) {
			if text := firstMCPString(logItem, "message"); text != "" {
				errorLogs = append(errorLogs, text)
			}
		}
	}
	out := map[string]interface{}{
		"status":               status,
		"success":              success,
		"matched":              matched,
		"result_status":        resultStatus,
		"message":              message,
		"error":                errorMessage,
		"has_request_response": request != "" || response != "",
		"request":              request,
		"response":             response,
		"matched_at":           firstMCPString(result, "matched_at"),
		"template_id":          firstMCPString(result, "template_id"),
		"severity":             firstMCPString(result, "severity"),
		"duration_ms":          firstPresentMCPValue(result, complete, "duration_ms"),
		"extracted":            firstPresentMCPValue(result, complete, "extracted"),
		"evidence":             parsed["evidence"],
		"side_effects":         parsed["side_effects"],
		"error_logs":           errorLogs,
	}
	if len(warnings) > 0 {
		out["warnings"] = warnings
	}
	return sanitizeMCPDebugEvent(out)
}

func parseMCPDebugResultMessage(result map[string]interface{}) map[string]interface{} {
	if result == nil {
		return map[string]interface{}{}
	}
	message := firstMCPString(result, "message")
	if message == "" || !strings.HasPrefix(strings.TrimSpace(message), "{") {
		return map[string]interface{}{}
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(message), &parsed); err != nil {
		return map[string]interface{}{}
	}
	return sanitizeMCPDebugEvent(parsed)
}

func boolFromMCPMap(values map[string]interface{}, key string) bool {
	if values == nil {
		return false
	}
	raw, ok := values[key]
	if !ok {
		return false
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true") || strings.EqualFold(strings.TrimSpace(v), "yes") || strings.EqualFold(strings.TrimSpace(v), "succeeded")
	default:
		return false
	}
}

func boolValuePresent(values map[string]interface{}, key string) bool {
	if values == nil {
		return false
	}
	_, ok := values[key]
	return ok
}

func firstMCPString(values map[string]interface{}, keys ...string) string {
	if values == nil {
		return ""
	}
	for _, key := range keys {
		if value, ok := values[key]; ok && value != nil {
			text := strings.TrimSpace(fmt.Sprint(value))
			if text != "" && text != "<nil>" {
				return sanitizeMCPDebugText(text)
			}
		}
	}
	return ""
}

func firstPresentMCPValue(first, second map[string]interface{}, key string) interface{} {
	if first != nil {
		if value, ok := first[key]; ok && value != nil {
			return sanitizeMCPDebugValue(value)
		}
	}
	if second != nil {
		if value, ok := second[key]; ok && value != nil {
			return sanitizeMCPDebugValue(value)
		}
	}
	return nil
}

func sourceLevelPyexpDryRunResponse(tmpl *pyexp.Template, target string, normalizedParams map[string]interface{}, paramErrors []string) gin.H {
	return gin.H{
		"status":            "validated",
		"source_level":      true,
		"dry_run":           true,
		"rule_type":         "pyexp",
		"exploit_id":        tmpl.ID,
		"rule_id":           tmpl.ID,
		"target":            target,
		"risk_level":        tmpl.RiskLevel,
		"policy":            tmpl.Policy,
		"params_valid":      len(paramErrors) == 0,
		"params_errors":     paramErrors,
		"normalized_params": normalizedParams,
		"execution_plan": gin.H{
			"mode":              "python",
			"engine":            pyexp.RuntimeEngine,
			"entry":             "run(ctx)",
			"cleanup_entry":     "cleanup(ctx)",
			"cleanup_defined":   tmpl.HasCleanup,
			"requirements":      tmpl.Requirements,
			"requirements_hash": tmpl.RequirementsHash,
			"sandbox_profile":   "local-python",
			"will_execute":      false,
		},
		"requirements":      tmpl.Requirements,
		"requirements_hash": tmpl.RequirementsHash,
	}
}

func enrichMCPPyexpDebugResult(result map[string]interface{}, sourceLevel bool, ruleID string) map[string]interface{} {
	if result == nil {
		result = map[string]interface{}{}
	}
	result["source_level"] = sourceLevel
	if ruleID != "" {
		result["rule_id"] = ruleID
	}
	result["rule_type"] = "pyexp"
	return result
}

func mcpPyexpSourceDebugGuidance(action string) gin.H {
	if action == "dry_run" {
		return gin.H{
			"next_steps":     []string{"if params_valid is true, run source-level debug against an online Agent", "save a Draft only after source-level debug succeeds"},
			"requires_admin": false,
			"warnings":       []string{"dry_run does not execute Python and does not check installed Agent dependencies", "dry_run does not save or publish any artifact"},
		}
	}
	return gin.H{
		"next_steps":     []string{"if status/result is successful, save the source with argus_rule_save", "if dependency check fails, install requirements only after saving a Draft and reviewing hashes"},
		"requires_admin": false,
		"warnings":       []string{"source-level debug does not create or update Draft artifacts", "failed debug output should be fixed before saving"},
	}
}

func isMCPDebugErrorLog(msg map[string]interface{}) bool {
	level := strings.ToUpper(strings.TrimSpace(fmt.Sprint(msg["level"])))
	text := strings.ToLower(strings.TrimSpace(fmt.Sprint(msg["message"])))
	if level == "ERROR" {
		return true
	}
	for _, marker := range []string{
		"could not load template",
		"syntax error",
		"mandatory",
		"could not validate",
		"could not run nuclei",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

const pyexpSpecText = `# Argus Python EXP format

Argus Python EXP files are normal Python scripts plus an ARGUS_EXP metadata contract. They must define an ARGUS_EXP dict literal at top level and either run(ctx) or main().

Required ARGUS_EXP fields:
- id: stable EXP id.
- name: display name.
- risk_level: low, medium, high, or destructive.
- policy: capabilities, timeout_sec, dry_run_supported, cleanup_supported, cleanup_required, side_effects.
- params: runtime parameter schema. Argparse usage can also be inferred into params.
- requirements: Agent environment requirements. This is a declaration, not an automatic install instruction.

Requirements must pin exact versions and include sha256 hashes, for example:
requests==2.32.3 --hash=sha256:<64 hex>

Execution boundaries:
- Server validates and stores EXP drafts as database artifacts in arsenals.
- Rule catalog rows are derived indexes from arsenals, not the source of truth.
- Agent executes against its configured Python runtime.
- EXP execution does not auto-install dependencies. Run the pyenv install flow first.
- Approval, publication, official runs, and risk waivers remain in the normal Argus UI/API flow.

Migration guidance:
- Prefer native Python for exploit logic. ctx.http, ctx.tcp, ctx.evidence and ctx.result are convenience APIs, not mandatory wrappers.
- Keep argparse usable so "python exp.py --help" remains meaningful during local migration.
- Use argus_rule_save with rule_type=pyexp to create a Draft database artifact, then argus_rule_apply action=install_requirements after the Draft exists.
- Prefer stable_ref fields artifact_id, rule_id, file_name, hash and version. exploit_rule_id is a legacy catalog row id and may change after catalog sync.
- Use argus_rule_debug with stable_ref, agent_id, target_url and params to validate behavior before publishing.
`

const argusMCPQuickstartText = `# Argus MCP quickstart

Use this sequence when the client has no Argus source code:

1. Read argus://argus-mcp/tool-guide.
2. Read the relevant spec and template resources.
3. Call argus_context with action=agents and select an Alive Agent.
4. Call argus_rule_debug to validate generated fingerprint, POC, or pyexp behavior.
5. Call argus_rule_save to create a Draft database artifact and capture stable_ref.
6. Call argus_rule_apply with action=publish as admin, passing the exact stable_ref hash/version returned by save.
7. Call argus_context with action=workflow_links to verify fingerprint -> POC linkage.

Publishing is protected by hash/version guards. A 409 means the Draft changed; re-read/save before retrying.

Storage model:
- POC, workflow, fingerprint and EXP source content is stored in the Argus database arsenals table.
- FingerprintRule, PocRule, WorkflowRule and ExploitRule catalog tables are derived indexes for lookup/execution.
- MCP is a thin orchestration layer over Argus native APIs; it should preserve tenant/RBAC/approval semantics instead of bypassing Server control.

Lifecycle intents:
- test_only: temporary validation work; cleanup is situational and recommended when the rule should not remain reusable.
- production_candidate: default for rules being prepared for review or reuse.
- approved_reusable: validated rule expected to remain in the library.
`

const argusMCPToolGuideText = `# Argus MCP tool guide

Argus intentionally exposes four aggregate tools:

- argus_context: read specs/templates, list Agents, inspect Agent pyenv, query workflow_links, workflow_recommend and workflow_conflicts.
- argus_rule_debug: validate fingerprint, POC or pyexp behavior through Argus Server and an online Agent.
- argus_rule_save: save fingerprint, POC, workflow or pyexp into the Argus database as a Draft artifact. Optional intent: test_only, production_candidate, approved_reusable.
- argus_rule_apply: admin-only controlled actions. action=publish uses stable_ref hash/version. action=install_requirements only supports pyexp.

Reference model:
- stable_ref.artifact_id, rule_id, file_name, hash and version are the preferred references.
- exploit_rule_id is a legacy derived catalog row id; MCP may resolve it internally but clients should not treat it as stable.

Recommended loop:
read resources -> debug -> save Draft artifact -> publish with stable_ref hash/version -> verify workflow_links.
`

const fingerprintSpecText = `# Argus fingerprint spec

Fingerprint rules are stored in the Argus database arsenals artifact named finger.yaml as a mapping from product_name to one or more rule expressions. FingerprintRule catalog rows are derived from that artifact.

Example:
MyProduct:
  - body="Welcome to MyProduct"
  - title="MyProduct Console"

MCP save shape:
- rule_type: fingerprint
- product_name: stable product name used by workflow
- rules: array of expressions such as body="marker", title="marker", header="marker"
- intent: optional lifecycle hint

Debug shape:
- rule_type: fingerprint
- agent_id and target_url are required
- product_name and rule inject one custom rule for debugging
- include_poc plus workflow_product/workflow_types/workflow_pocs/poc_content can validate the fingerprint -> POC chain
`

const fingerprintTemplateText = `ExampleProduct:
  - body="ExampleProduct"
`

const pocSpecText = `# Argus POC spec

POC rules use Nuclei-compatible YAML for v1 MCP flows.

POC source is stored as a database artifact in arsenals. PocRule catalog rows are derived from the artifact and are used for lookup, workflow association and Agent sync.

Required fields:
- id: stable safe identifier
- info.name
- info.severity
- requests: HTTP request definitions
- matchers: status, word, regex or other supported Nuclei matchers

Minimal structure:
id: example-poc
info:
  name: Example POC
  severity: info
requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "marker"

Use argus_rule_debug with rule_type=poc before saving. Use argus_rule_save with file_name ending in .yaml and content containing the complete YAML.
`

const workflowSpecText = `# Argus workflow spec

Workflow rules connect detected fingerprint products to POC files.

Workflow source is stored as the database artifact workflow.yaml. WorkflowRule catalog rows are derived from that artifact; missing or deleted POC references should be treated as conflicts before publication or deletion.

Supported match types:
- root
- base
- dir
- dir-fallback

YAML shape:
ProductName:
  type:
    - root
  pocs:
    - product-check.yaml

MCP save shape:
- rule_type: workflow
- product_name: must match fingerprint product_name
- workflow_types: array of supported match types
- workflow_pocs: array of POC file names

After publishing, call argus_context action=workflow_links with product_name or poc_name to verify the association.
`

const workflowTemplateText = `ExampleProduct:
  type:
    - root
  pocs:
    - example-poc.yaml
`

const fullChainExampleText = `# Fingerprint -> POC -> Workflow example

Fingerprint debug:
argus_rule_debug({
  "rule_type": "fingerprint",
  "agent_id": "agent-1",
  "target_url": "http://target/",
  "product_name": "ExampleProduct",
  "rule": "body=\"ExampleMarker\""
})

Fingerprint save:
argus_rule_save({
  "rule_type": "fingerprint",
  "intent": "test_only",
  "product_name": "ExampleProduct",
  "rules": ["body=\"ExampleMarker\""]
})

POC YAML:
id: example-product-check
info:
  name: Example Product Check
  severity: info
requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "ExampleMarker"

Workflow save:
argus_rule_save({
  "rule_type": "workflow",
  "product_name": "ExampleProduct",
  "workflow_types": ["root"],
  "workflow_pocs": ["example-product-check.yaml"]
})

Publish steps use argus_rule_apply action=publish with the exact stable_ref file_name, hash and version returned by save.

Verify:
argus_context({"action":"workflow_links","product_name":"ExampleProduct"})

Cleanup guidance:
For test_only work, cleanup is situational. Remove temporary rules when the goal was only to prove the MCP flow. Do not delete rules that passed validation and should remain reusable.
`

const pyexpTemplateText = `ARGUS_EXP = {
    "id": "exp-example",
    "name": "Example Python EXP",
    "description": "Minimal Argus Python EXP template.",
    "risk_level": "medium",
    "policy": {
        "capabilities": ["http.request", "result.write"],
        "dry_run_supported": True,
        "timeout_sec": 60,
    },
    "params": {},
    "requirements": [],
}

def run(ctx):
    resp = ctx.http.request(method="GET", path="/")
    ctx.evidence.add("status_code", resp.status_code)
    if resp.status_code < 500:
        return ctx.result.success("target responded")
    return ctx.result.fail("target did not match")
`

const pocTemplateText = `id: argus-example-poc
info:
  name: Example POC
  author: argus
  severity: info
requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`
