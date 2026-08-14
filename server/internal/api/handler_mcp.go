package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

const (
	defaultMCPSyncTimeoutSec = 60
	maxMCPSyncTimeoutSec     = 300
)

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
	{URI: "argus://argus-mcp/tool-guide", Name: "Argus MCP Tool Guide", Description: "Field combinations and expected sequencing for the aggregate MCP tools.", MIMEType: "text/markdown", Text: argusMCPToolGuideText},
	{URI: "argus://fingerprint/spec", Name: "Argus Fingerprint Spec", Description: "Fingerprint dictionary format and expression examples.", MIMEType: "text/markdown", Text: fingerprintSpecText},
	{URI: "argus://fingerprint/template", Name: "Argus Fingerprint Template", Description: "Minimal fingerprint YAML snippet.", MIMEType: "text/yaml", Text: fingerprintTemplateText},
	{URI: "argus://behavior-probe/spec", Name: "Argus Behavior Probe Spec", Description: "Governed Nuclei HTTP/HTTPS active fingerprint format and safety classification.", MIMEType: "text/markdown", Text: behaviorProbeSpecText},
	{URI: "argus://behavior-probe/template", Name: "Argus Behavior Probe Template", Description: "Minimal one-file Nuclei behavior probe.", MIMEType: "text/yaml", Text: behaviorProbeTemplateText},
	{URI: "argus://poc/spec", Name: "Argus POC Spec", Description: "POC YAML format accepted by Argus debug and draft flows.", MIMEType: "text/markdown", Text: pocSpecText},
	{URI: "argus://poc/template", Name: "Argus POC Template", Description: "Minimal POC YAML template.", MIMEType: "text/yaml", Text: pocTemplateText},
	{URI: "argus://workflow/spec", Name: "Argus Workflow Spec", Description: "Workflow rule format linking products to POC files.", MIMEType: "text/markdown", Text: workflowSpecText},
	{URI: "argus://workflow/template", Name: "Argus Workflow Template", Description: "Minimal workflow YAML snippet.", MIMEType: "text/yaml", Text: workflowTemplateText},
	{URI: "argus://examples/fingerprint-poc-workflow", Name: "Argus Full Chain Example", Description: "End-to-end fingerprint, POC, workflow, debug/save/publish example.", MIMEType: "text/markdown", Text: fullChainExampleText},
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

type mcpSaveDraftRequest struct {
	FileName string `json:"file_name"`
	Content  string `json:"content"`
}

type mcpPOCDebugRequest struct {
	AgentID    string `json:"agent_id"`
	TargetURL  string `json:"target_url"`
	PocContent string `json:"poc_content"`
	Proxy      string `json:"proxy"`
	TimeoutSec int32  `json:"timeout_sec"`
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

func mcpBehaviorProbeSpec(c *gin.Context) {
	writeMCPResource(c, "argus://behavior-probe/spec")
}

func mcpBehaviorProbeTemplate(c *gin.Context) {
	writeMCPResource(c, "argus://behavior-probe/template")
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

func mcpPOCDebug(c *gin.Context) {
	if routerRuntime().NotifyHub == nil {
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
	if !mcpValidateDebugAgent(c, tenantID, req.AgentID) {
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
	if err := routerRuntime().NotifyHub.SendDebugCommand(req.AgentID, cmd); err != nil {
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

func mcpValidateDebugAgent(c *gin.Context, tenantID, agentID string) bool {
	var node db.Node
	if err := scopedNodeQuery(tenantID).Where("agent_id = ? AND status = ?", agentID, "Alive").First(&node).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent is not alive in this tenant"})
		return false
	}
	if !isDebugCapableAgent(node.Version) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent does not support debug; please upgrade agent"})
		return false
	}
	if !routerRuntime().NotifyHub.IsAgentOnline(agentID) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent subscribe stream is offline"})
		return false
	}
	return true
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

const argusMCPQuickstartText = `# Argus MCP quickstart

Use this sequence when the client has no Argus source code:

1. Read argus://argus-mcp/tool-guide.
2. Read the relevant spec and template resources.
3. Call argus_context with action=agents and select an Alive Agent.
4. Call argus_rule_debug to validate generated fingerprint, behavior_probe or POC behavior; controlled behavior probes require risk_confirmed=true.
5. Call argus_rule_save to create a Draft database artifact and capture stable_ref.
6. Call argus_rule_apply with action=publish as admin, passing the exact stable_ref hash/version returned by save.
7. Call argus_context with action=workflow_links to verify fingerprint -> POC linkage.

Publishing is protected by hash/version guards. A 409 means the Draft changed; re-read/save before retrying.

Storage model:
- POC, workflow, passive fingerprint and behavior-probe source is stored in the Argus database arsenals table; Yaksha EXP source and artifacts are stored through the Server Workspace in private MinIO.
- FingerprintRule, ActiveFingerprintRule, PocRule and WorkflowRule catalog tables are derived indexes for lookup/execution.
- MCP is a thin orchestration layer over Argus native APIs; it should preserve tenant/RBAC/approval semantics instead of bypassing Server control.

Lifecycle intents:
- test_only: temporary validation work; cleanup is situational and recommended when the rule should not remain reusable.
- production_candidate: default for rules being prepared for review or reuse.
- approved_reusable: validated rule expected to remain in the library.
`

const argusMCPToolGuideText = `# Argus MCP tool guide
Argus exposes aggregate tools with Server-enforced governance boundaries:

- argus_context: read specs/templates, list Agents, query workflow_links, workflow_recommend and workflow_conflicts.
- argus_rule_debug: validate a passive fingerprint, behavior_probe or POC through Argus Server and an online Agent.
- argus_rule_save: save fingerprint, behavior_probe, POC or workflow into the Argus database as a Draft artifact.
- argus_rule_apply: admin-only publish, deprecate and rollback using stable_ref hash/version. Yaksha EXP governance uses argus_exp_workspace.
- argus_scan_task: preview and create argus.scan-policy/v1 tasks through one Server-authoritative compiler. Call preview first, then create with the exact plan_hash and a stable idempotency_key. It does not accept Scanner raw config, Agent paths, or a separate manual POC phase.

Reference model:
- stable_ref.artifact_id, rule_id, file_name, hash and version are the preferred references.
- MCP hides derived catalog row ids; clients should use stable_ref fields.

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

const behaviorProbeSpecText = `# Argus behavior probe spec

Each behavior probe is one complete Nuclei HTTP/HTTPS YAML file stored as an independently versioned active_fingerprint Arsenal artifact.

Required metadata:
- argus-rule-kind: active-fingerprint
- argus-product: product name written as an Active-Finger result on matcher success
- argus-auto-profile is informational; Server recomputes the effective classification
- max-request: positive request count

Safe automatic probes are limited to one GET/HEAD request, one same-origin BaseURL path, no body/raw/payload/fuzz/OAST/headless/code, and no dangerous headers. Other valid HTTP/HTTPS templates are classified controlled: they can be stored, published and individually debugged with risk_confirmed=true, but are never included in automatic scanning.

Use rule_type=behavior_probe for read, debug, save, publish, deprecate and rollback. Debug requires file_name, content, agent_id and target_url. Save always creates a Draft; admin lifecycle actions require the exact stable_ref hash/version.
`

const behaviorProbeTemplateText = `id: example-product-detect
info:
  name: Detect Example Product
  severity: info
  metadata:
    argus-rule-kind: active-fingerprint
    argus-product: ExampleProduct
    argus-auto-profile: safe
    max-request: 1
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        part: header
        words:
          - "Example-Product"
`

const pocSpecText = `# Argus POC spec

POC rules use Nuclei-compatible YAML for v1 MCP flows.

POC source is stored as a database artifact in arsenals. PocRule catalog rows are derived from the artifact and are used for lookup, workflow association and Agent sync.

Required fields:
- id: stable safe identifier
- info.name
- info.severity
- info.metadata.argus-execution-class: detection or verification
- info.metadata.argus-risk-level: low, medium or high
- requests: HTTP request definitions
- matchers: status, word, regex or other supported Nuclei matchers

Legacy templates without Argus governance metadata are indexed as detection + unknown and require elevated confirmation. The exploit/exp execution class is forbidden for POC rules; capabilities intended to exploit, persist, or change target state must use a separate EXP package. Every POC remains disabled in normal asset discovery and can run only after an explicit risk-validation confirmation; high and unknown risk require a second confirmation.

Minimal structure:
id: example-poc
info:
  name: Example POC
  severity: info
  metadata:
    argus-execution-class: detection
    argus-risk-level: low
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

Workflow product names have two meanings:
- Product-bound workflow: the name is a real fingerprint product name. The workflow is expected to run after that product is identified.
- General POC workflow: names with the reserved prefix General-Poc- are not real fingerprint products and must not be treated as product aliases. They are used for POC groups whose YAML performs its own product or condition matching. They do not require a same-name fingerprint, and governance tools should not report missing fingerprint support for them.

General POC workflows should stay narrow and low-risk. POCs placed there should have strict matchers, concise request scope, and clear evidence. High-risk or intrusive checks should remain product-bound or require explicit operator intent.

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
- product_name: a fingerprint product name, or a reserved General-Poc-* name for a general POC workflow
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

const pocTemplateText = `id: argus-example-poc
info:
  name: Example POC
  author: argus
  severity: info
  metadata:
    argus-execution-class: detection
    argus-risk-level: low
requests:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`
