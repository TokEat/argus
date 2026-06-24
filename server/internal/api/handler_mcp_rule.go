package api

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-server/internal/db"
	"gopkg.in/yaml.v3"
)

type mcpRuleContextRequest struct {
	Action      string `json:"action"`
	URI         string `json:"uri"`
	AgentID     string `json:"agent_id"`
	ProductName string `json:"product_name"`
	PocName     string `json:"poc_name"`
	Limit       int    `json:"limit"`
}

type mcpRuleDebugRequest struct {
	RuleType        string                 `json:"rule_type"`
	AgentID         string                 `json:"agent_id"`
	TargetURL       string                 `json:"target_url"`
	Proxy           string                 `json:"proxy"`
	TimeoutSec      int32                  `json:"timeout_sec"`
	ProductName     string                 `json:"product_name"`
	Rule            string                 `json:"rule"`
	IncludeDir      bool                   `json:"include_dir"`
	IncludePoc      bool                   `json:"include_poc"`
	WorkflowProduct string                 `json:"workflow_product"`
	WorkflowTypes   []string               `json:"workflow_types"`
	WorkflowPocs    []string               `json:"workflow_pocs"`
	PocContent      string                 `json:"poc_content"`
	Source          string                 `json:"source"`
	ExploitRuleID   uint                   `json:"exploit_rule_id"`
	ArtifactID      string                 `json:"artifact_id"`
	StableRuleID    string                 `json:"rule_id"`
	FileName        string                 `json:"file_name"`
	Params          map[string]interface{} `json:"params"`
	Action          string                 `json:"action"`
}

type mcpRuleSaveRequest struct {
	RuleType      string   `json:"rule_type"`
	FileName      string   `json:"file_name"`
	Content       string   `json:"content"`
	ProductName   string   `json:"product_name"`
	Rules         []string `json:"rules"`
	WorkflowTypes []string `json:"workflow_types"`
	WorkflowPocs  []string `json:"workflow_pocs"`
	Type          []string `json:"type"`
	Pocs          []string `json:"pocs"`
	Intent        string   `json:"intent"`
}

type mcpRuleApplyRequest struct {
	Action        string `json:"action"`
	RuleType      string `json:"rule_type"`
	FileName      string `json:"file_name"`
	Hash          string `json:"hash"`
	Version       int    `json:"version"`
	ExploitRuleID uint   `json:"exploit_rule_id"`
	ArtifactID    string `json:"artifact_id"`
	StableRuleID  string `json:"rule_id"`
	AgentID       string `json:"agent_id"`
}

type mcpDebugTranscript struct {
	Status          string                   `json:"status"`
	Logs            []map[string]interface{} `json:"logs,omitempty"`
	Results         []map[string]interface{} `json:"results,omitempty"`
	Complete        map[string]interface{}   `json:"complete,omitempty"`
	MatchedProducts []string                 `json:"matched_products,omitempty"`
	PocHits         []map[string]interface{} `json:"poc_hits,omitempty"`
	MCPGuidance     gin.H                    `json:"mcp_guidance,omitempty"`
}

func mcpRuleContext(c *gin.Context) {
	tenantID := currentTenantID(c)
	var req mcpRuleContextRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	switch req.Action {
	case "resources":
		mcpContextResources(c)
	case "quickstart":
		mcpContextQuickstart(c)
	case "lifecycle_policy":
		mcpContextLifecyclePolicy(c)
	case "resource":
		mcpContextResource(c, req.URI)
	case "agents":
		mcpContextAgents(c, tenantID)
	case "agent_pyenv":
		mcpContextAgentPyenv(c, tenantID, req.AgentID)
	case "workflow_links":
		mcpContextWorkflowLinks(c, tenantID, req.ProductName, req.PocName, req.Limit)
	case "workflow_recommend":
		mcpContextWorkflowTool(c, (&RecommendWorkflowRulesTool{TenantID: tenantID}).Execute, req)
	case "workflow_conflicts":
		mcpContextWorkflowTool(c, (&DetectWorkflowConflictsTool{TenantID: tenantID}).Execute, req)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported context action"})
	}
}

func mcpRuleDebug(c *gin.Context) {
	var req mcpRuleDebugRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	switch normalizeMCPRuleType(req.RuleType) {
	case "finger":
		mcpRuleDebugFingerprint(c, req)
	case "poc":
		body, _ := json.Marshal(mcpPOCDebugRequest{
			AgentID:    req.AgentID,
			TargetURL:  req.TargetURL,
			PocContent: req.PocContent,
			Proxy:      req.Proxy,
			TimeoutSec: req.TimeoutSec,
		})
		resetJSONBody(c, body)
		mcpPOCDebug(c)
	case "exp":
		action := strings.ToLower(strings.TrimSpace(req.Action))
		source := strings.TrimSpace(req.Source)
		if source == "" {
			source = strings.TrimSpace(req.PocContent)
		}
		if action == "dry_run" && source != "" {
			body, _ := json.Marshal(sourceExploitDryRunRequest{
				Source: source,
				Target: req.TargetURL,
				Params: req.Params,
			})
			resetJSONBody(c, body)
			dryRunSourceExploit(c)
			return
		}
		if source != "" {
			body, _ := json.Marshal(sourceExploitDebugRequest{
				AgentID:    req.AgentID,
				TargetURL:  req.TargetURL,
				Source:     source,
				Params:     req.Params,
				Proxy:      req.Proxy,
				TimeoutSec: req.TimeoutSec,
				Action:     req.Action,
			})
			resetJSONBody(c, body)
			debugSourceExploit(c)
			return
		}
		ruleID := req.ExploitRuleID
		if ruleID == 0 {
			resolved, err := resolveMCPExploitRuleID(currentTenantID(c), req.ArtifactID, req.StableRuleID, req.FileName)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			ruleID = resolved
		}
		body, _ := json.Marshal(mcpDebugExploitRequest{
			ExploitRuleID: ruleID,
			AgentID:       req.AgentID,
			TargetURL:     req.TargetURL,
			Source:        source,
			Params:        req.Params,
			Proxy:         req.Proxy,
			TimeoutSec:    req.TimeoutSec,
			Action:        req.Action,
		})
		resetJSONBody(c, body)
		mcpPyexpDebug(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule_type must be fingerprint, poc or pyexp"})
	}
}

func mcpRuleSave(c *gin.Context) {
	tenantID := currentTenantID(c)
	var req mcpRuleSaveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	var (
		resp gin.H
		err  error
	)
	switch normalizeMCPRuleType(req.RuleType) {
	case "finger":
		resp, err = saveMCPFingerprintDraft(tenantID, req)
	case "workflow":
		resp, err = saveMCPWorkflowDraft(tenantID, req)
	case "poc":
		resp, err = saveMCPPOCDraft(tenantID, req)
	case "exp":
		resp, err = saveMCPPyexpDraft(tenantID, req)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule_type must be fingerprint, poc, workflow or pyexp"})
		return
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	intent := normalizeMCPIntent(req.Intent)
	resp["intent"] = intent
	resp["mcp_guidance"] = mcpSaveGuidance(publicMCPRuleType(normalizeMCPRuleType(req.RuleType)), intent)
	c.JSON(http.StatusOK, resp)
}

func mcpRuleApply(c *gin.Context) {
	tenantID := currentTenantID(c)
	if !roleAtLeast(tenantID, c.GetString("role"), "admin") {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin role required"})
		return
	}
	var req mcpRuleApplyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	switch req.Action {
	case "publish":
		mcpRulePublish(c, tenantID, req)
	case "install_requirements":
		if normalizeMCPRuleType(req.RuleType) != "exp" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "install_requirements only supports pyexp"})
			return
		}
		if strings.TrimSpace(req.AgentID) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
			return
		}
		ruleID := req.ExploitRuleID
		if ruleID == 0 {
			resolved, err := resolveMCPExploitRuleID(tenantID, req.ArtifactID, req.StableRuleID, req.FileName)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			ruleID = resolved
		}
		if ruleID == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "stable pyexp reference is required"})
			return
		}
		body, _ := json.Marshal(agentPyenvInstallRequest{ExploitRuleID: ruleID})
		resetJSONBody(c, body)
		c.Params = append(c.Params, gin.Param{Key: "id", Value: strings.TrimSpace(req.AgentID)})
		installAgentPyenvRequirements(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be publish or install_requirements"})
	}
}

func resolveMCPExploitRuleID(tenantID, artifactID, ruleID, fileName string) (uint, error) {
	artifactID = strings.TrimSpace(artifactID)
	ruleID = strings.TrimSpace(ruleID)
	fileName = strings.TrimSpace(fileName)
	if artifactID == "" && ruleID == "" && fileName == "" {
		return 0, fmt.Errorf("artifact_id, rule_id or file_name is required for pyexp")
	}
	query := db.DB.Where("tenant_id = ?", tenantID)
	switch {
	case artifactID != "":
		query = query.Where("artifact_id = ?", artifactID)
	case ruleID != "":
		query = query.Where("rule_id = ?", ruleID)
	default:
		query = query.Where("source_file = ?", fileName)
	}
	var rule db.ExploitRule
	if err := query.First(&rule).Error; err != nil {
		return 0, fmt.Errorf("EXP rule not found for stable reference")
	}
	return rule.ID, nil
}

func saveMCPFingerprintDraft(tenantID string, req mcpRuleSaveRequest) (gin.H, error) {
	fileName := strings.TrimSpace(req.FileName)
	if fileName == "" {
		fileName = "finger.yaml"
	}
	if err := validateDraftFileName(fileName, true); err != nil {
		return nil, err
	}
	data := map[string][]string{}
	arsenal, err := db.FindTenantArsenalByTypeAndFile(tenantID, "finger", fileName)
	if err == nil {
		if err := yaml.Unmarshal([]byte(arsenal.Content), &data); err != nil {
			return nil, fmt.Errorf("failed to parse existing finger yaml: %w", err)
		}
	} else {
		arsenal = &db.Arsenal{ID: db.BuildTenantArsenalID(tenantID, "finger", fileName), TenantID: tenantID, Type: "finger", FileName: fileName}
	}
	if strings.TrimSpace(req.Content) != "" {
		if err := yaml.Unmarshal([]byte(req.Content), &data); err != nil {
			return nil, fmt.Errorf("content is not valid fingerprint YAML: %w", err)
		}
	}
	product := strings.TrimSpace(req.ProductName)
	if product != "" || len(req.Rules) > 0 {
		if product == "" || len(req.Rules) == 0 {
			return nil, fmt.Errorf("product_name and rules are required together")
		}
		rules := cleanStringSlice(req.Rules)
		if len(rules) == 0 {
			return nil, fmt.Errorf("rules must contain at least one entry")
		}
		data[product] = rules
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("fingerprint draft is empty")
	}
	return saveMCPYAMLDraft(arsenal, data, "fingerprint")
}

func saveMCPWorkflowDraft(tenantID string, req mcpRuleSaveRequest) (gin.H, error) {
	fileName := strings.TrimSpace(req.FileName)
	if fileName == "" {
		fileName = "workflow.yaml"
	}
	if err := validateDraftFileName(fileName, true); err != nil {
		return nil, err
	}
	data := map[string]WorkflowEntry{}
	arsenal, err := db.FindTenantArsenalByTypeAndFile(tenantID, "workflow", fileName)
	if err == nil {
		if err := yaml.Unmarshal([]byte(arsenal.Content), &data); err != nil {
			return nil, fmt.Errorf("failed to parse existing workflow yaml: %w", err)
		}
	} else {
		arsenal = &db.Arsenal{ID: db.BuildTenantArsenalID(tenantID, "workflow", fileName), TenantID: tenantID, Type: "workflow", FileName: fileName}
	}
	if strings.TrimSpace(req.Content) != "" {
		if err := yaml.Unmarshal([]byte(req.Content), &data); err != nil {
			return nil, fmt.Errorf("content is not valid workflow YAML: %w", err)
		}
	}
	product := strings.TrimSpace(req.ProductName)
	types := cleanStringSlice(firstNonEmptyStringSlice(req.WorkflowTypes, req.Type))
	pocs := cleanStringSlice(firstNonEmptyStringSlice(req.WorkflowPocs, req.Pocs))
	if product != "" || len(types) > 0 || len(pocs) > 0 {
		if product == "" || len(types) == 0 || len(pocs) == 0 {
			return nil, fmt.Errorf("product_name, workflow_types and workflow_pocs are required together")
		}
		for _, trigger := range types {
			if !allowedWorkflowTrigger(trigger) {
				return nil, fmt.Errorf("unsupported workflow trigger stage %q", trigger)
			}
		}
		for _, poc := range pocs {
			if err := validateDraftFileName(poc, false); err != nil {
				return nil, fmt.Errorf("invalid poc reference %q: %w", poc, err)
			}
		}
		data[product] = WorkflowEntry{Type: types, Pocs: pocs}
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("workflow draft is empty")
	}
	return saveMCPYAMLDraft(arsenal, data, "workflow")
}

func saveMCPPOCDraft(tenantID string, req mcpRuleSaveRequest) (gin.H, error) {
	result, err := executeCreatePOCDraft(tenantID, map[string]interface{}{"file_name": req.FileName, "content": req.Content})
	if err != nil {
		return nil, err
	}
	fileName := strings.TrimSpace(req.FileName)
	resp := gin.H{
		"rule_type":   "poc",
		"artifact_id": db.BuildTenantArsenalID(tenantID, "poc", fileName),
	}
	for k, v := range result.Object {
		resp[k] = v
	}
	return resp, nil
}

func saveMCPPyexpDraft(tenantID string, req mcpRuleSaveRequest) (gin.H, error) {
	result, err := executeCreateExpDraft(tenantID, map[string]interface{}{"file_name": req.FileName, "content": req.Content})
	if err != nil {
		return nil, err
	}
	resp, err := mcpSavedExpDraftResponse(tenantID, req.FileName, result)
	if err != nil {
		return nil, err
	}
	resp["rule_type"] = "pyexp"
	return resp, nil
}

func saveMCPYAMLDraft(arsenal *db.Arsenal, data interface{}, ruleType string) (gin.H, error) {
	out, err := yaml.Marshal(data)
	if err != nil {
		return nil, err
	}
	arsenal.PreviousContent = arsenal.Content
	arsenal.PreviousHash = arsenal.Hash
	arsenal.Content = string(out)
	arsenal.Hash = fmt.Sprintf("%x", md5.Sum(out))
	arsenal.State = "Draft"
	if arsenal.Version <= 0 {
		arsenal.Version = 1
	} else {
		arsenal.Version++
	}
	if arsenal.ID == "" {
		arsenal.ID = db.BuildTenantArsenalID(arsenal.TenantID, arsenal.Type, arsenal.FileName)
	}
	if err := db.DB.Save(arsenal).Error; err != nil {
		return nil, err
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		return nil, err
	}
	return gin.H{
		"status":         "saved",
		"rule_type":      ruleType,
		"artifact_id":    arsenal.ID,
		"type":           arsenal.Type,
		"file_name":      arsenal.FileName,
		"state":          arsenal.State,
		"hash":           arsenal.Hash,
		"version":        arsenal.Version,
		"content_length": len(arsenal.Content),
	}, nil
}

func mcpRulePublish(c *gin.Context, tenantID string, req mcpRuleApplyRequest) {
	if strings.TrimSpace(req.Hash) == "" || req.Version <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "hash and version are required for publish"})
		return
	}
	switch normalizeMCPRuleType(req.RuleType) {
	case "exp":
		mcpPublishPyexp(c, tenantID, req)
	case "finger", "poc", "workflow":
		typ := normalizeMCPRuleType(req.RuleType)
		fileName := strings.TrimSpace(req.FileName)
		if fileName == "" {
			fileName = defaultMCPRuleFileName(typ)
		}
		mcpPublishArsenal(c, tenantID, typ, fileName, req.Hash, req.Version)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule_type must be fingerprint, poc, workflow or pyexp"})
	}
}

func mcpPublishPyexp(c *gin.Context, tenantID string, req mcpRuleApplyRequest) {
	ruleID := req.ExploitRuleID
	if ruleID == 0 {
		resolved, err := resolveMCPExploitRuleID(tenantID, req.ArtifactID, req.StableRuleID, req.FileName)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ruleID = resolved
	}
	var rule db.ExploitRule
	if err := db.DB.Where("id = ? AND tenant_id = ?", ruleID, tenantID).First(&rule).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Exploit rule not found"})
		return
	}
	var arsenal db.Arsenal
	if err := db.DB.Where("id = ? AND tenant_id = ?", rule.ArtifactID, tenantID).First(&arsenal).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "EXP source package not found"})
		return
	}
	if !mcpDraftGuardMatches(c, arsenal, req.Hash, req.Version) {
		return
	}
	updated, _, err := updateExploitRuleReviewState(tenantID, fmt.Sprint(ruleID), "Approved", true)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":       "approved",
		"rule_type":    "pyexp",
		"artifact_id":  updated.ArtifactID,
		"rule_id":      updated.RuleID,
		"file_name":    updated.SourceFile,
		"state":        updated.State,
		"mcp_guidance": mcpPublishGuidance("pyexp"),
	})
}

func mcpPublishArsenal(c *gin.Context, tenantID, typ, fileName, expectedHash string, expectedVersion int) {
	if err := validateDraftFileName(fileName, true); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	arsenal, err := db.FindTenantArsenalByTypeAndFile(tenantID, typ, fileName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Arsenal not found"})
		return
	}
	if !mcpDraftGuardMatches(c, *arsenal, expectedHash, expectedVersion) {
		return
	}
	if err := db.DB.Model(&db.Arsenal{}).Where("tenant_id = ? AND type IN ? AND file_name = ?", tenantID, db.ArsenalTypeAliases(typ), fileName).Update("state", "Approved").Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ruleVersion := BumpRuleVersion()
	c.JSON(http.StatusOK, gin.H{"status": "approved", "rule_type": publicMCPRuleType(typ), "file_name": fileName, "hash": expectedHash, "version": expectedVersion, "rule_version": ruleVersion, "mcp_guidance": mcpPublishGuidance(publicMCPRuleType(typ))})
}

func mcpDraftGuardMatches(c *gin.Context, arsenal db.Arsenal, expectedHash string, expectedVersion int) bool {
	if arsenal.Hash != expectedHash || arsenal.Version != expectedVersion {
		c.JSON(http.StatusConflict, gin.H{
			"error":           "draft hash or version mismatch",
			"current_hash":    arsenal.Hash,
			"current_version": arsenal.Version,
			"state":           arsenal.State,
		})
		return false
	}
	return true
}

func mcpContextResource(c *gin.Context, uri string) {
	resource, ok := mcpResourceByURI(uri)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown resource uri"})
		return
	}
	c.JSON(http.StatusOK, mcpResourceResponse{URI: resource.URI, MIMEType: resource.MIMEType, Text: resource.Text})
}

func mcpContextResources(c *gin.Context) {
	resources := make([]gin.H, 0, len(mcpResourceDocs))
	for _, resource := range mcpResourceDocs {
		resources = append(resources, gin.H{
			"uri":         resource.URI,
			"name":        resource.Name,
			"description": resource.Description,
			"mime_type":   resource.MIMEType,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"status":                    "success",
		"resources":                 resources,
		"recommended_reading_order": []string{"argus://argus-mcp/quickstart", "argus://argus-mcp/tool-guide", "argus://fingerprint/spec", "argus://poc/spec", "argus://workflow/spec", "argus://examples/fingerprint-poc-workflow"},
	})
}

func mcpContextQuickstart(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"workflow": []string{
			"Read resources with argus_context action=resources or resources/read.",
			"Use argus_context action=agents to select an Alive Agent.",
			"Use argus_rule_debug before saving rules whenever a target is available.",
			"Use argus_rule_save to create Draft artifacts and capture hash/version.",
			"Use argus_rule_apply action=publish as admin with hash/version guard.",
			"Use argus_context action=workflow_links to verify fingerprint -> POC workflow_links.",
			"Treat General-Poc-* workflow names as reserved general POC groups, not real fingerprint products or aliases.",
		},
		"minimum_tools": []string{"argus_context", "argus_rule_debug", "argus_rule_save", "argus_rule_apply"},
		"next_steps":    []string{"debug", "save", "publish", "workflow_links"},
	})
}

func mcpContextLifecyclePolicy(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"intents": []gin.H{
			{"name": "test_only", "meaning": "temporary validation artifact; cleanup is situational and recommended when the test should not remain reusable"},
			{"name": "production_candidate", "meaning": "default intent for rules being prepared for review or reuse"},
			{"name": "approved_reusable", "meaning": "rule is expected to remain available after successful validation"},
		},
		"cleanup_policy": "cleanup is situational: remove test_only artifacts when they were created only to prove the MCP flow; do not auto-delete rules that passed validation and should be reused.",
	})
}

func mcpContextAgents(c *gin.Context, tenantID string) {
	var nodes []db.Node
	scopedNodeQuery(tenantID).Order("agent_id asc").Find(&nodes)
	out := make([]gin.H, 0, len(nodes))
	for _, node := range nodes {
		tags := decodeTagMap(node.Tags)
		out = append(out, gin.H{
			"agent_id":          node.AgentID,
			"status":            node.Status,
			"version":           node.Version,
			"os":                node.OS,
			"arch":              node.Arch,
			"running_tasks":     node.RunningTasks,
			"capacity":          node.Capacity,
			"rule_version":      node.RuleVersion,
			"python_exp":        tags["python_exp"],
			"pyexp_python":      tags["pyexp_python"],
			"pyexp_pip":         tags["pyexp_pip"],
			"pyexp_installable": tags["pyexp_install"],
		})
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "agents": out})
}

func mcpContextAgentPyenv(c *gin.Context, tenantID, agentID string) {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id is required"})
		return
	}
	var node db.Node
	if err := scopedNodeQuery(tenantID).Where("agent_id = ?", agentID).First(&node).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return
	}
	tags := decodeTagMap(node.Tags)
	resp := agentPyenvResponse{
		AgentID:          node.AgentID,
		Status:           node.Status,
		PythonPath:       tags["pyexp_python"],
		PythonVersion:    tags["pyexp_python_version"],
		PipAvailable:     strings.EqualFold(tags["pyexp_pip"], "true"),
		InstallAvailable: agentPyexpInstallAvailable(tags),
		Tags:             tags,
	}
	c.JSON(http.StatusOK, resp)
}

func mcpContextWorkflowLinks(c *gin.Context, tenantID, productName, pocName string, limit int) {
	limit = clampToolLimit(limit, 12, 50)
	productFilter := strings.ToLower(strings.TrimSpace(productName))
	pocFilter := strings.ToLower(strings.TrimSpace(pocName))

	var fingerprints []db.FingerprintRule
	fpQuery := db.DB.Where("tenant_id = ?", tenantID)
	if productFilter != "" {
		fpQuery = fpQuery.Where("LOWER(product_name) LIKE ?", "%"+productFilter+"%")
	}
	fpQuery.Order("updated_at desc").Limit(limit).Find(&fingerprints)

	var pocs []db.PocRule
	pocQuery := db.DB.Where("tenant_id = ?", tenantID)
	if pocFilter != "" {
		pocQuery = pocQuery.Where("LOWER(name) LIKE ? OR LOWER(source_file) LIKE ?", "%"+pocFilter+"%", "%"+pocFilter+"%")
	}
	pocQuery.Order("updated_at desc").Limit(limit).Find(&pocs)

	var workflows []db.WorkflowRule
	wfQuery := db.DB.Where("tenant_id = ?", tenantID)
	if productFilter != "" {
		wfQuery = wfQuery.Where("LOWER(product_name) LIKE ?", "%"+productFilter+"%")
	}
	if pocFilter != "" {
		wfQuery = wfQuery.Where("LOWER(poc_name) LIKE ?", "%"+pocFilter+"%")
	}
	wfQuery.Order("updated_at desc").Limit(limit).Find(&workflows)

	var hits []db.FingerprintHit
	hitQuery := db.DB.Where("tenant_id = ? AND product_name <> ''", tenantID)
	if productFilter != "" {
		hitQuery = hitQuery.Where("LOWER(product_name) LIKE ?", "%"+productFilter+"%")
	}
	hitQuery.Order("created_at desc").Limit(limit).Find(&hits)

	c.JSON(http.StatusOK, gin.H{
		"status":       "success",
		"fingerprints": summarizeMCPFingerprintRules(fingerprints),
		"pocs":         summarizePocRules(pocs),
		"workflows":    summarizeWorkflowRules(workflows),
		"recent_hits":  summarizeMCPFingerprintHits(hits),
	})
}

func mcpContextWorkflowTool(c *gin.Context, execute func(context.Context, json.RawMessage) (interface{}, error), req mcpRuleContextRequest) {
	payload, _ := json.Marshal(map[string]interface{}{"product_name": req.ProductName, "poc_name": req.PocName, "limit": req.Limit})
	result, err := execute(c.Request.Context(), payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func mcpRuleDebugFingerprint(c *gin.Context, req mcpRuleDebugRequest) {
	if notifyHub == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent notify hub is not ready"})
		return
	}
	tenantID := currentTenantID(c)
	req.AgentID = strings.TrimSpace(req.AgentID)
	req.TargetURL = strings.TrimSpace(req.TargetURL)
	req.Proxy = strings.TrimSpace(req.Proxy)
	if req.AgentID == "" || req.TargetURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id and target_url are required"})
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
	if !mcpValidateFingerprintDebugAgent(c, tenantID, req.AgentID) {
		return
	}

	timeoutSec := normalizeMCPSyncTimeout(req.TimeoutSec)
	payload := gin.H{"include_dir": req.IncludeDir, "include_poc": req.IncludePoc}
	customRule := strings.TrimSpace(req.Rule)
	if customRule != "" {
		payload["custom_only"] = true
		if customProduct := strings.TrimSpace(req.ProductName); customProduct != "" {
			payload["custom_product"] = customProduct
		}
		payload["custom_rule"] = customRule
	}
	workflowProduct := strings.TrimSpace(req.WorkflowProduct)
	workflowPocs := cleanStringSlice(req.WorkflowPocs)
	if workflowProduct != "" && len(workflowPocs) > 0 {
		payload["custom_wf_product"] = workflowProduct
		payload["custom_wf_types"] = strings.Join(cleanStringSlice(req.WorkflowTypes), ",")
		payload["custom_wf_pocs"] = strings.Join(workflowPocs, ",")
	}
	if strings.TrimSpace(req.PocContent) != "" {
		if !req.IncludePoc || workflowProduct == "" || len(workflowPocs) != 1 || len(req.WorkflowTypes) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "poc_content requires include_poc, one workflow_pocs entry, workflow_product and workflow_types"})
			return
		}
		if !safeDebugPocIDPattern.MatchString(workflowPocs[0]) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "workflow_pocs must contain a single safe POC id"})
			return
		}
		payload["custom_poc_content"] = req.PocContent
	}
	payloadJSON, _ := json.Marshal(payload)
	resultChan := make(chan map[string]interface{}, 32)
	session, ok := pocDebugSessions.start(tenantID, req.AgentID, time.Duration(timeoutSec)*time.Second, resultChan)
	if !ok {
		c.JSON(http.StatusConflict, gin.H{"error": "tenant already has a running debug session"})
		return
	}
	cmd := &pb.DebugCommand{
		Action:     "start_fingerprint_debug",
		SessionId:  session.SessionID,
		TenantId:   tenantID,
		PocContent: string(payloadJSON),
		TargetUrl:  req.TargetURL,
		Proxy:      req.Proxy,
		TimeoutSec: timeoutSec,
	}
	if err := notifyHub.SendDebugCommand(req.AgentID, cmd); err != nil {
		pocDebugSessions.finish(session.SessionID)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to send fingerprint debug command to agent"})
		return
	}
	go expireDebugSession(session)
	waited, err := waitMCPDebugTranscript(resultChan, time.Duration(timeoutSec+15)*time.Second)
	if err != nil {
		pocDebugSessions.finish(session.SessionID)
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": err.Error()})
		return
	}
	waited.MCPGuidance = mcpDebugGuidance("fingerprint")
	c.JSON(http.StatusOK, waited)
}

func mcpValidateFingerprintDebugAgent(c *gin.Context, tenantID, agentID string) bool {
	var node db.Node
	if err := scopedNodeQuery(tenantID).Where("agent_id = ? AND status = ?", agentID, "Alive").First(&node).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent is not alive in this tenant"})
		return false
	}
	if !isFingerprintDebugCapableAgent(node.Version) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent does not support fingerprint debug; please upgrade agent to v2.3.0+"})
		return false
	}
	if !notifyHub.IsAgentOnline(agentID) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent subscribe stream is offline"})
		return false
	}
	return true
}

func waitMCPDebugTranscript(resultChan <-chan map[string]interface{}, timeout time.Duration) (mcpDebugTranscript, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	out := mcpDebugTranscript{Status: "completed"}
	productSeen := map[string]bool{}
	for {
		select {
		case msg := <-resultChan:
			switch msg["type"] {
			case "debug_log":
				out.Logs = append(out.Logs, msg)
			case "debug_result":
				out.Results = append(out.Results, msg)
				templateID, _ := msg["template_id"].(string)
				if templateID == "Finger" || templateID == "Active-Finger" {
					for _, product := range stringSliceFromInterface(msg["extracted"]) {
						product = strings.TrimPrefix(product, "[custom]")
						if product != "" && !productSeen[product] {
							productSeen[product] = true
							out.MatchedProducts = append(out.MatchedProducts, product)
						}
					}
				}
				if strings.HasPrefix(templateID, "Nuclei:") || strings.HasPrefix(templateID, "GoPoc:") {
					out.PocHits = append(out.PocHits, msg)
				}
			case "debug_complete":
				out.Complete = msg
				return out, nil
			}
		case <-timer.C:
			return mcpDebugTranscript{}, fmt.Errorf("debug execution timeout after %s", timeout)
		}
	}
}

func summarizeMCPFingerprintRules(rules []db.FingerprintRule) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(rules))
	for _, rule := range rules {
		out = append(out, map[string]interface{}{
			"product_name": rule.ProductName,
			"rule_expr":    rule.RuleExpr,
			"source_file":  rule.SourceFile,
			"state":        rule.State,
			"enabled":      rule.Enabled,
		})
	}
	return out
}

func summarizeMCPFingerprintHits(hits []db.FingerprintHit) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(hits))
	for _, hit := range hits {
		out = append(out, map[string]interface{}{
			"target":       hit.Target,
			"product_name": hit.ProductName,
			"created_at":   hit.CreatedAt,
		})
	}
	return out
}

func normalizeMCPRuleType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "finger", "fingerprint":
		return "finger"
	case "poc":
		return "poc"
	case "workflow":
		return "workflow"
	case "exp", "exploit", "pyexp":
		return "exp"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func publicMCPRuleType(typ string) string {
	if typ == "finger" {
		return "fingerprint"
	}
	if typ == "exp" {
		return "pyexp"
	}
	return typ
}

func normalizeMCPIntent(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "test_only", "production_candidate", "approved_reusable":
		return strings.ToLower(strings.TrimSpace(raw))
	case "":
		return "production_candidate"
	default:
		return "production_candidate"
	}
}

func mcpSaveGuidance(ruleType, intent string) gin.H {
	next := []string{"debug against a representative target if not already done", "publish with argus_rule_apply using the returned file_name, hash and version", "verify relationships with argus_context action=workflow_links"}
	guidance := gin.H{
		"next_steps":       next,
		"requires_admin":   false,
		"lifecycle_hint":   intent,
		"warnings":         []string{"save creates or updates a Draft only; it does not publish or sync rules to Agents as active rules"},
		"publish_boundary": "argus_rule_apply action=publish requires admin and exact hash/version",
	}
	if intent == "test_only" {
		guidance["cleanup_hint"] = "cleanup is situational: remove this artifact if it was created only to prove a test flow; keep it if validation made it reusable"
	} else {
		guidance["cleanup_hint"] = "do not auto-delete; cleanup depends on whether the rule should remain reusable"
	}
	return guidance
}

func mcpPublishGuidance(ruleType string) gin.H {
	return gin.H{
		"next_steps":     []string{"verify active rule state", "for fingerprint/workflow changes, call argus_context action=workflow_links", "for test-only work, decide whether cleanup is appropriate"},
		"requires_admin": true,
		"warnings":       []string{"publish changes active rule catalog and may be synced to Agents", "hash/version guards prevent publishing stale Draft content"},
		"cleanup_hint":   "cleanup is situational: delete temporary test rules only when they should not remain reusable",
		"rule_type":      ruleType,
	}
}

func mcpDebugGuidance(ruleType string) gin.H {
	return gin.H{
		"next_steps":     []string{"if the result is correct, call argus_rule_save with the complete rule source", "if saving for temporary validation, set intent=test_only"},
		"requires_admin": false,
		"warnings":       []string{"debug does not save or publish rules"},
		"rule_type":      ruleType,
	}
}

func defaultMCPRuleFileName(typ string) string {
	switch typ {
	case "finger":
		return "finger.yaml"
	case "workflow":
		return "workflow.yaml"
	default:
		return ""
	}
}

func cleanStringSlice(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func firstNonEmptyStringSlice(first, second []string) []string {
	if len(first) > 0 {
		return first
	}
	return second
}

func stringSliceFromInterface(raw interface{}) []string {
	switch values := raw.(type) {
	case []string:
		return values
	case []interface{}:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if s, ok := value.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func resetJSONBody(c *gin.Context, body []byte) {
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	c.Request.ContentLength = int64(len(body))
	c.Request.Header.Set("Content-Type", "application/json")
}
