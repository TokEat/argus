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

	"github.com/P0lar1ght/argus/server/internal/db"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

type mcpRuleContextRequest struct {
	Action       string `json:"action"`
	URI          string `json:"uri"`
	AgentID      string `json:"agent_id"`
	ProductName  string `json:"product_name"`
	PocName      string `json:"poc_name"`
	Limit        int    `json:"limit"`
	Query        string `json:"query"`
	RangeStart   int    `json:"range_start"`
	RangeEnd     int    `json:"range_end"`
	Missing      string `json:"missing"`
	IncludeNames *bool  `json:"include_names"`
}

type mcpRuleDebugRequest struct {
	RuleType        string   `json:"rule_type"`
	AgentID         string   `json:"agent_id"`
	TargetURL       string   `json:"target_url"`
	Proxy           string   `json:"proxy"`
	TimeoutSec      int32    `json:"timeout_sec"`
	ProductName     string   `json:"product_name"`
	Rule            string   `json:"rule"`
	IncludeDir      bool     `json:"include_dir"`
	IncludePoc      bool     `json:"include_poc"`
	WorkflowProduct string   `json:"workflow_product"`
	WorkflowTypes   []string `json:"workflow_types"`
	WorkflowPocs    []string `json:"workflow_pocs"`
	PocContent      string   `json:"poc_content"`
	FileName        string   `json:"file_name"`
	Content         string   `json:"content"`
	Paths           []string `json:"paths"`
	RiskConfirmed   bool     `json:"risk_confirmed"`
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
	Paths         []string `json:"paths"`
	RiskLevel     string   `json:"risk_level"`
	Intent        string   `json:"intent"`
}

type mcpRuleApplyRequest struct {
	Action     string `json:"action"`
	RuleType   string `json:"rule_type"`
	FileName   string `json:"file_name"`
	Hash       string `json:"hash"`
	Version    int    `json:"version"`
	ArtifactID string `json:"artifact_id"`
}

type mcpDebugTranscript struct {
	Status          string                   `json:"status"`
	Matched         bool                     `json:"matched"`
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
	case "help":
		mcpContextHelp(c)
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
	case "coverage":
		mcpContextCoverage(c, tenantID, req)
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
	case "dir":
		req.IncludeDir = true
		mcpRuleDebugFingerprint(c, req)
	case "workflow":
		req.IncludePoc = true
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
	case "active_fingerprint":
		mcpRuleDebugActiveFingerprint(c, req)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule_type must be fingerprint, behavior_probe, poc, workflow or dir"})
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
	case "dir":
		resp, err = saveMCPDirDraft(tenantID, req)
	case "poc":
		resp, err = saveMCPPOCDraft(tenantID, req)
	case "active_fingerprint":
		resp, err = saveMCPActiveFingerprintDraft(tenantID, req, c.GetString("user_id"))
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule_type must be fingerprint, behavior_probe, poc, workflow or dir"})
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
	if strings.TrimSpace(req.Hash) == "" || req.Version <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "hash and version are required for lifecycle actions"})
		return
	}
	switch req.Action {
	case "publish":
		mcpRulePublish(c, tenantID, req)
	case "deprecate":
		mcpRuleDeprecate(c, tenantID, req)
	case "rollback":
		mcpRuleRollback(c, tenantID, req)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be publish, deprecate or rollback"})
	}
}

func saveMCPFingerprintDraft(tenantID string, req mcpRuleSaveRequest) (gin.H, error) {
	fileName := strings.TrimSpace(req.FileName)
	if fileName == "" {
		fileName = "finger.yaml"
	}
	if err := validateDraftFileName(fileName, true); err != nil {
		return nil, err
	}
	arsenal, content, err := loadMCPDictArsenal(tenantID, "finger", fileName)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Content) != "" {
		data := map[string][]string{}
		if err := yaml.Unmarshal([]byte(req.Content), &data); err != nil {
			return nil, fmt.Errorf("content is not valid fingerprint YAML: %w", err)
		}
		content = req.Content
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
		content, err = upsertYAMLMappingKey(content, product, rules)
		if err != nil {
			return nil, err
		}
	}
	if err := validateMCPStringListDict(content, "fingerprint draft is empty"); err != nil {
		return nil, err
	}
	return saveMCPYAMLDraft(arsenal, content, "fingerprint")
}

func saveMCPWorkflowDraft(tenantID string, req mcpRuleSaveRequest) (gin.H, error) {
	fileName := strings.TrimSpace(req.FileName)
	if fileName == "" {
		fileName = "workflow.yaml"
	}
	if err := validateDraftFileName(fileName, true); err != nil {
		return nil, err
	}
	arsenal, content, err := loadMCPDictArsenal(tenantID, "workflow", fileName)
	if err != nil {
		return nil, err
	}
	data := map[string]WorkflowEntry{}
	if strings.TrimSpace(content) != "" {
		if err := yaml.Unmarshal([]byte(content), &data); err != nil {
			return nil, fmt.Errorf("failed to parse existing workflow yaml: %w", err)
		}
	}
	if strings.TrimSpace(req.Content) != "" {
		if err := yaml.Unmarshal([]byte(req.Content), &data); err != nil {
			return nil, fmt.Errorf("content is not valid workflow YAML: %w", err)
		}
		content = req.Content
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
		riskLevel, err := mcpWorkflowRiskLevel(req.RiskLevel, data[product].RiskLevel)
		if err != nil {
			return nil, err
		}
		content, err = upsertYAMLMappingKey(content, product, WorkflowEntry{Type: types, Pocs: pocs, RiskLevel: riskLevel})
		if err != nil {
			return nil, err
		}
	}
	if err := validateMCPWorkflowDict(content); err != nil {
		return nil, err
	}
	return saveMCPYAMLDraft(arsenal, content, "workflow")
}

func saveMCPDirDraft(tenantID string, req mcpRuleSaveRequest) (gin.H, error) {
	fileName := strings.TrimSpace(req.FileName)
	if fileName == "" {
		fileName = "dir.yaml"
	}
	if err := validateDraftFileName(fileName, true); err != nil {
		return nil, err
	}
	arsenal, content, err := loadMCPDictArsenal(tenantID, "dir", fileName)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Content) != "" {
		data := map[string][]string{}
		if err := yaml.Unmarshal([]byte(req.Content), &data); err != nil {
			return nil, fmt.Errorf("content is not valid dir YAML: %w", err)
		}
		content = req.Content
	}
	product := strings.TrimSpace(req.ProductName)
	paths := cleanStringSlice(req.Paths)
	if product != "" || len(paths) > 0 {
		if product == "" || len(paths) == 0 {
			return nil, fmt.Errorf("product_name and paths are required together")
		}
		for _, path := range paths {
			if err := validateDirPath(path); err != nil {
				return nil, err
			}
		}
		content, err = upsertYAMLMappingKey(content, product, paths)
		if err != nil {
			return nil, err
		}
	}
	if err := validateMCPStringListDict(content, "dir draft is empty"); err != nil {
		return nil, err
	}
	return saveMCPYAMLDraft(arsenal, content, "dir")
}

func loadMCPDictArsenal(tenantID, typ, fileName string) (*db.Arsenal, string, error) {
	arsenal, err := db.FindTenantArsenalByTypeAndFile(tenantID, typ, fileName)
	if err != nil {
		return &db.Arsenal{ID: db.BuildTenantArsenalID(tenantID, typ, fileName), TenantID: tenantID, Type: typ, FileName: fileName}, "", nil
	}
	return arsenal, arsenal.Content, nil
}

func validateMCPStringListDict(content, emptyErr string) error {
	data := map[string][]string{}
	if err := yaml.Unmarshal([]byte(content), &data); err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("%s", emptyErr)
	}
	return nil
}

func validateMCPWorkflowDict(content string) error {
	data := map[string]WorkflowEntry{}
	if err := yaml.Unmarshal([]byte(content), &data); err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("workflow draft is empty")
	}
	return nil
}

func mcpWorkflowRiskLevel(requested, existing string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		if strings.TrimSpace(existing) == "" {
			return db.PocRiskLevelUnknown, nil
		}
		return db.NormalizePocRiskLevel(existing)
	}
	return db.NormalizePocRiskLevel(requested)
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

func saveMCPYAMLDraft(arsenal *db.Arsenal, content, ruleType string) (gin.H, error) {
	out := []byte(content)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
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
	case "finger", "poc", "workflow", "dir", "active_fingerprint":
		typ := normalizeMCPRuleType(req.RuleType)
		fileName := strings.TrimSpace(req.FileName)
		if fileName == "" {
			fileName = defaultMCPRuleFileName(typ)
		}
		mcpPublishArsenal(c, tenantID, typ, fileName, req.ArtifactID, req.Hash, req.Version)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule_type must be fingerprint, behavior_probe, poc, workflow or dir"})
	}
}

func mcpPublishArsenal(c *gin.Context, tenantID, typ, fileName, expectedArtifactID, expectedHash string, expectedVersion int) {
	if err := validateDraftFileName(fileName, true); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	arsenal, err := db.FindTenantArsenalByTypeAndFile(tenantID, typ, fileName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Arsenal not found"})
		return
	}
	if !mcpArtifactGuardMatches(c, *arsenal, expectedArtifactID) {
		return
	}
	if !mcpDraftGuardMatches(c, *arsenal, expectedHash, expectedVersion) {
		return
	}
	if typ == "poc" {
		candidate := *arsenal
		candidate.State = "Approved"
		if err := db.ValidateRuleCatalogCandidate(candidate); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	arsenal.State = "Approved"
	persistApproval := func(tx *gorm.DB) error {
		if err := tx.Model(&db.Arsenal{}).Where("tenant_id = ? AND type IN ? AND file_name = ?", tenantID, db.ArsenalTypeAliases(typ), fileName).Update("state", "Approved").Error; err != nil {
			return err
		}
		return createArsenalEvent(tx, *arsenal, "published", c.GetString("user_id"), "", nil)
	}
	var approvalErr error
	if typ == "active_fingerprint" {
		approvalErr = db.ApplyRuleCatalogCandidate(*arsenal, persistApproval)
	} else {
		approvalErr = db.DB.Transaction(persistApproval)
	}
	if approvalErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": approvalErr.Error()})
		return
	}
	if typ != "active_fingerprint" {
		if err := db.SyncRuleCatalogFromArsenal(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	ruleVersion := BumpRuleVersion()
	c.JSON(http.StatusOK, gin.H{"status": "approved", "rule_type": publicMCPRuleType(typ), "file_name": fileName, "hash": expectedHash, "version": expectedVersion, "rule_version": ruleVersion, "mcp_guidance": mcpPublishGuidance(publicMCPRuleType(typ))})
}

func mcpRuleDeprecate(c *gin.Context, tenantID string, req mcpRuleApplyRequest) {
	typ := normalizeMCPRuleType(req.RuleType)
	if typ != "finger" && typ != "poc" && typ != "workflow" && typ != "dir" && typ != "active_fingerprint" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported rule_type"})
		return
	}
	fileName := strings.TrimSpace(req.FileName)
	if fileName == "" {
		fileName = defaultMCPRuleFileName(typ)
	}
	arsenal, err := db.FindTenantArsenalByTypeAndFile(tenantID, typ, fileName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Arsenal not found"})
		return
	}
	if !mcpDraftGuardMatches(c, *arsenal, req.Hash, req.Version) {
		return
	}
	if !mcpArtifactGuardMatches(c, *arsenal, req.ArtifactID) {
		return
	}
	arsenal.State = "Deprecated"
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(arsenal).Update("state", "Deprecated").Error; err != nil {
			return err
		}
		return createArsenalEvent(tx, *arsenal, "deprecated", c.GetString("user_id"), "", nil)
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "deprecated", "rule_type": publicMCPRuleType(typ), "file_name": arsenal.FileName, "hash": arsenal.Hash, "version": arsenal.Version, "rule_version": BumpRuleVersion()})
}

func mcpRuleRollback(c *gin.Context, tenantID string, req mcpRuleApplyRequest) {
	typ := normalizeMCPRuleType(req.RuleType)
	arsenal, err := db.FindTenantArsenalByTypeAndFile(tenantID, typ, strings.TrimSpace(req.FileName))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Arsenal not found"})
		return
	}
	if !mcpDraftGuardMatches(c, *arsenal, req.Hash, req.Version) {
		return
	}
	if !mcpArtifactGuardMatches(c, *arsenal, req.ArtifactID) {
		return
	}
	if arsenal.PreviousHash == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No previous version available for rollback"})
		return
	}
	arsenal.Content, arsenal.PreviousContent = arsenal.PreviousContent, arsenal.Content
	arsenal.Hash, arsenal.PreviousHash = arsenal.PreviousHash, arsenal.Hash
	arsenal.Version++
	arsenal.State = "Draft"
	if typ == "poc" || typ == "active_fingerprint" {
		if err := db.ValidateRuleCatalogCandidate(*arsenal); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(arsenal).Error; err != nil {
			return err
		}
		return createArsenalEvent(tx, *arsenal, "rolled_back", c.GetString("user_id"), arsenal.Content, nil)
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "rolled_back", "rule_type": publicMCPRuleType(typ), "file_name": arsenal.FileName, "hash": arsenal.Hash, "version": arsenal.Version, "rule_version": BumpRuleVersion()})
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

func mcpArtifactGuardMatches(c *gin.Context, arsenal db.Arsenal, expectedArtifactID string) bool {
	if expectedArtifactID != "" && expectedArtifactID != arsenal.ID {
		c.JSON(http.StatusConflict, gin.H{"error": "artifact_id mismatch"})
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
		"recommended_reading_order": []string{"argus://argus-mcp/quickstart", "argus://argus-mcp/tool-guide", "argus://fingerprint/spec", "argus://dir/spec", "argus://behavior-probe/spec", "argus://poc/spec", "argus://workflow/spec", "argus://examples/fingerprint-poc-workflow"},
	})
}

func mcpContextHelp(c *gin.Context) {
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
		"status":   "success",
		"audience": "source-less MCP client",
		"start_here": []string{
			"Call argus_help first. Do not guess YAML or REST paths.",
			"Fetch specs/templates with argus_resource and uri from resources[].",
			"Debug only on a user-authorized target with an Alive Agent from argus_agents.",
			"Save creates a Draft. Publish only as admin with exact stable_ref hash/version.",
			"Verify with argus_rule_get. Dict types return product names as a string array and omit YAML. Pass product_name for one mapping.",
			"Catalog coverage (fingerprint vs workflow POC) is argus_coverage; query is a product-name substring (hyphens are literal, not a range). Names are a compact string array.",
		},
		"workflow": []string{
			"argus_help -> argus_resource(spec) -> argus_resource(template) -> argus_agents -> argus_debug_* -> argus_save_* Draft -> (admin) argus_rule_apply publish -> argus_rule_get",
		},
		"rule_kinds": []gin.H{
			{"rule_type": "fingerprint", "spec": "argus://fingerprint/spec", "template": "argus://fingerprint/template", "save": "product_name + rules, or content YAML mapping", "debug": "agent_id, target_url, product_name, rule"},
			{"rule_type": "dir", "spec": "argus://dir/spec", "template": "argus://dir/template", "save": "product_name + paths, or content YAML mapping; unique file_name for isolated drafts", "debug": "agent_id, target_url, product_name, paths"},
			{"rule_type": "behavior_probe", "spec": "argus://behavior-probe/spec", "template": "argus://behavior-probe/template", "save": "file_name + complete Nuclei YAML (info.author required)", "debug": "agent_id, target_url, file_name, content; operator confirmation if controlled (elicitation when available, otherwise risk_confirmed=true)"},
			{"rule_type": "poc", "spec": "argus://poc/spec", "template": "argus://poc/template", "save": "file_name ending .yaml + complete Nuclei YAML (info.author required)", "debug": "agent_id, target_url, poc_content"},
			{"rule_type": "workflow", "spec": "argus://workflow/spec", "template": "argus://workflow/template", "save": "product_name + workflow_types + workflow_pocs + optional risk_level, or content YAML", "debug": "agent_id, target_url, workflow_product, workflow_types, workflow_pocs, optional poc_content"},
		},
		"verify":                    "argus_rule_get with rule_type and file_name or artifact_id; products is a name array; product_name extracts one mapping; include_content only for small files. Coverage is argus_coverage.",
		"resources":                 resources,
		"recommended_reading_order": []string{"argus://argus-mcp/quickstart", "argus://argus-mcp/tool-guide", "argus://fingerprint/spec", "argus://dir/spec", "argus://behavior-probe/spec", "argus://poc/spec", "argus://workflow/spec", "argus://examples/fingerprint-poc-workflow"},
		"minimum_tools":             []string{"argus_help", "argus_resource", "argus_agents", "argus_debug_fingerprint", "argus_save_fingerprint", "argus_rule_apply"},
		"constraints":               []string{"tenant/RBAC/approval stay on the Server", "do not debug unapproved targets", "do not publish test_only drafts unless the user asked", "Nuclei YAML requires info.author"},
	})
}

func mcpContextQuickstart(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "success",
		"workflow": []string{
			"If the host has no Argus source, call argus_help first.",
			"Read specs/templates with argus_resource (or resources/read).",
			"Use argus_agents to select an Alive Agent.",
			"Use argus_debug_* before saving rules whenever a target is available.",
			"Use argus_save_* to create Draft artifacts and capture hash/version.",
			"Use argus_rule_apply action=publish as admin with hash/version guard.",
			"Use argus_rule_get to verify the saved artifact; dict types return product names only. Pass product_name for one mapping. Use argus_coverage for fingerprint vs workflow POC counts.",
			"Treat General-Poc-* workflow names as reserved general POC groups, not real fingerprint products or aliases.",
		},
		"minimum_tools": []string{"argus_help", "argus_resource", "argus_agents", "argus_debug_fingerprint", "argus_save_fingerprint", "argus_rule_apply"},
		"next_steps":    []string{"argus_help", "argus_resource", "argus_debug_*", "argus_save_*", "argus_rule_apply", "argus_rule_get"},
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
		tags := map[string]string{}
		_ = json.Unmarshal([]byte(node.Tags), &tags)
		out = append(out, gin.H{
			"agent_id":       node.AgentID,
			"status":         node.Status,
			"version":        node.Version,
			"os":             node.OS,
			"arch":           node.Arch,
			"running_tasks":  node.RunningTasks,
			"capacity":       node.Capacity,
			"rule_version":   node.RuleVersion,
			"native_egress":  tags["native_egress"],
			"behavior_probe": tags["behavior_probe"],
		})
	}
	c.JSON(http.StatusOK, gin.H{"status": "success", "agents": out})
}

func mcpContextCoverage(c *gin.Context, tenantID string, req mcpRuleContextRequest) {
	missing := strings.ToLower(strings.TrimSpace(req.Missing))
	if missing == "" {
		missing = "fingerprint_without_poc"
	}
	if missing != "fingerprint_without_poc" && missing != "workflow_without_fingerprint" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing must be fingerprint_without_poc or workflow_without_fingerprint"})
		return
	}

	fpCount, err := mcpCountDistinctEnabledProducts(&db.FingerprintRule{}, tenantID, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	wfCount, err := mcpCountDistinctEnabledProducts(&db.WorkflowRule{}, tenantID, func(q *gorm.DB) *gorm.DB {
		return q.Where("LOWER(product_name) NOT LIKE ?", "general-poc-%")
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	generalCount, err := mcpCountDistinctEnabledProducts(&db.WorkflowRule{}, tenantID, func(q *gorm.DB) *gorm.DB {
		return q.Where("LOWER(product_name) LIKE ?", "general-poc-%")
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var pocCount int64
	if err := db.DB.Model(&db.PocRule{}).Where("tenant_id = ? AND enabled = ?", tenantID, true).Count(&pocCount).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	fpWithout, err := mcpListFingerprintWithoutPOC(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	wfWithout, err := mcpListWorkflowWithoutFingerprint(tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	names := fpWithout
	if missing == "workflow_without_fingerprint" {
		names = wfWithout
	}
	query := strings.ToLower(strings.TrimSpace(req.Query))
	if query != "" {
		filtered := make([]string, 0, len(names))
		for _, name := range names {
			if strings.Contains(strings.ToLower(name), query) {
				filtered = append(filtered, name)
			}
		}
		names = filtered
	}
	total := len(names)
	start, end := req.RangeStart, req.RangeEnd
	paged := start > 0 || end > 0
	if req.RangeStart > 0 && req.RangeEnd > 0 && req.RangeEnd < req.RangeStart {
		c.JSON(http.StatusBadRequest, gin.H{"error": "range_end must be greater than or equal to range_start"})
		return
	}
	if start <= 0 {
		start = 1
	}
	if end <= 0 || end > total {
		end = total
	}
	window := names
	if total == 0 {
		window = []string{}
		start, end = 0, 0
	} else if paged {
		if start > total {
			window = []string{}
		} else {
			if end < start {
				end = total
			}
			window = names[start-1 : end]
		}
	}

	includeNames := true
	if req.IncludeNames != nil {
		includeNames = *req.IncludeNames
	}

	out := gin.H{
		"status":                       "success",
		"action":                       "coverage",
		"binding":                      "A fingerprint product has a POC when enabled workflow_rules contain that product_name. General-Poc-* groups are excluded. Counts come from the tenant catalog, not by echoing arsenal YAML.",
		"fingerprint_products":         fpCount,
		"workflow_products_with_poc":   wfCount,
		"fingerprint_without_poc":      len(fpWithout),
		"workflow_without_fingerprint": len(wfWithout),
		"general_poc_groups":           generalCount,
		"poc_files":                    pocCount,
		"missing":                      missing,
		"total":                        total,
		"returned":                     0,
	}
	if query != "" {
		out["query"] = query
	}
	if includeNames {
		out["products"] = window
		out["returned"] = len(window)
		if paged {
			out["range_start"] = start
			out["range_end"] = end
			out["has_more"] = end < total
		}
	}
	c.JSON(http.StatusOK, out)
}

func mcpCountDistinctEnabledProducts(model interface{}, tenantID string, extra func(*gorm.DB) *gorm.DB) (int64, error) {
	query := db.DB.Model(model).Where("tenant_id = ? AND enabled = ?", tenantID, true)
	if extra != nil {
		query = extra(query)
	}
	var n int64
	if err := query.Distinct("product_name").Count(&n).Error; err != nil {
		return 0, err
	}
	return n, nil
}

func mcpListFingerprintWithoutPOC(tenantID string) ([]string, error) {
	sql := `
SELECT f.product_name
FROM (
  SELECT DISTINCT product_name FROM fingerprint_rules WHERE tenant_id = ? AND enabled = ?
) f
LEFT JOIN (
  SELECT DISTINCT product_name FROM workflow_rules WHERE tenant_id = ? AND enabled = ? AND LOWER(product_name) NOT LIKE ?
) w ON w.product_name = f.product_name
WHERE w.product_name IS NULL
ORDER BY f.product_name`
	var names []string
	if err := db.DB.Raw(sql, tenantID, true, tenantID, true, "general-poc-%").Scan(&names).Error; err != nil {
		return nil, err
	}
	if names == nil {
		names = []string{}
	}
	return names, nil
}

func mcpListWorkflowWithoutFingerprint(tenantID string) ([]string, error) {
	sql := `
SELECT w.product_name
FROM (
  SELECT DISTINCT product_name FROM workflow_rules WHERE tenant_id = ? AND enabled = ? AND LOWER(product_name) NOT LIKE ?
) w
LEFT JOIN (
  SELECT DISTINCT product_name FROM fingerprint_rules WHERE tenant_id = ? AND enabled = ?
) f ON f.product_name = w.product_name
WHERE f.product_name IS NULL
ORDER BY w.product_name`
	var names []string
	if err := db.DB.Raw(sql, tenantID, true, "general-poc-%", tenantID, true).Scan(&names).Error; err != nil {
		return nil, err
	}
	if names == nil {
		names = []string{}
	}
	return names, nil
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
	if routerRuntime().NotifyHub == nil {
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
	dirPaths := cleanStringSlice(req.Paths)
	if len(dirPaths) > 0 {
		payload["include_dir"] = true
		payload["custom_dir_paths"] = dirPaths
		if product := strings.TrimSpace(req.ProductName); product != "" {
			payload["custom_dir_product"] = product
		}
	}
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
		c.JSON(http.StatusConflict, gin.H{"error": "agent already has a running debug session"})
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
	if err := routerRuntime().NotifyHub.SendDebugCommand(req.AgentID, cmd); err != nil {
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
	guidanceType := "fingerprint"
	if len(dirPaths) > 0 {
		guidanceType = "dir"
	}
	waited.MCPGuidance = mcpDebugGuidance(guidanceType)
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
	if !routerRuntime().NotifyHub.IsAgentOnline(agentID) {
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
				if boolFromMCPMap(msg, "matched") {
					out.Matched = true
				}
				templateID, _ := msg["template_id"].(string)
				if templateID == "Finger" || templateID == "Active-Finger" || templateID == "Dir-Probe" {
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
				if out.Matched {
					msg["matched"] = true
				} else {
					out.Matched = boolFromMCPMap(msg, "matched")
				}
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
	case "behavior_probe", "active_fingerprint", "active-fingerprint":
		return "active_fingerprint"
	case "dir":
		return "dir"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func publicMCPRuleType(typ string) string {
	if typ == "finger" {
		return "fingerprint"
	}
	if typ == "active_fingerprint" {
		return "behavior_probe"
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
	next := []string{"debug against a representative target if not already done", "publish with argus_rule_apply using the returned file_name, hash and version", "verify with argus_rule_get using file_name and optional product_name"}
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
		"next_steps":     []string{"verify active rule state", "for fingerprint/workflow/dir changes, call argus_rule_get with product_name", "for test-only work, decide whether cleanup is appropriate"},
		"requires_admin": true,
		"warnings":       []string{"publish changes active rule catalog and may be synced to Agents", "hash/version guards prevent publishing stale Draft content"},
		"cleanup_hint":   "cleanup is situational: delete temporary test rules only when they should not remain reusable",
		"rule_type":      ruleType,
	}
}

func mcpDebugGuidance(ruleType string) gin.H {
	return gin.H{
		"next_steps":     []string{"if the result is correct, call the matching argus_save_* tool with the complete rule source", "if saving for temporary validation, set intent=test_only"},
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
	case "dir":
		return "dir.yaml"
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
