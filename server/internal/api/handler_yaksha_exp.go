package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	egresspkg "github.com/P0lar1ght/argus/server/internal/egress"
	"github.com/P0lar1ght/argus/server/internal/expworkspace"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type expMetadataRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	RiskLevel   string `json:"risk_level"`
	ProductName string `json:"product_name"`
	ParentExpID string `json:"parent_exp_id"`
	VariantKey  string `json:"variant_key"`
}

func expWorkspace(c *gin.Context) (*expworkspace.Service, bool) {
	service := routerRuntime().EXPWorkspace
	if service == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "EXP Workspace Unavailable"})
		return nil, false
	}
	return service, true
}

func createYakshaExp(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	var req expMetadataRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid EXP metadata"})
		return
	}
	item, err := service.CreateStructuredExp(c.Request.Context(), currentTenantID(c), currentUserID(c), req.Name, req.Description, req.RiskLevel, expworkspace.ExpStructureInput{ProductName: req.ProductName, ParentExpID: req.ParentExpID, VariantKey: req.VariantKey})
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusCreated, item)
}

func listYakshaExps(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	page, pageSize := pagination(c)
	items, total, err := service.ListExpsFiltered(c.Request.Context(), currentTenantID(c), c.Query("product_name"), c.Query("search"), (page-1)*pageSize, pageSize)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": total, "page": page, "page_size": pageSize})
}

func getYakshaExp(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	item, err := service.GetExp(c.Request.Context(), currentTenantID(c), c.Param("id"))
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, item)
}

func updateYakshaExp(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	var req expMetadataRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid EXP metadata"})
		return
	}
	if strings.TrimSpace(req.RiskLevel) != "" {
		current, err := service.GetExp(c.Request.Context(), currentTenantID(c), c.Param("id"))
		if err != nil {
			writeEXPWorkspaceError(c, err)
			return
		}
		if riskRank(req.RiskLevel) < riskRank(current.RiskLevel) && !currentUserIsAdmin(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "only Admin can lower EXP risk_level"})
			return
		}
	}
	item, err := service.UpdateExp(c.Request.Context(), currentTenantID(c), currentUserID(c), c.Param("id"), req.Name, req.Description, req.RiskLevel, currentUserIsAdmin(c))
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, item)
}

func riskRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func deprecateYakshaExp(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	if err := service.DeprecateExp(c.Request.Context(), currentTenantID(c), currentUserID(c), c.Param("id")); err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func listYakshaExpAudits(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	page, pageSize := pagination(c)
	items, total, err := service.ListAudits(c.Request.Context(), currentTenantID(c), c.Param("id"), (page-1)*pageSize, pageSize)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		result = append(result, expAuditResponse(item))
	}
	c.JSON(http.StatusOK, gin.H{"items": result, "total": total, "page": page, "page_size": pageSize})
}

func getYakshaExpRiskWaiver(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	item, err := service.GetRiskWaiver(c.Request.Context(), currentTenantID(c), c.Param("id"))
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, riskWaiverResponse(item))
}

func upsertYakshaExpRiskWaiver(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	var req struct {
		Reason    string `json:"reason"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid risk waiver"})
		return
	}
	var expiresAt *time.Time
	if strings.TrimSpace(req.ExpiresAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(req.ExpiresAt))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "expires_at must be RFC3339"})
			return
		}
		parsed = parsed.UTC()
		expiresAt = &parsed
	}
	item, err := service.UpsertRiskWaiver(c.Request.Context(), currentTenantID(c), currentUserID(c), c.Param("id"), expworkspace.RiskWaiverInput{Reason: req.Reason, ExpiresAt: expiresAt})
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, riskWaiverResponse(item))
}

func deleteYakshaExpRiskWaiver(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	if err := service.DeleteRiskWaiver(c.Request.Context(), currentTenantID(c), currentUserID(c), c.Param("id")); err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func createYakshaExpRevision(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	var req expworkspace.CreateTestedRevisionInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid revision package"})
		return
	}
	item, err := service.CreateTestedRevision(c.Request.Context(), currentTenantID(c), currentUserID(c), c.Param("id"), req)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusCreated, expRevisionResponse(item))
}

func inspectYakshaExpDraft(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	var req expworkspace.DraftPackageInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid in-memory EXP draft"})
		return
	}
	result, err := service.InspectDraft(c.Request.Context(), currentTenantID(c), c.Param("id"), req.Source)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func validateYakshaExpDraft(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	var req expworkspace.DraftPackageInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid in-memory EXP draft"})
		return
	}
	result, err := service.ValidateDraft(c.Request.Context(), currentTenantID(c), c.Param("id"), req)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func testYakshaExpDraft(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	var req expworkspace.DraftPackageInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid in-memory EXP draft"})
		return
	}
	result, err := service.TestDraft(c.Request.Context(), currentTenantID(c), currentUserID(c), c.Param("id"), req)
	if err != nil {
		if result.RuntimeResponse != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error(), "runtime_response": result.RuntimeResponse})
			return
		}
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func listYakshaExpRevisions(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	items, err := service.ListRevisions(c.Request.Context(), currentTenantID(c), c.Param("id"))
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		result = append(result, expRevisionResponse(item))
	}
	c.JSON(http.StatusOK, gin.H{"items": result})
}

func getYakshaExpRevision(c *gin.Context) {
	service, revision, ok := workspaceRevision(c)
	if !ok {
		return
	}
	item, err := service.GetRevision(c.Request.Context(), currentTenantID(c), c.Param("id"), revision)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, expRevisionResponse(item))
}

func getYakshaExpSealedPackage(c *gin.Context) {
	service, revision, ok := workspaceRevision(c)
	if !ok {
		return
	}
	sealed, err := service.BuildSealedPackage(c.Request.Context(), currentTenantID(c), c.Param("id"), revision, c.Query("include_tests") == "true")
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, sealed)
}

func inspectYakshaExpRevision(c *gin.Context) {
	service, revision, ok := workspaceRevision(c)
	if !ok {
		return
	}
	result, err := service.Inspect(c.Request.Context(), currentTenantID(c), currentUserID(c), c.Param("id"), revision)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func validateYakshaExpRevision(c *gin.Context) {
	service, revision, ok := workspaceRevision(c)
	if !ok {
		return
	}
	result, err := service.Validate(c.Request.Context(), currentTenantID(c), currentUserID(c), c.Param("id"), revision)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func publishYakshaExpRevision(c *gin.Context) {
	service, revision, ok := workspaceRevision(c)
	if !ok {
		return
	}
	var req struct {
		SourceSHA256 string `json:"source_sha256"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.SourceSHA256) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "source_sha256 confirmation is required"})
		return
	}
	if err := service.Publish(c.Request.Context(), currentTenantID(c), currentUserID(c), c.Param("id"), revision, req.SourceSHA256); err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "published", "revision": revision})
}

func setYakshaExpActiveRevision(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	var req struct {
		Revision int `json:"revision"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Revision < 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "positive revision is required"})
		return
	}
	if err := service.SetActiveRevision(c.Request.Context(), currentTenantID(c), currentUserID(c), c.Param("id"), req.Revision); err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"active_revision": req.Revision})
}

func createYakshaExpTestCase(c *gin.Context) {
	service, revision, ok := workspaceRevision(c)
	if !ok {
		return
	}
	var req expworkspace.TestCaseInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Fixture test case"})
		return
	}
	item, err := service.CreateTestCase(c.Request.Context(), currentTenantID(c), currentUserID(c), c.Param("id"), revision, req)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusCreated, testCaseResponse(item))
}

func listYakshaExpTestCases(c *gin.Context) {
	service, revision, ok := workspaceRevision(c)
	if !ok {
		return
	}
	items, err := service.ListTestCases(c.Request.Context(), currentTenantID(c), c.Param("id"), revision)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		result = append(result, testCaseResponse(item))
	}
	c.JSON(http.StatusOK, gin.H{"items": result})
}

func updateYakshaExpTestCase(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	var req expworkspace.TestCaseInput
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Fixture test case"})
		return
	}
	item, err := service.UpdateTestCase(c.Request.Context(), currentTenantID(c), c.Param("id"), c.Param("case_id"), req)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, testCaseResponse(item))
}

func deleteYakshaExpTestCase(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	if err := service.DeleteTestCase(c.Request.Context(), currentTenantID(c), c.Param("id"), c.Param("case_id")); err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func createYakshaExpAsset(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	var req struct {
		AssetID   string `json:"asset_id"`
		MediaType string `json:"media_type"`
		Encoding  string `json:"encoding"`
		Content   string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Asset"})
		return
	}
	content := []byte(req.Content)
	if req.Encoding == "base64" {
		decoded, err := base64.StdEncoding.DecodeString(req.Content)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid base64 Asset content"})
			return
		}
		content = decoded
	} else if req.Encoding != "" && req.Encoding != "utf8" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "encoding must be utf8 or base64"})
		return
	}
	item, err := service.PutAsset(c.Request.Context(), currentTenantID(c), currentUserID(c), req.AssetID, req.MediaType, content)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusCreated, item)
}

func listYakshaExpAssets(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	items, err := service.ListAssets(c.Request.Context(), currentTenantID(c))
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func getYakshaExpAssetContent(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	version, err := strconv.Atoi(c.Param("version"))
	if err != nil || version < 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "positive Asset version is required"})
		return
	}
	metadata, content, err := service.GetAssetContent(c.Request.Context(), currentTenantID(c), c.Param("asset_id"), version)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"asset_id": metadata.AssetID, "version": metadata.Version, "sha256": metadata.SHA256, "size": metadata.Size, "media_type": metadata.MediaType, "encoding": content.Encoding, "content": content.Content})
}

func deleteYakshaExpAsset(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	version, err := strconv.Atoi(c.Param("version"))
	if err != nil || version < 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "positive Asset version is required"})
		return
	}
	if err := service.DeleteAsset(c.Request.Context(), currentTenantID(c), c.Param("asset_id"), version); err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func runYakshaExpRevision(c *gin.Context) {
	service, revision, ok := workspaceRevision(c)
	if !ok {
		return
	}
	var input expworkspace.RunInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid EXP run request"})
		return
	}
	revisionRow, err := service.GetRevision(c.Request.Context(), currentTenantID(c), c.Param("id"), revision)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	if strings.TrimSpace(input.SourceSHA256) == "" || input.SourceSHA256 != revisionRow.SourceSHA256 {
		c.JSON(http.StatusConflict, gin.H{"error": "source_sha256 confirmation does not match the Server Revision"})
		return
	}
	input.RiskConfirmed = input.RiskConfirmed || input.Egress.RiskConfirmed
	if _, err := service.CheckExecutionAllowed(c.Request.Context(), currentTenantID(c), c.Param("id"), revision, input.Action, input.RiskConfirmed); err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	internalEgress, cleanup, err := prepareServerEXPEgress(c, input)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	if cleanup != nil {
		defer cleanup()
	}
	result, err := service.Execute(c.Request.Context(), currentTenantID(c), currentUserID(c), c.Param("id"), revision, input, internalEgress)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

func listYakshaExpRuns(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	page, pageSize := pagination(c)
	items, total, err := service.ListRuns(c.Request.Context(), currentTenantID(c), strings.TrimSpace(c.Query("exp_id")), (page-1)*pageSize, pageSize)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	result := make([]gin.H, 0, len(items))
	for _, item := range items {
		result = append(result, expRunResponse(item))
	}
	c.JSON(http.StatusOK, gin.H{"items": result, "total": total, "page": page, "page_size": pageSize})
}

func getYakshaExpRun(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	run, artifact, err := service.GetRun(c.Request.Context(), currentTenantID(c), c.Param("run_id"), true)
	if err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"run": expRunResponse(run), "artifact": artifact})
}

func cancelYakshaExpRun(c *gin.Context) {
	service, ok := expWorkspace(c)
	if !ok {
		return
	}
	if err := service.CancelRun(c.Request.Context(), currentTenantID(c), c.Param("run_id")); err != nil {
		writeEXPWorkspaceError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"status": "canceling"})
}

func prepareServerEXPEgress(c *gin.Context, input expworkspace.RunInput) (map[string]any, func(), error) {
	if input.TimeoutMS < 0 || input.TimeoutMS > 120000 {
		return nil, nil, errors.New("timeout_ms must be between 0 and 120000")
	}
	mode := strings.ToLower(strings.TrimSpace(input.Egress.Mode))
	if mode == "" {
		mode = "disabled"
	}
	if strings.EqualFold(input.Action, "test") {
		if mode != "disabled" || len(input.NetworkTargets) > 0 {
			return nil, nil, errors.New("test is permanently offline")
		}
		return map[string]any{"mode": "disabled"}, nil, nil
	}
	switch mode {
	case "disabled":
		return map[string]any{"mode": mode}, nil, nil
	case "direct":
		return map[string]any{"mode": mode}, nil, nil
	case "socks5":
		if !validEXPProxyURL(input.Egress.SOCKS5Proxy) {
			return nil, nil, errors.New("socks5_proxy must be a valid write-only SOCKS5 URL")
		}
		return map[string]any{"mode": mode, "socks5_proxy": input.Egress.SOCKS5Proxy}, nil, nil
	case "agent":
		if !input.Egress.RiskConfirmed || strings.TrimSpace(input.Egress.AgentID) == "" || (input.Action != "run" && input.Action != "debug") {
			return nil, nil, errors.New("Agent egress requires run/debug, agent_id and risk_confirmed=true")
		}
		broker := routerRuntime().EgressBroker
		if broker == nil {
			return nil, nil, errors.New("Agent Egress Unavailable: egress gateway is not configured")
		}
		var node db.Node
		agentID := strings.TrimSpace(input.Egress.AgentID)
		if err := scopedNodeQuery(currentTenantID(c)).Select("agent_id", "status", "token", "token_expires_at", "token_revoked_at").Where("agent_id = ?", agentID).First(&node).Error; err != nil {
			return nil, nil, errors.New("Agent not found or not accessible")
		}
		if !strings.EqualFold(node.Status, "Alive") || node.Token == "" || node.TokenRevokedAt != nil || (node.TokenExpiresAt != nil && time.Now().After(*node.TokenExpiresAt)) || !broker.AgentOnline(agentID) {
			return nil, nil, errors.New("Agent Egress Unavailable: agent tunnel is offline")
		}
		snapshot, err := broker.CreateRoute(c.Request.Context(), egressRouteRequest(currentTenantID(c), currentUserID(c), agentID, input.NetworkTargets, input.TimeoutMS))
		if err != nil {
			return nil, nil, err
		}
		cleanup := func() {
			if _, err := broker.Revoke(currentTenantID(c), snapshot.RouteID, "exp_run_finished"); err != nil {
				log.Printf("[EXP] failed to revoke completed Agent route: %v", err)
			}
		}
		return map[string]any{"mode": "relay", "route_id": snapshot.RouteID}, cleanup, nil
	default:
		return nil, nil, errors.New("egress.mode must be disabled, direct, socks5 or agent")
	}
}

func workspaceRevision(c *gin.Context) (*expworkspace.Service, int, bool) {
	service, ok := expWorkspace(c)
	if !ok {
		return nil, 0, false
	}
	revision, err := strconv.Atoi(c.Param("revision"))
	if err != nil || revision < 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "positive revision is required"})
		return nil, 0, false
	}
	return service, revision, true
}

func pagination(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	return page, pageSize
}

func testCaseResponse(item db.ExpTestCase) gin.H {
	var params, fixture, expect any
	_ = json.Unmarshal([]byte(item.Params), &params)
	_ = json.Unmarshal([]byte(item.Fixtures), &fixture)
	_ = json.Unmarshal([]byte(item.Assertions), &expect)
	return gin.H{"id": item.ID, "exp_id": item.ExpID, "revision": item.Revision, "name": item.Name, "params": params, "fixture": fixture, "expect": expect, "enabled": item.Enabled, "created_by": item.CreatedBy, "created_at": item.CreatedAt, "updated_at": item.UpdatedAt}
}

func riskWaiverResponse(item db.ExpRiskWaiver) gin.H {
	active := item.ExpiresAt == nil || item.ExpiresAt.After(time.Now().UTC())
	return gin.H{"exp_id": item.ExpID, "reason": item.Reason, "granted_by": item.GrantedBy, "expires_at": item.ExpiresAt, "active": active, "created_at": item.CreatedAt, "updated_at": item.UpdatedAt}
}

func expRevisionResponse(item db.ExpRevision) gin.H {
	return gin.H{
		"exp_id": item.ExpID, "revision": item.Revision, "status": item.Status,
		"source_sha256": item.SourceSHA256, "source_size": item.SourceSize,
		"cli_schema":       jsonValue(item.CLISchema, []any{}),
		"inspect_summary":  jsonValue(item.InspectSummary, map[string]any{}),
		"validate_summary": jsonValue(item.ValidateSummary, map[string]any{}),
		"tests_passed_at":  item.TestsPassedAt, "created_by": item.CreatedBy,
		"test_cases_sha256": item.TestCasesSHA256,
		"published_by":      item.PublishedBy, "published_at": item.PublishedAt, "created_at": item.CreatedAt,
	}
}

func expRunResponse(item db.ExpRun) gin.H {
	return gin.H{
		"id": item.ID, "exp_id": item.ExpID, "revision": item.Revision, "source_sha256": item.SourceSHA256,
		"action": item.Action, "operator_id": item.OperatorID, "egress_mode": item.EgressMode,
		"agent_id": item.AgentID, "status": item.Status, "result_summary": jsonValue(item.ResultSummary, map[string]any{}),
		"provenance": item.Provenance, "attested": item.Attested,
		"artifact_sha256": item.ArtifactSHA256, "artifact_expires_at": item.ArtifactExpiresAt,
		"error_code": item.ErrorCode, "started_at": item.StartedAt, "finished_at": item.FinishedAt, "created_at": item.CreatedAt,
	}
}

func expAuditResponse(item db.ExpAudit) gin.H {
	return gin.H{
		"id": item.ID, "exp_id": item.ExpID, "revision": item.Revision, "actor_id": item.ActorID,
		"action": item.Action, "details": jsonValue(item.Details, map[string]any{}), "created_at": item.CreatedAt,
	}
}

func jsonValue(raw string, fallback any) any {
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil || value == nil {
		return fallback
	}
	return value
}

func validEXPProxyURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "socks5" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	port, err := strconv.Atoi(parsed.Port())
	return err == nil && port > 0 && port <= 65535
}

func writeEXPWorkspaceError(c *gin.Context, err error) {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "EXP object not found or not accessible"})
		return
	}
	if errors.Is(err, expworkspace.ErrRiskConfirmationRequired) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	message := err.Error()
	if strings.Contains(message, "Unavailable") {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": message})
		return
	}
	for _, marker := range []string{"required", "invalid", "must", "cannot", "exceed", "mismatch", "duplicate", "cycle", "dependency", "asset", "revision", "publish", "deprecated", "only draft", "offline", "not found or not accessible", "resolver limit"} {
		if strings.Contains(strings.ToLower(message), strings.ToLower(marker)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": message})
			return
		}
	}
	log.Printf("[EXP] workspace operation failed: %v", err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "EXP workspace operation failed"})
}

func egressRouteRequest(tenantID, operatorID, agentID string, targets []string, timeoutMS int) egresspkg.RouteRequest {
	return egresspkg.RouteRequest{TenantID: tenantID, OperatorID: operatorID, AgentID: agentID, NetworkTargets: targets, Timeout: time.Duration(timeoutMS) * time.Millisecond}
}
