package api

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/shared/proto/go/activefingerprint"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func saveMCPActiveFingerprintDraft(tenantID string, req mcpRuleSaveRequest, actorID string) (gin.H, error) {
	fileName := strings.TrimSpace(req.FileName)
	content := strings.TrimSpace(req.Content)
	if fileName == "" || content == "" {
		return nil, fmt.Errorf("file_name and content are required for behavior_probe")
	}
	classification, err := activefingerprint.Inspect(fileName, []byte(req.Content))
	if err != nil {
		return nil, err
	}
	arsenal, findErr := db.FindTenantArsenalByTypeAndFile(tenantID, "active_fingerprint", fileName)
	if findErr != nil {
		arsenal = &db.Arsenal{ID: db.BuildTenantArsenalID(tenantID, "active_fingerprint", fileName), TenantID: tenantID, Type: "active_fingerprint", FileName: fileName}
	}
	arsenal.PreviousContent, arsenal.PreviousHash = arsenal.Content, arsenal.Hash
	arsenal.Content = req.Content
	arsenal.Hash = fmt.Sprintf("%x", md5.Sum([]byte(req.Content)))
	arsenal.State = "Draft"
	if arsenal.Version <= 0 {
		arsenal.Version = 1
	} else {
		arsenal.Version++
	}
	if err := db.ValidateRuleCatalogCandidate(*arsenal); err != nil {
		return nil, err
	}
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(arsenal).Error; err != nil {
			return err
		}
		return createArsenalEvent(tx, *arsenal, "saved", actorID, arsenal.Content, map[string]interface{}{"computed_profile": classification.ComputedProfile, "reasons": classification.Reasons})
	}); err != nil {
		return nil, err
	}
	if err := db.SyncRuleCatalogFromArsenal(); err != nil {
		return nil, err
	}
	return gin.H{
		"status": "saved", "rule_type": "behavior_probe", "artifact_id": arsenal.ID,
		"type": arsenal.Type, "file_name": arsenal.FileName, "state": arsenal.State,
		"hash": arsenal.Hash, "version": arsenal.Version, "content_length": len(arsenal.Content),
		"classification": classification,
	}, nil
}

func mcpRuleDebugActiveFingerprint(c *gin.Context, req mcpRuleDebugRequest) {
	if routerRuntime().NotifyHub == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent notify hub is not ready"})
		return
	}
	tenantID := currentTenantID(c)
	req.AgentID = strings.TrimSpace(req.AgentID)
	req.TargetURL = strings.TrimSpace(req.TargetURL)
	req.Proxy = strings.TrimSpace(req.Proxy)
	req.FileName = strings.TrimSpace(req.FileName)
	if req.AgentID == "" || req.TargetURL == "" || req.FileName == "" || strings.TrimSpace(req.Content) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id, target_url, file_name and content are required"})
		return
	}
	classification, err := activefingerprint.Inspect(req.FileName, []byte(req.Content))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !classification.AutoEligible && !req.RiskConfirmed {
		c.JSON(http.StatusBadRequest, gin.H{"error": "controlled behavior probe debug requires risk_confirmed=true", "classification": classification})
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
	if !mcpValidateActiveFingerprintDebugAgent(c, tenantID, req.AgentID) {
		return
	}

	timeoutSec := normalizeMCPSyncTimeout(req.TimeoutSec)
	resultChan := make(chan map[string]interface{}, 32)
	session, ok := pocDebugSessions.start(tenantID, req.AgentID, time.Duration(timeoutSec)*time.Second, resultChan)
	if !ok {
		c.JSON(http.StatusConflict, gin.H{"error": "agent already has a running debug session"})
		return
	}
	artifact := db.Arsenal{
		ID: db.BuildTenantArsenalID(tenantID, "active_fingerprint", req.FileName), TenantID: tenantID,
		Type: "active_fingerprint", FileName: req.FileName, Hash: fmt.Sprintf("%x", md5.Sum([]byte(req.Content))), State: "Transient",
	}
	if saved, findErr := db.FindTenantArsenalByTypeAndFile(tenantID, "active_fingerprint", req.FileName); findErr == nil {
		artifact.ID, artifact.Version = saved.ID, saved.Version
	}
	startDetails := map[string]interface{}{
		"agent_id": req.AgentID, "target_origin": debugTargetOrigin(req.TargetURL),
		"computed_profile": classification.ComputedProfile, "risk_confirmed": req.RiskConfirmed,
	}
	if err := createArsenalEvent(db.DB, artifact, "debug_started", c.GetString("user_id"), "", startDetails); err != nil {
		pocDebugSessions.finish(session.SessionID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist debug audit"})
		return
	}
	cmd := &pb.DebugCommand{
		Action: "start_active_fingerprint_debug", SessionId: session.SessionID, TenantId: tenantID,
		PocContent: req.Content, TargetUrl: req.TargetURL, Proxy: req.Proxy, TimeoutSec: timeoutSec,
	}
	if err := routerRuntime().NotifyHub.SendDebugCommand(req.AgentID, cmd); err != nil {
		pocDebugSessions.finish(session.SessionID)
		_ = createArsenalEvent(db.DB, artifact, "debug_failed", c.GetString("user_id"), "", map[string]interface{}{"reason": "agent command unavailable"})
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to send active fingerprint debug command to agent"})
		return
	}
	go expireDebugSession(session)
	waited, err := waitMCPDebugTranscript(resultChan, time.Duration(timeoutSec+15)*time.Second)
	if err != nil {
		pocDebugSessions.finish(session.SessionID)
		_ = createArsenalEvent(db.DB, artifact, "debug_failed", c.GetString("user_id"), "", map[string]interface{}{"reason": "timeout"})
		c.JSON(http.StatusGatewayTimeout, gin.H{"error": err.Error()})
		return
	}
	if err := createArsenalEvent(db.DB, artifact, "debug_completed", c.GetString("user_id"), "", map[string]interface{}{
		"matched_products": waited.MatchedProducts, "result_count": len(waited.Results),
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "debug completed but completion audit could not be persisted"})
		return
	}
	waited.MCPGuidance = mcpDebugGuidance("behavior_probe")
	c.JSON(http.StatusOK, gin.H{"transcript": waited, "classification": classification})
}

func mcpValidateActiveFingerprintDebugAgent(c *gin.Context, tenantID, agentID string) bool {
	var node db.Node
	if err := scopedNodeQuery(tenantID).Where("agent_id = ? AND status = ?", agentID, "Alive").First(&node).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent is not alive in this tenant"})
		return false
	}
	tags := map[string]string{}
	if err := json.Unmarshal([]byte(node.Tags), &tags); err != nil || tags["behavior_probe"] != "v1" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent does not advertise behavior_probe=v1"})
		return false
	}
	if !routerRuntime().NotifyHub.IsAgentOnline(agentID) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent subscribe stream is offline"})
		return false
	}
	return true
}

func debugTargetOrigin(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}
