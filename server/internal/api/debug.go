package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/gin-gonic/gin"
)

const (
	defaultDebugTimeoutSec = 60
	maxDebugTimeoutSec     = 300
)

var safeDebugPocIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type debugRequest struct {
	AgentID          string   `json:"agent_id"`
	PocContent       string   `json:"poc_content"`
	TargetURL        string   `json:"target_url"`
	Proxy            string   `json:"proxy"`
	TimeoutSec       int32    `json:"timeout_sec"`
	IncludeDir       bool     `json:"include_dir"`
	IncludePoc       bool     `json:"include_poc"`
	CustomOnly       bool     `json:"custom_only"`
	CustomProduct    string   `json:"custom_product"`
	CustomRule       string   `json:"custom_rule"`
	CustomRules      []string `json:"custom_rules"`
	CustomWfProduct  string   `json:"custom_wf_product"`
	CustomWfTypes    string   `json:"custom_wf_types"`
	CustomWfPocs     string   `json:"custom_wf_pocs"`
	CustomPocContent string   `json:"custom_poc_content"`
}

func cleanDebugRules(rules []string) []string {
	cleaned := make([]string, 0, len(rules))
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule != "" {
			cleaned = append(cleaned, rule)
		}
	}
	return cleaned
}

type debugSession struct {
	SessionID  string
	TenantID   string
	AgentID    string
	StartedAt  time.Time
	Timeout    time.Duration
	ResultChan chan map[string]interface{}
	done       chan struct{}
}

type debugSessionManager struct {
	mu           sync.Mutex
	sessions     map[string]*debugSession // sessionID -> session
	activeTenant map[string]string        // tenantID -> sessionID
}

var pocDebugSessions = &debugSessionManager{
	sessions:     make(map[string]*debugSession),
	activeTenant: make(map[string]string),
}

func (m *debugSessionManager) start(tenantID, agentID string, timeout time.Duration, resultChan chan map[string]interface{}) (*debugSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.activeTenant[tenantID]; ok {
		return nil, false
	}

	session := &debugSession{
		SessionID:  newDebugSessionID(),
		TenantID:   tenantID,
		AgentID:    agentID,
		StartedAt:  time.Time{},
		Timeout:    timeout,
		ResultChan: resultChan,
		done:       make(chan struct{}),
	}
	session.StartedAt = time.Now()
	m.sessions[session.SessionID] = session
	m.activeTenant[tenantID] = session.SessionID
	return session, true
}

func (m *debugSessionManager) get(sessionID string) (*debugSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[sessionID]
	return session, ok
}

func (m *debugSessionManager) finish(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return
	}
	delete(m.sessions, sessionID)
	if m.activeTenant[session.TenantID] == sessionID {
		delete(m.activeTenant, session.TenantID)
	}
	close(session.done)
}

func newDebugSessionID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "debug-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return "debug-" + hex.EncodeToString(buf)
}

func debugPocGateway(c *gin.Context) {
	switch c.Param("type") {
	case "debug":
		debugPoc(c)
	case "finger-debug":
		debugFingerprint(c)
	default:
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	}
}

func cancelDebugSessionGateway(c *gin.Context) {
	if c.Param("type") != "debug" {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	cancelDebugSession(c)
}

func debugPoc(c *gin.Context) {
	startAgentDebug(c, "start_debug", true)
}

func debugFingerprint(c *gin.Context) {
	startAgentDebug(c, "start_fingerprint_debug", false)
}

func startAgentDebug(c *gin.Context, action string, requirePocContent bool) {
	if routerRuntime().NotifyHub == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent notify hub is not ready"})
		return
	}

	var req debugRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	req.AgentID = strings.TrimSpace(req.AgentID)
	req.PocContent = strings.TrimSpace(req.PocContent)
	req.TargetURL = strings.TrimSpace(req.TargetURL)
	req.Proxy = strings.TrimSpace(req.Proxy)
	if req.TimeoutSec <= 0 {
		req.TimeoutSec = defaultDebugTimeoutSec
	}
	if req.TimeoutSec > maxDebugTimeoutSec {
		req.TimeoutSec = maxDebugTimeoutSec
	}

	if req.AgentID == "" || req.TargetURL == "" || (requirePocContent && req.PocContent == "") {
		if requirePocContent {
			c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id, poc_content and target_url are required"})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id and target_url are required"})
		}
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
	if action == "start_fingerprint_debug" && strings.TrimSpace(req.CustomPocContent) != "" {
		req.CustomWfProduct = strings.TrimSpace(req.CustomWfProduct)
		req.CustomWfPocs = strings.TrimSpace(req.CustomWfPocs)
		req.CustomWfTypes = strings.TrimSpace(req.CustomWfTypes)
		if !req.IncludePoc || req.CustomWfProduct == "" || req.CustomWfPocs == "" || req.CustomWfTypes == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "custom_poc_content requires include_poc, custom_wf_product, custom_wf_types and custom_wf_pocs"})
			return
		}
		if strings.Contains(req.CustomWfPocs, ",") || !safeDebugPocIDPattern.MatchString(req.CustomWfPocs) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "custom_wf_pocs must be a single safe POC id"})
			return
		}
	}
	customRules := cleanDebugRules(req.CustomRules)
	if action == "start_fingerprint_debug" && req.CustomOnly && strings.TrimSpace(req.CustomRule) == "" && len(customRules) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "custom_only fingerprint debug requires custom_rule"})
		return
	}

	tenantID := currentTenantID(c)
	var node db.Node
	if err := scopedNodeQuery(tenantID).Where("agent_id = ? AND status = ?", req.AgentID, "Alive").First(&node).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent is not alive in this tenant"})
		return
	}
	if action == "start_fingerprint_debug" && !isFingerprintDebugCapableAgent(node.Version) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent does not support fingerprint debug; please upgrade agent to v2.3.0+"})
		return
	}
	if action != "start_fingerprint_debug" && !isDebugCapableAgent(node.Version) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent does not support poc debug; please upgrade agent"})
		return
	}
	if !routerRuntime().NotifyHub.IsAgentOnline(req.AgentID) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent subscribe stream is offline"})
		return
	}

	session, ok := pocDebugSessions.start(tenantID, req.AgentID, time.Duration(req.TimeoutSec)*time.Second, nil)
	if !ok {
		c.JSON(http.StatusConflict, gin.H{"error": "tenant already has a running debug session"})
		return
	}

	pocContent := req.PocContent
	if action == "start_fingerprint_debug" {
		payloadMap := gin.H{"include_dir": req.IncludeDir, "include_poc": req.IncludePoc}
		if req.CustomOnly {
			payloadMap["custom_only"] = true
		}
		if req.CustomProduct != "" {
			payloadMap["custom_product"] = req.CustomProduct
		}
		if req.CustomRule != "" {
			payloadMap["custom_rule"] = req.CustomRule
		}
		if len(customRules) > 0 {
			payloadMap["custom_rules"] = customRules
		}
		if req.CustomWfProduct != "" && req.CustomWfPocs != "" {
			payloadMap["custom_wf_product"] = req.CustomWfProduct
			payloadMap["custom_wf_types"] = req.CustomWfTypes
			payloadMap["custom_wf_pocs"] = req.CustomWfPocs
		}
		if req.CustomPocContent != "" {
			payloadMap["custom_poc_content"] = req.CustomPocContent
		}
		payload, _ := json.Marshal(payloadMap)
		pocContent = string(payload)
	}

	cmd := &pb.DebugCommand{
		Action:     action,
		SessionId:  session.SessionID,
		TenantId:   tenantID,
		PocContent: pocContent,
		TargetUrl:  req.TargetURL,
		Proxy:      req.Proxy,
		TimeoutSec: req.TimeoutSec,
	}
	if err := routerRuntime().NotifyHub.SendDebugCommand(req.AgentID, cmd); err != nil {
		pocDebugSessions.finish(session.SessionID)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to send debug command to agent"})
		return
	}

	go expireDebugSession(session)

	Hub.BroadcastToTenant(tenantID, map[string]interface{}{
		"type":       "debug_log",
		"session_id": session.SessionID,
		"agent_id":   req.AgentID,
		"timestamp":  time.Now().UnixMilli(),
		"level":      "INFO",
		"message":    "debug command dispatched to agent",
	})

	c.JSON(http.StatusOK, gin.H{"session_id": session.SessionID, "status": "started"})
}

func cancelDebugSession(c *gin.Context) {
	if routerRuntime().NotifyHub == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent notify hub is not ready"})
		return
	}

	sessionID := strings.TrimSpace(c.Param("filename"))
	session, ok := pocDebugSessions.get(sessionID)
	if !ok || session.TenantID != currentTenantID(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "debug session not found"})
		return
	}

	cmd := &pb.DebugCommand{
		Action:    "cancel_debug",
		SessionId: session.SessionID,
		TenantId:  session.TenantID,
	}
	if err := routerRuntime().NotifyHub.SendDebugCommand(session.AgentID, cmd); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to send cancel command to agent"})
		return
	}

	Hub.BroadcastToTenant(session.TenantID, map[string]interface{}{
		"type":       "debug_log",
		"session_id": session.SessionID,
		"agent_id":   session.AgentID,
		"timestamp":  time.Now().UnixMilli(),
		"level":      "WARN",
		"message":    "cancel command dispatched to agent",
	})
	c.JSON(http.StatusOK, gin.H{"status": "cancelled"})
}

func handleAgentDebugEvent(event *pb.DebugEvent) {
	if event == nil {
		return
	}

	if handlePyenvDebugEvent(event) {
		return
	}

	// Handle EXP results separately
	if event.Type == "exp_result" {
		handleExploitResult(event)
		return
	}

	session, ok := pocDebugSessions.get(event.SessionId)
	if !ok || session.AgentID != event.AgentId || session.TenantID != event.TenantId {
		return
	}

	payload := map[string]interface{}{
		"type":        event.Type,
		"session_id":  event.SessionId,
		"agent_id":    event.AgentId,
		"tenant_id":   event.TenantId,
		"timestamp":   event.Timestamp,
		"level":       event.Level,
		"message":     event.Message,
		"matched":     event.Matched,
		"template_id": event.TemplateId,
		"severity":    event.Severity,
		"matched_at":  event.MatchedAt,
		"request":     event.Request,
		"response":    event.Response,
		"extracted":   event.Extracted,
		"duration_ms": event.DurationMs,
		"error":       event.Error,
	}
	Hub.BroadcastToTenant(session.TenantID, payload)

	if session.ResultChan != nil && (event.Type == "debug_log" || event.Type == "debug_result" || event.Type == "debug_complete") {
		select {
		case session.ResultChan <- payload:
		default:
		}
	}

	if event.Type == "debug_complete" {
		pocDebugSessions.finish(event.SessionId)
	}
}

func expireDebugSession(session *debugSession) {
	timer := time.NewTimer(session.Timeout + 15*time.Second)
	defer timer.Stop()

	select {
	case <-session.done:
		return
	case <-timer.C:
		if _, ok := pocDebugSessions.get(session.SessionID); !ok {
			return
		}
		payload := map[string]interface{}{
			"type":        "debug_complete",
			"session_id":  session.SessionID,
			"agent_id":    session.AgentID,
			"tenant_id":   session.TenantID,
			"timestamp":   time.Now().UnixMilli(),
			"duration_ms": time.Since(session.StartedAt).Milliseconds(),
			"error":       "debug session timed out waiting for agent completion",
		}
		Hub.BroadcastToTenant(session.TenantID, payload)
		if session.ResultChan != nil {
			select {
			case session.ResultChan <- payload:
			default:
			}
		}
		pocDebugSessions.finish(session.SessionID)
	}
}

func validateDebugTargetURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errString("target_url must be an absolute http or https URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return errString("target_url only supports http and https")
	}
	return nil
}

func validateDebugProxy(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errString("proxy must be an absolute proxy URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5":
		return nil
	default:
		return errString("proxy only supports http, https and socks5")
	}
}

func isDebugCapableAgent(version string) bool {
	return isAgentVersionAtLeast(version, 2, 2)
}

func isFingerprintDebugCapableAgent(version string) bool {
	return isAgentVersionAtLeast(version, 2, 3)
}

func isAgentVersionAtLeast(version string, minMajor int, minMinor int) bool {
	version = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(version), "v"))
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return strings.Contains(version, "debug")
	}
	return major > minMajor || (major == minMajor && minor >= minMinor)
}

type errString string

func (e errString) Error() string { return string(e) }

// handleExploitResult processes EXP execution results from Agent.
func handleExploitResult(event *pb.DebugEvent) {
	if event.Message == "" {
		return
	}

	var payload struct {
		RunID       uint                   `json:"run_id"`
		Status      string                 `json:"status"`
		ErrorMsg    string                 `json:"error_message"`
		Evidence    map[string]interface{} `json:"evidence"`
		SideEffects []string               `json:"side_effects"`
		DurationMs  int64                  `json:"duration_ms"`
	}

	if err := json.Unmarshal([]byte(event.Message), &payload); err != nil {
		log.Printf("[EXP] failed to parse result: %v", err)
		return
	}

	// Resolve run ID from session ID
	runID := payload.RunID
	if runID == 0 {
		if id, err := strconv.ParseUint(event.SessionId, 10, 64); err == nil {
			runID = uint(id)
		}
	}
	if runID == 0 {
		log.Printf("[EXP] invalid run ID in session %s", event.SessionId)
		return
	}

	exploitEvent := db.ExploitResultEvent{
		RunID:       runID,
		Status:      payload.Status,
		ErrorMsg:    payload.ErrorMsg,
		Evidence:    payload.Evidence,
		SideEffects: payload.SideEffects,
		DurationMs:  payload.DurationMs,
	}

	// Route cleanup results to the dedicated cleanup handler
	if payload.Status == "CleanupSucceeded" || payload.Status == "CleanupFailed" {
		db.HandleExploitCleanupResult(exploitEvent)
	} else {
		db.HandleExploitResult(exploitEvent)
	}
	log.Printf("[EXP] result processed: run=%d status=%s", runID, payload.Status)
}
