package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-server/internal/db"
)

const (
	defaultDebugTimeoutSec = 60
	maxDebugTimeoutSec     = 300
)

type debugRequest struct {
	AgentID    string `json:"agent_id"`
	PocContent string `json:"poc_content"`
	TargetURL  string `json:"target_url"`
	Proxy      string `json:"proxy"`
	TimeoutSec int32  `json:"timeout_sec"`
}

type debugSession struct {
	SessionID  string
	TenantID   string
	AgentID    string
	StartedAt  time.Time
	Timeout    time.Duration
	ResultChan chan map[string]interface{}
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
		StartedAt:  time.Time{}, // handled below to ensure consistent timestamp
		Timeout:    timeout,
		ResultChan: resultChan,
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
}

func newDebugSessionID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "debug-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return "debug-" + hex.EncodeToString(buf)
}

func debugPocGateway(c *gin.Context) {
	if c.Param("type") != "debug" {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	debugPoc(c)
}

func cancelDebugSessionGateway(c *gin.Context) {
	if c.Param("type") != "debug" {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	cancelDebugSession(c)
}

func debugPoc(c *gin.Context) {
	if notifyHub == nil {
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

	if req.AgentID == "" || req.PocContent == "" || req.TargetURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id, poc_content and target_url are required"})
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

	tenantID := currentTenantID(c)
	var node db.Node
	if err := scopedNodeQuery(tenantID).Where("agent_id = ? AND status = ?", req.AgentID, "Alive").First(&node).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent is not alive in this tenant"})
		return
	}
	if !isDebugCapableAgent(node.Version) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent does not support poc debug; please upgrade agent"})
		return
	}
	if !notifyHub.IsAgentOnline(req.AgentID) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "agent subscribe stream is offline"})
		return
	}

	session, ok := pocDebugSessions.start(tenantID, req.AgentID, time.Duration(req.TimeoutSec)*time.Second, nil)
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
		TimeoutSec: req.TimeoutSec,
	}
	if err := notifyHub.SendDebugCommand(req.AgentID, cmd); err != nil {
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
	if notifyHub == nil {
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
	if err := notifyHub.SendDebugCommand(session.AgentID, cmd); err != nil {
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

	if session.ResultChan != nil && (event.Type == "debug_result" || event.Type == "debug_complete") {
		session.ResultChan <- payload
	}

	if event.Type == "debug_complete" {
		pocDebugSessions.finish(event.SessionId)
	}
}

func expireDebugSession(session *debugSession) {
	select {
	case <-time.After(session.Timeout + 15*time.Second):
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
			session.ResultChan <- payload
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
	return major > 2 || (major == 2 && minor >= 2)
}

type errString string

func (e errString) Error() string { return string(e) }
