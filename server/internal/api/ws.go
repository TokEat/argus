package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	// Hub 维护所有的 WS 连接
	Hub = &WebSocketHub{
		clients:   make(map[*websocket.Conn]string),
		broadcast: make(chan wsEnvelope),
	}
)

type wsEnvelope struct {
	tenant string
	msg    interface{}
}

type WebSocketHub struct {
	clients   map[*websocket.Conn]string
	broadcast chan wsEnvelope
	mutex     sync.Mutex
}

// Start 启动 Hub 事件循环
func (h *WebSocketHub) Start() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case env := <-h.broadcast:
			h.writeEnvelope(env)
		case <-ticker.C:
			h.writeEnvelope(wsEnvelope{msg: map[string]interface{}{
				"type":  "heartbeat",
				"event": "ws.heartbeat",
				"data":  map[string]interface{}{"ts": time.Now().UnixMilli()},
			}})
		}
	}
}

func (h *WebSocketHub) writeEnvelope(env wsEnvelope) {
	msg := normalizeWSMessage(env.msg)
	if env.tenant != "" && msg["type"] != "heartbeat" && msg["id"] == nil {
		if id := persistWSEvent(env.tenant, msg); id > 0 {
			msg["id"] = id
		}
	}
	h.mutex.Lock()
	defer h.mutex.Unlock()
	for client, tenant := range h.clients {
		if env.tenant != "" && tenant != env.tenant {
			continue
		}
		err := client.WriteJSON(msg)
		if err != nil {
			log.Printf("WS error: %v", err)
			client.Close()
			delete(h.clients, client)
		}
	}
}

func persistWSEvent(tenantID string, msg map[string]interface{}) uint {
	payload, err := json.Marshal(msg)
	if err != nil || db.DB == nil {
		return 0
	}
	projectID := strings.TrimSpace(toWSString(msg["project_id"]))
	if projectID == "" {
		if data, ok := msg["data"].(map[string]interface{}); ok {
			projectID = strings.TrimSpace(toWSString(data["project_id"]))
		}
	}
	event := db.WSEventLog{
		TenantID:   tenantID,
		ProjectID:  projectID,
		EventType:  strings.TrimSpace(toWSString(msg["event"])),
		Payload:    string(payload),
		OccurredAt: time.Now(),
	}
	if event.EventType == "" {
		event.EventType = strings.TrimSpace(toWSString(msg["type"]))
	}
	if err := db.DB.Create(&event).Error; err != nil {
		log.Printf("WS event persist error: %v", err)
		return 0
	}
	return event.ID
}

func normalizeWSMessage(msg interface{}) map[string]interface{} {
	if raw, ok := msg.(string); ok {
		var decoded map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &decoded); err == nil {
			return normalizeWSMessage(decoded)
		}
		msg = map[string]interface{}{"type": "message", "data": raw}
	}

	out := make(map[string]interface{})
	switch src := msg.(type) {
	case map[string]interface{}:
		for key, val := range src {
			out[key] = val
		}
	case gin.H:
		for key, val := range src {
			out[key] = val
		}
	default:
		out["type"] = "data"
		out["data"] = msg
	}

	msgType := strings.TrimSpace(toWSString(out["type"]))
	if msgType == "" {
		msgType = strings.TrimSpace(toWSString(out["event"]))
	}
	if msgType == "" {
		msgType = "data"
	}
	out["type"] = msgType
	if _, ok := out["version"]; !ok {
		out["version"] = "v1"
	}
	if _, ok := out["event"]; !ok {
		out["event"] = msgType
	}
	if _, ok := out["occurred_at"]; !ok {
		out["occurred_at"] = time.Now().Format(time.RFC3339Nano)
	}
	if _, ok := out["data"]; !ok {
		data := make(map[string]interface{})
		for key, val := range out {
			switch key {
			case "type", "version", "event", "occurred_at", "data":
				continue
			}
			data[key] = val
		}
		out["data"] = data
	}
	return out
}

func toWSString(val interface{}) string {
	if s, ok := val.(string); ok {
		return s
	}
	return ""
}

// Broadcast 广播消息
func (h *WebSocketHub) Broadcast(msg interface{}) {
	h.broadcast <- wsEnvelope{msg: msg}
}

// BroadcastToTenant 按租户定向广播消息。
func (h *WebSocketHub) BroadcastToTenant(tenantID string, msg interface{}) {
	h.broadcast <- wsEnvelope{tenant: tenantID, msg: msg}
}

// HandleWS 处理 WebSocket 握手
func HandleWS(c *gin.Context) {
	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WS Upgrade failed: %v", err)
		return
	}

	replayWSEvents(c, ws)
	Hub.mutex.Lock()
	Hub.clients[ws] = currentTenantID(c)
	Hub.mutex.Unlock()

	// 保持连接
	for {
		if _, _, err := ws.NextReader(); err != nil {
			Hub.mutex.Lock()
			delete(Hub.clients, ws)
			Hub.mutex.Unlock()
			ws.Close()
			break
		}
	}
}

func replayWSEvents(c *gin.Context, ws *websocket.Conn) {
	if db.DB == nil {
		return
	}
	tenantID := currentTenantID(c)
	query := db.DB.Where("tenant_id = ?", tenantID)
	if raw := strings.TrimSpace(c.Query("last_event_id")); raw != "" {
		if id, err := strconv.ParseUint(raw, 10, 64); err == nil && id > 0 {
			query = query.Where("id > ?", id)
		}
	} else if raw := strings.TrimSpace(c.Query("since")); raw != "" {
		if ts, err := time.Parse(time.RFC3339, raw); err == nil {
			query = query.Where("occurred_at >= ?", ts)
		} else if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			query = query.Where("occurred_at >= ?", ts)
		}
	} else {
		return
	}
	if !currentUserIsAdmin(c) {
		ids := accessibleProjectIDs(c)
		if len(ids) == 0 {
			query = query.Where("project_id = '' OR project_id IS NULL")
		} else {
			query = query.Where("project_id = '' OR project_id IS NULL OR project_id IN ?", ids)
		}
	}
	var events []db.WSEventLog
	if err := query.Order("id ASC").Limit(200).Find(&events).Error; err != nil {
		log.Printf("WS replay query error: %v", err)
		return
	}
	for _, event := range events {
		msg := map[string]interface{}{}
		if err := json.Unmarshal([]byte(event.Payload), &msg); err != nil {
			continue
		}
		msg["id"] = event.ID
		if err := ws.WriteJSON(msg); err != nil {
			log.Printf("WS replay write error: %v", err)
			return
		}
	}
}
