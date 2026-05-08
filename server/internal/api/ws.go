package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

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
