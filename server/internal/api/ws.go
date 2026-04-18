package api

import (
	"log"
	"net/http"
	"sync"

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
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan interface{}),
	}
)

type WebSocketHub struct {
	clients   map[*websocket.Conn]bool
	broadcast chan interface{}
	mutex     sync.Mutex
}

// Start 启动 Hub 事件循环
func (h *WebSocketHub) Start() {
	for {
		msg := <-h.broadcast
		h.mutex.Lock()
		for client := range h.clients {
			err := client.WriteJSON(msg)
			if err != nil {
				log.Printf("WS error: %v", err)
				client.Close()
				delete(h.clients, client)
			}
		}
		h.mutex.Unlock()
	}
}

// Broadcast 广播消息
func (h *WebSocketHub) Broadcast(msg interface{}) {
	h.broadcast <- msg
}

// HandleWS 处理 WebSocket 握手
func HandleWS(c *gin.Context) {
	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WS Upgrade failed: %v", err)
		return
	}

	Hub.mutex.Lock()
	Hub.clients[ws] = true
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
