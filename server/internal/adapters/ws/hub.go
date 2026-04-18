package ws

import "context"

// Hub 预留给实时大屏和任务事件广播。
// 当前只沉淀接口与类型位置，后续再接入实际 websocket 或 event bus。
type Hub struct{}

func NewHub() *Hub {
	return &Hub{}
}

func (h *Hub) Start(ctx context.Context) error {
	return nil
}

func (h *Hub) Broadcast(_ any) {}
