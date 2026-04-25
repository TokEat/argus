package ai

import (
	"context"
	"encoding/json"
)

// Tool 定义了 Agent 可以调用的工具接口
type Tool interface {
	Name() string
	Description() string
	InputSchema() map[string]interface{}
	Execute(ctx context.Context, input json.RawMessage) (interface{}, error)
}
