package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

type Agent struct {
	Client ChatClient
	Tools  map[string]Tool
}

func NewAgent(client ChatClient) *Agent {
	return &Agent{
		Client: client,
		Tools:  make(map[string]Tool),
	}
}

func (a *Agent) RegisterTool(t Tool) {
	a.Tools[t.Name()] = t
}

func (a *Agent) GetToolDefinitions() []ToolDefinition {
	var defs []ToolDefinition
	names := make([]string, 0, len(a.Tools))
	for name := range a.Tools {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t := a.Tools[name]
		defs = append(defs, ToolDefinition{
			Type: "function",
			Function: struct {
				Name        string      `json:"name"`
				Description string      `json:"description"`
				Parameters  interface{} `json:"parameters"`
			}{
				Name:        t.Name(),
				Description: t.Description(),
				Parameters:  t.InputSchema(),
			},
		})
	}
	return defs
}

// QueryEngine 执行多轮 Agent 循环
func (a *Agent) QueryEngine(ctx context.Context, cfg Config, initialMessages []ChatMessage, maxTurns int, onEvent func(event string, data interface{})) (string, error) {
	messages := make([]ChatMessage, len(initialMessages))
	copy(messages, initialMessages)

	tools := a.GetToolDefinitions()

	for i := 0; i < maxTurns; i++ {
		var content string
		var toolCalls []ToolCall
		var err error

		content, toolCalls, err = a.Client.StreamWithTools(ctx, cfg, messages, tools,
			func(token string) {
				if onEvent != nil {
					onEvent("token", map[string]interface{}{"content": token})
				}
			},
			func(tc ToolCall) {
				// We can optionally stream when a tool call starts parsing
			})

		if err != nil {
			return "", err
		}

		// 将大模型的回复追加到历史中
		assistantMsg := ChatMessage{
			Role:      "assistant",
			Content:   content,
			ToolCalls: toolCalls,
		}
		messages = append(messages, assistantMsg)

		// 如果没有 tool call，说明任务完成
		if len(toolCalls) == 0 {
			return content, nil
		}

		// 执行所有的 tool call
		for _, tc := range toolCalls {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			if tc.Type != "function" {
				continue
			}

			if onEvent != nil {
				onEvent("tool_start", map[string]interface{}{
					"id":   tc.ID,
					"name": tc.Function.Name,
					"args": tc.Function.Arguments,
				})
			}
			startedAt := time.Now()

			tool, exists := a.Tools[tc.Function.Name]
			if !exists {
				resultContent := fmt.Sprintf("Error: unknown tool %s", tc.Function.Name)
				messages = append(messages, ChatMessage{
					Role:       "tool",
					Name:       tc.Function.Name,
					Content:    resultContent,
					ToolCallID: tc.ID,
				})
				if onEvent != nil {
					onEvent("tool_end", map[string]interface{}{
						"id":          tc.ID,
						"name":        tc.Function.Name,
						"result":      resultContent,
						"status":      "error",
						"duration_ms": time.Since(startedAt).Milliseconds(),
					})
				}
				continue
			}

			result, err := tool.Execute(ctx, []byte(tc.Function.Arguments))
			var resultContent string
			status := "ok"
			if err != nil {
				resultContent = fmt.Sprintf("Error: %v", err)
				status = "error"
			} else {
				resultBytes, _ := json.Marshal(result)
				resultContent = string(resultBytes)
			}

			if onEvent != nil {
				onEvent("tool_end", map[string]interface{}{
					"id":          tc.ID,
					"name":        tc.Function.Name,
					"result":      resultContent,
					"status":      status,
					"duration_ms": time.Since(startedAt).Milliseconds(),
				})
			}

			messages = append(messages, ChatMessage{
				Role:       "tool",
				Name:       tc.Function.Name,
				Content:    resultContent,
				ToolCallID: tc.ID,
			})
		}
	}

	return "", fmt.Errorf("agent reached max turns (%d) without completing", maxTurns)
}
