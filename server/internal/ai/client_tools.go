package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (c *HTTPClient) CompleteWithTools(ctx context.Context, cfg Config, messages []ChatMessage, tools []ToolDefinition) (string, []ToolCall, error) {
	client := c.Client
	if client == nil {
		client = defaultHTTPClient
	}

	body := map[string]interface{}{
		"model":       cfg.Model,
		"messages":    messages,
		"temperature": 0.1,
	}
	if len(tools) > 0 {
		body["tools"] = tools
		body["tool_choice"] = "auto"
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", nil, err
	}

	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", nil, fmt.Errorf("llm request failed: status=%d body=%s", resp.StatusCode, string(data))
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content   string     `json:"content"`
				ToolCalls []ToolCall `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", nil, fmt.Errorf("parse llm response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return "", nil, fmt.Errorf("llm response missing message content")
	}
	
	msg := parsed.Choices[0].Message
	return msg.Content, msg.ToolCalls, nil
}

func (c *HTTPClient) StreamWithTools(ctx context.Context, cfg Config, messages []ChatMessage, tools []ToolDefinition, onToken func(token string), onToolCall func(toolCall ToolCall)) (string, []ToolCall, error) {
	streamClient := &http.Client{
		Transport: defaultHTTPClient.Transport,
	}

	body := map[string]interface{}{
		"model":       cfg.Model,
		"messages":    messages,
		"temperature": 0.1,
		"stream":      true,
	}
	if len(tools) > 0 {
		body["tools"] = tools
		body["tool_choice"] = "auto"
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return "", nil, err
	}

	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := streamClient.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return "", nil, fmt.Errorf("llm stream request failed: status=%d body=%s", resp.StatusCode, string(errBody))
	}

	var full strings.Builder
	buf := make([]byte, 4096)
	var lineBuf strings.Builder
	
	// Track tool call accumulation across chunks
	type toolCallBuilder struct {
		ID       string
		Type     string
		Name     string
		Args     strings.Builder
	}
	toolBuilders := make(map[int]*toolCallBuilder)

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			lineBuf.Write(buf[:n])
			for {
				line, rest, found := strings.Cut(lineBuf.String(), "\n")
				if !found {
					break
				}
				lineBuf.Reset()
				lineBuf.WriteString(rest)

				line = strings.TrimSpace(line)
				if line == "" || line == "data: [DONE]" {
					continue
				}
				if !strings.HasPrefix(line, "data: ") {
					continue
				}
				jsonData := strings.TrimPrefix(line, "data: ")

				var chunk struct {
					Choices []struct {
						Delta struct {
							Content   string `json:"content"`
							ToolCalls []struct {
								Index    int    `json:"index"`
								ID       string `json:"id"`
								Type     string `json:"type"`
								Function struct {
									Name      string `json:"name"`
									Arguments string `json:"arguments"`
								} `json:"function"`
							} `json:"tool_calls"`
						} `json:"delta"`
					} `json:"choices"`
				}
				if err := json.Unmarshal([]byte(jsonData), &chunk); err != nil {
					continue
				}
				if len(chunk.Choices) > 0 {
					delta := chunk.Choices[0].Delta
					if delta.Content != "" {
						full.WriteString(delta.Content)
						if onToken != nil {
							onToken(delta.Content)
						}
					}
					
					for _, tc := range delta.ToolCalls {
						builder, ok := toolBuilders[tc.Index]
						if !ok {
							builder = &toolCallBuilder{}
							toolBuilders[tc.Index] = builder
						}
						if tc.ID != "" {
							builder.ID = tc.ID
						}
						if tc.Type != "" {
							builder.Type = tc.Type
						}
						if tc.Function.Name != "" {
							builder.Name = tc.Function.Name
						}
						if tc.Function.Arguments != "" {
							builder.Args.WriteString(tc.Function.Arguments)
						}
					}
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return full.String(), nil, readErr
		}
	}

	var finalToolCalls []ToolCall
	for _, b := range toolBuilders {
		tc := ToolCall{
			ID:   b.ID,
			Type: b.Type,
		}
		tc.Function.Name = b.Name
		tc.Function.Arguments = b.Args.String()
		finalToolCalls = append(finalToolCalls, tc)
		if onToolCall != nil {
			onToolCall(tc)
		}
	}

	return full.String(), finalToolCalls, nil
}
