package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type ChatClient interface {
	CompleteJSON(ctx context.Context, cfg Config, messages []ChatMessage) (string, error)
	CompleteWithTools(ctx context.Context, cfg Config, messages []ChatMessage, tools []ToolDefinition) (string, []ToolCall, error)
	StreamWithTools(ctx context.Context, cfg Config, messages []ChatMessage, tools []ToolDefinition, onToken func(token string), onToolCall func(toolCall ToolCall)) (string, []ToolCall, error)
}

type HTTPClient struct {
	Client *http.Client
}

var defaultHTTPClient = &http.Client{
	Timeout:   45 * time.Second,
	Transport: http.DefaultTransport.(*http.Transport).Clone(),
}

type ChatMessage struct {
	Role       string      `json:"role"`
	Content    string      `json:"content"`
	Name       string      `json:"name,omitempty"`
	ToolCalls  []ToolCall  `json:"tool_calls,omitempty"`
	ToolCallID string      `json:"tool_call_id,omitempty"`
}

type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"` // usually "function"
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type ToolDefinition struct {
	Type     string `json:"type"` // usually "function"
	Function struct {
		Name        string      `json:"name"`
		Description string      `json:"description"`
		Parameters  interface{} `json:"parameters"` // JSON Schema map[string]interface{}
	} `json:"function"`
}

func (c *HTTPClient) CompleteJSON(ctx context.Context, cfg Config, messages []ChatMessage) (string, error) {
	client := c.Client
	if client == nil {
		client = defaultHTTPClient
	}

	body := map[string]interface{}{
		"model":       cfg.Model,
		"messages":    messages,
		"temperature": 0.1,
		"response_format": map[string]string{
			"type": "json_object",
		},
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("llm request failed: status=%d body=%s", resp.StatusCode, string(data))
	}

	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", fmt.Errorf("parse llm response: %w", err)
	}
	if len(parsed.Choices) == 0 || strings.TrimSpace(parsed.Choices[0].Message.Content) == "" {
		return "", fmt.Errorf("llm response missing message content")
	}
	return parsed.Choices[0].Message.Content, nil
}

// StreamComplete calls the LLM with stream:true and invokes onToken for each content delta.
// Returns the full concatenated content when done.
func (c *HTTPClient) StreamComplete(ctx context.Context, cfg Config, messages []ChatMessage, onToken func(token string)) (string, error) {
	// Use a separate client without the global timeout — streaming needs more time.
	streamClient := &http.Client{
		Transport: defaultHTTPClient.Transport,
		// No Timeout — context cancellation controls the deadline.
	}

	body := map[string]interface{}{
		"model":       cfg.Model,
		"messages":    messages,
		"temperature": 0.1,
		"stream":      true,
	}
	// Note: some providers do not support response_format with stream=true.
	// We will try without it first, as streaming implies we parse it as it comes.
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := streamClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		return "", fmt.Errorf("llm stream request failed: status=%d body=%s", resp.StatusCode, string(errBody))
	}

	var full strings.Builder
	buf := make([]byte, 4096)
	var lineBuf strings.Builder

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
				if line == "" {
					continue
				}
				if line == "data: [DONE]" {
					continue
				}
				if !strings.HasPrefix(line, "data: ") {
					log.Printf("[AI-Stream] Non-data line received: %s", line)
					continue
				}
				jsonData := strings.TrimPrefix(line, "data: ")

				var chunk struct {
					Choices []struct {
						Delta struct {
							Content string `json:"content"`
						} `json:"delta"`
					} `json:"choices"`
				}
				if err := json.Unmarshal([]byte(jsonData), &chunk); err != nil {
					log.Printf("[AI-Stream] unmarshal error on '%s': %v", jsonData, err)
					continue
				}
				if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
					token := chunk.Choices[0].Delta.Content
					full.WriteString(token)
					if onToken != nil {
						onToken(token)
					}
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return full.String(), readErr
		}
	}

	result := full.String()
	if strings.TrimSpace(result) == "" {
		return "", fmt.Errorf("llm stream returned empty content")
	}
	return result, nil
}

// ModelInfo represents a single model from the OpenAI-compatible /models endpoint.
type ModelInfo struct {
	ID      string `json:"id"`
	Object  string `json:"object,omitempty"`
	OwnedBy string `json:"owned_by,omitempty"`
}

// ListModels calls GET {base_url}/models and returns the available model list.
func ListModels(ctx context.Context, cfg Config) ([]ModelInfo, error) {
	client := defaultHTTPClient

	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/models"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list models request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("list models failed: status=%d body=%s", resp.StatusCode, string(data))
	}

	var parsed struct {
		Data []ModelInfo `json:"data"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse models response: %w", err)
	}
	return parsed.Data, nil
}
