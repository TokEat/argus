package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ChatClient interface {
	CompleteJSON(ctx context.Context, cfg Config, messages []ChatMessage) (string, error)
}

type HTTPClient struct {
	Client *http.Client
}

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func (c *HTTPClient) CompleteJSON(ctx context.Context, cfg Config, messages []ChatMessage) (string, error) {
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second}
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
