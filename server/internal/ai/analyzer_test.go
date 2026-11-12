package ai

import (
	"context"
	"errors"
	"testing"

	"github.com/TokEat/argus/server/internal/db"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type fakeChatClient struct {
	calls int
	raw   string
}

func (f *fakeChatClient) CompleteJSON(ctx context.Context, cfg Config, messages []ChatMessage) (string, error) {
	f.calls++
	return f.raw, nil
}

func (f *fakeChatClient) CompleteWithTools(ctx context.Context, cfg Config, messages []ChatMessage, tools []ToolDefinition) (string, []ToolCall, error) {
	f.calls++
	return f.raw, nil, nil
}

func (f *fakeChatClient) StreamWithTools(ctx context.Context, cfg Config, messages []ChatMessage, tools []ToolDefinition, onToken func(token string), onToolCall func(toolCall ToolCall)) (string, []ToolCall, error) {
	f.calls++
	if onToken != nil {
		onToken(f.raw)
	}
	return f.raw, nil, nil
}

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	store, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&db.SystemConfig{}, &db.PocRule{}, &db.WorkflowRule{}, &db.ArsenalAIReview{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return store
}

func TestAnalyzerRequiresAIConfig(t *testing.T) {
	store := testDB(t)
	analyzer := Analyzer{DB: store, Client: &fakeChatClient{}}
	_, err := analyzer.Analyze(context.Background(), AnalyzeRequest{
		TenantID: "default",
		Type:     ArsenalTypePOC,
		Content:  validTemplate(),
	})
	if !errors.Is(err, ErrMissingConfig) {
		t.Fatalf("expected ErrMissingConfig, got %v", err)
	}
}

func TestPublicConfigMasksAPIKey(t *testing.T) {
	store := testDB(t)
	if err := SaveConfig(store, Config{BaseURL: "http://llm.local/v1", APIKey: "secret-token", Model: "test-model"}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	cfg, err := PublicConfigFromStore(store)
	if err != nil {
		t.Fatalf("public config: %v", err)
	}
	if !cfg.HasAPIKey || cfg.APIKey != "" || cfg.APIKeyMasked == "secret-token" || cfg.APIKeyMasked == "" {
		t.Fatalf("expected masked public key, got %+v", cfg)
	}
}

func TestStaticChecksFindInvalidYAMLAndDangerousPayload(t *testing.T) {
	result := runStaticChecks(context.Background(), nil, "default", "bad.yaml", "id: [", "hash")
	if len(result.Issues) == 0 || result.Issues[0].Category != "syntax" {
		t.Fatalf("expected syntax issue, got %+v", result.Issues)
	}

	danger := runStaticChecks(context.Background(), nil, "default", "danger.yaml", dangerousTemplate(), "hash")
	foundCritical := false
	for _, issue := range danger.Issues {
		if issue.Severity == "critical" && issue.Category == "safety" {
			foundCritical = true
		}
	}
	if !foundCritical {
		t.Fatalf("expected critical safety issue, got %+v", danger.Issues)
	}
}

func TestAnalyzerCachesByContentHashAndForceBypassesCache(t *testing.T) {
	store := testDB(t)
	if err := SaveConfig(store, Config{BaseURL: "http://llm.local/v1", APIKey: "test-key", Model: "test-model"}); err != nil {
		t.Fatalf("save config: %v", err)
	}
	client := &fakeChatClient{raw: `{"suggestion":"Approve","confidence":0.91,"summary":"检测测试模板","reason":"结构完整且匹配条件明确","issues":[]}`}
	analyzer := Analyzer{DB: store, Client: client}
	req := AnalyzeRequest{
		TenantID: "default",
		UserID:   "tester",
		Type:     ArsenalTypePOC,
		FileName: "test-poc.yaml",
		Content:  validTemplate(),
	}

	first, err := analyzer.Analyze(context.Background(), req)
	if err != nil {
		t.Fatalf("first analyze: %v", err)
	}
	if client.calls != 1 || first.Cached {
		t.Fatalf("expected first llm call without cache, calls=%d cached=%v", client.calls, first.Cached)
	}

	second, err := analyzer.Analyze(context.Background(), req)
	if err != nil {
		t.Fatalf("second analyze: %v", err)
	}
	if client.calls != 1 || !second.Cached {
		t.Fatalf("expected cache hit, calls=%d cached=%v", client.calls, second.Cached)
	}

	req.Force = true
	third, err := analyzer.Analyze(context.Background(), req)
	if err != nil {
		t.Fatalf("force analyze: %v", err)
	}
	if client.calls != 2 || third.Cached {
		t.Fatalf("expected force to bypass cache, calls=%d cached=%v", client.calls, third.Cached)
	}
}

func validTemplate() string {
	return `id: test-poc

info:
  name: Test POC
  author: tester
  severity: medium
  tags: test

http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "ok"
`
}

func dangerousTemplate() string {
	return `id: dangerous-poc

info:
  name: Dangerous POC
  author: tester
  severity: high

http:
  - method: POST
    path:
      - "{{BaseURL}}/run"
    body: "cmd=/bin/bash -c 'rm -rf /tmp/demo'"
    matchers:
      - type: word
        words:
          - "ok"
`
}
