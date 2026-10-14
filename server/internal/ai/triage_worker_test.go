package ai

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
)

// fakeErrChatClient returns a configurable error, unlike fakeChatClient which always succeeds.
type fakeErrChatClient struct {
	calls int
	raw   string
	err   error
}

func (f *fakeErrChatClient) CompleteJSON(ctx context.Context, cfg Config, messages []ChatMessage) (string, error) {
	f.calls++
	return f.raw, f.err
}
func (f *fakeErrChatClient) CompleteWithTools(ctx context.Context, cfg Config, messages []ChatMessage, tools []ToolDefinition) (string, []ToolCall, error) {
	f.calls++
	return f.raw, nil, f.err
}
func (f *fakeErrChatClient) StreamWithTools(ctx context.Context, cfg Config, messages []ChatMessage, tools []ToolDefinition, onToken func(string), onToolCall func(ToolCall)) (string, []ToolCall, error) {
	f.calls++
	return f.raw, nil, f.err
}

func TestRunTriageTickTriagesOnlyUntriaged(t *testing.T) {
	store := triageTestDB(t)
	seedTriageAIConfig(t, store)
	seedVuln(t, store, func(v *db.Vulnerability) { v.Plugin = "poc-a" })
	seedVuln(t, store, func(v *db.Vulnerability) { v.Plugin = "poc-b" })
	already := seedVuln(t, store, func(v *db.Vulnerability) {
		v.Plugin = "poc-c"
		now := time.Now()
		v.AITriagedAt = &now
		v.AIStatus = VerdictConfirmed
	})

	client := &fakeErrChatClient{raw: `{"verdict":"confirmed","confidence":0.9,"reason":"ok"}`}
	RunTriageTick(context.Background(), store, TriageWorkerOptions{Client: client, BatchSize: 10, Concurrency: 2})
	if client.calls != 2 {
		t.Fatalf("expected 2 LLM calls for 2 untriaged vulns, got %d", client.calls)
	}
	var untriaged int64
	store.Model(&db.Vulnerability{}).Where("ai_triaged_at IS NULL").Count(&untriaged)
	if untriaged != 0 {
		t.Fatalf("all open vulns should be triaged, %d still pending", untriaged)
	}
	if got := reloadVuln(t, store, already.ID); got.AIStatus != VerdictConfirmed {
		t.Fatalf("pre-triaged vuln must be untouched, got %s", got.AIStatus)
	}
}

func TestRunTriageTickDisabled(t *testing.T) {
	store := triageTestDB(t)
	seedTriageAIConfig(t, store)
	if err := store.Save(&db.SystemConfig{Key: TriageConfigKeyEnabled, Value: "false", UpdatedAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	vuln := seedVuln(t, store, nil)
	client := &fakeErrChatClient{raw: `{"verdict":"confirmed"}`}
	RunTriageTick(context.Background(), store, TriageWorkerOptions{Client: client})
	if client.calls != 0 {
		t.Fatalf("disabled worker must not call LLM, calls=%d", client.calls)
	}
	if got := reloadVuln(t, store, vuln.ID).AITriagedAt; got != nil {
		t.Fatalf("disabled worker must not mark triaged")
	}
}

func TestRunTriageTickRetriesOnLLMFailure(t *testing.T) {
	store := triageTestDB(t)
	seedTriageAIConfig(t, store)
	vuln := seedVuln(t, store, nil)
	client := &fakeErrChatClient{raw: "", err: errors.New("llm unreachable")}
	RunTriageTick(context.Background(), store, TriageWorkerOptions{Client: client})
	if got := reloadVuln(t, store, vuln.ID).AITriagedAt; got != nil {
		t.Fatalf("failed triage must leave ai_triaged_at nil so next tick retries")
	}
	// A subsequent healthy tick recovers the same vuln.
	healthy := &fakeErrChatClient{raw: `{"verdict":"confirmed","confidence":0.9,"reason":"ok"}`}
	RunTriageTick(context.Background(), store, TriageWorkerOptions{Client: healthy})
	if got := reloadVuln(t, store, vuln.ID).AITriagedAt; got == nil {
		t.Fatalf("healthy tick should recover the retriable vuln")
	}
}
