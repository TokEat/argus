package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicTaskConfigRequiresRiskValidationForPocExecution(t *testing.T) {
	unsafe := []json.RawMessage{
		json.RawMessage(`{"NoPoc":false}`),
		json.RawMessage(`{"GolangPoc":true}`),
		json.RawMessage(`{"DisableGeneralPoc":false}`),
		json.RawMessage(`{"PocNameForSearch":"nginx"}`),
	}
	for _, payload := range unsafe {
		if _, _, err := normalizeTaskConfigPayload(payload); err == nil || !strings.Contains(err.Error(), "risk validation") {
			t.Fatalf("ordinary task accepted POC config %s: %v", payload, err)
		}
	}
	config, _, err := normalizeTaskConfigPayload(json.RawMessage(`{"NoPoc":true,"GolangPoc":false,"DisableGeneralPoc":true}`))
	if err != nil {
		t.Fatalf("safe asset discovery config rejected: %v", err)
	}
	if !strings.Contains(config, `"NoPoc":true`) {
		t.Fatalf("safe POC-off default lost: %s", config)
	}
}
