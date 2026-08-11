package db

import "testing"

func TestTaskConfigHashCoversExecutionInputs(t *testing.T) {
	base := TaskConfigHash(`{"NoPoc":true}`, 1, 60, `{}`, `{}`)
	if base == "" || base != TaskConfigHash(`{"NoPoc":true}`, 1, 60, `{}`, `{}`) {
		t.Fatal("task config hash must be stable")
	}
	variants := []string{
		TaskConfigHash(`{"NoPoc":false}`, 1, 60, `{}`, `{}`),
		TaskConfigHash(`{"NoPoc":true}`, 2, 60, `{}`, `{}`),
		TaskConfigHash(`{"NoPoc":true}`, 1, 120, `{}`, `{}`),
		TaskConfigHash(`{"NoPoc":true}`, 1, 60, `{"zone":"office"}`, `{}`),
		TaskConfigHash(`{"NoPoc":true}`, 1, 60, `{}`, `{"not_match":{"maintenance":"true"}}`),
	}
	for i, variant := range variants {
		if variant == base {
			t.Fatalf("variant %d did not affect config hash", i)
		}
	}
}
