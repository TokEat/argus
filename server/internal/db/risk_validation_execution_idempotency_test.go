package db

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func riskValidationExecutionIdempotencyDraft() RiskValidationIdempotencyDraft {
	return RiskValidationIdempotencyDraft{TenantID: "tenant-a", ProjectID: "project-a", RootTaskID: "task-a", OperatorID: "operator-a", Operation: "execute_risk_validation_v1", IdempotencyKey: "key-a", RequestHash: strings.Repeat("a", 64), PlanHash: strings.Repeat("b", 64), POCSetHash: strings.Repeat("c", 64), ConfigVersion: 1, ConfigHash: strings.Repeat("d", 64), RuleVersion: "rules-v1", BatchID: "batch-a", BatchSequence: 0, AttemptID: "attempt-a", AttemptNo: 1, CandidateCount: 2, TargetCount: 1, POCCount: 1, EstimatedRequests: 3, SecondConfirmationRequired: true, BeforeStatus: "Completed", AfterStatus: "Running"}
}

func TestRiskValidationIdempotencyReplayConflictAndSafeModel(t *testing.T) {
	store := openTaskBatchRetryIdempotencyTestDB(t)
	if err := store.AutoMigrate(&RiskValidationExecutionIdempotency{}); err != nil {
		t.Fatal(err)
	}
	draft := riskValidationExecutionIdempotencyDraft()
	first, err := RecordRiskValidationIdempotencyTx(store, draft)
	if err != nil || first.Replayed || first.Record.IdempotencyKeyHash == draft.IdempotencyKey || !validRiskValidationExecutionIdempotencyHash(first.Record.IdempotencyKeyHash) {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	replayed, err := RecordRiskValidationIdempotencyTx(store, draft)
	if err != nil || !replayed.Replayed || replayed.Record.ID != first.Record.ID || replayed.Record.BatchID != first.Record.BatchID {
		t.Fatalf("replay=%#v err=%v", replayed, err)
	}
	_, err = LookupRiskValidationIdempotencyTx(store, draft.TenantID, draft.ProjectID, draft.RootTaskID, draft.OperatorID, draft.Operation, draft.IdempotencyKey, strings.Repeat("e", 64))
	if !errors.Is(err, ErrRiskValidationIdempotencyConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
	model := reflect.TypeOf(RiskValidationExecutionIdempotency{})
	for i := 0; i < model.NumField(); i++ {
		name := strings.ToLower(model.Field(i).Name)
		for _, forbidden := range []string{"poccontent", "provider", "credential", "token", "query"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("unsafe ledger field %s", model.Field(i).Name)
			}
		}
	}
}

func TestRiskValidationIdempotencyValidation(t *testing.T) {
	draft := riskValidationExecutionIdempotencyDraft()
	draft.POCSetHash = strings.Repeat("A", 64)
	if _, err := RecordRiskValidationIdempotencyTx(openTaskBatchRetryIdempotencyTestDB(t), draft); err == nil {
		t.Fatal("expected invalid hash rejection")
	}
}
