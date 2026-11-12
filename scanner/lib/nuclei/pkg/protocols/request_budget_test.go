package protocols

import (
	"errors"
	"testing"
)

func TestRequestBudgetFailsClosedBeforeRequestBeyondLimit(t *testing.T) {
	budget := NewRequestBudget(2)
	if err := budget.Take(); err != nil {
		t.Fatal(err)
	}
	if err := budget.Take(); err != nil {
		t.Fatal(err)
	}
	if err := budget.Take(); !errors.Is(err, ErrRequestBudgetExceeded) {
		t.Fatalf("third request error=%v", err)
	}
	if !budget.Exceeded() {
		t.Fatal("budget did not retain exceeded state for runner propagation")
	}
}

func TestZeroRequestBudgetPreservesUpstreamUnlimitedBehavior(t *testing.T) {
	if budget := NewRequestBudget(0); budget != nil {
		t.Fatalf("zero request budget should be disabled, got %+v", budget)
	}
	var budget *RequestBudget
	if err := budget.Take(); err != nil {
		t.Fatalf("nil request budget should be unlimited: %v", err)
	}
}
