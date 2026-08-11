package agent

import (
	"errors"
	"testing"
)

func TestCompleteNucleiDebugReportsExecutionFailure(t *testing.T) {
	var message string
	completeNucleiDebug(func(value string) { message = value }, errors.New("runner failed"))
	if message != "runner failed" {
		t.Fatalf("completion message = %q", message)
	}
}
