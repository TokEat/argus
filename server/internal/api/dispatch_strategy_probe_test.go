package api

import (
	"fmt"
	"testing"
)

// TestGroupAndBatchTargetsHundredIPFullPort probes the concrete dispatch plan
// for 100 full-port-scan IPs: batch count, batch size, target type, and agent
// selector per batch.
func TestGroupAndBatchTargetsHundredIPFullPort(t *testing.T) {
	targets := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		targets = append(targets, fmt.Sprintf("10.0.%d.%d", i/250, i%250+1))
	}

	groups := groupAndBatchTargets(targets, taskTargetModeDirect)
	t.Logf("100 IPs -> %d batches", len(groups))
	for i, group := range groups {
		t.Logf("batch[%d] type=%s size=%d selector=%s first=%s last=%s",
			i, group.TargetType, len(group.Targets), group.SelectorJSON, group.Targets[0], group.Targets[len(group.Targets)-1])
	}

	if len(groups) != 2 {
		t.Fatalf("100 ip targets must split into 2 batches of 50, got %d", len(groups))
	}
	for _, group := range groups {
		if group.TargetType != "ip" || len(group.Targets) != 50 {
			t.Fatalf("unexpected batch: type=%s size=%d", group.TargetType, len(group.Targets))
		}
		if group.SelectorJSON != `{"target_type": "ip"}` {
			t.Fatalf("unexpected selector: %s", group.SelectorJSON)
		}
	}
}
