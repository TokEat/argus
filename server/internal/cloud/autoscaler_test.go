package cloud

import (
	"testing"
	"time"

	"github.com/user/dddd-server/internal/db"
)

func TestCalculateScaleUpDecisionColdStartsBelowThreshold(t *testing.T) {
	policy := db.CloudScalingPolicy{
		MaxInstances:     5,
		ScaleUpThreshold: 50,
	}

	needed, reason := calculateScaleUpDecision(&policy, 1, 0, 0, 0)
	if needed != 1 || reason != scaleUpReasonColdStart {
		t.Fatalf("decision = (%d, %s), want (1, %s)", needed, reason, scaleUpReasonColdStart)
	}
}

func TestCalculateScaleUpDecisionDoesNotColdStartWhenInstanceInFlight(t *testing.T) {
	policy := db.CloudScalingPolicy{
		MaxInstances:     5,
		ScaleUpThreshold: 50,
	}

	needed, reason := calculateScaleUpDecision(&policy, 1, 1, 1, 0)
	if needed != 0 || reason != scaleUpReasonNone {
		t.Fatalf("decision = (%d, %s), want no scale up", needed, reason)
	}
}

func TestCalculateScaleUpDecisionMaintainsMinimumInstances(t *testing.T) {
	policy := db.CloudScalingPolicy{
		MinInstances: 2,
		MaxInstances: 5,
	}

	needed, reason := calculateScaleUpDecision(&policy, 0, 0, 0, 0)
	if needed != 2 || reason != scaleUpReasonMinCapacity {
		t.Fatalf("decision = (%d, %s), want (2, %s)", needed, reason, scaleUpReasonMinCapacity)
	}
}

func TestCalculateScaleUpDecisionRespectsThresholdWhenAgentsExist(t *testing.T) {
	policy := db.CloudScalingPolicy{
		MaxInstances:     5,
		ScaleUpThreshold: 50,
	}

	needed, reason := calculateScaleUpDecision(&policy, 49, 1, 0, 1)
	if needed != 0 || reason != scaleUpReasonNone {
		t.Fatalf("decision below threshold = (%d, %s), want no scale up", needed, reason)
	}

	needed, reason = calculateScaleUpDecision(&policy, 307, 1, 0, 1)
	if needed != 2 || reason != scaleUpReasonThreshold {
		t.Fatalf("decision above threshold = (%d, %s), want (2, %s)", needed, reason, scaleUpReasonThreshold)
	}
}

func TestColdStartBypassesCooldown(t *testing.T) {
	lastAction := time.Now()
	policy := db.CloudScalingPolicy{
		MaxInstances:     5,
		ScaleUpThreshold: 50,
		CooldownSeconds:  300,
		LastScaleAction:  &lastAction,
	}

	if !policyInCooldown(&policy) {
		t.Fatalf("expected policy to be in cooldown")
	}

	needed, reason := calculateScaleUpDecision(&policy, 1, 0, 0, 0)
	if needed != 1 || !scaleUpReasonBypassesCooldown(reason) {
		t.Fatalf("cold-start decision = (%d, %s), want cooldown-bypassing scale up", needed, reason)
	}
}
