package cloud

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/user/dddd-server/internal/db"
	"gorm.io/gorm"
)

func setupAutoScalerTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&db.CloudInstance{}); err != nil {
		t.Fatalf("automigrate cloud instances: %v", err)
	}
	return store
}

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

func TestCapScaleUpCountByActiveInstancesRefreshesBeforeProvisioning(t *testing.T) {
	store := setupAutoScalerTestDB(t)
	as := NewAutoScaler(store, nil)
	policy := db.CloudScalingPolicy{ID: "policy-1", MaxInstances: 3}
	instances := []db.CloudInstance{
		{ID: "ci-1", PolicyID: policy.ID, Status: db.CloudStatusProvisioning},
		{ID: "ci-2", PolicyID: policy.ID, Status: db.CloudStatusRunning},
		{ID: "ci-3", PolicyID: policy.ID, Status: db.CloudStatusError},
	}
	if err := store.Create(&instances).Error; err != nil {
		t.Fatalf("seed cloud instances: %v", err)
	}

	if got := as.capScaleUpCountByActiveInstances(&policy, 5); got != 1 {
		t.Fatalf("capScaleUpCountByActiveInstances = %d, want 1", got)
	}

	if err := store.Create(&db.CloudInstance{ID: "ci-4", PolicyID: policy.ID, Status: db.CloudStatusWaitingReady}).Error; err != nil {
		t.Fatalf("seed waiting instance: %v", err)
	}
	if got := as.capScaleUpCountByActiveInstances(&policy, 5); got != 0 {
		t.Fatalf("capScaleUpCountByActiveInstances after reaching max = %d, want 0", got)
	}
}
