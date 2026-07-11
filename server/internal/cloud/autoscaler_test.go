package cloud

import (
	"context"
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
	if err := store.AutoMigrate(&db.CloudAccount{}, &db.CloudScalingPolicy{}, &db.CloudInstance{}, &db.Node{}); err != nil {
		t.Fatalf("automigrate cloud models: %v", err)
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

func TestCapAutomaticScaleUpCountLimitsLargeCycle(t *testing.T) {
	if got := capAutomaticScaleUpCount(60); got != 10 {
		t.Fatalf("capAutomaticScaleUpCount(60) = %d, want 10", got)
	}
}

func TestCapAutomaticScaleUpCountPreservesSmallerDecision(t *testing.T) {
	for _, needed := range []int64{0, 1, 9, 10} {
		if got := capAutomaticScaleUpCount(needed); got != needed {
			t.Fatalf("capAutomaticScaleUpCount(%d) = %d, want %d", needed, got, needed)
		}
	}
}

func TestAutomaticScaleUpDecisionRespectsRemainingCapacityBeforeCycleCap(t *testing.T) {
	policy := db.CloudScalingPolicy{
		MaxInstances:     7,
		ScaleUpThreshold: 0,
	}

	needed, reason := calculateScaleUpDecision(&policy, 60*256, 0, 0, 1)
	if reason != scaleUpReasonThreshold || needed != 7 {
		t.Fatalf("decision = (%d, %s), want (7, %s)", needed, reason, scaleUpReasonThreshold)
	}
	if got := capAutomaticScaleUpCount(needed); got != 7 {
		t.Fatalf("capAutomaticScaleUpCount(%d) = %d, want remaining capacity 7", needed, got)
	}
}

func TestEvaluatePolicyCapsAutomaticScaleUpCycle(t *testing.T) {
	store := setupAutoScalerTestDB(t)
	policy := db.CloudScalingPolicy{
		ID:               "policy-cycle-cap",
		CloudAccountID:   "missing-account",
		Name:             "cycle cap",
		MaxInstances:     100,
		ScaleUpThreshold: 0,
	}
	if err := store.Create(&policy).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	if err := store.Create(&db.Node{AgentID: "alive-agent", TenantID: "default", Status: "Alive"}).Error; err != nil {
		t.Fatalf("seed alive agent: %v", err)
	}

	var got int
	autoScaler := NewAutoScaler(store, nil)
	autoScaler.scaleUpOverride = func(_ context.Context, _ *db.CloudScalingPolicy, count int, _, _ string) {
		got = count
	}
	autoScaler.evaluatePolicy(context.Background(), &policy, 60*256)
	if got != 10 {
		t.Fatalf("automatic scale-up count = %d, want 10", got)
	}
}

func TestScaleUpManualDoesNotApplyAutomaticCycleCap(t *testing.T) {
	store := setupAutoScalerTestDB(t)
	policy := db.CloudScalingPolicy{
		ID:             "policy-manual-no-cycle-cap",
		CloudAccountID: "missing-account",
		Name:           "manual no cycle cap",
		MaxInstances:   100,
	}
	if err := store.Create(&policy).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	var got int
	autoScaler := NewAutoScaler(store, nil)
	autoScaler.scaleUpOverride = func(_ context.Context, _ *db.CloudScalingPolicy, count int, _, _ string) {
		got = count
	}
	autoScaler.ScaleUpManual(context.Background(), &policy, 60, "", "")
	if got != 60 {
		t.Fatalf("manual scale-up count = %d, want 60", got)
	}
}

func TestColdStartRespectsCooldown(t *testing.T) {
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
	if needed != 1 || reason != scaleUpReasonColdStart {
		t.Fatalf("cold-start decision = (%d, %s), want a decision that evaluatePolicy gates on cooldown", needed, reason)
	}
}

func TestEvaluatePolicyDoesNotBypassCooldownForColdStart(t *testing.T) {
	store := setupAutoScalerTestDB(t)
	lastAction := time.Now().Add(-time.Minute).UTC().Truncate(time.Millisecond)
	policy := db.CloudScalingPolicy{
		ID:               "policy-cold-start-cooldown",
		CloudAccountID:   "missing-account",
		Name:             "cold start cooldown",
		MaxInstances:     1,
		ScaleUpThreshold: 50,
		CooldownSeconds:  300,
		LastScaleAction:  &lastAction,
	}
	if err := store.Create(&policy).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	as := NewAutoScaler(store, nil)
	as.evaluatePolicy(context.Background(), &policy, 1)

	var got db.CloudScalingPolicy
	if err := store.First(&got, "id = ?", policy.ID).Error; err != nil {
		t.Fatalf("reload policy: %v", err)
	}
	if got.LastScaleAction == nil || !got.LastScaleAction.Equal(lastAction) {
		t.Fatalf("cold start bypassed cooldown: last_scale_action=%v want=%v", got.LastScaleAction, lastAction)
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

func TestIsFatalProvisionError(t *testing.T) {
	tests := []struct {
		message string
		want    bool
	}{
		{message: "NotEnoughBalance: account balance is insufficient", want: true},
		{message: "Forbidden.RiskControl", want: true},
		{message: "InvalidParameter.InstanceType", want: true},
		{message: "QuotaExceeded", want: true},
		{message: "Throttling.User", want: true},
		{message: "InvalidAccessKeyId.NotFound", want: true},
		{message: "SignatureDoesNotMatch", want: true},
		{message: "decrypt access_key_secret: invalid ciphertext", want: true},
		{message: "unsupported cloud provider: demo", want: true},
		{message: "该云凭证尚未配置地域", want: true},
		{message: "该云凭证未配置 OSS", want: true},
		{message: "NoStock: instance type unavailable", want: false},
		{message: "InternalError: retry later", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			if got := isFatalProvisionError(tt.message); got != tt.want {
				t.Fatalf("isFatalProvisionError(%q) = %v, want %v", tt.message, got, tt.want)
			}
		})
	}
}

func TestScaleUpOutcomeRequiresCooldown(t *testing.T) {
	tests := []struct {
		name       string
		successes  int64
		fatalFails int64
		want       bool
	}{
		{name: "successful provision", successes: 1, want: true},
		{name: "fatal failure", fatalFails: 1, want: true},
		{name: "transient failures only", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scaleUpOutcomeRequiresCooldown(tt.successes, tt.fatalFails); got != tt.want {
				t.Fatalf("scaleUpOutcomeRequiresCooldown(%d, %d) = %v, want %v", tt.successes, tt.fatalFails, got, tt.want)
			}
		})
	}
}

func TestScaleUpMissingAccountStartsCooldown(t *testing.T) {
	store := setupAutoScalerTestDB(t)
	policy := db.CloudScalingPolicy{
		ID:             "policy-missing-account",
		CloudAccountID: "missing-account",
		Name:           "missing account",
		MaxInstances:   1,
	}
	if err := store.Create(&policy).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	as := NewAutoScaler(store, nil)
	as.scaleUp(context.Background(), &policy, 1, "", "")

	var got db.CloudScalingPolicy
	if err := store.First(&got, "id = ?", policy.ID).Error; err != nil {
		t.Fatalf("reload policy: %v", err)
	}
	if got.LastScaleAction == nil {
		t.Fatal("missing cloud account did not start scale-up cooldown")
	}
}

func TestScaleUpManagerInitializationFailureStartsCooldown(t *testing.T) {
	store := setupAutoScalerTestDB(t)
	account := db.CloudAccount{
		ID:              "invalid-credentials",
		Name:            "invalid credentials",
		Provider:        "aliyun",
		AccessKeyID:     "not-base64",
		AccessKeySecret: "not-base64",
		Status:          "active",
	}
	if err := store.Create(&account).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}
	policy := db.CloudScalingPolicy{
		ID:             "policy-invalid-credentials",
		CloudAccountID: account.ID,
		Name:           "invalid credentials",
		MaxInstances:   1,
	}
	if err := store.Create(&policy).Error; err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	as := NewAutoScaler(store, nil)
	as.scaleUp(context.Background(), &policy, 1, "", "")

	var got db.CloudScalingPolicy
	if err := store.First(&got, "id = ?", policy.ID).Error; err != nil {
		t.Fatalf("reload policy: %v", err)
	}
	if got.LastScaleAction == nil {
		t.Fatal("manager initialization failure did not start scale-up cooldown")
	}
}
