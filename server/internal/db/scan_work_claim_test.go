package db

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func seedScanWorkClaimDestination(t *testing.T, fixture scanReuseFixture, suffix string, trigger string, batchKind string) (TaskBatch, SubTask) {
	t.Helper()
	rootID := "task-" + suffix
	batchID := "batch-" + suffix
	attemptID := "attempt-" + suffix
	root := RootTask{
		ID: rootID, TenantID: fixture.project.TenantID, ProjectID: fixture.project.ID,
		Status: "Queued", TotalChunks: 1, TotalTargets: 1,
	}
	batch := TaskBatch{
		ID: batchID, TenantID: fixture.project.TenantID, ProjectID: fixture.project.ID, RootTaskID: rootID,
		Sequence: 0, Kind: batchKind, Targets: fixture.attempt.ChunkTargets, TargetCount: 1, Status: "Pending",
		ControlState: string(BatchControlActive), ConfigVersion: 1, RuleVersion: fixture.attempt.RuleVersion,
		LatestAttemptID: attemptID, CurrentAttemptNo: 1, AttemptCount: 1,
	}
	attempt := fixture.attempt
	attempt.ID = attemptID
	attempt.RootTaskID = rootID
	attempt.BatchID = batchID
	attempt.Trigger = trigger
	attempt.Status = "Pending"
	attempt.AgentID = ""
	attempt.StreamMsgID = ""
	attempt.StartedAt = nil
	attempt.FinishedAt = nil
	if err := fixture.store.Create(&root).Error; err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Create(&batch).Error; err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Create(&attempt).Error; err != nil {
		t.Fatal(err)
	}
	return batch, attempt
}

func acquireScanWorkClaimFixture(t *testing.T, store *gorm.DB, plan ScanWorkClaimPlan) ScanWorkClaimAcquireResult {
	t.Helper()
	var acquired ScanWorkClaimAcquireResult
	if err := store.Transaction(func(tx *gorm.DB) error {
		var err error
		acquired, err = AcquireScanWorkClaimsAtLease(tx, plan)
		if err != nil || acquired.Conflict {
			return err
		}
		updated := tx.Model(&SubTask{}).Where(
			"id = ? AND tenant_id = ? AND status IN ?", plan.AttemptID, plan.TenantID, []string{"Pending", "Dispatching", "Recovered"},
		).Updates(map[string]interface{}{"status": "Running", "agent_id": plan.AgentID, "stream_msg_id": "lease-message"})
		if updated.Error != nil {
			return updated.Error
		}
		for index := range acquired.Links {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&acquired.Links[index]).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("acquire scan work claim: %v", err)
	}
	if acquired.Conflict || len(acquired.Claims) == 0 {
		t.Fatalf("unexpected scan work claim acquisition: %+v", acquired)
	}
	return acquired
}

func TestScanWorkClaimAttachesDuplicateExecutionWithoutAgentLease(t *testing.T) {
	fixture := newScanReuseFixture(t, []string{"https://duplicate.example.test"})
	_, waiter := seedScanWorkClaimDestination(t, fixture, "waiter", AttemptTriggerInitial, "asset_scan")

	ownerPlan, err := PlanScanWorkClaimsAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a", nil)
	if err != nil || !ownerPlan.Enabled || len(ownerPlan.Claims) != 1 {
		t.Fatalf("owner plan=%+v err=%v", ownerPlan, err)
	}
	acquired := acquireScanWorkClaimFixture(t, fixture.store, ownerPlan)
	if acquired.Claims[0].OwnerAttemptID != fixture.attempt.ID {
		t.Fatalf("wrong claim owner: %+v", acquired.Claims[0])
	}

	waiterPlan, err := PlanScanWorkClaimsAtClaim(fixture.store, waiter.ID, waiter.TenantID, "agent-a", nil)
	if err != nil || !waiterPlan.Enabled || waiterPlan.Claims[0].WorkKeyHash != ownerPlan.Claims[0].WorkKeyHash {
		t.Fatalf("waiter plan=%+v err=%v", waiterPlan, err)
	}
	for pass := 0; pass < 2; pass++ {
		attached, count, err := AttachAttemptToActiveWorkClaims(fixture.store, waiterPlan)
		if err != nil || !attached || count != 1 {
			t.Fatalf("attach pass %d attached=%v count=%d err=%v", pass, attached, count, err)
		}
	}

	var parked SubTask
	if err := fixture.store.First(&parked, "id = ?", waiter.ID).Error; err != nil {
		t.Fatal(err)
	}
	if parked.Status != "Pending" || parked.AgentID != "" || !strings.HasPrefix(parked.StreamMsgID, scanWorkClaimMarkerPrefix) {
		t.Fatalf("duplicate execution consumed a lease: %+v", parked)
	}
	var claimCount, linkCount int64
	fixture.store.Model(&ScanWorkClaim{}).Count(&claimCount)
	fixture.store.Model(&TaskCoverageLink{}).Where("attempt_id = ? AND link_type = ?", waiter.ID, taskCoverageLinkInFlight).Count(&linkCount)
	if claimCount != 1 || linkCount != 1 {
		t.Fatalf("claim/link count=%d/%d, want 1/1", claimCount, linkCount)
	}
}

func TestResolveCompletedScanWorkClaimReplansWaiter(t *testing.T) {
	fixture := newScanReuseFixture(t, []string{"https://completed.example.test"})
	_, waiter := seedScanWorkClaimDestination(t, fixture, "completed-waiter", AttemptTriggerInitial, "asset_scan")
	ownerPlan, _ := PlanScanWorkClaimsAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a", nil)
	acquired := acquireScanWorkClaimFixture(t, fixture.store, ownerPlan)
	waiterPlan, _ := PlanScanWorkClaimsAtClaim(fixture.store, waiter.ID, waiter.TenantID, "agent-a", nil)
	if attached, _, err := AttachAttemptToActiveWorkClaims(fixture.store, waiterPlan); err != nil || !attached {
		t.Fatalf("attach waiter: attached=%v err=%v", attached, err)
	}
	finished := time.Now().UTC()
	if err := fixture.store.Model(&SubTask{}).Where("id = ?", fixture.attempt.ID).Updates(map[string]interface{}{
		"status": "Done", "finished_at": finished,
	}).Error; err != nil {
		t.Fatal(err)
	}

	ready, err := ResolveScanWorkClaimsForAttempt(fixture.store, fixture.attempt.ID)
	if err != nil || len(ready) != 1 || ready[0].ID != waiter.ID || ready[0].Status != "Dispatching" {
		t.Fatalf("resolved waiters=%+v err=%v", ready, err)
	}
	var claim ScanWorkClaim
	if err := fixture.store.First(&claim, acquired.Claims[0].ID).Error; err != nil {
		t.Fatal(err)
	}
	if claim.Status != scanWorkClaimStatusComplete || claim.ReleasedAt == nil || claim.LeaseExpiresAt != nil {
		t.Fatalf("completed claim not released: %+v", claim)
	}
	var waiterLink, executedLink TaskCoverageLink
	if err := fixture.store.Where("attempt_id = ? AND link_type = ?", waiter.ID, taskCoverageLinkInFlight).First(&waiterLink).Error; err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Where("attempt_id = ? AND link_type = ?", fixture.attempt.ID, taskCoverageLinkExecuted).First(&executedLink).Error; err != nil {
		t.Fatal(err)
	}
	if waiterLink.Status != "resolved" || executedLink.Status != scanWorkClaimStatusComplete {
		t.Fatalf("settled links waiter=%+v executed=%+v", waiterLink, executedLink)
	}
}

func TestFailedScanWorkClaimReplansAndRecyclesSingleClaim(t *testing.T) {
	fixture := newScanReuseFixture(t, []string{"https://failed.example.test"})
	_, waiter := seedScanWorkClaimDestination(t, fixture, "failed-waiter", AttemptTriggerInitial, "asset_scan")
	ownerPlan, _ := PlanScanWorkClaimsAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a", nil)
	first := acquireScanWorkClaimFixture(t, fixture.store, ownerPlan)
	waiterPlan, _ := PlanScanWorkClaimsAtClaim(fixture.store, waiter.ID, waiter.TenantID, "agent-a", nil)
	if attached, _, err := AttachAttemptToActiveWorkClaims(fixture.store, waiterPlan); err != nil || !attached {
		t.Fatalf("attach waiter: attached=%v err=%v", attached, err)
	}
	if err := fixture.store.Model(&SubTask{}).Where("id = ?", fixture.attempt.ID).Updates(map[string]interface{}{
		"status": "Failed", "failure_reason": "source failed",
	}).Error; err != nil {
		t.Fatal(err)
	}
	ready, err := ResolveScanWorkClaimsForAttempt(fixture.store, fixture.attempt.ID)
	if err != nil || len(ready) != 1 {
		t.Fatalf("resolve failed source ready=%+v err=%v", ready, err)
	}
	if err := fixture.store.Model(&SubTask{}).Where("id = ?", waiter.ID).Updates(map[string]interface{}{
		"status": "Pending", "stream_msg_id": "queued",
	}).Error; err != nil {
		t.Fatal(err)
	}
	replanned, err := PlanScanWorkClaimsAtClaim(fixture.store, waiter.ID, waiter.TenantID, "agent-a", nil)
	if err != nil || !replanned.Enabled {
		t.Fatalf("replan=%+v err=%v", replanned, err)
	}
	second := acquireScanWorkClaimFixture(t, fixture.store, replanned)
	var claimCount int64
	fixture.store.Model(&ScanWorkClaim{}).Count(&claimCount)
	if claimCount != 1 || second.Claims[0].ID != first.Claims[0].ID || second.Claims[0].Revision != first.Claims[0].Revision+1 || second.Claims[0].OwnerAttemptID != waiter.ID {
		t.Fatalf("claim was not safely recycled first=%+v second=%+v count=%d", first.Claims[0], second.Claims[0], claimCount)
	}
	var waitingLink TaskCoverageLink
	if err := fixture.store.Where("attempt_id = ? AND link_type = ?", waiter.ID, taskCoverageLinkInFlight).First(&waitingLink).Error; err != nil {
		t.Fatal(err)
	}
	if waitingLink.Status != "source_failed" {
		t.Fatalf("failed source provenance was overwritten: %+v", waitingLink)
	}
}

func TestScanWorkClaimSafetyBypassAndNetworkZoneIsolation(t *testing.T) {
	fixture := newScanReuseFixture(t, []string{"https://isolated.example.test"})
	if err := fixture.store.Create(&Node{AgentID: "agent-b", TenantID: fixture.project.TenantID, Status: "Alive"}).Error; err != nil {
		t.Fatal(err)
	}
	_, manual := seedScanWorkClaimDestination(t, fixture, "manual", AttemptTriggerManualRetry, "asset_scan")
	_, risk := seedScanWorkClaimDestination(t, fixture, "risk", AttemptTriggerInitial, "risk_validation")
	for name, attempt := range map[string]SubTask{"manual": manual, "risk": risk} {
		plan, err := PlanScanWorkClaimsAtClaim(fixture.store, attempt.ID, attempt.TenantID, "agent-a", nil)
		if err != nil || plan.Enabled {
			t.Fatalf("%s bypass plan=%+v err=%v", name, plan, err)
		}
	}
	planA, err := PlanScanWorkClaimsAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a", nil)
	if err != nil || !planA.Enabled {
		t.Fatalf("agent-a plan=%+v err=%v", planA, err)
	}
	planB, err := PlanScanWorkClaimsAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-b", nil)
	if err != nil || !planB.Enabled || planA.Claims[0].WorkKeyHash == planB.Claims[0].WorkKeyHash {
		t.Fatalf("agent zones were merged: a=%+v b=%+v err=%v", planA, planB, err)
	}
	var targets []string
	if err := json.Unmarshal([]byte(fixture.attempt.ChunkTargets), &targets); err != nil || len(targets) != 1 {
		t.Fatalf("fixture targets changed: %v %v", targets, err)
	}
}

func TestPlanScanWorkClaimsUsesPublicAndPrivateNetworkZones(t *testing.T) {
	for _, test := range []struct {
		name       string
		target     string
		agentATags string
		agentBTags string
		wantSame   bool
		wantZone   string
	}{
		{name: "public shared across Agents", target: "https://example.com", wantSame: true, wantZone: "public"},
		{name: "same private label shared", target: "http://10.0.0.8", agentATags: `{"network_zone":"corp"}`, agentBTags: `{"network_zone":"corp"}`, wantSame: true, wantZone: "private:corp"},
		{name: "different private labels isolated", target: "http://10.0.0.8", agentATags: `{"network_zone":"corp-a"}`, agentBTags: `{"network_zone":"corp-b"}`, wantSame: false, wantZone: "private:corp-a"},
		{name: "unlabelled private Agents isolated", target: "http://10.0.0.8", wantSame: false, wantZone: "agent:agent-a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newScanReuseFixture(t, []string{test.target})
			if err := fixture.store.Model(&Node{}).Where("agent_id = ?", "agent-a").Update("tags", test.agentATags).Error; err != nil {
				t.Fatal(err)
			}
			if err := fixture.store.Create(&Node{AgentID: "agent-b", TenantID: fixture.attempt.TenantID, Status: "Alive", Tags: test.agentBTags}).Error; err != nil {
				t.Fatal(err)
			}
			planA, err := PlanScanWorkClaimsAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-a", nil)
			if err != nil || !planA.Enabled || len(planA.Claims) != 1 {
				t.Fatalf("agent-a plan=%+v err=%v", planA, err)
			}
			planB, err := PlanScanWorkClaimsAtClaim(fixture.store, fixture.attempt.ID, fixture.attempt.TenantID, "agent-b", nil)
			if err != nil || !planB.Enabled || len(planB.Claims) != 1 {
				t.Fatalf("agent-b plan=%+v err=%v", planB, err)
			}
			if same := planA.Claims[0].WorkKeyHash == planB.Claims[0].WorkKeyHash; same != test.wantSame {
				t.Fatalf("WorkKey sameness=%v, want %v; a=%+v b=%+v", same, test.wantSame, planA.Claims[0], planB.Claims[0])
			}
			if planA.Claims[0].NetworkZone != test.wantZone {
				t.Fatalf("agent-a zone=%q, want %q", planA.Claims[0].NetworkZone, test.wantZone)
			}
		})
	}
}
