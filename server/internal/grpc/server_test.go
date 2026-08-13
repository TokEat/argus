package grpc

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/scheduler"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"github.com/glebarez/sqlite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
)

const grpcReusableTestConfig = `{"Hunter":false,"Fofa":false,"Quake":false,"OnlyIPPort":false,"Subdomain":true,"SkipHostDiscovery":false,"NoICMPPing":false,"TCPPing":false,"NoHostBind":true,"NoDirSearch":true,"NoPoc":true,"GolangPoc":false,"DisableGeneralPoc":true,"PocNameForSearch":""}`

func TestAttestedAgentTagsCannotSpoofTransportTLS(t *testing.T) {
	plain := attestedAgentTags(context.Background(), map[string]string{
		"transport_tls": "verified",
		"zone":          "private-a",
	})
	if _, exists := plain["transport_tls"]; exists {
		t.Fatal("plaintext Agent was allowed to self-assert transport_tls")
	}
	if plain["zone"] != "private-a" {
		t.Fatalf("ordinary Agent tag was lost: %#v", plain)
	}

	tlsContext := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{
		State: tls.ConnectionState{Version: tls.VersionTLS13},
	}})
	attested := attestedAgentTags(tlsContext, map[string]string{"transport_tls": "spoofed"})
	if attested["transport_tls"] != "verified" {
		t.Fatalf("TLS transport was not server-attested: %#v", attested)
	}
}

func setupRegisterTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	store, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := store.AutoMigrate(&db.SystemConfig{}, &db.Node{}, &db.CloudInstance{}, &db.Project{}, &db.RootTask{}, &db.TaskBatch{}, &db.SubTask{}, &db.TaskConfigRevision{}, &db.TenantQuota{}, &db.ScanObservation{}, &db.ScanCoverage{}, &db.ScanWorkClaim{}, &db.TaskCoverageLink{}, &db.ScanTimingEvent{}, &db.CredentialBundle{}, &db.CredentialFindingSecret{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	old := db.DB
	db.DB = store
	t.Cleanup(func() {
		db.DB = old
	})
	return store
}

func validStageObservationEvent() scanplan.StageObservationEvent {
	now := time.Now().UTC()
	return scanplan.StageObservationEvent{
		SchemaVersion: scanplan.SchemaVersion,
		EventID:       "event-a",
		AttemptID:     "attempt-coverage",
		AgentID:       "agent-coverage",
		Stage:         scanplan.StageHTTPProbe,
		Outcome:       scanplan.ObservationNegative,
		Targets:       []string{"https://example.test"},
		ConfigHash:    "config-a",
		RuleVersion:   "rules-a",
		StartedAt:     now.Add(-time.Second),
		FinishedAt:    now,
		ContentHash:   "content-a",
	}
}

func seedGRPCReusableURLCoverage(t *testing.T, store *gorm.DB, attempt db.SubTask, target, agentID string) {
	t.Helper()
	if err := store.Where(db.SubTask{ID: "source-attempt"}).Attrs(db.SubTask{
		TenantID: attempt.TenantID, ProjectID: attempt.ProjectID, Status: "Done",
	}).FirstOrCreate(&db.SubTask{}).Error; err != nil {
		t.Fatal(err)
	}
	scopeDigest := sha256.Sum256([]byte(`{}`))
	scopeHash := fmt.Sprintf("%x", scopeDigest)
	configHash := db.TaskConfigHash(attempt.Config, attempt.Priority, attempt.TimeoutSec, attempt.AgentSelector, attempt.AgentSelectorRules)
	now := time.Now().UTC()
	for _, stage := range []scanplan.Stage{scanplan.StageHTTPProbe, scanplan.StageFingerprint} {
		key := scanplan.WorkKey{
			TenantID: attempt.TenantID, ProjectID: attempt.ProjectID, NetworkZone: "agent:" + agentID,
			NormalizedTarget: target, Stage: stage, ScopeHash: scopeHash, ConfigHash: configHash, RuleVersion: attempt.RuleVersion,
		}
		workHash, err := key.Digest()
		if err != nil {
			t.Fatal(err)
		}
		coverage := db.ScanCoverage{
			SchemaVersion: scanplan.SchemaVersion, TenantID: attempt.TenantID, ProjectID: attempt.ProjectID,
			NetworkZone: key.NetworkZone, NormalizedTarget: target, Stage: string(stage), WorkKeyHash: workHash,
			ScopeHash: scopeHash, ConfigHash: configHash, RuleVersion: attempt.RuleVersion,
			Status: string(scanplan.CoverageComplete), Outcome: string(scanplan.ObservationNegative),
			StartedAt: now.Add(-time.Second), FinishedAt: now, SourceTaskID: "source-task",
			SourceBatchID: "source-batch", SourceAttemptID: "source-attempt", Revision: 1,
		}
		if err := store.Create(&coverage).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func seedGRPCPortResumeCoverage(t *testing.T, store *gorm.DB, attempt db.SubTask, target, agentID string) db.ScanCoverage {
	t.Helper()
	source := db.SubTask{ID: "source-resume-attempt", TenantID: attempt.TenantID, ProjectID: attempt.ProjectID, Status: "Done"}
	if err := store.Create(&source).Error; err != nil {
		t.Fatal(err)
	}
	scopeDigest := sha256.Sum256([]byte(`{}`))
	scopeHash := fmt.Sprintf("%x", scopeDigest)
	configHash := db.TaskConfigHash(attempt.Config, attempt.Priority, attempt.TimeoutSec, attempt.AgentSelector, attempt.AgentSelectorRules)
	networkZone := "agent:" + agentID
	workKey := scanplan.WorkKey{
		TenantID: attempt.TenantID, ProjectID: attempt.ProjectID, NetworkZone: networkZone,
		NormalizedTarget: target, Stage: scanplan.StagePortScan, ScopeHash: scopeHash,
		ConfigHash: configHash, RuleVersion: attempt.RuleVersion,
	}
	workHash, err := workKey.Digest()
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion,
		Stage:         scanplan.StagePortScan,
		OpenPorts:     []string{target + ":443"},
	}
	checkpointJSON, err := checkpoint.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	checkpointDigest := sha256.Sum256(checkpointJSON)
	checkpointHash := fmt.Sprintf("%x", checkpointDigest)
	now := time.Now().UTC()
	observationContract := scanplan.Observation{
		SchemaVersion: scanplan.SchemaVersion, WorkKey: workKey, Outcome: scanplan.ObservationSuccess,
		ObservedAt: now, ContentHash: "content-v1", CheckpointHash: checkpointHash,
	}
	evidenceJSON, err := json.Marshal(observationContract)
	if err != nil {
		t.Fatal(err)
	}
	evidenceDigest := sha256.Sum256(evidenceJSON)
	evidenceHash := fmt.Sprintf("%x", evidenceDigest)
	observation := db.ScanObservation{
		SchemaVersion: scanplan.SchemaVersion, TenantID: attempt.TenantID, ProjectID: attempt.ProjectID,
		NetworkZone: networkZone, NormalizedTarget: target, Stage: string(scanplan.StagePortScan),
		WorkKeyHash: workHash, ScopeHash: scopeHash, ConfigHash: configHash, RuleVersion: attempt.RuleVersion,
		RootTaskID: "source-task", BatchID: "source-batch", AttemptID: source.ID, AgentID: "source-agent",
		Outcome: string(scanplan.ObservationSuccess), ContentHash: "content-v1", Checkpoint: string(checkpointJSON),
		CheckpointHash: checkpointHash, EvidenceHash: evidenceHash, ObservedAt: now,
	}
	if err := store.Create(&observation).Error; err != nil {
		t.Fatal(err)
	}
	validUntil := now.Add(time.Hour)
	coverage := db.ScanCoverage{
		SchemaVersion: scanplan.SchemaVersion, TenantID: attempt.TenantID, ProjectID: attempt.ProjectID,
		NetworkZone: networkZone, NormalizedTarget: target, Stage: string(scanplan.StagePortScan),
		WorkKeyHash: workHash, ScopeHash: scopeHash, ConfigHash: configHash, RuleVersion: attempt.RuleVersion,
		Status: string(scanplan.CoverageComplete), Outcome: string(scanplan.ObservationSuccess),
		StartedAt: now.Add(-time.Second), FinishedAt: now, ValidUntil: &validUntil,
		ObservationHash: evidenceHash, SourceObservationID: observation.ID,
		SourceTaskID: "source-task", SourceBatchID: "source-batch", SourceAttemptID: source.ID, Revision: 1,
	}
	if err := store.Create(&coverage).Error; err != nil {
		t.Fatal(err)
	}
	return coverage
}

func TestValidateStageObservationResultBindsStreamTaskID(t *testing.T) {
	event := validStageObservationEvent()
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	parsed, err := validateStageObservationResult(&pb.ScanResult{TaskId: event.AttemptID, PayloadType: scanplan.StageObservationPayloadType, Payload: payload})
	if err != nil || parsed.EventID != event.EventID {
		t.Fatalf("valid coverage event rejected: parsed=%+v err=%v", parsed, err)
	}
	if _, err := validateStageObservationResult(&pb.ScanResult{TaskId: "other-attempt", PayloadType: scanplan.StageObservationPayloadType, Payload: payload}); err == nil {
		t.Fatal("coverage event with mismatched stream task ID was accepted")
	}
}

func TestValidateStageObservationOwnershipRejectsAgentAndTargetSpoofing(t *testing.T) {
	store := setupRegisterTestDB(t)
	attempt := db.SubTask{
		ID: "attempt-coverage", TenantID: "tenant-a", ProjectID: "project-a", RootTaskID: "task-a", BatchID: "batch-a",
		AgentID: "agent-coverage", ChunkTargets: `["https://example.test"]`, Status: "Running",
	}
	if err := store.Create(&attempt).Error; err != nil {
		t.Fatalf("seed attempt: %v", err)
	}
	event := validStageObservationEvent()
	owned, err := validateStageObservationOwnership(event)
	if err != nil || owned.TenantID != "tenant-a" || owned.ProjectID != "project-a" {
		t.Fatalf("valid event ownership rejected: owned=%+v err=%v", owned, err)
	}
	foreignTarget := event
	foreignTarget.Targets = []string{"https://foreign.test"}
	if _, err := validateStageObservationOwnership(foreignTarget); err == nil {
		t.Fatal("coverage event outside assigned targets was accepted")
	}
	foreignAgent := event
	foreignAgent.AgentID = "agent-other"
	if _, err := validateStageObservationOwnership(foreignAgent); err == nil {
		t.Fatal("coverage event from an unassigned agent was accepted")
	}
}

func TestClaimTaskRespectsTenantRunningSubTaskQuota(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.TenantQuota{TenantID: "default", MaxRunningSubTasks: 1}).Error; err != nil {
		t.Fatalf("seed quota: %v", err)
	}
	if err := store.Create(&db.SubTask{ID: "already-running", TenantID: "default", Status: "Running"}).Error; err != nil {
		t.Fatalf("seed running subtask: %v", err)
	}
	if err := store.Create(&db.SubTask{ID: "queued-task", TenantID: "default", Status: "Dispatching"}).Error; err != nil {
		t.Fatalf("seed queued subtask: %v", err)
	}

	server := NewServer(50051)
	returned := 0
	server.SetClaimTaskHook(func(agentID string) (*pb.Task, string, error) {
		return &pb.Task{TaskId: "queued-task", Targets: []string{"https://example.com"}}, "msg-1", nil
	})
	server.SetReturnTaskHook(func(task *pb.Task, msgID string) error {
		returned++
		return nil
	})

	task, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{
		AgentId:   "agent-1",
		FreeSlots: 1,
	})
	if err != nil {
		t.Fatalf("claim task: %v", err)
	}
	if task.GetTaskId() != "" {
		t.Fatalf("expected quota-blocked claim to return empty task, got %+v", task)
	}
	if returned != 1 {
		t.Fatalf("expected quota-blocked task to be returned to queue once, got %d", returned)
	}
	var sub db.SubTask
	if err := store.First(&sub, "id = ?", "queued-task").Error; err != nil {
		t.Fatalf("load queued task: %v", err)
	}
	if sub.Status != "Dispatching" || sub.AgentID != "" {
		t.Fatalf("quota-blocked task should remain unclaimed, got %+v", sub)
	}
}

func TestClaimTaskDoesNotFetchForDrainingAgent(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.Node{AgentID: "agent-draining", TenantID: "default", Status: "Draining"}).Error; err != nil {
		t.Fatalf("seed draining node: %v", err)
	}

	server := NewServer(50051)
	fetched := 0
	server.SetClaimTaskHook(func(string) (*pb.Task, string, error) {
		fetched++
		return &pb.Task{TaskId: "must-not-fetch"}, "msg", nil
	})
	task, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{AgentId: "agent-draining", FreeSlots: 1})
	if err != nil {
		t.Fatalf("ClaimTask draining agent: %v", err)
	}
	if task.GetTaskId() != "" || fetched != 0 {
		t.Fatalf("draining agent fetched task=%+v calls=%d", task, fetched)
	}
}

func TestClaimTaskReturnsFetchedMessageWhenAgentStartsDraining(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.Node{AgentID: "agent-draining-race", TenantID: "tenant-a", Status: "Alive"}).Error; err != nil {
		t.Fatalf("seed alive node: %v", err)
	}
	if err := store.Create(&db.SubTask{ID: "task-draining-race", TenantID: "tenant-a", Status: "Pending"}).Error; err != nil {
		t.Fatalf("seed pending subtask: %v", err)
	}

	server := NewServer(50051)
	returned := 0
	server.SetClaimTaskHook(func(string) (*pb.Task, string, error) {
		if err := store.Model(&db.Node{}).Where("agent_id = ?", "agent-draining-race").Update("status", "Draining").Error; err != nil {
			t.Fatalf("mark node draining: %v", err)
		}
		return &pb.Task{TaskId: "task-draining-race"}, "msg-race", nil
	})
	server.SetReturnTaskHook(func(task *pb.Task, msgID string) error {
		if task.TaskId != "task-draining-race" || msgID != "msg-race" {
			t.Fatalf("unexpected returned message: task=%+v msg=%s", task, msgID)
		}
		returned++
		return nil
	})

	task, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{AgentId: "agent-draining-race", FreeSlots: 1})
	if err != nil {
		t.Fatalf("ClaimTask draining race: %v", err)
	}
	if task.GetTaskId() != "" || returned != 1 {
		t.Fatalf("draining race task=%+v returned=%d, want empty/1", task, returned)
	}
	var sub db.SubTask
	if err := store.First(&sub, "id = ?", "task-draining-race").Error; err != nil {
		t.Fatalf("reload pending subtask: %v", err)
	}
	if sub.Status != "Pending" || sub.AgentID != "" || sub.StreamMsgID != "" {
		t.Fatalf("draining race changed lease: %+v", sub)
	}
}

func TestClaimTaskDropsQueuedMessageWhenRootTaskPaused(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.RootTask{ID: "root-paused", TenantID: "default", Status: "Paused"}).Error; err != nil {
		t.Fatalf("seed root task: %v", err)
	}
	if err := store.Create(&db.SubTask{ID: "queued-paused", TenantID: "default", RootTaskID: "root-paused", Status: "Pending"}).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}

	server := NewServer(50051)
	acked := 0
	returned := 0
	server.SetClaimTaskHook(func(agentID string) (*pb.Task, string, error) {
		if acked+returned > 0 {
			return nil, "", nil
		}
		return &pb.Task{TaskId: "queued-paused", Targets: []string{"https://example.com"}}, "msg-paused", nil
	})
	server.SetAckTaskHook(func(msgID string) error {
		if msgID == "msg-paused" {
			acked++
		}
		return nil
	})
	server.SetReturnTaskHook(func(task *pb.Task, msgID string) error {
		returned++
		return nil
	})

	task, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{
		AgentId:   "agent-1",
		FreeSlots: 1,
	})
	if err != nil {
		t.Fatalf("claim task: %v", err)
	}
	if task.GetTaskId() != "" {
		t.Fatalf("expected paused task claim to return empty task, got %+v", task)
	}
	if acked != 1 || returned != 0 {
		t.Fatalf("expected paused queue message to be acked once and not returned, acked=%d returned=%d", acked, returned)
	}
	var sub db.SubTask
	if err := store.First(&sub, "id = ?", "queued-paused").Error; err != nil {
		t.Fatalf("load queued task: %v", err)
	}
	if sub.Status != "Paused" || sub.AgentID != "" || sub.StreamMsgID != "" {
		t.Fatalf("expected queued task to be marked Paused and unassigned, got %+v", sub)
	}
}

func TestClaimTaskDropsDuplicateMessageForRunningSubTask(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.SubTask{
		ID:          "already-running",
		TenantID:    "default",
		Status:      "Running",
		AgentID:     "agent-existing",
		StreamMsgID: "msg-existing",
	}).Error; err != nil {
		t.Fatalf("seed running subtask: %v", err)
	}

	server := NewServer(50051)
	delivered := false
	acked := 0
	returned := 0
	server.SetClaimTaskHook(func(agentID string) (*pb.Task, string, error) {
		if delivered {
			return nil, "", nil
		}
		delivered = true
		return &pb.Task{TaskId: "already-running", Targets: []string{"https://example.com"}}, "msg-duplicate", nil
	})
	server.SetAckTaskHook(func(msgID string) error {
		if msgID == "msg-duplicate" {
			acked++
		}
		return nil
	})
	server.SetReturnTaskHook(func(task *pb.Task, msgID string) error {
		returned++
		return nil
	})

	task, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{AgentId: "agent-new", FreeSlots: 1})
	if err != nil {
		t.Fatalf("claim task: %v", err)
	}
	if task.GetTaskId() != "" {
		t.Fatalf("duplicate running task should not be returned to agent, got %+v", task)
	}
	if acked != 1 || returned != 0 {
		t.Fatalf("duplicate running message should be acked, not requeued: acked=%d returned=%d", acked, returned)
	}

	var sub db.SubTask
	if err := store.First(&sub, "id = ?", "already-running").Error; err != nil {
		t.Fatalf("load running subtask: %v", err)
	}
	if sub.Status != "Running" || sub.AgentID != "agent-existing" || sub.StreamMsgID != "msg-existing" {
		t.Fatalf("duplicate message changed running assignment: %+v", sub)
	}
}

func TestClaimTaskReturnsErrorWhenRunningDuplicateCannotBeAcknowledged(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.SubTask{ID: "running-no-ack", TenantID: "default", Status: "Running"}).Error; err != nil {
		t.Fatalf("seed running subtask: %v", err)
	}

	server := NewServer(50051)
	server.SetClaimTaskHook(func(agentID string) (*pb.Task, string, error) {
		return &pb.Task{TaskId: "running-no-ack"}, "msg-running", nil
	})
	if _, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{AgentId: "agent-1", FreeSlots: 1}); err == nil {
		t.Fatal("expected missing ACK hook to be reported")
	}
}

func TestClaimTaskRecordsAttemptStartAndBatchState(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.Node{AgentID: "agent-history", TenantID: "tenant-a", Status: "Alive", Capacity: 1}).Error; err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	root := db.RootTask{ID: "root-claim-history", TenantID: "tenant-a", Status: "Queued", TotalChunks: 1}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	attempt := db.SubTask{ID: "batch-claim-attempt-1", BatchID: "batch-claim", AttemptNo: 1, TenantID: root.TenantID, RootTaskID: root.ID, Status: "Pending", ChunkTargets: `["https://one.test"]`}
	if err := store.Create(&attempt).Error; err != nil {
		t.Fatalf("seed attempt: %v", err)
	}
	if err := store.Create(&db.TaskBatch{ID: attempt.BatchID, TenantID: root.TenantID, RootTaskID: root.ID, Sequence: 0, Status: "Pending", LatestAttemptID: attempt.ID, CurrentAttemptNo: 1, AttemptCount: 1}).Error; err != nil {
		t.Fatalf("seed batch: %v", err)
	}

	server := NewServer(50051)
	server.SetClaimTaskHook(func(string) (*pb.Task, string, error) {
		return &pb.Task{TaskId: attempt.ID, Targets: []string{"https://one.test"}}, "claim-history-msg", nil
	})
	server.SetReturnTaskHook(func(*pb.Task, string) error { return nil })
	claimed, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{AgentId: "agent-history", FreeSlots: 1})
	if err != nil || claimed.GetTaskId() != attempt.ID {
		t.Fatalf("claim attempt = %+v err=%v", claimed, err)
	}
	if err := store.First(&attempt, "id = ?", attempt.ID).Error; err != nil {
		t.Fatalf("reload attempt: %v", err)
	}
	if attempt.Status != "Running" || attempt.AgentID != "agent-history" || attempt.StartedAt == nil {
		t.Fatalf("claim did not record execution start: %+v", attempt)
	}
	var batch db.TaskBatch
	if err := store.First(&batch, "id = ?", attempt.BatchID).Error; err != nil {
		t.Fatalf("reload batch: %v", err)
	}
	if batch.Status != "Running" || batch.LatestAttemptID != attempt.ID {
		t.Fatalf("claim did not update batch state: %+v", batch)
	}
}

func TestClaimTaskCompletesFullyReusableCoverageWithoutAgentAssignment(t *testing.T) {
	store := setupRegisterTestDB(t)
	target := "https://reused.example.test"
	project := db.Project{ID: "project-reuse", TenantID: "tenant-reuse", Scope: `{}`}
	root := db.RootTask{ID: "root-reuse", TenantID: project.TenantID, ProjectID: project.ID, Status: "Queued", TotalChunks: 1, TotalTargets: 1}
	attempt := db.SubTask{
		ID: "attempt-reuse", TenantID: project.TenantID, ProjectID: project.ID, RootTaskID: root.ID,
		BatchID: "batch-reuse", AttemptNo: 1, Trigger: db.AttemptTriggerInitial, ChunkTargets: `[` + `"` + target + `"` + `]`,
		Status: "Pending", Config: grpcReusableTestConfig, Priority: 1, TimeoutSec: 60, ConfigVersion: 1,
		RuleVersion: "rules-v1", AgentSelector: `{}`, AgentSelectorRules: `{}`,
	}
	batch := db.TaskBatch{
		ID: attempt.BatchID, TenantID: attempt.TenantID, ProjectID: project.ID, RootTaskID: root.ID,
		Sequence: 0, Kind: "asset_scan", Targets: attempt.ChunkTargets, TargetCount: 1, Status: "Pending",
		ControlState: string(db.BatchControlActive), ConfigVersion: 1, RuleVersion: attempt.RuleVersion,
		LatestAttemptID: attempt.ID, CurrentAttemptNo: 1, AttemptCount: 1,
	}
	for _, record := range []interface{}{
		&project,
		&root,
		&db.Node{AgentID: "agent-reuse", TenantID: project.TenantID, Status: "Alive", Capacity: 1},
		&batch,
		&attempt,
	} {
		if err := store.Create(record).Error; err != nil {
			t.Fatalf("seed reuse claim: %v", err)
		}
	}
	seedGRPCReusableURLCoverage(t, store, attempt, target, "agent-reuse")

	server := NewServer(50051)
	delivered := false
	server.SetClaimTaskHook(func(string) (*pb.Task, string, error) {
		if delivered {
			return nil, "", nil
		}
		delivered = true
		return &pb.Task{TaskId: attempt.ID, Targets: []string{target}, Config: []byte(grpcReusableTestConfig)}, "reuse-msg", nil
	})
	acked := 0
	server.SetAckTaskHook(func(msgID string) error {
		if msgID != "reuse-msg" {
			t.Fatalf("unexpected ACK message %q", msgID)
		}
		acked++
		return nil
	})
	server.SetReturnTaskHook(func(*pb.Task, string) error {
		t.Fatal("fully reused work was returned to the queue")
		return nil
	})
	claimed, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{AgentId: "agent-reuse", FreeSlots: 1})
	if err != nil || claimed.GetTaskId() != "" || acked != 1 {
		t.Fatalf("fully reused claim=%+v acked=%d err=%v", claimed, acked, err)
	}
	if err := store.First(&attempt, "id = ?", attempt.ID).Error; err != nil {
		t.Fatal(err)
	}
	if db.CanonicalAttemptState(attempt.Status) != db.AttemptStateCompleted || attempt.AgentID != "" || attempt.StartedAt != nil {
		t.Fatalf("reused attempt acquired an Agent lease: %+v", attempt)
	}
	if err := store.First(&batch, "id = ?", batch.ID).Error; err != nil {
		t.Fatal(err)
	}
	if db.CanonicalAttemptState(batch.Status) != db.AttemptStateCompleted || batch.TargetCount != 1 {
		t.Fatalf("reused batch state=%+v", batch)
	}
	if err := store.First(&root, "id = ?", root.ID).Error; err != nil {
		t.Fatal(err)
	}
	if db.CanonicalTaskState(root.Status) != db.TaskStateCompleted || root.CompletedChunks != 1 || root.CompletedTargets != 1 {
		t.Fatalf("reused root progress=%+v", root)
	}
	var node db.Node
	if err := store.First(&node, "agent_id = ?", "agent-reuse").Error; err != nil {
		t.Fatal(err)
	}
	if node.RunningTasks != 0 {
		t.Fatalf("reused work consumed Agent capacity: %+v", node)
	}
	var linkCount int64
	store.Model(&db.TaskCoverageLink{}).Where("attempt_id = ? AND link_type = ?", attempt.ID, "reused").Count(&linkCount)
	if linkCount != 2 {
		t.Fatalf("reused link count=%d, want 2", linkCount)
	}
}

func TestClaimTaskCommitsPartialReuseWithAgentLease(t *testing.T) {
	store := setupRegisterTestDB(t)
	covered := "https://covered.example.test"
	remaining := "https://remaining.example.test"
	targetJSON, _ := json.Marshal([]string{covered, remaining})
	project := db.Project{ID: "project-partial-reuse", TenantID: "tenant-partial-reuse", Scope: `{}`}
	root := db.RootTask{ID: "root-partial-reuse", TenantID: project.TenantID, ProjectID: project.ID, Status: "Queued", TotalChunks: 1, TotalTargets: 2}
	attempt := db.SubTask{
		ID: "attempt-partial-reuse", TenantID: project.TenantID, ProjectID: project.ID, RootTaskID: root.ID,
		BatchID: "batch-partial-reuse", AttemptNo: 1, Trigger: db.AttemptTriggerInitial, ChunkTargets: string(targetJSON),
		Status: "Pending", Config: grpcReusableTestConfig, Priority: 1, TimeoutSec: 60, ConfigVersion: 1,
		RuleVersion: "rules-v1", AgentSelector: `{}`, AgentSelectorRules: `{}`,
	}
	batch := db.TaskBatch{
		ID: attempt.BatchID, TenantID: attempt.TenantID, ProjectID: project.ID, RootTaskID: root.ID,
		Sequence: 0, Kind: "asset_scan", Targets: attempt.ChunkTargets, TargetCount: 2, Status: "Pending",
		ControlState: string(db.BatchControlActive), ConfigVersion: 1, RuleVersion: attempt.RuleVersion,
		LatestAttemptID: attempt.ID, CurrentAttemptNo: 1, AttemptCount: 1,
	}
	for _, record := range []interface{}{
		&project,
		&root,
		&db.Node{AgentID: "agent-partial-reuse", TenantID: project.TenantID, Status: "Alive", Capacity: 1},
		&batch,
		&attempt,
	} {
		if err := store.Create(record).Error; err != nil {
			t.Fatalf("seed partial reuse claim: %v", err)
		}
	}
	seedGRPCReusableURLCoverage(t, store, attempt, covered, "agent-partial-reuse")

	server := NewServer(50051)
	server.SetClaimTaskHook(func(string) (*pb.Task, string, error) {
		return &pb.Task{TaskId: attempt.ID, Targets: []string{covered, remaining}, Config: []byte(grpcReusableTestConfig)}, "partial-reuse-msg", nil
	})
	server.SetAckTaskHook(func(string) error {
		t.Fatal("running partial reuse was acknowledged before completion")
		return nil
	})
	server.SetReturnTaskHook(func(*pb.Task, string) error {
		t.Fatal("partial reuse was returned instead of leased")
		return nil
	})
	claimed, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{AgentId: "agent-partial-reuse", FreeSlots: 1})
	if err != nil || claimed.GetTaskId() != attempt.ID || len(claimed.Targets) != 1 || claimed.Targets[0] != remaining {
		t.Fatalf("partial reused claim=%+v err=%v", claimed, err)
	}
	if err := store.First(&attempt, "id = ?", attempt.ID).Error; err != nil {
		t.Fatal(err)
	}
	if db.CanonicalAttemptState(attempt.Status) != db.AttemptStateRunning || attempt.AgentID != "agent-partial-reuse" || attempt.ChunkTargets != `["https://remaining.example.test"]` {
		t.Fatalf("partial reuse was not committed with the Agent lease: %+v", attempt)
	}
	if err := store.First(&batch, "id = ?", batch.ID).Error; err != nil {
		t.Fatal(err)
	}
	if db.CanonicalAttemptState(batch.Status) != db.AttemptStateRunning || batch.TargetCount != 2 || batch.Targets != string(targetJSON) {
		t.Fatalf("partial reuse changed stable batch scope: %+v", batch)
	}
	var linkCount int64
	store.Model(&db.TaskCoverageLink{}).Where("attempt_id = ? AND link_type = ?", attempt.ID, "reused").Count(&linkCount)
	if linkCount != 2 {
		t.Fatalf("partial reused link count=%d, want 2", linkCount)
	}
	var node db.Node
	if err := store.First(&node, "agent_id = ?", "agent-partial-reuse").Error; err != nil {
		t.Fatal(err)
	}
	if node.RunningTasks != 1 {
		t.Fatalf("partial reuse did not consume exactly one Agent slot: %+v", node)
	}
}

func TestClaimTaskAppliesResumeOnlyForCompatibleAgent(t *testing.T) {
	for _, test := range []struct {
		name        string
		version     string
		ruleVersion string
		wantResume  bool
	}{
		{name: "checkpoint capable", version: "v2.6.0", ruleVersion: "rules-v1", wantResume: true},
		{name: "legacy full scan", version: "v2.5.9", ruleVersion: "rules-v1", wantResume: false},
		{name: "rule drift full scan", version: "v2.6.0", ruleVersion: "rules-v2", wantResume: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := setupRegisterTestDB(t)
			target := "10.0.0.10"
			project := db.Project{ID: "project-resume", TenantID: "tenant-resume", Scope: `{}`}
			root := db.RootTask{ID: "root-resume", TenantID: project.TenantID, ProjectID: project.ID, Status: "Queued", TotalChunks: 1, TotalTargets: 1}
			attempt := db.SubTask{
				ID: "attempt-resume", TenantID: project.TenantID, ProjectID: project.ID, RootTaskID: root.ID,
				BatchID: "batch-resume", AttemptNo: 1, Trigger: db.AttemptTriggerInitial, ChunkTargets: `[` + `"` + target + `"` + `]`,
				Status: "Pending", Config: grpcReusableTestConfig, Priority: 1, TimeoutSec: 60, ConfigVersion: 1,
				RuleVersion: "rules-v1", AgentSelector: `{}`, AgentSelectorRules: `{}`,
			}
			batch := db.TaskBatch{
				ID: attempt.BatchID, TenantID: attempt.TenantID, ProjectID: project.ID, RootTaskID: root.ID,
				Sequence: 0, Kind: "asset_scan", Targets: attempt.ChunkTargets, TargetCount: 1, Status: "Pending",
				ControlState: string(db.BatchControlActive), ConfigVersion: 1, RuleVersion: attempt.RuleVersion,
				LatestAttemptID: attempt.ID, CurrentAttemptNo: 1, AttemptCount: 1,
			}
			for _, record := range []interface{}{
				&project, &root,
				&db.Node{AgentID: "agent-resume", TenantID: project.TenantID, Status: "Alive", Capacity: 1, Version: test.version, RuleVersion: test.ruleVersion},
				&batch, &attempt,
			} {
				if err := store.Create(record).Error; err != nil {
					t.Fatal(err)
				}
			}
			seedGRPCPortResumeCoverage(t, store, attempt, target, "agent-resume")

			server := NewServer(50051)
			server.SetClaimTaskHook(func(string) (*pb.Task, string, error) {
				return &pb.Task{TaskId: attempt.ID, Targets: []string{target}, Config: []byte(grpcReusableTestConfig)}, "resume-msg", nil
			})
			server.SetAckTaskHook(func(string) error { return nil })
			server.SetReturnTaskHook(func(*pb.Task, string) error {
				t.Fatal("stable resume evidence was unexpectedly returned")
				return nil
			})
			claimed, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{AgentId: "agent-resume", FreeSlots: 1})
			if err != nil || claimed.GetTaskId() != attempt.ID {
				t.Fatalf("claim=%+v err=%v", claimed, err)
			}
			var envelope struct {
				ResumePlan            *scanplan.ResumePlan
				ResumePlanHash        string
				ObservationConfigHash string
			}
			if err := json.Unmarshal(claimed.Config, &envelope); err != nil {
				t.Fatal(err)
			}
			var resumeLinks int64
			store.Model(&db.TaskCoverageLink{}).Where("attempt_id = ? AND link_type = ? AND reason LIKE ?", attempt.ID, "reused", "resume_plan:%").Count(&resumeLinks)
			if test.wantResume {
				baseDigest := sha256.Sum256([]byte(attempt.Config))
				if envelope.ResumePlan == nil || envelope.ResumePlan.StartStage != scanplan.StageProtocolIdentify ||
					envelope.ResumePlanHash == "" || envelope.ObservationConfigHash != fmt.Sprintf("%x", baseDigest) || resumeLinks != 1 {
					t.Fatalf("compatible Agent did not receive atomic resume plan: envelope=%+v links=%d", envelope, resumeLinks)
				}
			} else if envelope.ResumePlan != nil || envelope.ResumePlanHash != "" || envelope.ObservationConfigHash != "" || resumeLinks != 0 {
				t.Fatalf("legacy Agent received resume state: envelope=%+v links=%d", envelope, resumeLinks)
			}
		})
	}
}

func TestClaimTaskAttachesDuplicateWorkAndCompletionRequeuesWaiter(t *testing.T) {
	store := setupRegisterTestDB(t)
	target := "https://in-flight.example.test"
	project := db.Project{ID: "project-in-flight", TenantID: "tenant-in-flight", Scope: `{}`, Status: "active"}
	if err := store.Create(&project).Error; err != nil {
		t.Fatal(err)
	}
	if err := store.Create(&db.Node{AgentID: "agent-in-flight", TenantID: project.TenantID, Status: "Alive", Capacity: 2}).Error; err != nil {
		t.Fatal(err)
	}
	makeAttempt := func(suffix string) db.SubTask {
		rootID := "root-in-flight-" + suffix
		batchID := "batch-in-flight-" + suffix
		attempt := db.SubTask{
			ID: "attempt-in-flight-" + suffix, TenantID: project.TenantID, ProjectID: project.ID,
			RootTaskID: rootID, BatchID: batchID, AttemptNo: 1, Trigger: db.AttemptTriggerInitial,
			ChunkTargets: `[` + `"` + target + `"` + `]`, Status: "Pending", Config: grpcReusableTestConfig,
			Priority: 1, TimeoutSec: 60, ConfigVersion: 1, RuleVersion: "rules-v1",
			AgentSelector: `{}`, AgentSelectorRules: `{}`,
		}
		if err := store.Create(&db.RootTask{
			ID: rootID, TenantID: project.TenantID, ProjectID: project.ID, Status: "Queued", TotalChunks: 1, TotalTargets: 1,
		}).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.Create(&db.TaskBatch{
			ID: batchID, TenantID: project.TenantID, ProjectID: project.ID, RootTaskID: rootID,
			Sequence: 0, Kind: "asset_scan", Targets: attempt.ChunkTargets, TargetCount: 1, Status: "Pending",
			ControlState: string(db.BatchControlActive), ConfigVersion: 1, RuleVersion: attempt.RuleVersion,
			LatestAttemptID: attempt.ID, CurrentAttemptNo: 1, AttemptCount: 1,
		}).Error; err != nil {
			t.Fatal(err)
		}
		if err := store.Create(&attempt).Error; err != nil {
			t.Fatal(err)
		}
		return attempt
	}
	owner := makeAttempt("owner")
	waiter := makeAttempt("waiter")
	deliveries := []struct {
		attempt db.SubTask
		msgID   string
	}{{owner, "owner-message"}, {waiter, "waiter-message"}}
	deliveryIndex := 0
	acked := make(map[string]int)
	requeued := make([]*pb.Task, 0, 1)

	server := NewServer(50051)
	server.SetClaimTaskHook(func(string) (*pb.Task, string, error) {
		if deliveryIndex >= len(deliveries) {
			return nil, "", nil
		}
		delivery := deliveries[deliveryIndex]
		deliveryIndex++
		return &pb.Task{TaskId: delivery.attempt.ID, Targets: []string{target}, Config: []byte(grpcReusableTestConfig), Priority: int32(delivery.attempt.Priority)}, delivery.msgID, nil
	})
	server.SetAckTaskHook(func(msgID string) error {
		acked[msgID]++
		return nil
	})
	server.SetReturnTaskHook(func(task *pb.Task, msgID string) error {
		t.Fatalf("in-flight work was returned: task=%s message=%s", task.TaskId, msgID)
		return nil
	})
	server.SetRequeueTaskHook(func(task *pb.Task) error {
		requeued = append(requeued, task)
		return nil
	})

	claimed, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{AgentId: "agent-in-flight", FreeSlots: 2})
	if err != nil || claimed.GetTaskId() != owner.ID {
		t.Fatalf("owner claim=%+v err=%v", claimed, err)
	}
	duplicate, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{AgentId: "agent-in-flight", FreeSlots: 1})
	if err != nil || duplicate.GetTaskId() != "" || acked["waiter-message"] != 1 {
		t.Fatalf("duplicate claim=%+v acked=%v err=%v", duplicate, acked, err)
	}
	var parked db.SubTask
	if err := store.First(&parked, "id = ?", waiter.ID).Error; err != nil {
		t.Fatal(err)
	}
	if parked.Status != "Pending" || parked.AgentID != "" || !strings.HasPrefix(parked.StreamMsgID, "workclaim:") {
		t.Fatalf("duplicate work acquired Agent capacity: %+v", parked)
	}
	var node db.Node
	if err := store.First(&node, "agent_id = ?", "agent-in-flight").Error; err != nil {
		t.Fatal(err)
	}
	if node.RunningTasks != 1 {
		t.Fatalf("duplicate work changed Agent running count: %+v", node)
	}
	var claimCount, waiterLinkCount int64
	store.Model(&db.ScanWorkClaim{}).Count(&claimCount)
	store.Model(&db.TaskCoverageLink{}).Where("attempt_id = ? AND link_type = ?", waiter.ID, "in_flight").Count(&waiterLinkCount)
	if claimCount != 1 || waiterLinkCount != 1 {
		t.Fatalf("claim/link count=%d/%d, want 1/1", claimCount, waiterLinkCount)
	}

	ack, err := server.TaskComplete(context.Background(), &pb.TaskCompleteReq{
		TaskId: owner.ID, AgentId: "agent-in-flight", Status: "DONE",
	})
	if err != nil || !ack.Success || len(requeued) != 1 || requeued[0].TaskId != waiter.ID || requeued[0].Priority != int32(waiter.Priority) {
		t.Fatalf("completion ack=%+v requeued=%+v err=%v", ack, requeued, err)
	}
	if acked["owner-message"] != 1 {
		t.Fatalf("owner queue message was not ACKed: %v", acked)
	}
	if err := store.First(&parked, "id = ?", waiter.ID).Error; err != nil {
		t.Fatal(err)
	}
	if parked.Status != "Pending" || parked.StreamMsgID != retryQueuedMarker {
		t.Fatalf("resolved waiter was not queued: %+v", parked)
	}
	if err := store.First(&node, "agent_id = ?", "agent-in-flight").Error; err != nil {
		t.Fatal(err)
	}
	if node.RunningTasks != 0 {
		t.Fatalf("completed owner did not release Agent capacity: %+v", node)
	}
}

func TestClaimTaskReturnsRiskValidationForIncompatibleAgent(t *testing.T) {
	for _, test := range []struct {
		name        string
		version     string
		ruleVersion string
	}{
		{name: "old agent", version: "v2.3.0", ruleVersion: "rules-v2"},
		{name: "stale rules", version: "v2.4.0", ruleVersion: "rules-v1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := setupRegisterTestDB(t)
			if err := store.Create(&db.Node{AgentID: "agent-risk", TenantID: "default", Status: "Alive", Version: test.version, RuleVersion: test.ruleVersion}).Error; err != nil {
				t.Fatal(err)
			}
			attempt := db.SubTask{ID: "risk-attempt", TenantID: "default", Status: "Dispatching", RuleVersion: "rules-v2"}
			if err := store.Create(&attempt).Error; err != nil {
				t.Fatal(err)
			}
			server := NewServer(50051)
			server.SetClaimTaskHook(func(string) (*pb.Task, string, error) {
				return &pb.Task{TaskId: attempt.ID, Config: []byte(`{"ExecutionMode":"risk_validation"}`)}, "risk-msg", nil
			})
			returned := 0
			server.SetReturnTaskHook(func(*pb.Task, string) error { returned++; return nil })
			claimed, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{AgentId: "agent-risk", FreeSlots: 1})
			if err != nil || claimed.GetTaskId() != "" || returned != 1 {
				t.Fatalf("incompatible risk claim=%+v returned=%d err=%v", claimed, returned, err)
			}
			if err := store.First(&attempt, "id = ?", attempt.ID).Error; err != nil {
				t.Fatal(err)
			}
			if attempt.Status != "Dispatching" || attempt.AgentID != "" {
				t.Fatalf("incompatible Agent acquired risk attempt: %+v", attempt)
			}
		})
	}
}

func TestAgentSupportsRiskValidation(t *testing.T) {
	for version, want := range map[string]bool{
		"v2.3.9": false,
		"v2.4.0": true,
		"2.5.1":  true,
		"v3.0.0": true,
		"v2.4":   false,
		"latest": false,
	} {
		if got := agentSupportsRiskValidation(version); got != want {
			t.Fatalf("agentSupportsRiskValidation(%q)=%v want=%v", version, got, want)
		}
	}
}

func TestClaimTaskRejectsCredentialValidationWhenTLSCapabilityIsOnlyRequestSupplied(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.Node{
		AgentID: "agent-credential", TenantID: "default", Status: "Alive",
		Tags: `{"credential_validation":"v1"}`,
	}).Error; err != nil {
		t.Fatal(err)
	}
	attempt := db.SubTask{ID: "credential-attempt", TenantID: "default", Status: "Dispatching"}
	if err := store.Create(&attempt).Error; err != nil {
		t.Fatal(err)
	}
	server := NewServer(50051)
	server.SetClaimTaskHook(func(string) (*pb.Task, string, error) {
		return &pb.Task{TaskId: attempt.ID, Config: []byte(`{"ExecutionMode":"credential_validation"}`)}, "credential-msg", nil
	})
	returned := 0
	server.SetReturnTaskHook(func(*pb.Task, string) error { returned++; return nil })
	claimed, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{
		AgentId: "agent-credential", FreeSlots: 1,
		Tags: map[string]string{"credential_validation": "v1", "transport_tls": "verified"},
	})
	if status.Code(err) != codes.FailedPrecondition || claimed.GetTaskId() != "" || returned != 1 {
		t.Fatalf("credential claim=%+v returned=%d err=%v", claimed, returned, err)
	}
	if err := store.First(&attempt, "id = ?", attempt.ID).Error; err != nil {
		t.Fatal(err)
	}
	if attempt.Status != "Dispatching" || attempt.AgentID != "" {
		t.Fatalf("plaintext Agent acquired credential attempt: %+v", attempt)
	}
}

func TestAgentSupportsCredentialValidationRequiresAttestedTLS(t *testing.T) {
	for tags, want := range map[string]bool{
		`{"credential_validation":"v1","transport_tls":"verified"}`: true,
		`{"credential_validation":"v1"}`:                            false,
		`{"transport_tls":"verified"}`:                              false,
		`{"credential_validation":"v1","transport_tls":"spoofed"}`:  false,
		`not-json`: false,
	} {
		if got := agentSupportsCredentialValidation(tags); got != want {
			t.Fatalf("agentSupportsCredentialValidation(%q)=%v want=%v", tags, got, want)
		}
	}
}

func TestSYNCapabilityUsesRegisteredTagsAndStructuredConfig(t *testing.T) {
	if !taskRequestsSYN(&pb.Task{Config: []byte(`{"PortScanType":"syn"}`)}) {
		t.Fatal("structured SYN task was not detected")
	}
	if taskRequestsSYN(&pb.Task{Config: []byte(`{"PortScanType":"tcp"}`)}) || taskRequestsSYN(&pb.Task{Config: []byte(`not-json`)}) {
		t.Fatal("non-SYN task was treated as SYN")
	}
	if !agentHasCapabilities(`{"scan_syn":"v1"}`, "scan_syn") {
		t.Fatal("registered scan_syn capability was rejected")
	}
	if agentHasCapabilities(`{"scan_syn":"true"}`, "scan_syn") || agentHasCapabilities(`not-json`, "scan_syn") {
		t.Fatal("invalid scan_syn capability was accepted")
	}
}

func TestAgentSupportsCheckpointResume(t *testing.T) {
	for version, want := range map[string]bool{
		"v2.5.9": false,
		"v2.6.0": true,
		"2.6.1":  true,
		"v3.0.0": true,
		"v2.6":   false,
		"latest": false,
	} {
		if got := agentSupportsCheckpointResume(version); got != want {
			t.Fatalf("agentSupportsCheckpointResume(%q)=%v want=%v", version, got, want)
		}
	}
}

func TestClaimTaskRejectsUnconfirmedPocExecutionBeforeAgentAssignment(t *testing.T) {
	store := setupRegisterTestDB(t)
	attempt := db.SubTask{ID: "ordinary-poc-attempt", TenantID: "default", Status: "Dispatching"}
	if err := store.Create(&attempt).Error; err != nil {
		t.Fatal(err)
	}
	server := NewServer(50051)
	delivered := false
	server.SetClaimTaskHook(func(string) (*pb.Task, string, error) {
		if delivered {
			return nil, "", nil
		}
		delivered = true
		return &pb.Task{TaskId: attempt.ID, Config: []byte(`{"NoPoc":false,"GolangPoc":true}`)}, "ordinary-poc-msg", nil
	})
	acked := 0
	server.SetAckTaskHook(func(string) error { acked++; return nil })
	claimed, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{AgentId: "legacy-agent", FreeSlots: 1})
	if err != nil || claimed.GetTaskId() != "" || acked != 1 {
		t.Fatalf("unconfirmed POC claim=%+v acked=%d err=%v", claimed, acked, err)
	}
	if err := store.First(&attempt, "id = ?", attempt.ID).Error; err != nil {
		t.Fatal(err)
	}
	if attempt.Status != "Failed" || attempt.AgentID != "" || !strings.Contains(attempt.FailureReason, "risk-validation") {
		t.Fatalf("unsafe ordinary POC task was not failed closed: %+v", attempt)
	}
}

func TestTaskRequestsUnconfirmedPOC(t *testing.T) {
	for _, test := range []struct {
		config string
		want   bool
	}{
		{config: `{}`, want: false},
		{config: `{"NoPoc":true,"GolangPoc":false,"DisableGeneralPoc":true}`, want: false},
		{config: `{"NoPoc":false}`, want: true},
		{config: `{"PocNameForSearch":"nginx"}`, want: true},
		{config: `{"ExecutionMode":"risk_validation","NoPoc":false}`, want: false},
	} {
		if got := taskRequestsUnconfirmedPOC(&pb.Task{Config: []byte(test.config)}); got != test.want {
			t.Fatalf("taskRequestsUnconfirmedPOC(%s)=%v want=%v", test.config, got, test.want)
		}
	}
}

func TestClaimTaskReturnsUnknownStatusMessageToQueue(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.SubTask{ID: "future-status", TenantID: "default", Status: "Retrying"}).Error; err != nil {
		t.Fatalf("seed future-status subtask: %v", err)
	}

	server := NewServer(50051)
	claimCalls := 0
	acked := 0
	returned := 0
	server.SetClaimTaskHook(func(agentID string) (*pb.Task, string, error) {
		claimCalls++
		return &pb.Task{TaskId: "future-status"}, "msg-future", nil
	})
	server.SetAckTaskHook(func(msgID string) error {
		acked++
		return nil
	})
	server.SetReturnTaskHook(func(task *pb.Task, msgID string) error {
		returned++
		return nil
	})

	task, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{AgentId: "agent-1", FreeSlots: 1})
	if err != nil {
		t.Fatalf("claim unknown-status task: %v", err)
	}
	if task.GetTaskId() != "" || acked != 0 || returned != 1 || claimCalls != 1 {
		t.Fatalf("unknown status must be returned once and end claim: task=%+v acked=%d returned=%d claims=%d", task, acked, returned, claimCalls)
	}
}

func TestClaimTaskReturnsErrorWhenUnknownStatusCannotBeRequeued(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.SubTask{ID: "unknown-requeue-fail", TenantID: "default", Status: "Retrying"}).Error; err != nil {
		t.Fatalf("seed unknown-status subtask: %v", err)
	}

	server := NewServer(50051)
	server.SetClaimTaskHook(func(agentID string) (*pb.Task, string, error) {
		return &pb.Task{TaskId: "unknown-requeue-fail"}, "msg-unknown", nil
	})
	server.SetReturnTaskHook(func(task *pb.Task, msgID string) error {
		return errors.New("injected requeue failure")
	})

	if _, err := server.ClaimTask(context.Background(), &pb.ClaimTaskReq{AgentId: "agent-1", FreeSlots: 1}); err == nil {
		t.Fatal("expected unknown-status requeue failure to be returned")
	}
}

func TestTaskCompleteDoesNotRetryCancelledRootTask(t *testing.T) {
	store := setupRegisterTestDB(t)
	root := db.RootTask{ID: "root-cancelled-complete", TenantID: "default", Status: "Cancelled", TotalChunks: 1}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed cancelled root: %v", err)
	}
	sub := db.SubTask{
		ID:           "sub-cancelled-complete",
		TenantID:     "default",
		RootTaskID:   root.ID,
		Status:       "Running",
		AgentID:      "agent-1",
		ChunkTargets: `["https://one.test"]`,
		MaxRetry:     3,
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed running subtask: %v", err)
	}

	server := NewServer(50051)
	queue := scheduler.NewTaskQueue("")
	defer queue.Close()
	server.SetRequeueTaskHook(func(task *pb.Task) error {
		return queue.PushTaskToFront(context.Background(), task)
	})
	ack, err := server.TaskComplete(context.Background(), &pb.TaskCompleteReq{
		TaskId:       sub.ID,
		AgentId:      "agent-1",
		Status:       "FAILED",
		ErrorMessage: "dial refused",
	})
	if err != nil {
		t.Fatalf("TaskComplete: %v", err)
	}
	if !ack.Success {
		t.Fatalf("TaskComplete ack failed: %+v", ack)
	}
	if depth := queue.QueueDepth(context.Background())["memory"]; depth != 0 {
		t.Fatalf("cancelled root task queue depth = %d, want 0", depth)
	}
	var got db.SubTask
	if err := store.First(&got, "id = ?", sub.ID).Error; err != nil {
		t.Fatalf("reload subtask: %v", err)
	}
	if got.Status != "FAILED" || got.AgentID != "agent-1" || got.FinishedAt == nil || got.FailureReason != "dial refused" {
		t.Fatalf("cancelled root completion evidence mismatch: %+v", got)
	}
	var gotRoot db.RootTask
	if err := store.First(&gotRoot, "id = ?", root.ID).Error; err != nil {
		t.Fatalf("reload root task: %v", err)
	}
	if gotRoot.Status != "Cancelled" {
		t.Fatalf("cancelled root status = %s, want Cancelled", gotRoot.Status)
	}
}

func TestTaskCompleteSettlesCancelPendingWithoutRetry(t *testing.T) {
	store := setupRegisterTestDB(t)
	root := db.RootTask{ID: "root-cancel-pending", TenantID: "default", Status: "Running", TotalChunks: 1}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	sub := db.SubTask{
		ID:           "sub-cancel-pending",
		TenantID:     "default",
		RootTaskID:   root.ID,
		Status:       "CancelPending",
		AgentID:      "agent-1",
		ChunkTargets: `["https://one.test","https://two.test"]`,
		MaxRetry:     3,
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}

	server := NewServer(50051)
	queue := scheduler.NewTaskQueue("")
	defer queue.Close()
	server.SetRequeueTaskHook(func(task *pb.Task) error {
		return queue.PushTaskToFront(context.Background(), task)
	})
	if _, err := server.TaskComplete(context.Background(), &pb.TaskCompleteReq{
		TaskId: sub.ID, AgentId: sub.AgentID, Status: "FAILED",
	}); err != nil {
		t.Fatalf("TaskComplete: %v", err)
	}
	if depth := queue.QueueDepth(context.Background())["memory"]; depth != 0 {
		t.Fatalf("cancel-pending task queue depth = %d, want 0", depth)
	}
	var got db.SubTask
	if err := store.First(&got, "id = ?", sub.ID).Error; err != nil {
		t.Fatalf("reload subtask: %v", err)
	}
	if got.Status != "CANCELLED" || got.AgentID != "agent-1" || got.FinishedAt == nil {
		t.Fatalf("cancel-pending completion evidence mismatch: %+v", got)
	}
}

func TestTaskCompleteFailureDoesNotRetryPausedBatch(t *testing.T) {
	store := setupRegisterTestDB(t)
	root := db.RootTask{ID: "root-paused-batch-complete", TenantID: "default", Status: "Running", TotalChunks: 1, TotalTargets: 2}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	sub := db.SubTask{
		ID: "batch-paused-complete-attempt-1", BatchID: "batch-paused-complete", AttemptNo: 1,
		TenantID: "default", RootTaskID: root.ID, Status: "Running", AgentID: "agent-1",
		ChunkTargets: `["https://one.test","https://two.test"]`, MaxRetry: 3,
	}
	batch := db.TaskBatch{
		ID: sub.BatchID, TenantID: "default", RootTaskID: root.ID, Sequence: 0,
		Targets: sub.ChunkTargets, TargetCount: 2, Status: "Running", ControlState: string(db.BatchControlPaused),
		LatestAttemptID: sub.ID, CurrentAttemptNo: 1, AttemptCount: 1,
	}
	if err := store.Create(&batch).Error; err != nil {
		t.Fatalf("seed batch: %v", err)
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}

	server := NewServer(50051)
	queue := scheduler.NewTaskQueue("")
	defer queue.Close()
	server.SetRequeueTaskHook(func(task *pb.Task) error {
		return queue.PushTaskToFront(context.Background(), task)
	})
	ack, err := server.TaskComplete(context.Background(), &pb.TaskCompleteReq{
		TaskId: sub.ID, AgentId: sub.AgentID, Status: "FAILED", ErrorMessage: "dial refused",
	})
	if err != nil || !ack.Success {
		t.Fatalf("TaskComplete ack=%+v err=%v", ack, err)
	}
	if depth := queue.QueueDepth(context.Background())["memory"]; depth != 0 {
		t.Fatalf("paused batch queued %d retries, want 0", depth)
	}
	var attempts int64
	store.Model(&db.SubTask{}).Where("batch_id = ?", batch.ID).Count(&attempts)
	if attempts != 1 {
		t.Fatalf("paused batch created %d attempts, want 1", attempts)
	}
	if err := store.First(&batch, "id = ?", batch.ID).Error; err != nil {
		t.Fatal(err)
	}
	if batch.Status != "FAILED" || db.CanonicalBatchControlState(batch.ControlState) != db.BatchControlPaused {
		t.Fatalf("paused batch completion state mismatch: %+v", batch)
	}
}

func TestTaskCompleteDuplicateFailureDoesNotSplitTwice(t *testing.T) {
	store := setupRegisterTestDB(t)
	root := db.RootTask{ID: "root-duplicate-complete", TenantID: "default", Status: "Running", TotalChunks: 1}
	if err := store.Create(&root).Error; err != nil {
		t.Fatalf("seed root: %v", err)
	}
	sub := db.SubTask{
		ID:           "sub-duplicate-complete",
		TenantID:     "default",
		RootTaskID:   root.ID,
		Status:       "Running",
		AgentID:      "agent-1",
		ChunkTargets: `["https://one.test","https://two.test"]`,
		MaxRetry:     3,
	}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatalf("seed subtask: %v", err)
	}

	server := NewServer(50051)
	queue := scheduler.NewTaskQueue("")
	defer queue.Close()
	server.SetRequeueTaskHook(func(task *pb.Task) error {
		return queue.PushTaskToFront(context.Background(), task)
	})
	req := &pb.TaskCompleteReq{TaskId: sub.ID, AgentId: sub.AgentID, Status: "FAILED"}
	for i := 0; i < 2; i++ {
		if _, err := server.TaskComplete(context.Background(), req); err != nil {
			t.Fatalf("TaskComplete call %d: %v", i+1, err)
		}
	}
	if depth := queue.QueueDepth(context.Background())["memory"]; depth != 2 {
		t.Fatalf("duplicate completion queue depth = %d, want exactly first split pair", depth)
	}
	var count int64
	if err := store.Model(&db.SubTask{}).Where("root_task_id = ?", root.ID).Count(&count).Error; err != nil {
		t.Fatalf("count subtasks: %v", err)
	}
	if count != 3 {
		t.Fatalf("duplicate completion created %d attempts, want original plus first split pair", count)
	}
	var queued []db.SubTask
	if err := store.Where("root_task_id = ? AND status = ?", root.ID, "Pending").Find(&queued).Error; err != nil {
		t.Fatalf("load queued retries: %v", err)
	}
	if len(queued) != 2 {
		t.Fatalf("queued retry attempts = %d, want 2", len(queued))
	}
	for _, item := range queued {
		if item.Status != "Pending" || item.StreamMsgID != retryQueuedMarker {
			t.Fatalf("requeued subtask did not advance to Pending: %+v", item)
		}
	}
}

func seedEmergencyDumpAgent(t *testing.T, store *gorm.DB, agentID, tenantID, token string, spot bool, instanceStatus string) {
	t.Helper()
	expiresAt := time.Now().Add(time.Hour)
	if err := store.Create(&db.Node{
		AgentID:        agentID,
		TenantID:       tenantID,
		Status:         "Alive",
		Token:          token,
		TokenExpiresAt: &expiresAt,
		RunningTasks:   1,
	}).Error; err != nil {
		t.Fatalf("seed emergency node: %v", err)
	}
	if err := store.Create(&db.CloudInstance{
		ID:       "cloud-" + agentID,
		AgentID:  agentID,
		TenantID: tenantID,
		Spot:     spot,
		Status:   instanceStatus,
	}).Error; err != nil {
		t.Fatalf("seed emergency cloud instance: %v", err)
	}
}

func emergencyDumpContext(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-agent-token", token))
}

func TestEmergencyDumpRejectsInvalidAgentSession(t *testing.T) {
	store := setupRegisterTestDB(t)
	seedEmergencyDumpAgent(t, store, "agent-spot", "tenant-a", "valid-token", true, db.CloudStatusRunning)

	_, err := NewServer(50051).EmergencyDump(emergencyDumpContext("wrong-token"), &pb.EmergencyReq{AgentId: "agent-spot"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("EmergencyDump invalid token error = %v, want Unauthenticated", err)
	}
}

func TestEmergencyDumpRejectsNonSpotOrCrossTenantInstance(t *testing.T) {
	t.Run("non spot", func(t *testing.T) {
		store := setupRegisterTestDB(t)
		seedEmergencyDumpAgent(t, store, "agent-non-spot", "tenant-a", "token", false, db.CloudStatusRunning)
		_, err := NewServer(50051).EmergencyDump(emergencyDumpContext("token"), &pb.EmergencyReq{AgentId: "agent-non-spot"})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("EmergencyDump non-spot error = %v, want FailedPrecondition", err)
		}
	})

	t.Run("cross tenant", func(t *testing.T) {
		store := setupRegisterTestDB(t)
		expiresAt := time.Now().Add(time.Hour)
		if err := store.Create(&db.Node{AgentID: "agent-cross", TenantID: "tenant-a", Status: "Alive", Token: "token", TokenExpiresAt: &expiresAt}).Error; err != nil {
			t.Fatalf("seed cross-tenant node: %v", err)
		}
		if err := store.Create(&db.CloudInstance{ID: "cloud-cross", AgentID: "agent-cross", TenantID: "tenant-b", Spot: true, Status: db.CloudStatusRunning}).Error; err != nil {
			t.Fatalf("seed cross-tenant instance: %v", err)
		}
		_, err := NewServer(50051).EmergencyDump(emergencyDumpContext("token"), &pb.EmergencyReq{AgentId: "agent-cross"})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("EmergencyDump cross-tenant error = %v, want FailedPrecondition", err)
		}
	})
}

func TestEmergencyDumpAckFailureKeepsOriginalLease(t *testing.T) {
	store := setupRegisterTestDB(t)
	seedEmergencyDumpAgent(t, store, "agent-spot", "tenant-a", "token", true, db.CloudStatusRunning)
	if err := store.Create(&db.SubTask{ID: "task-ack-fail", TenantID: "tenant-a", Status: "Running", AgentID: "agent-spot", StreamMsgID: "msg-old"}).Error; err != nil {
		t.Fatalf("seed running subtask: %v", err)
	}

	server := NewServer(50051)
	requeued := 0
	server.SetAckTaskHook(func(string) error { return errors.New("ack failed") })
	server.SetRequeueTaskHook(func(*pb.Task) error { requeued++; return nil })
	ack, err := server.EmergencyDump(emergencyDumpContext("token"), &pb.EmergencyReq{AgentId: "agent-spot"})
	if err != nil {
		t.Fatalf("EmergencyDump ACK failure: %v", err)
	}
	if ack.Success {
		t.Fatalf("EmergencyDump ACK failure unexpectedly succeeded: %+v", ack)
	}
	if requeued != 0 {
		t.Fatalf("ACK failure requeued %d tasks, want 0", requeued)
	}
	var sub db.SubTask
	if err := store.First(&sub, "id = ?", "task-ack-fail").Error; err != nil {
		t.Fatalf("reload subtask: %v", err)
	}
	if sub.Status != "Running" || sub.AgentID != "agent-spot" || sub.StreamMsgID != "msg-old" {
		t.Fatalf("ACK failure changed original lease: %+v", sub)
	}
}

func TestEmergencyDumpRequeuesRunningLeaseOnceAndIgnoresLateCompletion(t *testing.T) {
	store := setupRegisterTestDB(t)
	seedEmergencyDumpAgent(t, store, "agent-spot", "tenant-a", "token", true, db.CloudStatusRunning)
	if err := store.Create(&db.SubTask{ID: "task-requeue", TenantID: "tenant-a", Status: "Running", AgentID: "agent-spot", StreamMsgID: "msg-old", ChunkTargets: `["https://example.test"]`}).Error; err != nil {
		t.Fatalf("seed running subtask: %v", err)
	}

	server := NewServer(50051)
	acked := 0
	requeued := 0
	server.SetAckTaskHook(func(msgID string) error {
		if msgID != "msg-old" {
			t.Fatalf("unexpected ACK msg id: %s", msgID)
		}
		acked++
		return nil
	})
	server.SetRequeueTaskHook(func(task *pb.Task) error {
		if task.TaskId != "task-requeue-attempt-2" {
			t.Fatalf("unexpected requeued task: %+v", task)
		}
		requeued++
		return nil
	})

	for call := 1; call <= 2; call++ {
		ack, err := server.EmergencyDump(emergencyDumpContext("token"), &pb.EmergencyReq{AgentId: "agent-spot"})
		if err != nil || !ack.Success {
			t.Fatalf("EmergencyDump call %d = ack=%+v err=%v", call, ack, err)
		}
	}
	if acked != 1 || requeued != 1 {
		t.Fatalf("duplicate dump ACK/requeue = %d/%d, want 1/1", acked, requeued)
	}

	var original db.SubTask
	if err := store.First(&original, "id = ?", "task-requeue").Error; err != nil {
		t.Fatalf("reload original attempt: %v", err)
	}
	if original.Status != "Failed" || original.AgentID != "agent-spot" || original.FinishedAt == nil {
		t.Fatalf("Spot recovery overwrote original attempt: %+v", original)
	}
	var retry db.SubTask
	if err := store.First(&retry, "id = ?", "task-requeue-attempt-2").Error; err != nil {
		t.Fatalf("reload retry attempt: %v", err)
	}
	if retry.Status != "Pending" || retry.AgentID != "" || retry.StreamMsgID != retryQueuedMarker || retry.ParentAttemptID != original.ID {
		t.Fatalf("unexpected requeued attempt: %+v", retry)
	}
	if _, err := server.TaskComplete(context.Background(), &pb.TaskCompleteReq{TaskId: original.ID, AgentId: "agent-spot", Status: "DONE"}); err != nil {
		t.Fatalf("late TaskComplete: %v", err)
	}
	if err := store.First(&retry, "id = ?", retry.ID).Error; err != nil {
		t.Fatalf("reload retry after late completion: %v", err)
	}
	if retry.Status != "Pending" {
		t.Fatalf("late completion changed requeued attempt: %+v", retry)
	}

	var node db.Node
	if err := store.First(&node, "agent_id = ?", "agent-spot").Error; err != nil {
		t.Fatalf("reload emergency node: %v", err)
	}
	if node.Status != "Offline" {
		t.Fatalf("emergency node status = %s, want Offline", node.Status)
	}
	var instance db.CloudInstance
	if err := store.First(&instance, "agent_id = ?", "agent-spot").Error; err != nil {
		t.Fatalf("reload emergency instance: %v", err)
	}
	if instance.Status != db.CloudStatusTerminating {
		t.Fatalf("emergency instance status = %s, want %s", instance.Status, db.CloudStatusTerminating)
	}
}

func TestEmergencyDumpCASCompetitionDoesNotRequeueChangedLease(t *testing.T) {
	store := setupRegisterTestDB(t)
	seedEmergencyDumpAgent(t, store, "agent-spot", "tenant-a", "token", true, db.CloudStatusRunning)
	if err := store.Create(&db.SubTask{ID: "task-cas-race", TenantID: "tenant-a", Status: "Running", AgentID: "agent-spot", StreamMsgID: "msg-race"}).Error; err != nil {
		t.Fatalf("seed running subtask: %v", err)
	}

	server := NewServer(50051)
	requeued := 0
	server.SetAckTaskHook(func(string) error {
		return store.Model(&db.SubTask{}).Where("id = ?", "task-cas-race").Updates(map[string]interface{}{"status": "Done", "agent_id": "", "stream_msg_id": ""}).Error
	})
	server.SetRequeueTaskHook(func(*pb.Task) error { requeued++; return nil })
	ack, err := server.EmergencyDump(emergencyDumpContext("token"), &pb.EmergencyReq{AgentId: "agent-spot"})
	if err != nil || !ack.Success {
		t.Fatalf("EmergencyDump CAS race = ack=%+v err=%v", ack, err)
	}
	if requeued != 0 {
		t.Fatalf("CAS race requeued %d tasks, want 0", requeued)
	}
}

func TestEmergencyDumpRequeueFailureLeavesDispatchingForRecovery(t *testing.T) {
	store := setupRegisterTestDB(t)
	seedEmergencyDumpAgent(t, store, "agent-spot", "tenant-a", "token", true, db.CloudStatusRunning)
	if err := store.Create(&db.SubTask{ID: "task-push-fail", TenantID: "tenant-a", Status: "Running", AgentID: "agent-spot", StreamMsgID: "msg-old"}).Error; err != nil {
		t.Fatalf("seed running subtask: %v", err)
	}

	server := NewServer(50051)
	server.SetAckTaskHook(func(string) error { return nil })
	server.SetRequeueTaskHook(func(*pb.Task) error { return errors.New("publish failed") })
	ack, err := server.EmergencyDump(emergencyDumpContext("token"), &pb.EmergencyReq{AgentId: "agent-spot"})
	if err != nil || !ack.Success {
		t.Fatalf("EmergencyDump push failure = ack=%+v err=%v", ack, err)
	}
	var sub db.SubTask
	if err := store.First(&sub, "parent_attempt_id = ?", "task-push-fail").Error; err != nil {
		t.Fatalf("reload push-failed retry attempt: %v", err)
	}
	if sub.Status != "Dispatching" || sub.AgentID != "" || sub.StreamMsgID != "" {
		t.Fatalf("push failure did not preserve recoverable Dispatching state: %+v", sub)
	}
}

func TestEmergencyDumpSettlesCancelPendingWithoutRequeue(t *testing.T) {
	store := setupRegisterTestDB(t)
	seedEmergencyDumpAgent(t, store, "agent-spot", "tenant-a", "token", true, db.CloudStatusRunning)
	if err := store.Create(&db.SubTask{ID: "task-cancel", TenantID: "tenant-a", Status: "CancelPending", AgentID: "agent-spot", StreamMsgID: "msg-cancel"}).Error; err != nil {
		t.Fatalf("seed cancel-pending subtask: %v", err)
	}

	server := NewServer(50051)
	requeued := 0
	server.SetAckTaskHook(func(string) error { return nil })
	server.SetRequeueTaskHook(func(*pb.Task) error { requeued++; return nil })
	ack, err := server.EmergencyDump(emergencyDumpContext("token"), &pb.EmergencyReq{AgentId: "agent-spot"})
	if err != nil || !ack.Success {
		t.Fatalf("EmergencyDump CancelPending = ack=%+v err=%v", ack, err)
	}
	if requeued != 0 {
		t.Fatalf("CancelPending requeued %d tasks, want 0", requeued)
	}
	var sub db.SubTask
	if err := store.First(&sub, "id = ?", "task-cancel").Error; err != nil {
		t.Fatalf("reload cancelled subtask: %v", err)
	}
	if sub.Status != "Cancelled" || sub.AgentID != "agent-spot" || sub.StreamMsgID != "" || sub.FinishedAt == nil {
		t.Fatalf("unexpected cancelled subtask: %+v", sub)
	}
}

func TestHeartbeatDoesNotReviveTerminatingSpotAgent(t *testing.T) {
	store := setupRegisterTestDB(t)
	seedEmergencyDumpAgent(t, store, "agent-terminating", "tenant-a", "token", true, db.CloudStatusTerminating)
	if err := store.Model(&db.Node{}).Where("agent_id = ?", "agent-terminating").Update("status", "Offline").Error; err != nil {
		t.Fatalf("mark terminating node offline: %v", err)
	}

	resp, err := NewServer(50051).Heartbeat(context.Background(), &pb.HeartbeatReq{
		AgentId:      "agent-terminating",
		RunningTasks: 1,
	})
	if err != nil {
		t.Fatalf("Heartbeat terminating Spot agent: %v", err)
	}
	if !resp.ShouldTerminate {
		t.Fatalf("Heartbeat response = %+v, want ShouldTerminate", resp)
	}
	var node db.Node
	if err := store.First(&node, "agent_id = ?", "agent-terminating").Error; err != nil {
		t.Fatalf("reload terminating node: %v", err)
	}
	if node.Status != "Offline" {
		t.Fatalf("late heartbeat revived terminating Spot node: %+v", node)
	}
}

func TestSubscribeDoesNotReviveTerminatingSpotAgent(t *testing.T) {
	store := setupRegisterTestDB(t)
	seedEmergencyDumpAgent(t, store, "agent-terminating-subscribe", "tenant-a", "token", true, db.CloudStatusTerminating)
	if err := store.Model(&db.Node{}).Where("agent_id = ?", "agent-terminating-subscribe").Update("status", "Offline").Error; err != nil {
		t.Fatalf("mark terminating node offline: %v", err)
	}

	NewServer(50051).markSubscribedAgentAlive("agent-terminating-subscribe", 4)
	var node db.Node
	if err := store.First(&node, "agent_id = ?", "agent-terminating-subscribe").Error; err != nil {
		t.Fatalf("reload terminating node: %v", err)
	}
	if node.Status != "Offline" {
		t.Fatalf("late subscribe revived terminating Spot node: %+v", node)
	}
}

func TestRegisterPromotesWaitingCloudInstanceToRunning(t *testing.T) {
	store := setupRegisterTestDB(t)
	if err := store.Create(&db.CloudInstance{
		ID:       "ci-1",
		TenantID: "default",
		AgentID:  "agent-1",
		Status:   db.CloudStatusWaitingReady,
	}).Error; err != nil {
		t.Fatalf("seed cloud instance: %v", err)
	}

	server := NewServer(50051)
	resp, err := server.Register(context.Background(), &pb.RegisterReq{
		AgentId:  "agent-1",
		Version:  "1.0.0",
		Capacity: 2,
		Tags:     map[string]string{"cloud": "auto-scaled"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !resp.Success || resp.Token == "" {
		t.Fatalf("unexpected register response: %+v", resp)
	}

	var instance db.CloudInstance
	if err := store.First(&instance, "id = ?", "ci-1").Error; err != nil {
		t.Fatalf("load cloud instance: %v", err)
	}
	if instance.Status != db.CloudStatusRunning {
		t.Fatalf("expected status %s, got %s", db.CloudStatusRunning, instance.Status)
	}
	if instance.ReadyAt == nil {
		t.Fatalf("expected ready_at to be populated after register")
	}

	secondResp, err := server.Register(context.Background(), &pb.RegisterReq{
		AgentId:  "agent-1",
		Version:  "1.0.1",
		Capacity: 2,
		Tags:     map[string]string{"cloud": "auto-scaled"},
	})
	if err != nil {
		t.Fatalf("second register: %v", err)
	}
	if secondResp.Token == "" || secondResp.Token == resp.Token {
		t.Fatalf("expected re-register to rotate session token, first=%q second=%q", resp.Token, secondResp.Token)
	}
	var node db.Node
	if err := store.First(&node, "agent_id = ?", "agent-1").Error; err != nil {
		t.Fatalf("load node: %v", err)
	}
	if node.Token != secondResp.Token || node.Version != "1.0.1" {
		t.Fatalf("expected node to store rotated token and latest version, got %+v", node)
	}
}
