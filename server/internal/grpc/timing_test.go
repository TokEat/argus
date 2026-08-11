package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-proto/go/scanplan"
	"github.com/user/dddd-server/internal/db"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func validTimingEvent(t *testing.T, attemptID, agentID string) scanplan.TimingEvent {
	t.Helper()
	event, err := (scanplan.TimingEventBuilder{
		AttemptID: attemptID,
		AgentID:   agentID,
		Kind:      scanplan.TimingContextInit,
		Outcome:   scanplan.ObservationSuccess,
		StartedAt: time.Now().UTC().Add(-time.Second),
		Duration:  time.Second,
	}).Build()
	if err != nil {
		t.Fatalf("build timing event: %v", err)
	}
	return event
}

func TestValidateTimingEventResultIsStrictAndBindsAttempt(t *testing.T) {
	event := validTimingEvent(t, "attempt-timing", "agent-timing")
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := validateTimingEventResult(&pb.ScanResult{TaskId: event.AttemptID, PayloadType: scanplan.TimingEventPayloadType, Payload: payload})
	if err != nil || parsed.EventID != event.EventID {
		t.Fatalf("valid timing event rejected: parsed=%+v err=%v", parsed, err)
	}
	if _, err := validateTimingEventResult(&pb.ScanResult{TaskId: "other-attempt", Payload: payload}); err == nil {
		t.Fatal("timing event with mismatched stream task ID was accepted")
	}
	withUnknown := append(payload[:len(payload)-1], []byte(`,"target":"must-not-be-accepted"}`)...)
	if _, err := validateTimingEventResult(&pb.ScanResult{TaskId: event.AttemptID, Payload: withUnknown}); err == nil {
		t.Fatal("timing event with an unknown field was accepted")
	}
	if _, err := validateTimingEventResult(&pb.ScanResult{TaskId: event.AttemptID, Payload: make([]byte, maxTimingEventPayloadBytes+1)}); err == nil {
		t.Fatal("oversized timing event was accepted")
	}
	stale, err := (scanplan.TimingEventBuilder{AttemptID: event.AttemptID, AgentID: event.AgentID, Kind: scanplan.TimingRulePrepare, Outcome: scanplan.ObservationSuccess, StartedAt: time.Now().UTC().Add(-48*time.Hour - time.Second), Duration: time.Second}).Build()
	if err != nil {
		t.Fatal(err)
	}
	stalePayload, _ := json.Marshal(stale)
	if _, err := validateTimingEventResult(&pb.ScanResult{TaskId: event.AttemptID, Payload: stalePayload}); err == nil {
		t.Fatal("stale timing event was accepted as a live Attempt observation")
	}
}

type timingResultTestStream struct {
	ctx      context.Context
	recv     []*pb.ScanResult
	ack      *pb.Ack
	closeErr error
}

func (s *timingResultTestStream) Recv() (*pb.ScanResult, error) {
	if len(s.recv) == 0 {
		return nil, io.EOF
	}
	result := s.recv[0]
	s.recv = s.recv[1:]
	return result, nil
}

func (s *timingResultTestStream) SendAndClose(ack *pb.Ack) error { s.ack = ack; return s.closeErr }
func (s *timingResultTestStream) SetHeader(metadata.MD) error    { return nil }
func (s *timingResultTestStream) SendHeader(metadata.MD) error   { return nil }
func (s *timingResultTestStream) SetTrailer(metadata.MD)         {}
func (s *timingResultTestStream) Context() context.Context       { return s.ctx }
func (s *timingResultTestStream) SendMsg(interface{}) error      { return nil }
func (s *timingResultTestStream) RecvMsg(interface{}) error      { return io.EOF }

func TestStreamResultPersistsTimingWithSessionAndAttemptOwnership(t *testing.T) {
	store := setupRegisterTestDB(t)
	now := time.Now().UTC()
	suffix := fmt.Sprintf("%d", now.UnixNano())
	tenantID := "tenant-timing-" + suffix
	agentID := "agent-timing-" + suffix
	token := "session-timing-" + suffix
	expires := now.Add(time.Hour)
	if err := store.Create(&db.Node{TenantID: tenantID, AgentID: agentID, Status: "Alive", Token: token, TokenExpiresAt: &expires}).Error; err != nil {
		t.Fatal(err)
	}
	root := db.RootTask{ID: "root-timing-" + suffix, TenantID: tenantID, ProjectID: "project-timing-" + suffix, Status: "Running"}
	batch := db.TaskBatch{ID: "batch-timing-" + suffix, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, Sequence: 1, Status: "Running"}
	attempt := db.SubTask{ID: "attempt-timing-" + suffix, TenantID: root.TenantID, ProjectID: root.ProjectID, RootTaskID: root.ID, BatchID: batch.ID, AgentID: agentID, Status: "Running", ConfigVersion: 1, RuleVersion: "rules-timing"}
	for _, item := range []interface{}{&root, &batch, &attempt} {
		if err := store.Create(item).Error; err != nil {
			t.Fatalf("seed timing ownership: %v", err)
		}
	}
	event := validTimingEvent(t, attempt.ID, attempt.AgentID)
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-agent-token", token))
	stream := &timingResultTestStream{ctx: ctx, recv: []*pb.ScanResult{
		{TaskId: attempt.ID, PayloadType: scanplan.TimingEventPayloadType, Payload: payload},
		{TaskId: attempt.ID, PayloadType: scanplan.TimingEventPayloadType, Payload: payload},
	}}
	if err := NewServer(50051).StreamResult(stream); err != nil {
		t.Fatalf("stream timing result: %v", err)
	}
	if stream.ack == nil || !stream.ack.Success {
		t.Fatalf("missing successful stream acknowledgement: %+v", stream.ack)
	}
	var count int64
	if err := store.Model(&db.ScanTimingEvent{}).Where("tenant_id = ? AND attempt_id = ?", root.TenantID, attempt.ID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("idempotent timing rows = %d, err=%v", count, err)
	}

	badContext := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-agent-token", "wrong"))
	badStream := &timingResultTestStream{ctx: badContext, recv: []*pb.ScanResult{{TaskId: attempt.ID, PayloadType: scanplan.TimingEventPayloadType, Payload: payload}}}
	err = NewServer(50051).StreamResult(badStream)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("invalid Agent session status = %v, want Unauthenticated (%v)", status.Code(err), err)
	}
	if err := store.Model(&db.ScanTimingEvent{}).Where("tenant_id = ? AND attempt_id = ?", root.TenantID, attempt.ID).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("invalid session changed timing evidence: count=%d err=%v", count, err)
	}
}
