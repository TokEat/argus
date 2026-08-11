package grpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	pb "github.com/user/dddd-proto/go/scan"
	"github.com/user/dddd-proto/go/scanplan"
	"github.com/user/dddd-server/internal/db"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const maxTimingEventPayloadBytes = 16 * 1024
const maxTimingEventDeliveryDelay = 24 * time.Hour
const maxTimingEventFutureSkew = 10 * time.Minute

func persistTimingEvent(ctx context.Context, result *pb.ScanResult) error {
	event, err := validateTimingEventResult(result)
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	node, err := validateEmergencyAgentSession(ctx, event.AgentID)
	if err != nil {
		return err
	}
	if !containsStatus([]string{"Alive", "Draining"}, node.Status) {
		return status.Error(codes.FailedPrecondition, "timing event Agent session is not active")
	}
	attempt, err := validateTimingEventOwnership(event)
	if err != nil || attempt.TenantID != node.TenantID {
		return status.Error(codes.PermissionDenied, "timing event does not belong to this Agent session")
	}
	if _, _, err := db.RecordScanTimingEvent(db.DB, attempt, event); err != nil {
		if errors.Is(err, db.ErrScanTimingEventConflict) {
			return status.Error(codes.AlreadyExists, "timing event id conflicts with existing evidence")
		}
		return status.Error(codes.Internal, "record timing event failed")
	}
	return nil
}

func validateTimingEventResult(result *pb.ScanResult) (scanplan.TimingEvent, error) {
	if result == nil || strings.TrimSpace(result.TaskId) == "" {
		return scanplan.TimingEvent{}, errors.New("timing event requires task_id")
	}
	if len(result.Payload) == 0 || len(result.Payload) > maxTimingEventPayloadBytes {
		return scanplan.TimingEvent{}, errors.New("timing event payload exceeds the allowed size")
	}
	var event scanplan.TimingEvent
	decoder := json.NewDecoder(bytes.NewReader(result.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return scanplan.TimingEvent{}, fmt.Errorf("decode timing event: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return scanplan.TimingEvent{}, errors.New("timing event payload must contain one JSON object")
	}
	if err := event.Validate(); err != nil {
		return scanplan.TimingEvent{}, fmt.Errorf("validate timing event: %w", err)
	}
	now := time.Now().UTC()
	if event.FinishedAt.Before(now.Add(-maxTimingEventDeliveryDelay)) || event.FinishedAt.After(now.Add(maxTimingEventFutureSkew)) {
		return scanplan.TimingEvent{}, errors.New("timing event timestamp is outside the accepted delivery window")
	}
	if event.AttemptID != strings.TrimSpace(result.TaskId) {
		return scanplan.TimingEvent{}, errors.New("timing event attempt_id does not match stream task_id")
	}
	return event, nil
}

func validateTimingEventOwnership(event scanplan.TimingEvent) (db.SubTask, error) {
	var attempt db.SubTask
	if err := db.DB.Where("id = ? AND agent_id = ? AND status IN ?", event.AttemptID, event.AgentID, activeSubTaskStatuses).
		First(&attempt).Error; err != nil {
		return db.SubTask{}, errors.New("timing event does not belong to an active attempt assigned to this agent")
	}
	return attempt, nil
}
