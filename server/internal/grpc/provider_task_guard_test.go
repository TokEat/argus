package grpc

import (
	"errors"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/server/internal/db"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"gorm.io/gorm"
)

func TestRejectLegacyProviderTaskPersistsBeforeAck(t *testing.T) {
	store := setupRegisterTestDB(t)
	sub := db.SubTask{ID: "provider-attempt", TenantID: "tenant-a", Status: "Dispatching"}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatal(err)
	}

	server := NewServer(0)
	ackCalls := 0
	server.SetAckTaskHook(func(messageID string) error {
		ackCalls++
		if messageID != "message-a" {
			t.Fatalf("unexpected message ID %q", messageID)
		}
		var persisted db.SubTask
		if err := store.First(&persisted, "id = ?", sub.ID).Error; err != nil {
			t.Fatal(err)
		}
		if persisted.Status != "Failed" || persisted.FailureReason != "Provider discovery configuration is Server-only" {
			t.Fatalf("ACK ran before terminal rejection was durable: %+v", persisted)
		}
		return nil
	})

	if err := server.rejectLegacyProviderTask(&pb.Task{TaskId: sub.ID}, "message-a", sub); err != nil {
		t.Fatalf("reject provider task: %v", err)
	}
	if ackCalls != 1 {
		t.Fatalf("expected one ACK, got %d", ackCalls)
	}
}

func TestRejectLegacyProviderTaskDoesNotAckWhenPersistenceFails(t *testing.T) {
	store := setupRegisterTestDB(t)
	sub := db.SubTask{ID: "provider-attempt-failure", TenantID: "tenant-a", Status: "Dispatching"}
	if err := store.Create(&sub).Error; err != nil {
		t.Fatal(err)
	}

	const callbackName = "g41:fail_provider_rejection_update"
	if err := store.Callback().Update().Before("gorm:update").Register(callbackName, func(tx *gorm.DB) {
		if tx.Statement.Table == "sub_tasks" {
			tx.AddError(errors.New("forced provider rejection persistence failure"))
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Callback().Update().Remove(callbackName) })

	server := NewServer(0)
	ackCalls := 0
	server.SetAckTaskHook(func(string) error {
		ackCalls++
		return nil
	})

	err := server.rejectLegacyProviderTask(&pb.Task{TaskId: sub.ID}, "message-a", sub)
	if err == nil || !strings.Contains(err.Error(), "forced provider rejection persistence failure") {
		t.Fatalf("expected forced persistence error, got %v", err)
	}
	if ackCalls != 0 {
		t.Fatalf("queue message was ACKed despite persistence failure: %d", ackCalls)
	}
	var persisted db.SubTask
	if err := store.First(&persisted, "id = ?", sub.ID).Error; err != nil {
		t.Fatal(err)
	}
	if persisted.Status != "Dispatching" {
		t.Fatalf("persistence failure changed attempt status: %s", persisted.Status)
	}
}
