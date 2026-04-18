package scheduler

import (
	"context"
	"testing"

	pb "github.com/user/dddd-proto/go/scan"
)

func TestNewTaskQueueFallsBackToMemory(t *testing.T) {
	queue := NewTaskQueue("", "", 0)
	if queue.Mode() != "memory" {
		t.Fatalf("expected memory mode, got %s", queue.Mode())
	}
}

func TestMemoryQueuePushOrder(t *testing.T) {
	queue := NewTaskQueue("", "", 0)

	if err := queue.PushTask(context.Background(), &pb.Task{TaskId: "normal"}); err != nil {
		t.Fatalf("push task failed: %v", err)
	}
	if err := queue.PushTaskToFront(context.Background(), &pb.Task{TaskId: "priority"}); err != nil {
		t.Fatalf("push front failed: %v", err)
	}

	first, err := queue.PopTask(context.Background())
	if err != nil {
		t.Fatalf("first pop failed: %v", err)
	}
	if first == nil || first.TaskId != "priority" {
		t.Fatalf("expected priority task first, got %#v", first)
	}

	second, err := queue.PopTask(context.Background())
	if err != nil {
		t.Fatalf("second pop failed: %v", err)
	}
	if second == nil || second.TaskId != "normal" {
		t.Fatalf("expected normal task second, got %#v", second)
	}
}
