package scheduler

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
)

func TestTaskQueueMemoryModeRequiresEmptyAMQPURL(t *testing.T) {
	queue := NewTaskQueue("")
	defer queue.Close()
	if queue.Mode() != "memory" {
		t.Fatalf("expected memory mode, got %q", queue.Mode())
	}
	task := &pb.Task{TaskId: "memory-task", Priority: PriorityNormal}
	if err := queue.PushTask(context.Background(), task); err != nil {
		t.Fatalf("push memory task: %v", err)
	}
	got, _, err := queue.TryPopTask(context.Background(), "agent-memory")
	if err != nil {
		t.Fatalf("pop memory task: %v", err)
	}
	if got == nil || got.TaskId != task.TaskId {
		t.Fatalf("unexpected memory task: %+v", got)
	}
}

func TestTaskQueueExplicitRabbitMQDoesNotFallbackToMemory(t *testing.T) {
	queue := NewTaskQueue("amqp://guest:guest@127.0.0.1:1/")
	defer queue.Close()
	if queue.Mode() != "rabbitmq" {
		t.Fatalf("expected explicit rabbitmq mode, got %q", queue.Mode())
	}
	if queue.mem != nil {
		t.Fatal("explicit rabbitmq mode must not initialize an in-memory fallback")
	}
	if depths := queue.QueueDepth(context.Background()); len(depths) != 0 {
		t.Fatalf("disconnected rabbitmq depth should be empty, got %+v", depths)
	}
	err := queue.PushTask(context.Background(), &pb.Task{TaskId: "must-not-fallback"})
	if err == nil || !strings.Contains(err.Error(), "RabbitMQ connect failed") {
		t.Fatalf("expected bounded reconnect error, got %v", err)
	}
}

func TestTaskQueueDeliveryIDsDifferAcrossQueueLifecycles(t *testing.T) {
	first := NewTaskQueue("")
	defer first.Close()
	second := NewTaskQueue("")
	defer second.Close()
	first.generation = 1
	second.generation = 1
	firstID := first.deliveryID(priorityQueues[PriorityNormal], 1)
	secondID := second.deliveryID(priorityQueues[PriorityNormal], 1)
	if first.epoch == second.epoch || firstID == secondID {
		t.Fatalf("delivery IDs must differ across queue lifecycles: first=%q second=%q", firstID, secondID)
	}
}

func TestTaskQueueRabbitMQReconnectInvalidatesOldDelivery(t *testing.T) {
	amqpURL := strings.TrimSpace(os.Getenv("ARGUS_RABBITMQ_TEST_URL"))
	if amqpURL == "" {
		t.Skip("ARGUS_RABBITMQ_TEST_URL is not set")
	}

	queue := NewTaskQueue(amqpURL)
	defer queue.Close()
	if queue.Mode() != "rabbitmq" {
		t.Fatalf("expected rabbitmq mode, got %q", queue.Mode())
	}
	queue.chMu.Lock()
	initialGeneration := queue.generation
	connected := queue.connectionHealthyLocked()
	queue.chMu.Unlock()
	initialToken := queue.RecoveryToken()
	if !connected {
		t.Fatal("expected initial RabbitMQ connection")
	}

	task := &pb.Task{TaskId: "reconnect-task", Priority: PriorityNormal}
	if err := queue.PushTask(context.Background(), task); err != nil {
		t.Fatalf("push task: %v", err)
	}
	claimed, oldDeliveryID := popTaskEventually(t, queue, "agent-old")
	if claimed.TaskId != task.TaskId || oldDeliveryID == "" {
		t.Fatalf("unexpected initial delivery: task=%+v id=%q", claimed, oldDeliveryID)
	}

	queue.chMu.Lock()
	if err := queue.conn.Close(); err != nil {
		queue.chMu.Unlock()
		t.Fatalf("close RabbitMQ connection: %v", err)
	}
	queue.chMu.Unlock()

	recoveryDeadline := time.Now().Add(10 * time.Second)
	var newGeneration uint64
	for time.Now().Before(recoveryDeadline) {
		queue.chMu.Lock()
		newGeneration = queue.generation
		healthy := queue.connectionHealthyLocked()
		queue.chMu.Unlock()
		if healthy && newGeneration > initialGeneration {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if newGeneration <= initialGeneration {
		t.Fatalf("expected generation to advance from %d, got %d", initialGeneration, newGeneration)
	}
	if recoveredToken := queue.RecoveryToken(); recoveredToken == initialToken {
		t.Fatalf("expected recovery token to change after reconnect, token=%q", recoveredToken)
	}
	if counts := queue.PendingCount(context.Background()); len(counts) != 0 {
		t.Fatalf("expected old pending deliveries to be invalidated, got %+v", counts)
	}
	if err := queue.AckTask(context.Background(), oldDeliveryID); err != nil {
		t.Fatalf("stale ACK should be ignored, got %v", err)
	}
	if err := queue.NackTask(context.Background(), oldDeliveryID); err != nil {
		t.Fatalf("stale NACK should be ignored, got %v", err)
	}

	requeued, newDeliveryID := popTaskEventually(t, queue, "agent-new")
	if requeued.TaskId != task.TaskId {
		t.Fatalf("expected unacked task to be requeued, got %+v", requeued)
	}
	if newDeliveryID == "" || newDeliveryID == oldDeliveryID {
		t.Fatalf("expected a new generation delivery id, old=%q new=%q", oldDeliveryID, newDeliveryID)
	}
	if err := queue.AckTask(context.Background(), newDeliveryID); err != nil {
		t.Fatalf("ack requeued task: %v", err)
	}
}

func TestTaskQueueRabbitMQBrokerRestartSmoke(t *testing.T) {
	if os.Getenv("ARGUS_RABBITMQ_OUTAGE_SMOKE") != "1" {
		t.Skip("ARGUS_RABBITMQ_OUTAGE_SMOKE is not enabled")
	}
	amqpURL := strings.TrimSpace(os.Getenv("ARGUS_RABBITMQ_TEST_URL"))
	if amqpURL == "" {
		t.Fatal("ARGUS_RABBITMQ_TEST_URL is required")
	}

	queue := NewTaskQueue(amqpURL)
	defer queue.Close()
	if err := queue.PushTask(context.Background(), &pb.Task{TaskId: "broker-restart-before", Priority: PriorityNormal}); err != nil {
		t.Fatalf("initial push: %v", err)
	}
	_, initialDeliveryID := popTaskEventually(t, queue, "agent-before-restart")
	if err := queue.AckTask(context.Background(), initialDeliveryID); err != nil {
		t.Fatalf("initial ack: %v", err)
	}

	t.Log("BROKER_OUTAGE_READY")
	time.Sleep(15 * time.Second)
	outageDeadline := time.Now().Add(20 * time.Second)
	for {
		if !queueIsHealthy(queue) {
			break
		}
		if time.Now().After(outageDeadline) {
			t.Fatal("broker outage was not observed")
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Log("BROKER_OUTAGE_OBSERVED")

	recoveryDeadline := time.Now().Add(60 * time.Second)
	for {
		if queueIsHealthy(queue) {
			break
		}
		if time.Now().After(recoveryDeadline) {
			t.Fatal("broker did not recover")
		}
		time.Sleep(500 * time.Millisecond)
	}

	task := &pb.Task{TaskId: "broker-restart-after", Priority: PriorityNormal}
	if err := queue.PushTask(context.Background(), task); err != nil {
		t.Fatalf("push after broker restart: %v", err)
	}
	got, deliveryID := popTaskEventually(t, queue, "agent-after-restart")
	if got.TaskId != task.TaskId {
		t.Fatalf("unexpected task after restart: %+v", got)
	}
	if err := queue.AckTask(context.Background(), deliveryID); err != nil {
		t.Fatalf("ack after broker restart: %v", err)
	}
}

func queueIsHealthy(queue *TaskQueue) bool {
	queue.chMu.Lock()
	defer queue.chMu.Unlock()
	return queue.connectionHealthyLocked()
}

func popTaskEventually(t *testing.T, queue *TaskQueue, agentID string) (*pb.Task, string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		task, deliveryID, err := queue.TryPopTask(context.Background(), agentID)
		if err != nil {
			t.Fatalf("pop task: %v", err)
		}
		if task != nil {
			return task, deliveryID
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timed out waiting for task")
	return nil, ""
}
