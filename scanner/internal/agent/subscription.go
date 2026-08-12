package agent

import (
	"context"
	"io"
	"log"
	"time"

	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
)

func (w *Worker) cancelActiveExecutions() {
	w.cancelRunningTasks()
	w.debugMu.Lock()
	debugCancel := w.debugCancel
	w.debugMu.Unlock()
	if debugCancel != nil {
		debugCancel()
	}
	w.expMu.Lock()
	expCancels := make([]context.CancelFunc, 0, len(w.expCancels))
	for _, cancel := range w.expCancels {
		expCancels = append(expCancels, cancel)
	}
	w.expMu.Unlock()
	for _, cancel := range expCancels {
		cancel()
	}
}

// subscribeAndClaim 建立 Subscribe 流并监听任务通知，收到通知后 ClaimTask 认领。
func (w *Worker) subscribeAndClaim(quit chan struct{}) {
	if w.draining.Load() {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-quit:
		case <-w.stopCh:
		case <-w.reconnectCh:
			log.Println("[Subscribe] Heartbeat detected connection failure, forcing stream reconnect...")
		case <-ctx.Done():
		}
		cancel()
	}()
	stream, err := w.client.Subscribe(ctx)
	if err != nil {
		log.Printf("[Subscribe] Failed to connect: %v", err)
		return
	}

	freeSlots := w.freeSlots.Load()
	if w.draining.Load() {
		freeSlots = 0
	}
	if err := stream.Send(&pb.AgentSignal{AgentId: w.agentID, FreeSlots: freeSlots, SignalType: "ready"}); err != nil {
		log.Printf("[Subscribe] Failed to send initial signal: %v", err)
		return
	}
	log.Printf("[Subscribe] Stream established, listening for task notifications...")

	stopCapacity := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopCapacity:
				return
			case <-ticker.C:
				freeSlots := w.freeSlots.Load()
				if w.draining.Load() {
					freeSlots = 0
				}
				_ = stream.Send(&pb.AgentSignal{AgentId: w.agentID, FreeSlots: freeSlots, SignalType: "capacity_update"})
			}
		}
	}()
	defer close(stopCapacity)

	for {
		notify, recvErr := stream.Recv()
		if recvErr == io.EOF {
			log.Println("[Subscribe] Server closed the stream (EOF)")
			return
		}
		if recvErr != nil {
			log.Printf("[Subscribe] Stream error: %v", recvErr)
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		log.Printf("[Subscribe] Received notification: type=%s, available=%d, priority=%d", notify.NotifyType, notify.AvailableTasks, notify.Priority)
		if w.draining.Load() {
			return
		}
		if notify.DebugCommand != nil {
			w.handleDebugCommand(notify.DebugCommand)
			continue
		}
		w.claimAvailableTasks()
	}
}
