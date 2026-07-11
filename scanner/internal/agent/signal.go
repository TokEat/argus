package agent

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	pb "github.com/user/dddd-proto/go/scan"
	"google.golang.org/grpc/metadata"
)

const defaultSpotTerminationURL = "http://100.100.100.200/latest/meta-data/instance/spot/termination-time"

func spotTerminationURL() string {
	if value := strings.TrimSpace(os.Getenv("ARGUS_SPOT_TERMINATION_URL")); value != "" {
		return value
	}
	return defaultSpotTerminationURL
}

// StartSpotTerminationListener listens for a cloud Spot termination notice.
func (w *Worker) StartSpotTerminationListener() {
	client := &http.Client{Timeout: 5 * time.Second}
	go w.runSpotTerminationListener(context.Background(), client, spotTerminationURL(), 30*time.Second, 2*time.Second)
}

func (w *Worker) runSpotTerminationListener(ctx context.Context, client *http.Client, endpoint string, pollInterval, retryInterval time.Duration) {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	if pollInterval <= 0 {
		pollInterval = 30 * time.Second
	}
	if retryInterval <= 0 {
		retryInterval = 2 * time.Second
	}

	for {
		terminationTime, err := fetchSpotTermination(ctx, client, endpoint)
		if err != nil {
			log.Printf("[Spot] Metadata check failed: %v", err)
		} else if terminationTime != "" {
			w.draining.Store(true)
			log.Printf("[EMERGENCY] Spot instance is scheduled for termination at %s. Draining worker and releasing leases.", terminationTime)
			for {
				if w.sendEmergencyDump(ctx) {
					w.cancelRunningTasks()
					log.Println("[Spot] Emergency dump accepted; local running tasks cancelled")
					return
				}
				if !w.waitSpotListener(ctx, retryInterval) {
					return
				}
			}
		}

		if !w.waitSpotListener(ctx, pollInterval) {
			return
		}
	}
}

func fetchSpotTermination(ctx context.Context, client *http.Client, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func (w *Worker) sendEmergencyDump(ctx context.Context) bool {
	if w.client == nil {
		return false
	}
	rpcCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rpcCtx = metadata.AppendToOutgoingContext(rpcCtx, "x-agent-token", w.sessionToken)
	ack, err := w.client.EmergencyDump(rpcCtx, &pb.EmergencyReq{AgentId: w.agentID})
	if err != nil {
		log.Printf("[Spot] Emergency dump RPC failed: %v", err)
		return false
	}
	if ack == nil || !ack.Success {
		message := "empty response"
		if ack != nil {
			message = ack.Message
		}
		log.Printf("[Spot] Emergency dump was not accepted: %s", message)
		return false
	}
	return true
}

func (w *Worker) cancelRunningTasks() {
	w.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(w.runningTasks))
	for _, cancel := range w.runningTasks {
		cancels = append(cancels, cancel)
	}
	w.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
}

func (w *Worker) waitSpotListener(ctx context.Context, wait time.Duration) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-w.stopCh:
		return false
	case <-timer.C:
		return true
	}
}
