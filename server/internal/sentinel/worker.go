package sentinel

import (
	"context"
	"log"
	"time"

	"github.com/P0lar1ght/argus/server/internal/ai"
	"gorm.io/gorm"
)

// WorkerOptions tunes the sentinel loop.
type WorkerOptions struct {
	Client       ai.ChatClient // nil → HTTPClient (real LLM)
	Pusher       TaskPusher    // nil → rescan left Pending for the reconciler
	Interval     time.Duration // default 30s
	InitialDelay time.Duration // default 15s (let results settle after startup)
	DecideBatch  int           // default 10
	Detector     DetectorOptions
}

func (o WorkerOptions) withDefaults() WorkerOptions {
	if o.Interval <= 0 {
		o.Interval = 30 * time.Second
	}
	if o.InitialDelay <= 0 {
		o.InitialDelay = 15 * time.Second
	}
	if o.DecideBatch <= 0 {
		o.DecideBatch = 10
	}
	return o
}

// LoadEnabled reports whether the sentinel layer runs (default true).
func LoadEnabled(store *gorm.DB) bool {
	return loadSystemBool(store, ConfigKeyEnabled, true)
}

// LoadAutoExecute reports whether rescan-on-other-node may run without a
// human confirmation (default false — the conservative default).
func LoadAutoExecute(store *gorm.DB) bool {
	return loadSystemBool(store, ConfigKeyAutoExecute, false)
}

// StartSentinelWorker launches the detect → decide → execute loop.
func StartSentinelWorker(ctx context.Context, store *gorm.DB, opts WorkerOptions) {
	opts = opts.withDefaults()
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(opts.InitialDelay):
		}
		ticker := time.NewTicker(opts.Interval)
		defer ticker.Stop()
		for {
			if err := RunSentinelTick(ctx, store, opts); err != nil {
				log.Printf("[Sentinel] tick failed: %v", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// RunSentinelTick runs one full pass; exported for tests.
func RunSentinelTick(ctx context.Context, store *gorm.DB, opts WorkerOptions) error {
	opts = opts.withDefaults()
	if !LoadEnabled(store) {
		return nil
	}
	if err := RunDetectTick(ctx, store, opts.Detector); err != nil {
		return err
	}
	if _, err := Decide(ctx, store, opts.Client, opts.DecideBatch); err != nil {
		log.Printf("[Sentinel] decide: %v", err)
	}
	return RunExecuteTick(ctx, store, opts.Pusher, LoadAutoExecute(store))
}
