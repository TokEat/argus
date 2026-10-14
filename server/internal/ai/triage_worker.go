package ai

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"gorm.io/gorm"
)

// TriageWorkerOptions configures the background false-positive triage worker.
type TriageWorkerOptions struct {
	Client       ChatClient
	Interval     time.Duration // 扫描周期，默认 30s
	BatchSize    int           // 每 tick 最多研判条数，默认 20
	Concurrency  int           // 并发研判数，默认 3
	InitialDelay time.Duration // 启动后首次扫描延迟，默认 10s
}

func (o *TriageWorkerOptions) withDefaults() {
	if o.Interval <= 0 {
		o.Interval = 30 * time.Second
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 20
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 3
	}
	if o.InitialDelay < 0 {
		o.InitialDelay = 0
	}
}

// StartTriageWorker launches a background goroutine that periodically triages
// open, untriaged vulnerabilities. It does not touch the ingest path, so a
// slow/unreachable LLM never blocks result reporting.
func StartTriageWorker(ctx context.Context, store *gorm.DB, opts TriageWorkerOptions) {
	opts.withDefaults()
	go func() {
		if opts.InitialDelay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(opts.InitialDelay):
			}
		}
		ticker := time.NewTicker(opts.Interval)
		defer ticker.Stop()
		for {
			RunTriageTick(ctx, store, opts)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// RunTriageTick performs one scan-and-triage pass. Exported so tests can drive
// a single tick without managing goroutines.
func RunTriageTick(ctx context.Context, store *gorm.DB, opts TriageWorkerOptions) {
	opts.withDefaults()
	if !LoadTriageEnabled(store) {
		return
	}
	var vulns []db.Vulnerability
	if err := store.WithContext(ctx).
		Where("status = 'open' AND ai_triaged_at IS NULL").
		Order("id").
		Limit(opts.BatchSize).
		Find(&vulns).Error; err != nil {
		log.Printf("[AI] triage worker select failed: %v", err)
		return
	}
	if len(vulns) == 0 {
		return
	}
	analyzer := &TriageAnalyzer{DB: store, Client: opts.Client}
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	for i := range vulns {
		vuln := vulns[i]
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			triageCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			// LLM failure leaves ai_triaged_at unset so the next tick retries.
			if _, err := analyzer.Triage(triageCtx, vuln, TriageOptions{}); err != nil {
				log.Printf("[AI] triage worker vuln=%d failed: %v", vuln.ID, err)
			}
		}()
	}
	wg.Wait()
}
