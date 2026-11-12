package subdomainpassive

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/TokEat/argus/server/internal/db"
	"gorm.io/gorm"
)

// CapabilityTag is advertised by Agents that understand the sealed
// SubdomainPassiveResults config field. Claim-time sealing is skipped for
// Agents that do not advertise it so they keep today's agent-side behavior.
const CapabilityTag = "passive_server"

// HoldStatus is the non-claimable attempt state used while pre-dispatch
// collection is running. It intentionally reuses the canonical QUEUED state,
// which the dispatch recovery daemon ignores (it only re-pushes Dispatching).
const HoldStatus = "Queued"

// Job states.
const (
	JobStatePending   = "pending"
	JobStateRunning   = "running"
	JobStateReleased  = "released"
	JobStateFailed    = "failed"
	jobStaleWindow    = 3 * time.Minute
	defaultHoldLimit  = 8 * time.Minute
	defaultCacheTTL   = 24 * time.Hour
	defaultInterval   = 5 * time.Second
	collectOperatorID = "system"
)

// Enabled reports whether Server-side passive collection is active. It can
// be disabled with ARGUS_SERVER_PASSIVE_SUBDOMAIN=off when the Server has no
// egress to public passive sources; dispatch then keeps today's behavior.
func Enabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ARGUS_SERVER_PASSIVE_SUBDOMAIN"))) {
	case "off", "0", "false", "disabled":
		return false
	default:
		return true
	}
}

// AliveNodes loads the tags of all ALIVE agents for hold decisions.
func AliveNodes(store *gorm.DB) []db.Node {
	if store == nil {
		return nil
	}
	var nodes []db.Node
	if err := store.Select("tags").
		Where("UPPER(status) = ?", "ALIVE").
		Find(&nodes).Error; err != nil {
		return nil
	}
	return nodes
}

// CapableAgentMatchesSelector reports whether at least one ALIVE agent both
// satisfies the batch's effective selector and advertises the passive_server
// capability. Holds are only created in that case so the collected batch is
// never dispatched to agents that cannot consume sealed results.
func CapableAgentMatchesSelector(nodes []db.Node, legacy map[string]string, rules db.AgentSelectorRules) bool {
	for _, node := range nodes {
		if !AgentHasCapability(node.Tags) {
			continue
		}
		if matched, _ := db.NodeMatchesSelectorRules(legacy, rules, node.Tags); matched {
			return true
		}
	}
	return false
}

// AgentHasCapability parses a Node tags JSON blob.
func AgentHasCapability(tagsJSON string) bool {
	if strings.TrimSpace(tagsJSON) == "" {
		return false
	}
	var tags map[string]string
	if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
		return false
	}
	return tags[CapabilityTag] == "v1"
}

// HoldApplies decides whether a domain batch must wait for Server-side
// collection before dispatch. capableAgent already encodes the selector-aware
// passive_server capability check for this batch.
func HoldApplies(configHasSubdomain, configNoSubFinder bool, targetType string, capableAgent bool) bool {
	return capableAgent &&
		targetType == "domain" &&
		configHasSubdomain && !configNoSubFinder
}

// PassiveJobID derives a deterministic job id from the attempt id.
func PassiveJobID(attemptID string) string {
	return "spj-" + attemptID
}

// SealConfig injects collected results into an attempt config as
// SubdomainPassiveResults. It deliberately never sets NoSubFinder: a released
// batch may be claimed by an agent without the passive_server capability,
// which would silently drop passive enumeration if the flag were forced here.
// Agents that understand the map skip subfinder per covered domain anyway;
// NoSubFinder=true is only applied at claim time for verified capable agents.
func SealConfig(config []byte, byDomain map[string][]string) ([]byte, bool, error) {
	if len(byDomain) == 0 {
		return config, false, nil
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(config, &payload); err != nil {
		return nil, false, fmt.Errorf("decode task config for passive seal: %w", err)
	}
	if _, exists := payload["SubdomainPassiveResults"]; exists {
		return config, false, nil
	}
	covered := make(map[string][]string, len(byDomain))
	for domain, values := range byDomain {
		// Empty-but-valid results are sealed too: map presence (even empty)
		// tells the Agent this domain was already collected Server-side.
		covered[strings.ToLower(domain)] = append([]string(nil), values...)
	}
	payload["SubdomainPassiveResults"] = covered
	sealed, err := json.Marshal(payload)
	if err != nil {
		return nil, false, fmt.Errorf("encode sealed task config: %w", err)
	}
	return sealed, true, nil
}

// sealNoSubFinder forces NoSubFinder=true on an already-sealed config. It is
// only used on the claim path, after the claiming agent's capability has been
// verified and full chunk coverage confirmed.
func sealNoSubFinder(config []byte) []byte {
	var payload map[string]interface{}
	if err := json.Unmarshal(config, &payload); err != nil {
		return config
	}
	payload["NoSubFinder"] = true
	sealed, err := json.Marshal(payload)
	if err != nil {
		return config
	}
	return sealed
}

// CacheResult is a fresh cache entry payload.
type CacheResult struct {
	Subdomains []string
	Sources    []string
}

// LoadFreshCache returns cached results for the domains that have not expired.
func LoadFreshCache(store *gorm.DB, domains []string, now time.Time) map[string]CacheResult {
	results := make(map[string]CacheResult, len(domains))
	if len(domains) == 0 {
		return results
	}
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		normalized = append(normalized, strings.ToLower(strings.TrimSpace(domain)))
	}
	var rows []db.SubdomainPassiveCache
	if err := store.Where("domain IN ? AND expires_at > ?", normalized, now).Find(&rows).Error; err != nil {
		return results
	}
	for _, row := range rows {
		var subdomains, sources []string
		if err := json.Unmarshal([]byte(row.Subdomains), &subdomains); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(row.Sources), &sources)
		results[row.Domain] = CacheResult{Subdomains: subdomains, Sources: sources}
	}
	return results
}

// StoreCache upserts one domain entry.
func StoreCache(store *gorm.DB, domain string, subdomains, sources []string, now time.Time, ttl time.Duration) error {
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	subdomainsJSON, err := json.Marshal(subdomains)
	if err != nil {
		return err
	}
	sourcesJSON, err := json.Marshal(sources)
	if err != nil {
		return err
	}
	entry := db.SubdomainPassiveCache{
		Domain:      strings.ToLower(strings.TrimSpace(domain)),
		Subdomains:  string(subdomainsJSON),
		Sources:     string(sourcesJSON),
		CollectedAt: now,
		ExpiresAt:   now.Add(ttl),
	}
	return store.Where("domain = ?", entry.Domain).
		Assign(map[string]interface{}{
			"subdomains":   entry.Subdomains,
			"sources":      entry.Sources,
			"collected_at": entry.CollectedAt,
			"expires_at":   entry.ExpiresAt,
		}).
		FirstOrCreate(&entry).Error
}

// Worker drains pending collection jobs, releases their held attempts back
// into the dispatch flow, and seals collected results into the attempt
// config before enqueue.
type Worker struct {
	DB        *gorm.DB
	Collector *Collector
	// Enqueue pushes an already-Dispatching attempt into the task queue and
	// flips it to Pending; wired to the api dispatch path in main.
	Enqueue func(ctx context.Context, sub db.SubTask) error

	CacheTTL  time.Duration
	HoldLimit time.Duration
	Interval  time.Duration
	Now       func() time.Time
}

func NewWorker(store *gorm.DB, collector *Collector, enqueue func(ctx context.Context, sub db.SubTask) error) *Worker {
	return &Worker{
		DB:        store,
		Collector: collector,
		Enqueue:   enqueue,
		CacheTTL:  defaultCacheTTL,
		HoldLimit: defaultHoldLimit,
		Interval:  defaultInterval,
		Now:       time.Now,
	}
}

// Run scans jobs until the context is cancelled. The DB scan (rather than an
// in-memory queue) makes holds survive Server restarts.
func (w *Worker) Run(ctx context.Context) {
	if w.DB == nil || w.Collector == nil || w.Enqueue == nil {
		log.Printf("[PassiveSubdomain] worker disabled: DB, collector, or enqueue hook missing")
		return
	}
	interval := w.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.step(ctx)
		}
	}
}

func (w *Worker) step(ctx context.Context) {
	if !Enabled() {
		// Feature disabled or rolled back: drain every hold immediately so no
		// attempt stays stranded in Queued (the recovery daemon only re-pushes
		// Dispatching).
		w.releaseAllHolds("feature disabled; released for agent-side collection")
		return
	}
	w.releaseExpiredHolds()
	w.resetStaleRunning()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		job, ok := w.claimPending()
		if !ok {
			return
		}
		w.processJob(ctx, job)
	}
}

// claimPending CAS-transitions one pending job to running.
func (w *Worker) claimPending() (db.SubdomainPassiveJob, bool) {
	var job db.SubdomainPassiveJob
	err := w.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("state = ?", JobStatePending).
			Order("created_at ASC").
			First(&job).Error; err != nil {
			return err
		}
		res := tx.Model(&db.SubdomainPassiveJob{}).
			Where("id = ? AND state = ?", job.ID, JobStatePending).
			Updates(map[string]interface{}{"state": JobStateRunning, "updated_at": w.Now()})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
	if err != nil {
		return db.SubdomainPassiveJob{}, false
	}
	return job, true
}

// resetStaleRunning re-queues running jobs whose owner likely crashed.
func (w *Worker) resetStaleRunning() {
	cutoff := w.Now().Add(-jobStaleWindow)
	res := w.DB.Model(&db.SubdomainPassiveJob{}).
		Where("state = ? AND updated_at < ?", JobStateRunning, cutoff).
		Updates(map[string]interface{}{"state": JobStatePending, "updated_at": w.Now()})
	if res.RowsAffected > 0 {
		log.Printf("[PassiveSubdomain] reset %d stale running job(s)", res.RowsAffected)
	}
}

// releaseAllHolds releases every active hold without collecting. Used in
// drain mode (feature disabled / rollback) so attempts never strand.
func (w *Worker) releaseAllHolds(note string) {
	var jobs []db.SubdomainPassiveJob
	w.DB.Where("state IN ?", []string{JobStatePending, JobStateRunning}).Find(&jobs)
	for _, job := range jobs {
		if _, ok := w.releaseAttempt(job); ok {
			log.Printf("[PassiveSubdomain] drained hold for %s (%s)", job.AttemptID, note)
		}
		w.finishJob(job, JobStateFailed, note, nil)
	}
}

// releaseExpiredHolds enqueues attempts whose collection exceeded the hold
// limit; their agents fall back to agent-side passive collection.
func (w *Worker) releaseExpiredHolds() {
	cutoff := w.Now().Add(-w.HoldLimit)
	var jobs []db.SubdomainPassiveJob
	w.DB.Where("state IN ? AND created_at < ?", []string{JobStatePending, JobStateRunning}, cutoff).
		Find(&jobs)
	for _, job := range jobs {
		if _, ok := w.releaseAttempt(job); ok {
			log.Printf("[PassiveSubdomain] hold timeout for %s, dispatched without seal", job.AttemptID)
		}
		w.finishJob(job, JobStateFailed, "hold timeout; released for agent-side collection", nil)
	}
}

func (w *Worker) processJob(ctx context.Context, job db.SubdomainPassiveJob) {
	var domains []string
	if err := json.Unmarshal([]byte(job.Domains), &domains); err != nil || len(domains) == 0 {
		// Release first, then record: a crash between the two must leave the
		// attempt recoverable (job re-claimed via stale-running reset, release
		// becomes a no-op once the attempt left Queued).
		_, _ = w.releaseAttempt(job)
		w.finishJob(job, JobStateFailed, "undecodable job domains", nil)
		return
	}

	// The hold budget is enforced from job creation, not from claim time, so
	// backlogged jobs cannot extend the overall dispatch delay.
	// A zero/negative remaining budget expires the context immediately,
	// which routes every uncached domain to the failed path.
	remaining := w.HoldLimit - w.Now().Sub(job.CreatedAt)
	if remaining < 0 {
		remaining = 0
	}
	jobCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()

	cached := LoadFreshCache(w.DB, domains, w.Now())
	collected := make(map[string][]string, len(domains))
	var failed []string
	// The persisted counter is a monotonic floor: a stale-running reset and
	// re-claim reprocesses every domain, so persist max(previous, current-run
	// count) — progress never moves backwards and never exceeds the total.
	done := job.DomainsDone
	if done > len(domains) {
		done = len(domains)
	}
	processed := 0
	advanceProgress := func() {
		processed++
		candidate := processed
		if candidate < done {
			candidate = done
		}
		done = candidate
		w.DB.Model(&db.SubdomainPassiveJob{}).
			Where("id = ?", job.ID).
			Updates(map[string]interface{}{"domains_done": done, "updated_at": w.Now()})
	}
	for _, domain := range domains {
		select {
		case <-jobCtx.Done():
			failed = append(failed, strings.ToLower(strings.TrimSpace(domain)))
			continue
		default:
		}
		key := strings.ToLower(strings.TrimSpace(domain))
		if hit, ok := cached[key]; ok {
			collected[key] = hit.Subdomains
			advanceProgress()
			continue
		}
		result, err := w.Collector.Collect(jobCtx, domain)
		if err != nil {
			failed = append(failed, key)
			log.Printf("[PassiveSubdomain] collect %s failed: %v", domain, err)
			advanceProgress()
			continue
		}
		if err := StoreCache(w.DB, key, result.Subdomains, result.Sources, w.Now(), w.CacheTTL); err != nil {
			log.Printf("[PassiveSubdomain] cache store %s failed: %v", key, err)
		}
		collected[key] = result.Subdomains
		advanceProgress()
	}

	if len(collected) == 0 && len(cached) == 0 && len(failed) > 0 && len(failed) == len(domains) {
		// Nothing collected anywhere: dispatch unsealed so the Agent runs
		// today's agent-side passive collection.
		_, _ = w.releaseAttempt(job)
		w.finishJob(job, JobStateFailed, "all sources failed; released for agent-side collection", map[string]interface{}{
			"domains": domains,
			"failed":  failed,
		})
		return
	}

	w.sealAndRelease(job, domains, collected)
	// Audit keeps counts only; full hostname lists stay in the cache table.
	w.finishJob(job, JobStateReleased, fmt.Sprintf("collected=%d cached=%d failed=%d", len(collected), len(cached), len(failed)), map[string]interface{}{
		"domains":        domains,
		"collectedCount": len(collected),
		"cachedCount":    len(cached),
		"failed":         failed,
	})
}

// sealAndRelease rewrites the attempt config with collected results (before
// enqueue, so the queue message already carries them) and dispatches it.
func (w *Worker) sealAndRelease(job db.SubdomainPassiveJob, domains []string, collected map[string][]string) {
	var sub db.SubTask
	if err := w.DB.Where("id = ? AND tenant_id = ?", job.AttemptID, job.TenantID).First(&sub).Error; err != nil {
		log.Printf("[PassiveSubdomain] attempt %s missing for seal: %v", job.AttemptID, err)
		return
	}
	var chunkTargets []string
	_ = json.Unmarshal([]byte(sub.ChunkTargets), &chunkTargets)
	if sealed, ok, err := SealConfig([]byte(sub.Config), DropInputHosts(collected, chunkTargets)); err != nil {
		log.Printf("[PassiveSubdomain] seal %s failed: %v", sub.ID, err)
	} else if ok {
		if err := w.DB.Model(&db.SubTask{}).
			Where("id = ? AND tenant_id = ? AND status = ?", sub.ID, sub.TenantID, HoldStatus).
			Update("config", string(sealed)).Error; err != nil {
			log.Printf("[PassiveSubdomain] persist sealed config for %s failed: %v", sub.ID, err)
			sub.Config = string(sealed)
		} else {
			sub.Config = string(sealed)
		}
	}
	w.releaseAttemptFor(job, sub)
}

// releaseAttempt loads the attempt and releases it.
func (w *Worker) releaseAttempt(job db.SubdomainPassiveJob) (db.SubTask, bool) {
	var sub db.SubTask
	if err := w.DB.Where("id = ? AND tenant_id = ?", job.AttemptID, job.TenantID).First(&sub).Error; err != nil {
		return sub, false
	}
	w.releaseAttemptFor(job, sub)
	return sub, true
}

// releaseAttemptFor transitions Queued→Dispatching and enqueues. Failures
// leave the attempt in Dispatching, which the dispatch recovery daemon
// re-pushes, so the hold can never permanently strand a batch.
func (w *Worker) releaseAttemptFor(job db.SubdomainPassiveJob, sub db.SubTask) {
	if sub.Status != HoldStatus {
		// Already moved on (paused/resumed/retried): nothing to release.
		return
	}
	res := w.DB.Model(&db.SubTask{}).
		Where("id = ? AND tenant_id = ? AND status = ?", sub.ID, sub.TenantID, HoldStatus).
		Updates(map[string]interface{}{"status": "Dispatching", "updated_at": w.Now()})
	if res.Error != nil || res.RowsAffected == 0 {
		return
	}
	sub.Status = "Dispatching"
	if err := w.Enqueue(context.Background(), sub); err != nil {
		log.Printf("[PassiveSubdomain] enqueue %s after release failed: %v (recovery daemon will re-push)", sub.ID, err)
	}
}

// finishJob records the terminal job state and a task audit row.
func (w *Worker) finishJob(job db.SubdomainPassiveJob, state, note string, details map[string]interface{}) {
	res := w.DB.Model(&db.SubdomainPassiveJob{}).
		Where("id = ? AND state IN ?", job.ID, []string{JobStatePending, JobStateRunning}).
		Updates(map[string]interface{}{"state": state, "note": note, "updated_at": w.Now()})
	if res.Error != nil || res.RowsAffected == 0 {
		// Another path already finalized this job; do not double-audit.
		return
	}
	if details == nil {
		details = map[string]interface{}{}
	}
	details["note"] = note
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return
	}
	_ = w.DB.Create(&db.TaskAudit{
		TenantID:    job.TenantID,
		ProjectID:   job.ProjectID,
		RootTaskID:  job.RootTaskID,
		BatchID:     job.BatchID,
		AttemptID:   job.AttemptID,
		OperatorID:  collectOperatorID,
		Action:      "passive_subdomain_" + state,
		AfterStatus: state,
		Details:     string(detailsJSON),
	}).Error
}

// ClaimSeal applies claim-time sealing for capable agents: fresh cache hits
// for the attempt's registrable apex domains are injected into the config
// being handed to the Agent. It is best-effort; errors keep the unsealed config.
func ClaimSeal(store *gorm.DB, agentTagsJSON string, chunkTargets []string, config []byte) []byte {
	if !Enabled() || !AgentHasCapability(agentTagsJSON) || len(config) == 0 {
		return config
	}
	var metadata struct {
		Subdomain                bool
		NoSubFinder              bool
		SubdomainPassiveResults  map[string][]string
		SubdomainDictionaryWords []string
	}
	if err := json.Unmarshal(config, &metadata); err != nil {
		return config
	}
	if !metadata.Subdomain || metadata.NoSubFinder || len(metadata.SubdomainPassiveResults) > 0 {
		return config
	}
	domains := CollectionDomains(chunkTargets)
	if len(domains) == 0 {
		return config
	}
	cached := LoadFreshCache(store, domains, time.Now())
	if len(cached) == 0 {
		return config
	}
	sealed, ok, err := SealConfig(config, DropInputHosts(cacheToMap(cached), chunkTargets))
	if err != nil || !ok {
		if err != nil {
			log.Printf("[PassiveSubdomain] claim seal skipped: %v", err)
		}
		return config
	}
	if fullCoverage(cached, domains) {
		// Capability was verified by the caller; full coverage lets this
		// agent skip passive queries for the whole chunk.
		sealed = sealNoSubFinder(sealed)
	}
	return sealed
}

// fullCoverage reports whether every registrable apex has a fresh cache entry
// (entries may legitimately be empty lists).
func fullCoverage(cached map[string]CacheResult, domains []string) bool {
	for _, domain := range domains {
		if _, ok := cached[strings.ToLower(strings.TrimSpace(domain))]; !ok {
			return false
		}
	}
	return true
}

func cacheToMap(cached map[string]CacheResult) map[string][]string {
	byDomain := make(map[string][]string, len(cached))
	for domain, hit := range cached {
		byDomain[domain] = hit.Subdomains
	}
	return byDomain
}
