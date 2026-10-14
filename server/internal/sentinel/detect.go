package sentinel

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"gorm.io/gorm"
)

// DetectorOptions tunes the rule detectors. Zero values fall back to defaults.
type DetectorOptions struct {
	// Homogeneity: a host whose distinct scanned ports sharing one identical
	// response body reaches MinDistinctPorts (and MinHits total rows) inside
	// Lookback is a catch-all / WAF-intercept suspect.
	Lookback        time.Duration // default 2h
	MinDistinctPorts int           // default 4
	MinHits         int           // default 4
	// SuccessDrop: a root task whose finished-attempt failure ratio in the
	// recent window reaches FailRatio while enough attempts finished is
	// losing its egress (ban / rate limit).
	SuccessWindow  time.Duration // default 30m
	MinFinished    int           // default 5
	FailRatio      float64       // default 0.6
}

func (o DetectorOptions) withDefaults() DetectorOptions {
	if o.Lookback <= 0 {
		o.Lookback = 2 * time.Hour
	}
	if o.MinDistinctPorts <= 0 {
		o.MinDistinctPorts = 4
	}
	if o.MinHits <= 0 {
		o.MinHits = 4
	}
	if o.SuccessWindow <= 0 {
		o.SuccessWindow = 30 * time.Minute
	}
	if o.MinFinished <= 0 {
		o.MinFinished = 5
	}
	if o.FailRatio <= 0 {
		o.FailRatio = 0.6
	}
	return o
}

type evidence map[string]interface{}

func (e evidence) JSON() string {
	raw, err := json.Marshal(e)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// splitTarget splits "host:port" into host/port. Targets without an explicit
// port keep the whole value as host.
func splitTarget(target string) (string, string) {
	target = strings.TrimSpace(target)
	if host, port, err := net.SplitHostPort(target); err == nil {
		return strings.TrimSpace(host), strings.TrimSpace(port)
	}
	// URL-ish targets: strip scheme/path, keep host part.
	if idx := strings.Index(target, "://"); idx >= 0 {
		rest := target[idx+3:]
		if cut := strings.IndexAny(rest, "/:?"); cut >= 0 {
			return rest[:cut], ""
		}
		return rest, ""
	}
	if cut := strings.IndexAny(target, "/?"); cut >= 0 {
		return target[:cut], ""
	}
	return target, ""
}

// RunDetectTick runs all rule detectors once and inserts deduped events.
func RunDetectTick(ctx context.Context, store *gorm.DB, opts DetectorOptions) error {
	opts = opts.withDefaults()
	if err := detectHomogeneity(ctx, store, opts); err != nil {
		return err
	}
	return detectSuccessDrop(ctx, store, opts)
}

// insertEventIfNew inserts ev unless an event with the same scope fired within
// suppressWindow. Dedup is time-windowed and status-agnostic: once a signal is
// handled (executed/dismissed) the same underlying evidence must not re-fire on
// every tick, but a genuinely new incident after the window still alerts.
func insertEventIfNew(store *gorm.DB, ev db.EgressBanEvent, suppressWindow time.Duration) error {
	q := store.Model(&db.EgressBanEvent{}).
		Where("tenant_id = ? AND signal_type = ? AND created_at > ?", ev.TenantID, ev.SignalType, time.Now().Add(-suppressWindow))
	// Host-scoped signals (homogeneity) dedupe by target; task-scoped signals
	// (success_drop) dedupe by root task — so distinct hosts under one task are
	// all reported, not swallowed by the first.
	if ev.Target != "" {
		q = q.Where("target = ?", ev.Target)
	} else {
		q = q.Where("root_task_id = ?", ev.RootTaskID)
	}
	var existing int64
	if err := q.Limit(1).Count(&existing).Error; err != nil {
		return err
	}
	if existing > 0 {
		return nil
	}
	return store.Create(&ev).Error
}

// detectHomogeneity groups recent vulnerabilities of actively-scanning tasks
// by (host, response-body hash). One dominant body across many distinct ports
// means the target answers everything with the same page.
func detectHomogeneity(ctx context.Context, store *gorm.DB, opts DetectorOptions) error {
	var rootIDs []string
	if err := store.Model(&db.SubTask{}).
		Where("status IN ? AND updated_at > ?", []string{"Running", "Dispatching", "Pending"}, time.Now().Add(-opts.Lookback)).
		Distinct().
		Pluck("root_task_id", &rootIDs).Error; err != nil {
		return err
	}
	if len(rootIDs) == 0 {
		return nil
	}

	type row struct {
		Target     string
		Plugin     string
		Response   string
		RootTaskID string
		ProjectID  string
	}
	var rows []row
	if err := store.Model(&db.Vulnerability{}).
		Select("target", "plugin", "response", "root_task_id", "project_id").
		Where("root_task_id IN ? AND created_at > ?", rootIDs, time.Now().Add(-opts.Lookback)).
		Find(&rows).Error; err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}

	type agg struct {
		host     string
		hash     string
		ports    map[string]struct{}
		targets  map[string]struct{}
		plugins  map[string]struct{}
		snippet  string
		rootTask string
		project  string
	}
	groups := map[string]*agg{}
	for _, r := range rows {
		host, port := splitTarget(r.Target)
		if host == "" || port == "" {
			continue
		}
		hash := bodyHash(r.Response)
		key := host + "|" + hash
		g, ok := groups[key]
		if !ok {
			g = &agg{host: host, hash: hash, ports: map[string]struct{}{}, targets: map[string]struct{}{}, plugins: map[string]struct{}{}, snippet: firstRunes(r.Response, 160), rootTask: r.RootTaskID, project: r.ProjectID}
			groups[key] = g
		}
		g.ports[port] = struct{}{}
		g.targets[r.Target] = struct{}{}
		g.plugins[r.Plugin] = struct{}{}
	}

	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := groups[k]
		if len(g.ports) < opts.MinDistinctPorts || len(g.targets) < opts.MinHits {
			continue
		}
		ev := db.EgressBanEvent{
			TenantID:   "default",
			RootTaskID: g.rootTask,
			ProjectID:  g.project,
			Target:     g.host,
			Host:       g.host,
			SignalType: SignalHomogeneity,
			Evidence: evidence{
				"body_hash":      g.hash,
				"distinct_ports": len(g.ports),
				"hits":           len(g.targets),
				"ports":          sortedKeys(g.ports)[:min(len(sortedKeys(g.ports)), 12)],
				"plugins":        sortedKeys(g.plugins)[:min(len(sortedKeys(g.plugins)), 8)],
				"sample":         g.snippet,
			}.JSON(),
		}
		if err := insertEventIfNew(store, ev, opts.Lookback); err != nil {
			return err
		}
		log.Printf("[Sentinel] homogeneity signal: host=%s ports=%d hits=%d hash=%s", g.host, len(g.ports), len(g.targets), g.hash[:8])
	}
	return nil
}

// detectSuccessDrop compares a root task's finished-attempt failure ratio in
// the recent window: a sudden jump means the egress is being banned mid-scan.
func detectSuccessDrop(ctx context.Context, store *gorm.DB, opts DetectorOptions) error {
	cutoff := time.Now().Add(-opts.SuccessWindow)
	type stat struct {
		RootTaskID string
		Finished   int64
		Failed     int64
	}
	var stats []stat
	if err := store.Model(&db.SubTask{}).
		Select("root_task_id, COUNT(*) AS finished, SUM(CASE WHEN status IN ('Failed','Timeout') THEN 1 ELSE 0 END) AS failed").
		Where("finished_at IS NOT NULL AND finished_at > ?", cutoff).
		Group("root_task_id").
		Having("COUNT(*) >= ? AND CAST(SUM(CASE WHEN status IN ('Failed','Timeout') THEN 1 ELSE 0 END) AS FLOAT) / COUNT(*) >= ?", opts.MinFinished, opts.FailRatio).
		Scan(&stats).Error; err != nil {
		return err
	}
	for _, s := range stats {
		ratio := 0.0
		if s.Finished > 0 {
			ratio = float64(s.Failed) / float64(s.Finished)
		}
		// Most common agent among the failures — the suspected banned egress.
		var agentRows []struct {
			AgentID string
			N       int64
		}
		if err := store.Model(&db.SubTask{}).
			Select("agent_id", "COUNT(*) AS n").
			Where("root_task_id = ? AND finished_at > ? AND status IN ? AND agent_id <> ''", s.RootTaskID, cutoff, []string{"Failed", "Timeout"}).
			Group("agent_id").
			Order("n DESC").
			Limit(1).
			Scan(&agentRows).Error; err != nil {
			return err
		}
		agentID := ""
		if len(agentRows) > 0 {
			agentID = agentRows[0].AgentID
		}
		ev := db.EgressBanEvent{
			TenantID:   "default",
			RootTaskID: s.RootTaskID,
			AgentID:    agentID,
			SignalType: SignalSuccessDrop,
			Evidence: evidence{
				"window_minutes": int(opts.SuccessWindow.Minutes()),
				"finished":       s.Finished,
				"failed":         s.Failed,
				"failure_ratio":  round2(ratio),
				"suspect_agent":  agentID,
			}.JSON(),
		}
		if err := insertEventIfNew(store, ev, opts.SuccessWindow); err != nil {
			return err
		}
		log.Printf("[Sentinel] success_drop signal: root=%s finished=%d failed=%d agent=%s", s.RootTaskID, s.Finished, s.Failed, agentID)
	}
	return nil
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func firstRunes(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n])
	}
	return string(r)
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
