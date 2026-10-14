// Package dispatch implements the k8s-style controller-push dispatcher.
//
// For sub-tasks whose effective dispatch strategy is controller_push, the
// controller owns the "which agent" decision: it filters alive,
// selector-matching, capacity-available agents, scores them by least load
// (RunningTasks/Capacity), routes the sub-task to the winner's dedicated
// per-agent queue, and re-routes when the original target goes offline or a
// routing goes stale. Push is advisory only — binding still happens in the
// ClaimTask lease CAS, so every claim-time safety gate (reuse, work-claims,
// quota, capability, selector) re-runs for pushed work.
package dispatch

import (
	"context"
	"encoding/json"
	"log"
	"math"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/server/internal/scheduler"
	pb "github.com/P0lar1ght/argus/shared/proto/go/scan"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
	"gorm.io/gorm"
)

const (
	defaultPollInterval  = 2 * time.Second
	defaultReRouteWindow = 120 * time.Second
	reconcileBatchLimit  = 200
	// agentLivenessWindowMillis mirrors the heartbeat death-detector freshness
	// window: an Alive node whose LastBeat is older than this and has no active
	// subscribe stream is treated as not alive for routing.
	agentLivenessWindowMillis = 60000
)

// AgentNotifier is the narrow NotifyHub surface the controller needs. It is
// satisfied by *grpc.NotifyHub and keeps this package free of a grpc import,
// avoiding any api/grpc import cycle.
type AgentNotifier interface {
	NotifyAgent(agentID string, availableTasks int32, notifyType string)
	IsAgentOnline(agentID string) bool
}

// AgentPusher is the narrow queue surface used to route to a per-agent queue.
// *scheduler.TaskQueue satisfies it.
type AgentPusher interface {
	PushToAgentQueue(ctx context.Context, agentID string, task *pb.Task) error
}

// Controller reconciles Dispatching controller-push sub-tasks onto agent queues.
type Controller struct {
	db            *gorm.DB
	queue         AgentPusher
	notifier      AgentNotifier
	notify        chan struct{}
	pollInterval  time.Duration
	reRouteWindow time.Duration
	now           func() time.Time
	defaultStrat  func() scanpolicy.DispatchStrategy
}

// NewController builds a controller over the shared queue and notifier.
func NewController(dbHandle *gorm.DB, queue *scheduler.TaskQueue, notifier AgentNotifier) *Controller {
	return &Controller{
		db:            dbHandle,
		queue:         queue,
		notifier:      notifier,
		notify:        make(chan struct{}, 1),
		pollInterval:  defaultPollInterval,
		reRouteWindow: defaultReRouteWindow,
		now:           time.Now,
		defaultStrat:  scanpolicy.DefaultDispatchStrategy,
	}
}

// Notify signals the reconcile loop that dispatchable work may exist. It never
// blocks; a coalesced signal is sufficient because reconcile re-queries state.
func (c *Controller) Notify() {
	if c == nil {
		return
	}
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

// Run executes reconcile immediately, then on every Notify signal and poll tick
// until ctx is cancelled.
func (c *Controller) Run(ctx context.Context) {
	if c == nil || c.db == nil || c.queue == nil {
		return
	}
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()
	for {
		c.reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-c.notify:
		case <-ticker.C:
		}
	}
}

func (c *Controller) reconcile(ctx context.Context) {
	if err := c.dispatchNew(ctx); err != nil {
		log.Printf("[DispatchCtl] dispatch pass failed: %v", err)
	}
	if err := c.rerouteStale(ctx); err != nil {
		log.Printf("[DispatchCtl] reroute pass failed: %v", err)
	}
}

// dispatchNew routes freshly-Dispatching, unrouted push sub-tasks to an agent.
func (c *Controller) dispatchNew(ctx context.Context) error {
	now := c.now().UTC()
	var subs []db.SubTask
	// Priority is ascending-urgent (0=urgent). Only unrouted rows are candidates;
	// pull-mode Dispatching rows are owned by dispatchSubTasks.
	if err := c.db.Where("status = ? AND routed_agent_id = ? AND (next_eligible_at IS NULL OR next_eligible_at <= ?)",
		"Dispatching", "", now).
		Order("priority ASC, created_at ASC").
		Limit(reconcileBatchLimit).
		Find(&subs).Error; err != nil {
		return err
	}
	// Count in-flight routings (routed-but-unclaimed) so a single pass spreads
	// across agents instead of piling every sub-task onto the one agent that was
	// least loaded when the pass began. Routing does not bump RunningTasks (that
	// happens at ClaimTask binding), so without this the whole batch would land
	// on a single agent and the rest would idle.
	inflight := c.inflightPerAgent()
	for i := range subs {
		sub := &subs[i]
		if c.effectiveStrategy(sub) != scanpolicy.DispatchStrategyControllerPush {
			continue
		}
		agentID := c.selectAgent(sub, nil, inflight)
		if agentID == "" {
			continue // no eligible agent right now; retry on a later pass
		}
		pbSub, err := db.SubTaskToProto(sub)
		if err != nil || pbSub == nil {
			log.Printf("[DispatchCtl] encode subtask %s failed: %v", sub.ID, err)
			continue
		}
		// Reserve the routing atomically so concurrent controllers cannot push the
		// same sub-task to two agents. The row stays Dispatching; binding happens
		// later in the ClaimTask CAS.
		res := c.db.Model(&db.SubTask{}).
			Where("id = ? AND tenant_id = ? AND status = ? AND routed_agent_id = ?", sub.ID, sub.TenantID, "Dispatching", "").
			Updates(map[string]interface{}{"routed_agent_id": agentID, "routed_at": now})
		if res.Error != nil {
			log.Printf("[DispatchCtl] reserve subtask %s failed: %v", sub.ID, res.Error)
			continue
		}
		if res.RowsAffected != 1 {
			continue // lost the routing race
		}
		if err := c.queue.PushToAgentQueue(ctx, agentID, pbSub); err != nil {
			log.Printf("[DispatchCtl] push subtask %s to agent %s failed: %v", sub.ID, agentID, err)
			c.releaseRouting(sub.ID, sub.TenantID, agentID)
			continue
		}
		inflight[agentID]++ // keep this pass's scoring aware of the new routing
		log.Printf("[DispatchCtl] routed subtask %s -> agent %s", sub.ID, agentID)
		if c.notifier != nil {
			c.notifier.NotifyAgent(agentID, 1, "new_task")
		}
	}
	return nil
}

// rerouteStale re-routes push sub-tasks whose routing target is gone or whose
// routing has gone stale while still unclaimed. The old queue copy cannot be
// deleted, so the stale delivery is neutralized later by the ClaimTask
// RUNNING-duplicate path.
func (c *Controller) rerouteStale(ctx context.Context) error {
	cutoff := c.now().UTC().Add(-c.reRouteWindow)
	var subs []db.SubTask
	if err := c.db.Where("status = ? AND routed_agent_id <> ? AND routed_at < ?", "Dispatching", "", cutoff).
		Limit(reconcileBatchLimit).
		Find(&subs).Error; err != nil {
		return err
	}
	// In-flight routings count against an agent's load so a re-route target is not
	// already saturated with unclaimed pushes.
	inflight := c.inflightPerAgent()
	for i := range subs {
		sub := &subs[i]
		if c.effectiveStrategy(sub) != scanpolicy.DispatchStrategyControllerPush {
			continue
		}
		current := strings.TrimSpace(sub.RoutedAgentID)
		offline := c.notifier == nil || !c.notifier.IsAgentOnline(current)
		veryStale := sub.RoutedAt != nil && c.now().UTC().Sub(sub.RoutedAt.UTC()) > 2*c.reRouteWindow
		if !offline && !veryStale {
			continue
		}
		exclude := map[string]bool{current: true}
		agentID := c.selectAgent(sub, exclude, inflight)
		if agentID == "" {
			continue
		}
		pbSub, err := db.SubTaskToProto(sub)
		if err != nil || pbSub == nil {
			log.Printf("[DispatchCtl] encode subtask %s for reroute failed: %v", sub.ID, err)
			continue
		}
		res := c.db.Model(&db.SubTask{}).
			Where("id = ? AND tenant_id = ? AND status = ? AND routed_agent_id = ?", sub.ID, sub.TenantID, "Dispatching", current).
			Updates(map[string]interface{}{"routed_agent_id": agentID, "routed_at": c.now().UTC()})
		if res.Error != nil || res.RowsAffected != 1 {
			continue
		}
		if err := c.queue.PushToAgentQueue(ctx, agentID, pbSub); err != nil {
			log.Printf("[DispatchCtl] reroute push subtask %s to agent %s failed: %v", sub.ID, agentID, err)
			c.releaseRouting(sub.ID, sub.TenantID, agentID)
			continue
		}
		inflight[agentID]++
		log.Printf("[DispatchCtl] re-routed subtask %s: %s -> %s", sub.ID, current, agentID)
		if c.notifier != nil {
			c.notifier.NotifyAgent(agentID, 1, "new_task")
		}
	}
	return nil
}

// releaseRouting clears a routing reservation after a failed push so a later
// pass retries from a clean unrouted state.
func (c *Controller) releaseRouting(id, tenantID, agentID string) {
	if err := c.db.Model(&db.SubTask{}).
		Where("id = ? AND tenant_id = ? AND routed_agent_id = ?", id, tenantID, agentID).
		Updates(map[string]interface{}{"routed_agent_id": "", "routed_at": nil}).Error; err != nil {
		log.Printf("[DispatchCtl] release routing for %s failed: %v", id, err)
	}
}

// selectAgent picks the least-loaded alive, selector-matching agent with free
// capacity. exclude optionally removes agents from consideration (re-route).
// inflight carries routed-but-unclaimed counts per agent so scoring reflects
// work already committed this pass; effective load is RunningTasks+inflight.
// Agent tenancy is not a routing boundary here, matching the global shared
// queues used by the legacy pull model.
func (c *Controller) selectAgent(sub *db.SubTask, exclude map[string]bool, inflight map[string]int64) string {
	var nodes []db.Node
	if err := c.db.Where("status = ?", "Alive").Find(&nodes).Error; err != nil {
		log.Printf("[DispatchCtl] load alive nodes failed: %v", err)
		return ""
	}
	selectorMap := parseLegacySelector(sub.AgentSelector)
	rules := db.ParseSelectorRulesJSON(sub.AgentSelectorRules)
	nowMilli := c.now().UnixMilli()

	bestAgent := ""
	bestRatio := math.MaxFloat64
	bestFree := int64(-1)
	var bestBeat int64 = -1
	for i := range nodes {
		n := &nodes[i]
		if exclude != nil && exclude[n.AgentID] {
			continue
		}
		// Alive requires a strong liveness signal: either a fresh heartbeat or an
		// active subscribe stream (mirrors the death detector's OR-logic).
		fresh := nowMilli-n.LastBeat < agentLivenessWindowMillis
		online := c.notifier != nil && c.notifier.IsAgentOnline(n.AgentID)
		if !online && !fresh {
			continue
		}
		matched, _ := db.NodeMatchesSelectorRules(selectorMap, rules, n.Tags)
		if !matched {
			continue
		}
		capacity := n.Capacity
		if capacity < 1 {
			capacity = 1
		}
		load := int64(n.RunningTasks) + inflight[n.AgentID]
		free := int64(capacity) - load
		if free <= 0 {
			continue
		}
		ratio := float64(load) / float64(capacity)
		if bestAgent == "" ||
			ratio < bestRatio ||
			(ratio == bestRatio && free > bestFree) ||
			(ratio == bestRatio && free == bestFree && n.LastBeat > bestBeat) {
			bestAgent = n.AgentID
			bestRatio = ratio
			bestFree = free
			bestBeat = n.LastBeat
		}
	}
	return bestAgent
}

// inflightPerAgent counts routed-but-unclaimed (Dispatching, routed) sub-tasks
// per agent. These occupy agent capacity until the ClaimTask CAS binds them.
func (c *Controller) inflightPerAgent() map[string]int64 {
	out := map[string]int64{}
	type agentCount struct {
		Agent string
		Cnt   int64
	}
	var rows []agentCount
	if err := c.db.Model(&db.SubTask{}).
		Select("routed_agent_id AS agent, count(*) AS cnt").
		Where("status = ? AND routed_agent_id <> ?", "Dispatching", "").
		Group("routed_agent_id").
		Scan(&rows).Error; err != nil {
		log.Printf("[DispatchCtl] load in-flight routings failed: %v", err)
		return out
	}
	for _, r := range rows {
		out[r.Agent] = r.Cnt
	}
	return out
}

func (c *Controller) effectiveStrategy(sub *db.SubTask) scanpolicy.DispatchStrategy {
	return scanpolicy.NormalizeDispatchStrategy(scanpolicy.DispatchStrategy(sub.DispatchStrategy), c.defaultStrat())
}

func parseLegacySelector(raw string) map[string]string {
	selector := strings.TrimSpace(raw)
	var selectorMap map[string]string
	if selector != "" && selector != "{}" {
		_ = json.Unmarshal([]byte(selector), &selectorMap)
	}
	return selectorMap
}
