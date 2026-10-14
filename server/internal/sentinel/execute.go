package sentinel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"gorm.io/gorm"
)

// TaskPusher delivers an already-persisted sub task to one specific agent's
// dedicated queue. *scheduler.TaskQueue satisfies this via a thin adapter in
// main; tests substitute a fake. Routing this way is hard exclusion — the
// banned agent never sees the task because it is never put on a shared queue.
type TaskPusher interface {
	PushSubTaskToAgent(ctx context.Context, agentID string, sub db.SubTask) error
}

// ExecutorOptions carries the policy gate and clock.
type ExecutorOptions struct {
	// AutoExecute gates rescan-on-other-node: false (default) means a human
	// must confirm via the API. backoff / flag_findings always auto-execute
	// because they only ever narrow.
	AutoExecute bool
	// CooldownBase is the per-classification ban cooldown base; defaults to
	// the sentinel_cooldown_minutes config (10m) when zero.
	CooldownBase time.Duration
	Now          func() time.Time
}

type Executor struct {
	DB     *gorm.DB
	Pusher TaskPusher
	Opts   ExecutorOptions
}

var ErrEventNotActionable = errors.New("sentinel event not open or not actionable")

func (e *Executor) now() time.Time {
	if e.Opts.Now != nil {
		return e.Opts.Now()
	}
	return time.Now()
}

// RunExecuteTick applies convergent actions automatically and leaves
// gated actions (rescan/halt) open for a human when AutoExecute is off.
func RunExecuteTick(ctx context.Context, store *gorm.DB, pusher TaskPusher, autoExecute bool) error {
	ex := &Executor{DB: store, Pusher: pusher, Opts: ExecutorOptions{AutoExecute: autoExecute}}
	var events []db.EgressBanEvent
	if err := store.WithContext(ctx).
		Where("status = ? AND classification <> ?", EventOpen, ClassPending).
		Order("id").
		Limit(20).
		Find(&events).Error; err != nil {
		return err
	}
	for i := range events {
		ev := &events[i]
		keepOpen, err := ex.execute(ctx, ev, "sentinel-auto")
		if err != nil {
			log.Printf("[Sentinel] execute event=%d failed: %v", ev.ID, err)
			continue
		}
		if keepOpen {
			continue // awaiting human / no clean egress left the event open
		}
	}
	return nil
}

// ExecuteByID runs the recommended action for one event (human confirm path).
// operator identifies who confirmed; forceAction overrides the AI suggestion
// when non-empty. Events already executed are rejected.
func (e *Executor) ExecuteByID(ctx context.Context, eventID uint, operator, forceAction string) (*db.EgressBanEvent, error) {
	var ev db.EgressBanEvent
	if err := e.DB.First(&ev, eventID).Error; err != nil {
		return nil, err
	}
	if ev.Status != EventOpen {
		return nil, ErrEventNotActionable
	}
	if forceAction != "" {
		ev.RecommendedAction = forceAction
	}
	_, err := e.execute(ctx, &ev, operator)
	if err != nil {
		return nil, err
	}
	var fresh db.EgressBanEvent
	if err := e.DB.First(&fresh, eventID).Error; err != nil {
		return nil, err
	}
	return &fresh, nil
}

// execute runs the event's recommended action. Returns keepOpen=true when the
// event should stay open (gated action without permission, or no clean egress
// left after the fallback backoff — in which case it is still marked executed).
func (e *Executor) execute(ctx context.Context, ev *db.EgressBanEvent, operator string) (bool, error) {
	action := ev.RecommendedAction
	if action == "" {
		action = ActionNone
	}
	switch {
	case ev.Classification == ClassFalsePositive || ev.Classification == ClassScannerBug || ev.Classification == ClassTargetDown:
		return false, e.markExecuted(ev, operator, "auto-dismissed: "+ev.Classification)
	case action == ActionNone:
		return false, e.markExecuted(ev, operator, "no action recommended")
	case action == ActionBackoff:
		e.recordBan(ev)
		return false, e.markExecuted(ev, operator, "backoff applied")
	case action == ActionFlagFindings:
		if n, err := e.flagFindings(ev); err != nil {
			return false, err
		} else {
			return false, e.markExecuted(ev, operator, fmt.Sprintf("flagged %d findings", n))
		}
	case action == ActionRescanOtherNode:
		if !e.Opts.AutoExecute && operator == "sentinel-auto" {
			return true, nil // gated: await human confirm
		}
		note, err := e.rescanOtherNode(ctx, ev)
		if err != nil {
			return false, err
		}
		return false, e.markExecuted(ev, operator, note)
	case action == ActionHalt:
		if operator == "sentinel-auto" {
			return true, nil // never auto-halt a task
		}
		return false, e.markExecuted(ev, operator, "halt recommended; operator pauses the task manually")
	default:
		return false, e.markExecuted(ev, operator, "unknown action "+action)
	}
}

func (e *Executor) markExecuted(ev *db.EgressBanEvent, operator, note string) error {
	now := e.now()
	res := e.DB.Model(&db.EgressBanEvent{}).
		Where("id = ? AND status = ?", ev.ID, EventOpen).
		Updates(map[string]interface{}{
			"status":      EventExecuted,
			"executed_at": now,
			"executed_by": operator,
			"action_reason": gorm.Expr("action_reason || ?", "\n[executed "+now.Format(time.RFC3339)+" by "+operator+"] "+note),
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrEventNotActionable
	}
	ev.Status = EventExecuted
	return nil
}

// cooldownFor picks the ban-memory cooldown per classification.
func (e *Executor) cooldownFor(classification string) time.Duration {
	base := e.Opts.CooldownBase
	if base <= 0 {
		if mins := loadSystemInt(e.DB, ConfigKeyCooldownMinutes, 10); mins > 0 {
			base = time.Duration(mins) * time.Minute
		} else {
			base = 10 * time.Minute
		}
	}
	switch classification {
	case ClassBanned:
		return base * 3
	case ClassWAFChallenge:
		return base * 2
	default: // rate_limited and unknowns
		return base
	}
}

// recordBan upserts ban memory so a later rescan never routes back to a
// known-banned (target, agent) pair within the cooldown.
func (e *Executor) recordBan(ev *db.EgressBanEvent) {
	if ev.Target == "" {
		return
	}
	now := e.now()
	cooldown := e.cooldownFor(ev.Classification)
	until := now.Add(cooldown)
	var ban db.NodeBan
	err := e.DB.Where("tenant_id = ? AND target = ? AND agent_id = ?", ev.TenantID, ev.Target, ev.AgentID).First(&ban).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		e.DB.Create(&db.NodeBan{
			TenantID: ev.TenantID, Target: ev.Target, AgentID: ev.AgentID,
			EgressIP: "", HitCount: 1, BannedAt: now, CooldownUntil: &until,
		})
		return
	}
	if err != nil {
		log.Printf("[Sentinel] recordBan read failed: %v", err)
		return
	}
	e.DB.Model(&db.NodeBan{}).Where("id = ?", ban.ID).Updates(map[string]interface{}{
		"hit_count":      ban.HitCount + 1,
		"banned_at":      now,
		"cooldown_until": until,
	})
}

// flagFindings taints the affected vulnerabilities as untrusted evidence.
// v1 only handles host-scoped (homogeneity) events; task-wide taint stays a
// human decision to avoid over-marking.
func (e *Executor) flagFindings(ev *db.EgressBanEvent) (int64, error) {
	if ev.Host == "" {
		return 0, nil
	}
	res := e.DB.Model(&db.Vulnerability{}).
		Where("tenant_id = ? AND (target = ? OR target LIKE ? OR target LIKE ?)",
			ev.TenantID, ev.Host, ev.Host+":%", "%://"+ev.Host+"/%").
		Updates(map[string]interface{}{
			"taint_status": TaintSuspectWAF,
			"taint_reason": "sentinel: 同主机多端口响应一致，疑似 WAF/catch-all 拦截页（event " + itoa(ev.ID) + "）",
		})
	if res.Error != nil {
		return 0, res.Error
	}
	e.audit(ev, "sentinel_flag_findings", map[string]interface{}{
		"host": ev.Host, "tainted": res.RowsAffected,
	})
	return res.RowsAffected, nil
}

// rescanOtherNode appends a fresh attempt for the affected sub task and pushes
// it to a clean agent's dedicated queue — hard-routed away from the banned
// egress. When no clean egress exists it falls back to a backoff and reports
// that in the note.
func (e *Executor) rescanOtherNode(ctx context.Context, ev *db.EgressBanEvent) (string, error) {
	sub, err := e.findRescanSubTask(ev)
	if err != nil {
		e.recordBan(ev)
		return "no rescanable subtask; ban recorded", nil
	}
	agent, err := e.pickCleanAgent(ev)
	if err != nil {
		e.recordBan(ev)
		return "no clean egress; backoff applied", nil
	}
	e.recordBan(ev)

	now := e.now()
	var prepared db.SubTask
	err = e.DB.Transaction(func(tx *gorm.DB) error {
		next, ok, err := db.AppendSubTaskAttemptTx(tx, sub, db.AttemptRetryOptions{
			Trigger:              TriggerEgressBanRecovery,
			UseCurrentTaskConfig: true,
			AllowTerminalRoot:    true,
			AllowControlledBatch: true,
			PreparedStatus:       "Pending",
			ConsumeRetryBudget:   true,
		})
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("subtask not retryable (state changed or retry budget exhausted)")
		}
		if err := tx.Model(&db.SubTask{}).Where("id = ?", next.ID).Updates(map[string]interface{}{
			"routed_agent_id": agent,
			"routed_at":       now,
			"stream_msg_id":   "sentinel-queued",
		}).Error; err != nil {
			return err
		}
		next.AgentID = ""
		next.RoutedAgentID = agent
		prepared = next
		return nil
	})
	if err != nil {
		return "", err
	}

	note := fmt.Sprintf("rescan attempt %s routed to agent %s", prepared.ID, agent)
	if e.Pusher != nil {
		if err := e.Pusher.PushSubTaskToAgent(ctx, agent, prepared); err != nil {
			log.Printf("[Sentinel] push attempt %s to %s failed: %v", prepared.ID, agent, err)
			note += " (queue push failed; attempt left Pending for reconciler)"
		}
	} else {
		note += " (no pusher wired; reconciler will dispatch)"
	}
	e.audit(ev, "sentinel_rescan_other_node", map[string]interface{}{
		"attempt_id": prepared.ID, "agent_id": agent,
		"banned_agent": ev.AgentID, "sub_task_id": sub.ID,
	})
	log.Printf("[Sentinel] %s: %s", note, ev.Target)
	return note, nil
}

// findRescanSubTask locates the terminal attempt covering the event's scope:
// the exact sub task when recorded, else the newest finished attempt whose
// chunk contains the target host.
func (e *Executor) findRescanSubTask(ev *db.EgressBanEvent) (*db.SubTask, error) {
	var sub db.SubTask
	if ev.SubTaskID != "" {
		if err := e.DB.Where("id = ?", ev.SubTaskID).First(&sub).Error; err == nil {
			if sub.Status == "Running" || sub.Status == "Dispatching" {
				return nil, errors.New("attempt still in flight")
			}
			return &sub, nil
		}
	}
	q := e.DB.Where("root_task_id = ? AND status IN ? AND chunk_targets <> ''", ev.RootTaskID, []string{"Failed", "Timeout", "Succeeded"})
	if ev.Host != "" {
		q = q.Where("chunk_targets LIKE ?", "%"+ev.Host+"%")
	}
	q = q.Order("created_at DESC")
	if err := q.First(&sub).Error; err != nil {
		return nil, err
	}
	if sub.Status == "Running" || sub.Status == "Dispatching" {
		return nil, errors.New("attempt still in flight")
	}
	return &sub, nil
}

// pickCleanAgent returns the least-loaded claimable agent that is not the
// banned one and not in active ban memory for this target.
func (e *Executor) pickCleanAgent(ev *db.EgressBanEvent) (string, error) {
	var bannedAgents []string
	if ev.AgentID != "" {
		bannedAgents = append(bannedAgents, ev.AgentID)
	}
	var rows []struct {
		AgentID string
	}
	if err := e.DB.Model(&db.NodeBan{}).
		Select("agent_id").
		Where("tenant_id = ? AND target = ? AND agent_id <> '' AND (cooldown_until IS NULL OR cooldown_until > ?)", ev.TenantID, ev.Target, e.now()).
		Scan(&rows).Error; err != nil {
		return "", err
	}
	for _, r := range rows {
		bannedAgents = append(bannedAgents, r.AgentID)
	}

	q := e.DB.Model(&db.Node{}).
		Select("agent_id").
		Where("(status = '' OR status = 'Alive' OR status IS NULL)")
	if len(bannedAgents) > 0 {
		q = q.Where("agent_id NOT IN ?", bannedAgents)
	}
	q = q.Order("running_tasks ASC, agent_id ASC").Limit(1)
	var agent string
	if err := q.Scan(&agent).Error; err != nil {
		return "", err
	}
	if agent == "" {
		return "", errors.New("no clean agent available")
	}
	return agent, nil
}

func (e *Executor) audit(ev *db.EgressBanEvent, action string, detail map[string]interface{}) {
	detail["signal_type"] = ev.SignalType
	detail["target"] = ev.Target
	detail["classification"] = ev.Classification
	detail["event_id"] = ev.ID
	raw, _ := json.Marshal(detail)
	e.DB.Create(&db.TaskAudit{
		TenantID:   ev.TenantID,
		ProjectID:  ev.ProjectID,
		RootTaskID: ev.RootTaskID,
		OperatorID: "sentinel",
		Action:     action,
		Details:    string(raw),
		CreatedAt:  e.now(),
	})
}

func itoa(n uint) string {
	return fmt.Sprintf("%d", n)
}
