package sentinel

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"

	"github.com/TokEat/argus/server/internal/ai"
	"github.com/TokEat/argus/server/internal/db"
	"gorm.io/gorm"
)

// Decision is the AI verdict for one sentinel event.
type Decision struct {
	Classification string  `json:"classification"`
	Action         string  `json:"action"`
	Reason         string  `json:"reason"`
	Confidence     float64 `json:"confidence"`
}

var (
	// ErrNoEvents is returned when the pending queue is empty.
	ErrNoEvents = errors.New("no pending sentinel events")
	validClassifications = map[string]struct{}{
		ClassBanned: {}, ClassRateLimited: {}, ClassWAFChallenge: {},
		ClassTargetDown: {}, ClassScannerBug: {}, ClassFalsePositive: {},
	}
	validActions = map[string]struct{}{
		ActionBackoff: {}, ActionRescanOtherNode: {}, ActionFlagFindings: {},
		ActionHalt: {}, ActionNone: {},
	}
)

// Decide reads up to limit pending events, asks the LLM to classify each, and
// persists classification + recommended action. LLM failure leaves the event
// pending for the next tick (the worker retries). Returns the count decided.
func Decide(ctx context.Context, store *gorm.DB, client ai.ChatClient, limit int) (int, error) {
	if limit <= 0 {
		limit = 10
	}
	cfg, err := ai.LoadConfig(store)
	if err != nil {
		if errors.Is(err, ai.ErrMissingConfig) {
			return 0, nil // LLM not configured; stay pending
		}
		return 0, err
	}
	if client == nil {
		client = &ai.HTTPClient{}
	}
	var events []db.EgressBanEvent
	if err := store.WithContext(ctx).
		Where("classification = ?", ClassPending).
		Order("id").
		Limit(limit).
		Find(&events).Error; err != nil {
		return 0, err
	}
	decided := 0
	for i := range events {
		ev := &events[i]
		raw, err := client.CompleteJSON(ctx, cfg, buildDecisionMessages(ev))
		if err != nil {
			log.Printf("[Sentinel] decide failed event=%d: %v", ev.ID, err)
			continue
		}
		dec, err := parseDecision(raw)
		if err != nil {
			log.Printf("[Sentinel] decide parse failed event=%d: %v", ev.ID, err)
			continue
		}
		if err := store.Model(&db.EgressBanEvent{}).Where("id = ?", ev.ID).Updates(map[string]interface{}{
			"classification":     dec.Classification,
			"recommended_action": dec.Action,
			"action_reason":      dec.Reason,
			"confidence":         dec.Confidence,
		}).Error; err != nil {
			return decided, err
		}
		decided++
		log.Printf("[Sentinel] decided event=%d class=%s action=%s conf=%.2f", ev.ID, dec.Classification, dec.Action, dec.Confidence)
	}
	return decided, nil
}

func buildDecisionMessages(ev *db.EgressBanEvent) []ai.ChatMessage {
	user := `安全扫描平台的规则引擎在扫描过程中检测到一条可疑信号，请分类并给出处置建议。

信号类型: ` + ev.SignalType + `
目标: ` + ev.Target + `
主机: ` + ev.Host + `
关联任务: ` + ev.RootTaskID + `
关联子任务: ` + ev.SubTaskID + `
相关节点(agent): ` + ev.AgentID + `
规则采集证据(JSON):
` + ev.Evidence + `

请判断这条信号代表什么，并给出建议动作。重点区分:
- banned: 出口 IP 已被目标封禁（大面积连接拒绝/超时/403）
- rate_limited: 被限速，请求被延缓但未被完全封禁
- waf_challenge: WAF 拦截/challenge 页（如同一页面响应所有请求）
- target_down: 目标主机本身宕机或网络不可达
- scanner_bug: 扫描器自身故障导致的假信号
- false_positive: 规则误报，扫描实际正常

建议动作(action):
- backoff: 记录该出口被封并冷却一段时间
- rescan_other_node: 换一个未被封禁的节点重新扫描受影响目标
- halt: 建议人工暂停该扫描任务
- flag_findings: 将该窗口产生的 finding 标记为不可信
- none: 无需处理`

	system := "你是安全扫描平台的扫描对抗决策助手。\n" +
		"先输出分析过程，最后输出一个放在 ```json 代码块中的 JSON 对象。\n" +
		"JSON 字段必须包含:\n" +
		"classification: \"banned\" | \"rate_limited\" | \"waf_challenge\" | \"target_down\" | \"scanner_bug\" | \"false_positive\"\n" +
		"action: \"backoff\" | \"rescan_other_node\" | \"halt\" | \"flag_findings\" | \"none\"\n" +
		"confidence: 0 到 1 的数字\n" +
		"reason: 一句话说明判断依据\n" +
		"原则: 拿不准就保守；真封禁才建议 rescan_other_node，避免无谓换节点扩大对抗。"
	return []ai.ChatMessage{
		{Role: "system", Content: system},
		{Role: "user", Content: user},
	}
}

func parseDecision(raw string) (Decision, error) {
	raw = extractJSONObject(raw)
	var dec Decision
	if err := json.Unmarshal([]byte(raw), &dec); err != nil {
		return Decision{}, err
	}
	dec.Classification = strings.TrimSpace(dec.Classification)
	dec.Action = strings.TrimSpace(dec.Action)
	if _, ok := validClassifications[dec.Classification]; !ok {
		return Decision{}, errors.New("invalid classification: " + dec.Classification)
	}
	if _, ok := validActions[dec.Action]; !ok {
		return Decision{}, errors.New("invalid action: " + dec.Action)
	}
	if dec.Confidence < 0 {
		dec.Confidence = 0
	}
	if dec.Confidence > 1 {
		dec.Confidence = 1
	}
	if dec.Reason == "" {
		dec.Reason = "模型未返回理由。"
	}
	return dec, nil
}

// extractJSONObject pulls the first {...} block out of a model response that
// may wrap JSON in ```json fences or surround it with prose.
func extractJSONObject(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "```") {
		raw = strings.TrimPrefix(raw, "```json")
		raw = strings.TrimPrefix(raw, "```")
		raw = strings.TrimSuffix(raw, "```")
		raw = strings.TrimSpace(raw)
	}
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start >= 0 && end > start {
		return raw[start : end+1]
	}
	return raw
}
