// Package sentinel is the scan-time security-device countermeasure layer:
//
//	detect (rules, cheap, real-time)  →  decide (AI classifies + recommends)
//	→  execute (policy-gated, convergent-only by default)
//
// It exists to turn silent scan corruption into known, actionable facts:
// egress bans mid-scan (missed coverage becomes a reschedule instead of a
// silent false negative), and catch-all/WAF pages that make every port look
// identical (findings get tainted instead of trusted).
//
// Hard rule, same as the triage layer: AI is an advisor, never the executor.
// Rules detect, AI classifies and recommends, and only convergent actions
// (backoff / taint) run automatically — rescan-on-other-node needs either the
// sentinel_auto_execute policy switch or a human confirmation.
package sentinel

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/TokEat/argus/server/internal/db"
	"gorm.io/gorm"
)

// Signal types produced by the rule detectors.
const (
	SignalHomogeneity = "homogeneity" // 同一主机多个端口响应体完全一致（catch-all/WAF 页）
	SignalSuccessDrop = "success_drop" // 任务级成功率/完成率突降（封禁/限速导致大面积失败）
)

// AI classifications for an event.
const (
	ClassPending      = "pending"
	ClassBanned       = "banned"        // 出口 IP 被目标封禁
	ClassRateLimited  = "rate_limited"  // 被限速
	ClassWAFChallenge = "waf_challenge" // WAF challenge/拦截页
	ClassTargetDown   = "target_down"   // 目标本身挂了
	ClassScannerBug   = "scanner_bug"   // 扫描器自身问题
	ClassFalsePositive= "false_positive"// 规则误报
)

// Recommended actions. Only ActionBackoff / ActionFlagFindings auto-execute;
// ActionRescanOtherNode and ActionHalt need policy or a human.
const (
	ActionBackoff          = "backoff"            // 记录封禁记忆 + 冷却
	ActionRescanOtherNode  = "rescan_other_node"  // 换干净出口节点重扫
	ActionFlagFindings     = "flag_findings"      // 污染窗口 finding 打污点
	ActionHalt             = "halt"               // 建议人工暂停任务（v1 不自动执行）
	ActionNone             = "none"
)

// Event lifecycle.
const (
	EventOpen      = "open"
	EventExecuted  = "executed"
	EventDismissed = "dismissed"
	EventExpired   = "expired"
)

// SystemConfig keys.
const (
	ConfigKeyEnabled          = "sentinel_enabled"        // default true
	ConfigKeyAutoExecute      = "sentinel_auto_execute"   // default false — gate for rescan/halt
	ConfigKeyCooldownMinutes  = "sentinel_cooldown_minutes" // default 10
)

// Taint values written to vulnerabilities.taint_status.
const (
	TaintSuspectWAF = "suspect_waf"
)

// Trigger used on the fresh rescan attempt so audits/history show why it ran.
const TriggerEgressBanRecovery = "egress_ban_recovery"

func bodyHash(body string) string {
	sum := md5.Sum([]byte(body))
	return hex.EncodeToString(sum[:])
}

func loadSystemBool(store *gorm.DB, key string, def bool) bool {
	var row db.SystemConfig
	err := store.Where("key = ?", key).First(&row).Error
	if err != nil || row.Value == "" {
		return def
	}
	return row.Value == "true" || row.Value == "1"
}

func loadSystemInt(store *gorm.DB, key string, def int) int {
	var row db.SystemConfig
	err := store.Where("key = ?", key).First(&row).Error
	if err != nil || row.Value == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(row.Value))
	if err != nil {
		return def
	}
	return n
}
