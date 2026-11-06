package engine

import "github.com/P0lar1ght/argus/scanner/structs"

// --- 输入类型常量 ---

const (
	TypeDomain     = 1
	TypeDomainPort = 2
	TypeIPRange    = 3
	TypeCIDR       = 4
	TypeIP         = 5
	TypeIPPort     = 6
	TypeURL        = 7
	TypeUnSupport  = 0
)

// --- 配置 ---

// Config 扫描配置，从 CLI 参数或 Server 下发的任务中构造。
type Config = structs.Config

// --- 扫描数据实体 ---

// CDNResult CDN 检测结果。
type CDNResult = structs.CDNResult

// PortEntity 端口协议数据。
type PortEntity = structs.PortEntity

// ProtocolResult 协议识别结果。
type ProtocolResult = structs.ProtocolResult

// UrlPathEntity Web 路径响应数据。
type UrlPathEntity = structs.UrlPathEntity

// URLEntity Web URL 实体。
type URLEntity = structs.URLEntity

// --- 指纹/漏洞相关 ---

// RuleData 指纹匹配规则数据。
type RuleData = structs.RuleData

// FingerPEntity 指纹规则实体。
type FingerPEntity = structs.FingerPEntity

// WorkFlowEntity 指纹→PoC 工作流映射实体。
type WorkFlowEntity = structs.WorkFlowEntity

// PasswordDatabaseEntity 密码数据库实体。
type PasswordDatabaseEntity = structs.PasswordDatabaseEntity

// GoPocsResultType Go Poc 检测结果。
type GoPocsResultType = structs.GoPocsResultType

// UserPasswd 用户名密码凭证。
type UserPasswd = structs.UserPasswd

// HostInfo 主机信息（GoPoc 使用）。
type HostInfo = structs.HostInfo

// --- 输出相关 ---

// WebInfo and OutputMessage share the canonical scanner output contract. The
// aliases keep CLI report, local history, and Agent streaming consumers on the
// same structured event instead of maintaining parallel projections.
type WebInfo = structs.WebInfo
type OutputMessage = structs.OutputMessage

// --- 阶段进度事件 ---

// PhaseEvent 描述 Pipeline 扫描阶段的进度事件。
type PhaseEvent struct {
	Phase   string `json:"phase"`             // 阶段标识
	Status  string `json:"status"`            // "start" | "end"
	Message string `json:"message,omitempty"` // 可选附加信息（如目标数量）
}

// ProgressEvent 细粒度进度事件：当前阶段 + 活动计数 + 输入总数。
// 与 PhaseEvent（仅阶段边界）不同，ProgressEvent 在阶段内随活动节流上报，
// 让 server 端进度条在大批次执行期间持续前进，而不是卡在某个点。
//
// Unit=false（发现模式）：Done 是「发现类输出数」，与 Total 单位不同，仅作
// 「仍在推进」信号；Rate/EtaMillis 恒为 0，UI 不显示占比/ETA。
// Unit=true（单元模式）：Done 与 Total 同口径（如端口扫描 connect 尝试数），
// 可显示 done/total 占比；Rate 为吞吐（单元/秒），EtaMillis 为预计剩余毫秒。
type ProgressEvent struct {
	Phase     string `json:"phase"`       // 当前阶段标识
	Done      int    `json:"done"`        // 已完成活动计数（本阶段累计）
	Total     int    `json:"total"`       // 输入总数；0 表示总量未知（仅表示"有活动"）
	Unit      bool   `json:"unit,omitempty"`    // true=单元计数模式（done/total 同口径）
	Rate      float64 `json:"rate,omitempty"`   // 单元模式吞吐（单元/秒）
	EtaMillis int64  `json:"eta_ms,omitempty"`  // 单元模式预计剩余毫秒
}

// Pipeline 扫描阶段常量
const (
	PhaseSubdomain            = "subdomain"
	PhaseCDN                  = "cdn_check"
	PhaseICMP                 = "icmp_discovery"
	PhaseTCPPing              = "tcp_ping"
	PhasePortScan             = "port_scan"
	PhaseProtocol             = "protocol_identify"
	PhaseHTTPProbe            = "http_probe"
	PhaseHostBind             = "host_bind"
	PhaseBehaviorProbe        = "behavior_probe"
	PhaseDirBrute             = "dir_brute"
	PhaseFingerprint          = "fingerprint"
	PhaseNuclei               = "nuclei_scan"
	PhaseGoPoc                = "gopoc_scan"
	PhaseCredentialValidation = "credential_validation"
	PhaseWebCrawl             = "web_crawl"
	PhaseSensitiveInfo        = "sensitive_info"
)
