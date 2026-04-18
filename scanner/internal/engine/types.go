package engine

import "dddd/scanner/structs"

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

// WebInfo Web 页面信息
type WebInfo struct {
	Status string `json:"status,omitempty"`
	Title  string `json:"title,omitempty"`
}

// OutputMessage 统一输出消息格式
type OutputMessage struct {
	Type          string           `json:"type,omitempty"`
	IP            string           `json:"ip,omitempty"`
	IPs           []string         `json:"ips,omitempty"`
	Port          string           `json:"port,omitempty"`
	Protocol      string           `json:"protocol,omitempty"`
	Web           WebInfo          `json:"web,omitempty"`
	Finger        []string         `json:"finger,omitempty"`
	Domain        string           `json:"domain,omitempty"`
	GoPoc         GoPocsResultType `json:"go_poc,omitempty"`
	URI           string           `json:"uri,omitempty"`
	City          string           `json:"city,omitempty"`
	AdditionalMsg string           `json:"am,omitempty"`
	Show          string           `json:"-"`
	Nuclei        string           `json:"nuclei,omitempty"`
}
