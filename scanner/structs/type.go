package structs

import (
	"embed"
	"net"
	"sync"

	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"

	"github.com/lcvvvv/gonmap"
	"github.com/projectdiscovery/hmap/store/hybrid"
)

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

// WebInfo Web 页面信息。
type WebInfo struct {
	Status   string `json:"status,omitempty"`
	Title    string `json:"title,omitempty"`
	Cert     string `json:"cert,omitempty"`
	Size     string `json:"size,omitempty"`
	Redirect string `json:"redirect,omitempty"`
}

// OutputMessage 统一输出消息格式。
type OutputMessage struct {
	Type          string           `json:"type,omitempty"`
	IP            string           `json:"ip,omitempty"`
	IPs           []string         `json:"ips,omitempty"`
	Port          string           `json:"port,omitempty"`
	Protocol      string           `json:"protocol,omitempty"`
	Product       string           `json:"product,omitempty"`
	Version       string           `json:"version,omitempty"`
	Transport     string           `json:"transport,omitempty"`
	Web           WebInfo          `json:"web,omitempty"`
	Finger        []string         `json:"finger,omitempty"`
	Domain        string           `json:"domain,omitempty"`
	GoPoc         GoPocsResultType `json:"go_poc,omitempty"`
	URI           string           `json:"uri,omitempty"`
	City          string           `json:"city,omitempty"`
	AdditionalMsg string           `json:"am,omitempty"`
	// Tag marks special asset classes for Server-side asset tagging, e.g.
	// "cdn" for suspected CDN assets. Old peers ignore the unknown field.
	Tag    string `json:"tag,omitempty"`
	Show   string `json:"-"`
	Nuclei string `json:"nuclei,omitempty"`
}

type Config struct {
	// ExecutionMode and validation plans are internal Server-to-Agent
	// fields. Public task creation deliberately does not accept them; they are
	// populated only after a version-bound validation authorization.
	ExecutionMode              string
	RequiredRuleVersion        string
	RiskValidationTargets      map[string][]string
	RiskValidationPocHashes    map[string]string
	RiskValidationGoPocTargets []scanpolicy.GoPocTarget
	// TargetFingerprints 是原生匹配派发模式的目标指纹集合（目标 → 产品名列表）。
	// 与 RiskValidationTargets 互斥：设置时 Agent 使用本地 workflow.yaml 完成
	// 指纹→POC 匹配（与单次扫描同源逻辑），服务端不再构建显式映射表。
	TargetFingerprints map[string][]string
	// AllowHighRiskAutoExecution 对应策略预授权开关：未开启时 Agent 本地匹配
	// 会剔除 high/unknown 风险等级的 workflow 条目。
	AllowHighRiskAutoExecution  bool
	GoPocCatalogSHA256          string
	ProtocolCheckEnabled        bool
	ProtocolCheckTargetLimit    int
	ProtocolCheckRateLimit      int
	ProtocolCheckRequestBudget  int64
	CredentialValidationTargets []CredentialValidationTarget
	CredentialBundleRef         string
	CredentialBundleSHA256      string
	CredentialBundleCount       int
	CredentialPairLimit         int
	PreferredAgentID            string
	PreferredNetworkZone        string
	PreferredAgentUntilUnix     int64
	PreferredNetworkUntilUnix   int64
	ValidationBudgetID          string
	ValidationTargetConcurrency int
	ValidationRateLimit         int
	ValidationRequestBudget     int64
	ValidationEstimatedRequests int64
	// CredentialBundle is resolved over the authenticated Agent channel after
	// an Attempt is claimed. It must never be serialized into task JSON.
	CredentialBundle           []UserPasswd `json:"-"`
	Targets                    []string
	Ports                      string
	NoSubdomainBruteForce      bool
	NoSubFinder                bool
	Subdomain                  bool
	SubdomainBruteForceThreads int
	SubdomainBruteforceDepth   int
	SkipHostDiscovery          bool
	PortScanType               string
	GetBannerThreads           int
	GetBannerTimeout           int
	NoUDPIdentify              bool
	TCPPortScanThreads         int
	SYNPortScanThreads         int
	PortsThreshold             int
	TCPPortScanTimeout         int
	AllowLocalAreaDomain       bool
	AllowCDNAssets             bool
	NoHostBind                 bool
	// NoDomainProbe disables domain-form web probing. When false (default),
	// an open ip:port that has bound domains from CDN classification is
	// probed as scheme://domain:port instead of scheme://ip:port, so web
	// assets keep the imported domain form.
	NoDomainProbe bool
	// NoResolvedIPScan skips host discovery / port scanning of domain-
	// resolved IPs entirely; those domains are only probed blind as
	// scheme://domain:port across the configured port set.
	NoResolvedIPScan      bool
	SubdomainWordListFile string
	// SubdomainDictionaryWords is a Server-resolved, revision-bound additive
	// list. Scanner always unions it with built-in and managed Agent words.
	SubdomainDictionaryWords []string
	// SubdomainPassiveResults carries Server-side pre-collected passive
	// subdomains keyed by domain. Domains present here skip agent-side
	// subfinder queries; the map is sealed by the Server and deduplicated
	// with bruteforce results like any other enumeration output.
	SubdomainPassiveResults    map[string][]string
	HTTPProxy                  string
	HTTPProxyTest              bool
	HTTPProxyTestURL           string
	Hunter                     bool
	HunterPageSize             int
	HunterMaxPageCount         int
	Fofa                       bool
	FofaMaxCount               int
	NoDirSearch                bool
	DirSearchYaml              string
	BehaviorProbe              bool
	ActiveFingerprintTemplate  string
	ActiveFingerprintHashes    map[string]string
	ActiveFingerprintProducts  map[string]string
	BehaviorProbeRequestBudget int64
	GolangPoc                  bool
	NoGoPoc                    bool
	NoBrute                    bool
	GoPocModules               string
	UserAppend                 []string
	PasswordAppend             []string
	DisableGeneralPoc          bool
	WAFBypassHeaders           bool
	WAFSkipOnManyFingerprints  bool
	NucleiTemplate             string
	ExcludeTags                string
	Severities                 string
	WorkflowYamlPath           string
	ReportName                 string
	GoPocThreads               int
	WebThreads                 int
	WebTimeout                 int
	PocNameForSearch           string
	NoPoc                      bool
	LowPerceptionMode          bool
	Quake                      bool
	QuakeSize                  int
	NoICMPPing                 bool
	TCPPing                    bool
	UDPPing                    bool
	TraceRoute                 bool
	NoInteractsh               bool
	OnlyIPPort                 bool
	OutputFile                 string
	OutputType                 string
	APIConfigFilePath          string
	FingerConfigFilePath       string
	RuleFilesOnly              bool
	// KnowledgePackageHash and KnowledgeRuleVersion are verified Agent rule
	// identities. They are internal-only and must never enter task JSON.
	KnowledgePackageHash string `json:"-"`
	KnowledgeRuleVersion string `json:"-"`
	// MachineOutput is a standalone CLI presentation hint. It is never
	// accepted from Server task JSON and does not change scan stages.
	MachineOutput bool `json:"-"`
	// SkipSeenHistory opts into skipping datas/ IPs from previous completed
	// CLI runs. It is CLI-only and defaults to off.
	SkipSeenHistory bool `json:"-"`
	// ShowPocMap prints fingerprint-to-Nuclei YAML mapping. CLI-only, default off.
	ShowPocMap bool `json:"-"`
	// TraceOnly is CLI-only: -tr <target> runs traceroute without the scan pipeline.
	TraceOnly    bool `json:"-"`
	PasswordFile string
	Password     string
}

type CDNResult struct {
	Domain  string
	IsCDN   bool
	CDNName string
	IPs     []net.IP
}

var GlobalConfig Config

var GlobalEmbedPocs embed.FS

var GlobalEmbedActiveFingerprints embed.FS

var GlobalBannerHMap *hybrid.HybridMap

// GlobalIPPortMap IP:Port : Protocol
var GlobalIPPortMap map[string]string
var GlobalIPPortMapLock sync.Mutex

type PortEntity struct {
	Protocol   string // 协议
	BannerHash string // 响应
}

type ProtocolResult struct {
	IP       string
	Port     int
	Status   int
	Response *gonmap.Response
}

// ServiceRecord is the protocol-stage service picture for one endpoint.
// IPPortMap still stores only the canonical protocol name.
type ServiceRecord struct {
	Endpoint   string
	Transport  string
	Protocol   string
	Product    string
	Version    string
	Extra      string
	Confidence string
}

// GlobalIPDomainMap 存储ip->domains的关系
var GlobalIPDomainMap map[string][]string
var GlobalIPDomainMapLock sync.Mutex

type UrlPathEntity struct {
	// Path             string // 根目录为/
	Hash             string // md5
	IconHash         string //mmh3
	Title            string
	StatusCode       int
	ContentType      string
	Server           string
	ContentLength    int
	HeaderHashString string
	// Natural is true when this path was observed without the scanner choosing
	// it (homepage or same-origin redirect). Directory-probe responses stay false
	// so Identify() does not treat them as passive evidence.
	Natural bool
}

type URLEntity struct {
	IP       string
	Port     int
	WebPaths map[string]UrlPathEntity
	Cert     string // TLS证书
}

// GlobalURLMap RootURL:URLEntity
var GlobalURLMap map[string]URLEntity
var GlobalURLMapLock sync.Mutex

var GlobalHttpBodyHMap *hybrid.HybridMap
var GlobalHttpHeaderHMap *hybrid.HybridMap

type RuleData struct {
	Start int
	End   int
	Op    int16  // 0= 1!= 2== 3>= 4<= 5~=
	Key   string // body="123"中的body
	Value string // body="123"中的123
	All   string // body="123"
}

type WorkFlowEntity struct {
	RootType    bool
	DirType     bool
	BaseType    bool
	DirFallback bool   // dir匹配且状态码200时直接标记指纹，无需finger验证
	RiskLevel   string // 关联 POC 的风险等级（unknown/low/medium/high），供预授权门本地过滤
	PocsName    []string
}

type PasswordDatabaseEntity struct {
	Keys      []string
	Passwords []string
	Hints     []string
}

type FingerPEntity struct {
	ProductName      string
	AllString        string
	Rule             []RuleData
	IsExposureDetect bool
}

var FingerprintDB []FingerPEntity
var WorkFlowDB map[string]WorkFlowEntity
var DirDB map[string][]string

// GlobalResultMap 存储识别到的指纹
var GlobalResultMap map[string][]string

// DirFallbackResultMap 存储 dir-fallback 观察（路径 200 但无独立内容证据）。
// 不再合并进 ResultMap，避免无指纹 200 驱动 POC。
var DirFallbackResultMap map[string][]string
var DirFallbackResultMapLock sync.Mutex

// DirEvidenceResultMap 存储目录探测在独立内容证据下确认的产品（探测 URL → 产品）。
// 在正式指纹阶段之后合并进 ResultMap，供 Workflow/POC 使用。
var DirEvidenceResultMap map[string][]string
var DirEvidenceResultMapLock sync.Mutex

type GoPocsResultType struct {
	PocName     string
	Security    string
	Description string
	Target      string
	InfoLeft    string
	InfoRight   string
	Exchanges   []GoPocExchange `json:"exchanges,omitempty"`
	ShowMsg     string          // 格式化后的展示文本
}

// GoPocsResults 存储Go Poc的输出
// GoPocExchange preserves one successful verification exchange. Binary
// protocols use a lossless textual encoding such as hex-dump so evidence can
// pass through JSON and the offline HTML report without invalid UTF-8 loss.
type GoPocExchange struct {
	Label    string `json:"label,omitempty"`
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

var GoPocsResults []GoPocsResultType

type UserPasswd struct {
	UserName string
	Password string
}

type CredentialValidationTarget struct {
	Endpoint          string `json:"endpoint"`
	Service           string `json:"service"`
	Plugin            string `json:"plugin"`
	Eligibility       string `json:"eligibility"`
	ObservationSHA256 string `json:"observation_sha256"`
}

type HostInfo struct {
	Host                string
	Ports               string
	Url                 string
	InfoStr             []string
	UserPass            []string
	UserPassPairs       []UserPasswd
	CredentialPairLimit int
	CredentialAttempt   func()
	Password            string
	PasswordFile        string
	UserAppend          []string
	PasswordAppend      []string
	WriteResult         func(GoPocsResultType)
	Emit                func(OutputMessage)
	OutputType          string
	ObservedService     string
	BeforeExecute       func()
}

var AddScanNum int
var AddScanEnd int
