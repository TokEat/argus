package structs

import (
	"embed"
	"net"
	"sync"

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
	Status string `json:"status,omitempty"`
	Title  string `json:"title,omitempty"`
}

// OutputMessage 统一输出消息格式。
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

type Config struct {
	// ExecutionMode and validation plans are internal Server-to-Agent
	// fields. Public task creation deliberately does not accept them; they are
	// populated only after a version-bound validation authorization.
	ExecutionMode               string
	RequiredRuleVersion         string
	RiskValidationTargets       map[string][]string
	RiskValidationPocHashes     map[string]string
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
	TCPPortScanThreads         int
	SYNPortScanThreads         int
	PortsThreshold             int
	TCPPortScanTimeout         int
	MasscanPath                string
	AllowLocalAreaDomain       bool
	AllowCDNAssets             bool
	NoHostBind                 bool
	SubdomainWordListFile      string
	// SubdomainDictionaryWords is a Server-resolved, revision-bound additive
	// list. Scanner always unions it with built-in and managed Agent words.
	SubdomainDictionaryWords  []string
	HTTPProxy                 string
	HTTPProxyTest             bool
	HTTPProxyTestURL          string
	Hunter                    bool
	HunterPageSize            int
	HunterMaxPageCount        int
	Fofa                      bool
	FofaMaxCount              int
	NoDirSearch               bool
	DirSearchYaml             string
	GolangPoc                 bool
	DisableGeneralPoc         bool
	WAFBypassHeaders          bool
	WAFSkipOnManyFingerprints bool
	NucleiTemplate            string
	ExcludeTags               string
	Severities                string
	WorkflowYamlPath          string
	ReportName                string
	GoPocThreads              int
	WebThreads                int
	WebTimeout                int
	PocNameForSearch          string
	NoPoc                     bool
	LowPerceptionMode         bool
	Quake                     bool
	QuakeSize                 int
	NoICMPPing                bool
	TCPPing                   bool
	NoInteractsh              bool
	OnlyIPPort                bool
	OutputFile                string
	OutputType                string
	APIConfigFilePath         string
	FingerConfigFilePath      string
	RuleFilesOnly             bool
	// KnowledgePackageHash and KnowledgeRuleVersion are verified Agent rule
	// identities. They are internal-only and must never enter task JSON.
	KnowledgePackageHash string `json:"-"`
	KnowledgeRuleVersion string `json:"-"`
	// MachineOutput is a standalone CLI presentation hint. It is never
	// accepted from Server task JSON and does not change scan stages.
	MachineOutput bool `json:"-"`
	PasswordFile  string
	Password      string
}

type CDNResult struct {
	Domain  string
	IsCDN   bool
	CDNName string
	IPs     []net.IP
}

var GlobalConfig Config

var GlobalEmbedPocs embed.FS

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
	DirFallback bool // dir匹配且状态码200时直接标记指纹，无需finger验证
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

// DirFallbackResultMap 存储dir-fallback标记的指纹（在FingerprintIdentification之后合并到GlobalResultMap）
var DirFallbackResultMap map[string][]string
var DirFallbackResultMapLock sync.Mutex

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
	WriteResult         func(GoPocsResultType)
	Emit                func(OutputMessage)
}

var AddScanNum int
var AddScanEnd int
