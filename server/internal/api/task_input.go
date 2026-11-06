package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
)

// dispatchLivenessWindowMillis mirrors the heartbeat death-detector freshness
// window used when counting free slots for controller-push fan-out.
const dispatchLivenessWindowMillis = 60000

// defaultExcludedPoCTags 是产品级扫描降噪决策：所有带这些 nuclei 标签的模板
// （含其中 high/critical CVE）在每次任务运行期都被 ExcludeTags 跳过，不执行 PoC。
// 集中治理、可审计、可逆——恢复某类标签只需从本切片移除；模板文件保持不动。
var defaultExcludedPoCTags = []string{"xss", "smuggling"}

// unionExcludedPoCTags 把 defaultExcludedPoCTags 去重并集进 cfg.ExcludeTags，
// 调用方自填的其它标签全部保留，默认排除项强制存在。
func unionExcludedPoCTags(cfg *taskScanConfig) {
	if cfg == nil {
		return
	}
	seen := map[string]bool{}
	var tags []string
	for _, t := range strings.Split(cfg.ExcludeTags, ",") {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		tags = append(tags, t)
	}
	for _, t := range defaultExcludedPoCTags {
		if !seen[t] {
			seen[t] = true
			tags = append(tags, t)
		}
	}
	cfg.ExcludeTags = strings.Join(tags, ",")
}

type taskTargetMode string

const taskTargetModeDirect taskTargetMode = "direct"

type taskTargetSummary struct {
	Mode         string `json:"mode"`
	Total        int    `json:"total"`
	IPs          int    `json:"ips"`
	IPPorts      int    `json:"ip_ports"`
	CIDRs        int    `json:"cidrs"`
	IPRanges     int    `json:"ip_ranges"`
	Domains      int    `json:"domains"`
	DomainPorts  int    `json:"domain_ports"`
	URLs         int    `json:"urls"`
	SearchInputs int    `json:"search_inputs"`
}

type taskScanConfig struct {
	RequiredRuleVersion        string
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
	AllowLocalAreaDomain       bool
	AllowCDNAssets             bool
	NoHostBind                 bool
	// NoDomainProbe=false (default) keeps domain-form web probing enabled:
	// open ports bound to a scanned domain are probed as scheme://domain:port.
	NoDomainProbe bool
	// NoResolvedIPScan=true skips host discovery / port scanning of domain-
	// resolved IPs; those domains are only probed as scheme://domain:port.
	NoResolvedIPScan           bool
	SubdomainWordListFile      string
	SubdomainDictionaryWords   []string
	SubdomainDictionaryRefs    []scanpolicy.DictionaryRef
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
	DisableGeneralPoc          bool
	WAFBypassHeaders           bool
	WAFSkipOnManyFingerprints  bool
	NucleiTemplate             string
	ExcludeTags                string
	Severities                 string
	WorkflowYamlPath           string
	ReportName                 string
	GoPocThreads               int
	GoPocCatalogSHA256         string
	ProtocolCheckEnabled       bool
	ProtocolCheckTargetLimit   int
	ProtocolCheckRateLimit     int
	ProtocolCheckRequestBudget int64
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
	PortScanScatter            bool
	PortScanProbeInterval      int
	WebCrawl                   bool
	WebCrawlMaxDepth           int
	WebCrawlMaxPages           int
	WebCrawlMaxPathApps        int
	SensitiveInfo              bool
	WebCrawlAI                 bool
	SensitiveInfoAI            bool
	OutputFile                 string
	OutputType                 string
	APIConfigFilePath          string
	FingerConfigFilePath       string
	PasswordFile               string
	Password                   string
}

func defaultTaskScanConfig() taskScanConfig {
	return taskScanConfig{
		Ports:                      scanpolicy.Common100Ports,
		PortScanType:               "tcp",
		TCPPortScanThreads:         1000,
		SYNPortScanThreads:         10000,
		PortsThreshold:             300,
		TCPPortScanTimeout:         6,
		PortScanScatter:            false,
		PortScanProbeInterval:      scanpolicy.DefaultPacingIntervalMillis,
		GetBannerThreads:           500,
		GetBannerTimeout:           5,
		SubdomainBruteForceThreads: 150,
		SubdomainBruteforceDepth:   1,
		WebThreads:                 200,
		WebTimeout:                 10,
		HTTPProxyTest:              true,
		HTTPProxyTestURL:           "https://www.baidu.com",
		HunterPageSize:             100,
		HunterMaxPageCount:         10,
		FofaMaxCount:               100,
		QuakeSize:                  100,
		NoSubdomainBruteForce:      true,
		NoSubFinder:                false,
		Subdomain:                  true,
		NoHostBind:                 true,
		// NoDomainProbe=false keeps domain-form web probing enabled by
		// default; open ports bound to a domain are probed as domain:port.
		NoDomainProbe: false,
		// NoResolvedIPScan=false keeps domain-resolved IPs in the scan path.
		NoResolvedIPScan:          false,
		GoPocThreads:              50,
		NoDirSearch:               true,
		NoPoc:                     true,
		GolangPoc:                 false,
		DisableGeneralPoc:         true,
		WAFBypassHeaders:          true,
		WAFSkipOnManyFingerprints: true,
		NoInteractsh:              true,
		WebCrawlMaxDepth:          scanpolicy.DefaultWebCrawlMaxDepth,
		WebCrawlMaxPages:          scanpolicy.DefaultWebCrawlMaxPages,
		OutputFile:                "result.txt",
		OutputType:                "text",
		NucleiTemplate:            "config/pocs",
		WorkflowYamlPath:          "config/workflow.yaml",
		FingerConfigFilePath:      "config/finger.yaml",
		DirSearchYaml:             "config/dir.yaml",
		ActiveFingerprintTemplate: "config/active-fingerprints",
		SubdomainWordListFile:     "config/subdomains.txt",
	}
}

func normalizeTaskConfigPayload(raw json.RawMessage) (string, taskTargetMode, error) {
	body, err := normalizeJSONObjectPayload(raw)
	if err != nil {
		return "", taskTargetModeDirect, err
	}
	if err := rejectServerOnlyTaskConfigFields(body); err != nil {
		return "", taskTargetModeDirect, err
	}

	cfg := defaultTaskScanConfig()
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return "", taskTargetModeDirect, fmt.Errorf("config contains unsupported field or invalid value: %w", err)
	}

	unionExcludedPoCTags(&cfg)

	if err := validateTaskScanConfig(&cfg); err != nil {
		return "", taskTargetModeDirect, err
	}

	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return "", taskTargetModeDirect, err
	}

	return string(configJSON), taskTargetModeDirect, nil
}

func rejectServerOnlyTaskConfigFields(body []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return err
	}
	serverOnly := map[string]string{
		"requiredruleversion":        "RequiredRuleVersion",
		"behaviorprobe":              "BehaviorProbe",
		"activefingerprinttemplate":  "ActiveFingerprintTemplate",
		"activefingerprinthashes":    "ActiveFingerprintHashes",
		"activefingerprintproducts":  "ActiveFingerprintProducts",
		"behaviorproberequestbudget": "BehaviorProbeRequestBudget",
	}
	for rawField := range fields {
		if field, exists := serverOnly[strings.ToLower(rawField)]; exists {
			return fmt.Errorf("%s is Server-only; use semantic scan policy", field)
		}
	}
	return nil
}

func normalizeJSONObjectPayload(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return []byte("{}"), nil
	}

	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return []byte("{}"), nil
	}

	switch trimmed[0] {
	case '"':
		var input string
		if err := json.Unmarshal(raw, &input); err != nil {
			return nil, err
		}
		input = strings.TrimSpace(input)
		if input == "" || input == "null" {
			return []byte("{}"), nil
		}
		if !json.Valid([]byte(input)) {
			return nil, fmt.Errorf("config must be valid json")
		}
		trimmed = strings.TrimSpace(input)
		if trimmed == "" || trimmed == "null" {
			return []byte("{}"), nil
		}
		if trimmed[0] != '{' {
			return nil, fmt.Errorf("config must be a json object or json string")
		}
		return []byte(trimmed), nil
	case '{':
		if !json.Valid(raw) {
			return nil, fmt.Errorf("config must be valid json")
		}
		return []byte(trimmed), nil
	default:
		return nil, fmt.Errorf("config must be a json object or json string")
	}
}

func validateTaskScanConfig(cfg *taskScanConfig) error {
	if cfg.SubdomainBruteforceDepth < 1 || cfg.SubdomainBruteforceDepth > 4 {
		return fmt.Errorf("SubdomainBruteforceDepth must be between 1 and 4")
	}
	if cfg.SubdomainWordListFile != "" && cfg.SubdomainWordListFile != "config/subdomains.txt" {
		return fmt.Errorf("SubdomainWordListFile is Agent-managed; use project subdomain dictionary revisions")
	}
	if len(cfg.SubdomainDictionaryWords) > 0 {
		return fmt.Errorf("SubdomainDictionaryWords is Server-only; use project subdomain dictionary revisions")
	}
	if len(cfg.SubdomainDictionaryRefs) > 0 {
		return fmt.Errorf("SubdomainDictionaryRefs is Server-only; use semantic scan policy")
	}
	if !cfg.NoPoc || cfg.GolangPoc || !cfg.DisableGeneralPoc || strings.TrimSpace(cfg.PocNameForSearch) != "" {
		return fmt.Errorf("POC execution is isolated from asset discovery; use task risk validation")
	}
	if cfg.ProtocolCheckEnabled || cfg.ProtocolCheckTargetLimit != 0 || cfg.ProtocolCheckRateLimit != 0 || cfg.ProtocolCheckRequestBudget != 0 || strings.TrimSpace(cfg.GoPocCatalogSHA256) != "" {
		return fmt.Errorf("GoPoc protocol checks are Server-only; use semantic scan policy")
	}

	switch strings.ToLower(strings.TrimSpace(cfg.PortScanType)) {
	case "", "tcp", "syn":
	default:
		return fmt.Errorf("PortScanType must be tcp or syn")
	}

	if legacyProviderConfig(*cfg) {
		return fmt.Errorf("Provider discovery is Server-only; use project asset discovery")
	}

	if !cfg.SkipHostDiscovery && cfg.NoICMPPing && !cfg.TCPPing && !cfg.UDPPing {
		cfg.TCPPing = true
	}

	if cfg.ReportName != "" {
		suffix := strings.ToLower(path.Ext(cfg.ReportName))
		if suffix != ".html" && suffix != ".htm" {
			return fmt.Errorf("ReportName must end with .html or .htm")
		}
	}

	if cfg.WebCrawl {
		if cfg.WebCrawlMaxDepth == 0 {
			cfg.WebCrawlMaxDepth = scanpolicy.DefaultWebCrawlMaxDepth
		}
		if cfg.WebCrawlMaxPages == 0 {
			cfg.WebCrawlMaxPages = scanpolicy.DefaultWebCrawlMaxPages
		}
		if cfg.WebCrawlMaxDepth < 1 || cfg.WebCrawlMaxDepth > scanpolicy.MaximumWebCrawlMaxDepth {
			return fmt.Errorf("WebCrawlMaxDepth must be between 1 and %d", scanpolicy.MaximumWebCrawlMaxDepth)
		}
		if cfg.WebCrawlMaxPages < 1 || cfg.WebCrawlMaxPages > scanpolicy.MaximumWebCrawlMaxPages {
			return fmt.Errorf("WebCrawlMaxPages must be between 1 and %d", scanpolicy.MaximumWebCrawlMaxPages)
		}
		if cfg.WebCrawlMaxPathApps < 0 || cfg.WebCrawlMaxPathApps > scanpolicy.MaximumWebCrawlPathAppLimit {
			return fmt.Errorf("WebCrawlMaxPathApps must be between 0 and %d", scanpolicy.MaximumWebCrawlPathAppLimit)
		}
	} else {
		cfg.WebCrawlMaxDepth = 0
		cfg.WebCrawlMaxPages = 0
		cfg.WebCrawlMaxPathApps = 0
		cfg.WebCrawlAI = false
	}
	if !cfg.SensitiveInfo {
		cfg.SensitiveInfoAI = false
	}

	return nil
}

// legacyProviderConfig identifies task settings that could cause a Scanner or
// Agent to use third-party discovery credentials. They are retained solely so
// persisted legacy task JSON remains decodable and can be failed closed.
func legacyProviderConfig(cfg taskScanConfig) bool {
	return cfg.Hunter || cfg.Fofa || cfg.Quake || cfg.LowPerceptionMode || cfg.OnlyIPPort ||
		strings.TrimSpace(cfg.APIConfigFilePath) != ""
}

func legacyProviderConfigJSON(configJSON string) bool {
	if strings.TrimSpace(configJSON) == "" {
		return false
	}
	cfg := defaultTaskScanConfig()
	return json.Unmarshal([]byte(configJSON), &cfg) == nil && legacyProviderConfig(cfg)
}

func parseAndValidateTargetsForMode(raw json.RawMessage, mode taskTargetMode) ([]string, taskTargetSummary, error) {
	targets, err := parseTargets(raw)
	if err != nil {
		return nil, taskTargetSummary{}, err
	}
	targets = normalizeTargetsForMode(targets, mode)
	return validateTargetsByMode(targets, mode)
}

func detectTargetModeFromStoredConfig(configJSON string) taskTargetMode {
	return taskTargetModeDirect
}

func validateTargetsByMode(targets []string, mode taskTargetMode) ([]string, taskTargetSummary, error) {
	_, invalid, summary := classifyTargets(targets, mode)
	if len(invalid) > 0 {
		target := invalid[0].Target
		return nil, taskTargetSummary{}, fmt.Errorf("unsupported target %q", target)
	}

	return targets, summary, nil
}

func estimatedProtocolCheckEndpointCount(targets []string) int {
	total := 0
	for _, target := range targets {
		total += estimatedDirectTargetEndpointCount(target)
		if total >= scanpolicy.MaximumGoPocTargets {
			return scanpolicy.MaximumGoPocTargets
		}
	}
	if total < 1 && len(targets) > 0 {
		return 1
	}
	return total
}

func estimatedDirectTargetEndpointCount(target string) int {
	switch detectDirectTargetType(target) {
	case "cidr":
		return estimatedCIDREndpointCount(target)
	case "ip_range":
		return estimatedIPRangeEndpointCount(target)
	default:
		return 1
	}
}

func estimatedCIDREndpointCount(target string) int {
	_, network, err := net.ParseCIDR(strings.TrimSpace(target))
	if err != nil {
		return 1
	}
	ones, bits := network.Mask.Size()
	if ones < 0 || bits != 32 {
		return 1
	}
	hostBits := bits - ones
	if hostBits >= 12 {
		return scanpolicy.MaximumGoPocTargets
	}
	return 1 << uint(hostBits)
}

func estimatedIPRangeEndpointCount(target string) int {
	parts := strings.Split(strings.TrimSpace(target), "-")
	if len(parts) != 2 {
		return 1
	}
	start := net.ParseIP(strings.TrimSpace(parts[0])).To4()
	end := net.ParseIP(strings.TrimSpace(parts[1])).To4()
	if start == nil || end == nil {
		return 1
	}
	startValue := ipv4ToUint32(start)
	endValue := ipv4ToUint32(end)
	if endValue < startValue {
		return 1
	}
	count := uint64(endValue) - uint64(startValue) + 1
	if count > uint64(scanpolicy.MaximumGoPocTargets) {
		return scanpolicy.MaximumGoPocTargets
	}
	return int(count)
}

func ipv4ToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

type invalidTarget struct {
	Target string `json:"target"`
	Reason string `json:"reason"`
}

func classifyTargets(targets []string, mode taskTargetMode) (valid []string, invalid []invalidTarget, summary taskTargetSummary) {
	summary = taskTargetSummary{Mode: string(mode), Total: len(targets)}
	for _, target := range targets {
		switch detectDirectTargetType(target) {
		case "ip":
			summary.IPs++
		case "ip_port":
			summary.IPPorts++
		case "cidr":
			summary.CIDRs++
		case "ip_range":
			summary.IPRanges++
		case "domain":
			summary.Domains++
		case "domain_port":
			summary.DomainPorts++
		case "url":
			summary.URLs++
		default:
			invalid = append(invalid, invalidTarget{Target: target, Reason: "无法识别的目标格式"})
			continue
		}
		valid = append(valid, target)
	}
	return valid, invalid, summary
}

func detectDirectTargetType(input string) string {
	switch {
	case isIPv6(input):
		return ""
	case isIPv4(input):
		return "ip"
	case isIPRange(input):
		return "ip_range"
	case isCIDR(input):
		return "cidr"
	case isIPPort(input):
		return "ip_port"
	case isDomainPort(input):
		return "domain_port"
	case isDomain(input):
		return "domain"
	case isURL(input):
		return "url"
	default:
		return ""
	}
}

func isIPv4(str string) bool {
	for i := 0; i < len(str); i++ {
		if str[i] == '.' {
			return net.ParseIP(str) != nil
		}
	}
	return false
}

func isIPv6(str string) bool {
	for i := 0; i < len(str); i++ {
		if str[i] == ':' {
			return net.ParseIP(str) != nil
		}
	}
	return false
}

func isCIDR(str string) bool {
	_, _, err := net.ParseCIDR(str)
	return err == nil
}

func isIPPort(str string) bool {
	if !strings.Contains(str, ":") {
		return false
	}
	parts := strings.Split(str, ":")
	if len(parts) != 2 {
		return false
	}
	return isIPv4(parts[0]) && isPort(parts[1])
}

func isPort(str string) bool {
	port, err := strconv.Atoi(str)
	return err == nil && port > 0 && port < 65536
}

var (
	domainRootString = `[a-z]{2,5}`
	domainRegx       = regexp.MustCompile(`^([a-zA-Z0-9][-a-zA-Z0-9]{0,62}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})*\.(?:` + domainRootString + `))$`)
	urlDomainRegx    = regexp.MustCompile(`^([a-zA-Z0-9][-_a-zA-Z0-9]{0,62}(?:\.[a-zA-Z0-9][-_a-zA-Z0-9]{0,62})*\.(?:` + domainRootString + `))$`)
)

func stringContainsCTLByte(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < ' ' || b == 0x7f {
			return true
		}
	}
	return false
}

func isDomain(str string) bool {
	if stringContainsCTLByte(str) {
		return false
	}
	return domainRegx.MatchString(str)
}

func isDomainPort(str string) bool {
	parts := strings.Split(str, ":")
	if len(parts) != 2 {
		return false
	}
	return isDomain(parts[0]) && isPort(parts[1])
}

func isIPRange(str string) bool {
	parts := strings.Split(str, "-")
	return len(parts) == 2 && isIPv4(strings.TrimSpace(parts[0])) && isIPv4(strings.TrimSpace(parts[1]))
}

func isProtocol(str string) bool {
	ok, _ := regexp.MatchString("^[-a-z0-9A-Z]{1,20}$", str)
	return ok
}

func isNetloc(str string) bool {
	return isDomain(str) || isIPv4(str)
}

func isNetlocPort(str string) bool {
	parts := strings.Split(str, ":")
	if len(parts) != 2 {
		return false
	}
	return isNetloc(parts[0]) && isPort(parts[1])
}

func isHostPath(str string) bool {
	index := strings.Index(str, "/")
	if index == -1 {
		return false
	}
	host := str[:index]
	if strings.Contains(host, ":") {
		return isNetlocPort(host)
	}
	return isNetloc(host)
}

func isURLDomain(str string) bool {
	if stringContainsCTLByte(str) {
		return false
	}
	return urlDomainRegx.MatchString(str)
}

func isURLNetloc(str string) bool {
	if str == "" || strings.Contains(str, "@") {
		return false
	}
	if isNetloc(str) || isURLDomain(str) {
		return true
	}
	parts := strings.Split(str, ":")
	if len(parts) != 2 {
		return false
	}
	return (isIPv4(parts[0]) || isURLDomain(parts[0])) && isPort(parts[1])
}

func isURL(str string) bool {
	if stringContainsCTLByte(str) {
		return false
	}
	index := strings.Index(str, "://")
	if index == -1 {
		return false
	}
	protocol := str[:index]
	if !isProtocol(protocol) {
		return false
	}
	rest := str[index+3:]
	if slash := strings.Index(rest, "/"); slash >= 0 {
		rest = rest[:slash]
	}
	return isURLNetloc(rest)
}

// ============================================================================
// 批次聚合工具函数
//
// 激进档默认批大小：
//   - URL/Domain 类：32
//   - IP/CIDR/IPRange/IP:Port 类：64
//   - OSINT 查询：32
// ============================================================================

// targetBatchGroup 表示同一类型目标的一个批次
type targetBatchGroup struct {
	TargetType   string   // 目标类型标识 (ip, url, domain, osint, ...)
	SelectorJSON string   // 标签路由选择器 JSON
	Targets      []string // 该批次内的目标列表
}

// batchSizeForTargetType 按每类目标的扫描开销返回批大小（越重的类型批越小），
// 让每批在超时内跑完、避免因批过大超时后反复二分拆分重试。
func batchSizeForTargetType(targetType string) int {
	switch targetType {
	case "url":
		return 50 // http_probe + dir_brute + gopoc 爆破
	case "domain":
		return 50 // 子域枚举 + CDN + web，最重
	case "domain_port":
		return 200 // 指定 host:port，无子域枚举
	case "ip":
		return 50 // 端口扫描 + 协议识别 + gopoc 爆破，占用很大
	case "ip_port":
		return 200 // 直接协议识别 + web
	case "cidr", "ip_range":
		return 2 // 每条下游展开成几百个 IP（/24≈256），批要极小
	default:
		// osint, unknown 等：osint 为搜索查询数，每条又炸出大量主机
		return 100
	}
}

// selectorForTargetType 返回给定目标类型对应的节点选择器 JSON
func selectorForTargetType(targetType string) string {
	switch targetType {
	case "url":
		return `{"target_type": "url"}`
	case "ip", "cidr", "ip_range", "ip_port":
		return `{"target_type": "ip"}`
	case "domain", "domain_port":
		return `{"target_type": "domain"}`
	case "osint":
		return `{"target_type": "osint"}`
	default:
		return "{}"
	}
}

// groupAndBatchTargets 将目标按类型分组后切批，返回 targetBatchGroup 列表
// 对于 direct 模式：按 detectDirectTargetType 分组
// Task targets are always direct scan targets. Provider queries are Server-only.
func groupAndBatchTargets(targets []string, targetMode taskTargetMode) []targetBatchGroup {
	// Direct 模式：按目标类型分组
	grouped := make(map[string][]string) // targetType -> targets
	groupOrder := make([]string, 0)      // 保持稳定顺序
	for _, target := range targets {
		typ := detectDirectTargetType(target)
		if typ == "" {
			typ = "unknown"
		}
		if _, exists := grouped[typ]; !exists {
			groupOrder = append(groupOrder, typ)
		}
		grouped[typ] = append(grouped[typ], target)
	}

	var batches []targetBatchGroup
	for _, typ := range groupOrder {
		selectorJSON := selectorForTargetType(typ)
		batches = append(batches, batchTargetsOfType(grouped[typ], typ, selectorJSON)...)
	}
	return batches
}

// batchTargetsOfType 将同一类型的目标按批大小切分
func batchTargetsOfType(targets []string, targetType, selectorJSON string) []targetBatchGroup {
	batchSize := batchSizeForTargetType(targetType)
	chunks := chunkSlice(targets, batchSize)
	batches := make([]targetBatchGroup, 0, len(chunks))
	for _, chunk := range chunks {
		batches = append(batches, targetBatchGroup{
			TargetType:   targetType,
			SelectorJSON: selectorJSON,
			Targets:      chunk,
		})
	}
	return batches
}

// chunkSlice 将字符串切片按指定大小切分
func chunkSlice(items []string, size int) [][]string {
	if size <= 0 {
		size = 1
	}
	var chunks [][]string
	for i := 0; i < len(items); i += size {
		end := i + size
		if end > len(items) {
			end = len(items)
		}
		chunks = append(chunks, items[i:end])
	}
	return chunks
}

// dispatchFreeSlots sums max(0, Capacity-RunningTasks) over alive,
// selector-matching agents. It bounds how finely controller-push fan-out
// subdivides targets so the push uses the currently-free capacity instead of
// emitting a couple of oversized batches.
func dispatchFreeSlots(rules db.AgentSelectorRules) int {
	var nodes []db.Node
	if err := db.DB.Where("status = ?", "Alive").Find(&nodes).Error; err != nil {
		return 0
	}
	nowMilli := time.Now().UnixMilli()
	free := 0
	for i := range nodes {
		n := &nodes[i]
		if nowMilli-n.LastBeat >= dispatchLivenessWindowMillis {
			continue
		}
		matched, _ := db.NodeMatchesSelectorRules(nil, rules, n.Tags)
		if !matched {
			continue
		}
		if slot := n.Capacity - n.RunningTasks; slot > 0 {
			free += slot
		}
	}
	return free
}

// groupAndBatchTargetsForDispatch wraps the pure groupAndBatchTargets with
// controller-push fan-out: when the effective strategy is controller_push and
// free agent slots exist, each type's targets are re-chunked to roughly
// ceil(n/freeSlots) so the push fans out across alive agents. The legacy
// agent-claim path (or no free slots) returns the pure grouping unchanged.
// Coverage reuse keys on per-target WorkKey at claim time, so re-chunking
// never changes scan content identity.
func groupAndBatchTargetsForDispatch(targets []string, targetMode taskTargetMode, strategy scanpolicy.DispatchStrategy, freeSlots int) []targetBatchGroup {
	base := groupAndBatchTargets(targets, targetMode)
	if strategy != scanpolicy.DispatchStrategyControllerPush || freeSlots <= 0 {
		return base
	}
	countByType := make(map[string]int)
	for _, t := range targets {
		typ := detectDirectTargetType(t)
		if typ == "" {
			typ = "unknown"
		}
		countByType[typ]++
	}
	out := make([]targetBatchGroup, 0, len(base))
	for _, g := range base {
		size := batchSizeForTargetType(g.TargetType)
		if n := countByType[g.TargetType]; n > 0 {
			if chunk := (n + freeSlots - 1) / freeSlots; chunk < size {
				size = chunk
			}
		}
		if size < 1 {
			size = 1
		}
		for _, chunk := range chunkSlice(g.Targets, size) {
			out = append(out, targetBatchGroup{
				TargetType:   g.TargetType,
				SelectorJSON: g.SelectorJSON,
				Targets:      chunk,
			})
		}
	}
	return out
}

// batchProfile 描述一次聚合操作的批次概况
type batchProfile struct {
	TotalTargets  int            `json:"total_targets"`
	TotalBatches  int            `json:"total_batches"`
	BatchesByType map[string]int `json:"batches_by_type"` // targetType -> batch count
	BatchSize     map[string]int `json:"batch_size"`      // targetType -> configured batch size
}
