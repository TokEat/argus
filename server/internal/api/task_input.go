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
)

type taskTargetMode string

const (
	taskTargetModeDirect     taskTargetMode = "direct"
	taskTargetModeHunter     taskTargetMode = "hunter"
	taskTargetModeFofa       taskTargetMode = "fofa"
	taskTargetModeHunterFofa taskTargetMode = "hunter_fofa"
	taskTargetModeQuake      taskTargetMode = "quake"
)

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
	Ports                      string
	NoSubdomainBruteForce      bool
	NoSubFinder                bool
	Subdomain                  bool
	SubdomainBruteForceThreads int
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
	WebThreads                 int
	WebTimeout                 int
	PocNameForSearch           string
	NoPoc                      bool
	LowPerceptionMode          bool
	Quake                      bool
	QuakeSize                  int
	NoICMPPing                 bool
	TCPPing                    bool
	NoInteractsh               bool
	OnlyIPPort                 bool
	OutputFile                 string
	OutputType                 string
	APIConfigFilePath          string
	FingerConfigFilePath       string
	PasswordFile               string
	Password                   string
}

func defaultTaskScanConfig() taskScanConfig {
	return taskScanConfig{
		Ports:                      "21,22,23,25,53,69,80,81,88,110,111,135,137,139,143,161,179,389,443,445,465,500,514,548,554,587,636,873,993,995,1025,1080,1099,1194,1433,1521,1723,1900,2049,2082,2083,2121,2181,2222,2375,2379,2601,3000,3128,3306,3389,3690,4443,4848,5000,5236,5432,5555,5601,5632,5800,5900,5901,5984,5985,6000,6379,7001,7002,7080,8000,8001,8008,8009,8080,8081,8088,8089,8090,8161,8443,8848,8888,9000,9001,9043,9090,9091,9200,9300,9418,10000,11211,27017,27018,50000,50070,54321",
		PortScanType:               "tcp",
		TCPPortScanThreads:         1000,
		SYNPortScanThreads:         10000,
		PortsThreshold:             300,
		TCPPortScanTimeout:         6,
		MasscanPath:                "masscan",
		GetBannerThreads:           500,
		GetBannerTimeout:           5,
		SubdomainBruteForceThreads: 150,
		WebThreads:                 200,
		WebTimeout:                 10,
		HTTPProxyTest:              true,
		HTTPProxyTestURL:           "https://www.baidu.com",
		HunterPageSize:             100,
		HunterMaxPageCount:         10,
		FofaMaxCount:               100,
		QuakeSize:                  100,
		NoSubdomainBruteForce:      true,
		NoSubFinder:                true,
		NoHostBind:                 true,
		GoPocThreads:               50,
		GolangPoc:                  true,
		WAFBypassHeaders:           true,
		WAFSkipOnManyFingerprints:  true,
		NoInteractsh:               true,
		OutputFile:                 "result.txt",
		OutputType:                 "text",
		APIConfigFilePath:          "config/api-config.yaml",
		NucleiTemplate:             "config/pocs",
		WorkflowYamlPath:           "config/workflow.yaml",
		FingerConfigFilePath:       "config/finger.yaml",
		DirSearchYaml:              "config/dir.yaml",
		SubdomainWordListFile:      "config/subdomains.txt",
	}
}

func normalizeTaskConfigPayload(raw json.RawMessage) (string, taskTargetMode, error) {
	body, err := normalizeJSONObjectPayload(raw)
	if err != nil {
		return "", taskTargetModeDirect, err
	}

	cfg := defaultTaskScanConfig()
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return "", taskTargetModeDirect, fmt.Errorf("config contains unsupported field or invalid value: %w", err)
	}

	if err := validateTaskScanConfig(&cfg); err != nil {
		return "", taskTargetModeDirect, err
	}

	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return "", taskTargetModeDirect, err
	}

	return string(configJSON), detectTargetModeFromConfig(cfg), nil
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
	switch strings.ToLower(strings.TrimSpace(cfg.PortScanType)) {
	case "", "tcp", "syn":
	default:
		return fmt.Errorf("PortScanType must be tcp or syn")
	}

	if cfg.Quake && (cfg.Hunter || cfg.Fofa) {
		return fmt.Errorf("Quake cannot be combined with Hunter or Fofa")
	}

	if cfg.LowPerceptionMode {
		if cfg.Fofa {
			return fmt.Errorf("LowPerceptionMode only supports Hunter")
		}
		if !cfg.Hunter && !cfg.Fofa {
			cfg.Hunter = true
		}
		cfg.NoDirSearch = true
	}

	if !cfg.SkipHostDiscovery && cfg.NoICMPPing && !cfg.TCPPing {
		cfg.SkipHostDiscovery = true
	}

	if cfg.ReportName != "" {
		suffix := strings.ToLower(path.Ext(cfg.ReportName))
		if suffix != ".html" && suffix != ".htm" {
			return fmt.Errorf("ReportName must end with .html or .htm")
		}
	}

	if !strings.HasSuffix(strings.ToLower(cfg.APIConfigFilePath), ".yaml") {
		return fmt.Errorf("APIConfigFilePath must end with .yaml")
	}

	return nil
}

func parseAndValidateTargetsForMode(raw json.RawMessage, mode taskTargetMode) ([]string, taskTargetSummary, error) {
	targets, err := parseTargets(raw)
	if err != nil {
		return nil, taskTargetSummary{}, err
	}
	return validateTargetsByMode(targets, mode)
}

func detectTargetModeFromStoredConfig(configJSON string) taskTargetMode {
	if strings.TrimSpace(configJSON) == "" {
		return taskTargetModeDirect
	}

	cfg := defaultTaskScanConfig()
	_ = json.Unmarshal([]byte(configJSON), &cfg)
	return detectTargetModeFromConfig(cfg)
}

func detectTargetModeFromConfig(cfg taskScanConfig) taskTargetMode {
	switch {
	case cfg.Quake:
		return taskTargetModeQuake
	case cfg.Hunter && cfg.Fofa:
		return taskTargetModeHunterFofa
	case cfg.Hunter:
		return taskTargetModeHunter
	case cfg.Fofa:
		return taskTargetModeFofa
	default:
		return taskTargetModeDirect
	}
}

func validateTargetsByMode(targets []string, mode taskTargetMode) ([]string, taskTargetSummary, error) {
	summary := taskTargetSummary{
		Mode:  string(mode),
		Total: len(targets),
	}

	for _, target := range targets {
		switch mode {
		case taskTargetModeHunter, taskTargetModeFofa, taskTargetModeHunterFofa:
			if !strings.Contains(target, "=") {
				return nil, taskTargetSummary{}, fmt.Errorf("invalid search query %q: hunter/fofa mode requires field=value syntax", target)
			}
			summary.SearchInputs++
		case taskTargetModeQuake:
			if !strings.Contains(target, ":") {
				return nil, taskTargetSummary{}, fmt.Errorf("invalid Quake query %q: quake mode requires field:value syntax", target)
			}
			summary.SearchInputs++
		default:
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
				return nil, taskTargetSummary{}, fmt.Errorf("unsupported target %q", target)
			}
		}
	}

	return targets, summary, nil
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

// batchSizeForTargetType 返回给定目标类型的激进档批大小
func batchSizeForTargetType(targetType string) int {
	switch targetType {
	case "url":
		return 200
	case "domain", "domain_port":
		return 500
	case "ip", "cidr", "ip_range", "ip_port":
		return 1000
	default:
		// osint, unknown 等
		return 200
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
// 对于 OSINT 模式：统一归为 osint 类型
func groupAndBatchTargets(targets []string, targetMode taskTargetMode) []targetBatchGroup {
	if targetMode != taskTargetModeDirect {
		// OSINT 模式：所有目标统一类型
		return batchTargetsOfType(targets, "osint", selectorForTargetType("osint"))
	}

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

// batchProfile 描述一次聚合操作的批次概况
type batchProfile struct {
	TotalTargets  int            `json:"total_targets"`
	TotalBatches  int            `json:"total_batches"`
	BatchesByType map[string]int `json:"batches_by_type"` // targetType -> batch count
	BatchSize     map[string]int `json:"batch_size"`      // targetType -> configured batch size
}
