package engine

import (
	"embed"
	"fmt"
	commoncfg "github.com/TokEat/argus/scanner/common"
	"github.com/TokEat/argus/scanner/ddout"
	"github.com/TokEat/argus/scanner/lib/ddfinger"
	"github.com/TokEat/argus/scanner/structs"
	"github.com/TokEat/argus/scanner/utils"
	"github.com/TokEat/argus/shared/proto/go/scanpolicy"
	"os"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

func ApplyConfigDefaults(cfg *Config) {
	if cfg.PortScanType == "" {
		cfg.PortScanType = "tcp"
	}
	if cfg.TCPPortScanThreads == 0 {
		if runtime.GOOS == "linux" {
			cfg.TCPPortScanThreads = 4000
		} else {
			cfg.TCPPortScanThreads = 2000
		}
	}
	if cfg.SYNPortScanThreads == 0 {
		cfg.SYNPortScanThreads = 10000
	}
	if cfg.PortsThreshold == 0 {
		cfg.PortsThreshold = 300
	}
	if cfg.TCPPortScanTimeout == 0 {
		cfg.TCPPortScanTimeout = 3
	}
	if cfg.GetBannerThreads == 0 {
		cfg.GetBannerThreads = 500
	}
	if cfg.GetBannerTimeout == 0 {
		cfg.GetBannerTimeout = 3
	}
	if cfg.SubdomainBruteForceThreads == 0 {
		cfg.SubdomainBruteForceThreads = 150
	}
	if cfg.SubdomainBruteforceDepth == 0 {
		cfg.SubdomainBruteforceDepth = 1
	}
	if cfg.GoPocThreads == 0 {
		cfg.GoPocThreads = 50
	}
	if cfg.WebThreads == 0 {
		cfg.WebThreads = 200
	}
	if cfg.WebTimeout == 0 {
		cfg.WebTimeout = 10
	}
	if cfg.HTTPProxyTestURL == "" {
		cfg.HTTPProxyTestURL = "https://www.baidu.com"
	}
	if cfg.OutputType == "" {
		cfg.OutputType = "text"
	}
	if cfg.NucleiTemplate == "" {
		cfg.NucleiTemplate = "config/pocs"
	}
	if cfg.WorkflowYamlPath == "" {
		cfg.WorkflowYamlPath = "config/workflow.yaml"
	}
	if cfg.FingerConfigFilePath == "" {
		cfg.FingerConfigFilePath = "config/finger.yaml"
	}
	if cfg.DirSearchYaml == "" {
		cfg.DirSearchYaml = "config/dir.yaml"
	}
	if cfg.ActiveFingerprintTemplate == "" {
		cfg.ActiveFingerprintTemplate = "config/active-fingerprints"
	}
	if cfg.SubdomainWordListFile == "" {
		cfg.SubdomainWordListFile = "config/subdomains.txt"
	}
	if cfg.Ports == "" {
		cfg.Ports = commoncfg.PortCommon100
	}
	if !cfg.SkipHostDiscovery && !cfg.TCPPing && cfg.NoICMPPing && !cfg.UDPPing {
		cfg.TCPPing = true
	}
	if cfg.WebCrawl {
		if cfg.WebCrawlMaxDepth < 1 {
			cfg.WebCrawlMaxDepth = scanpolicy.DefaultWebCrawlMaxDepth
		}
		if cfg.WebCrawlMaxPages < 1 {
			cfg.WebCrawlMaxPages = scanpolicy.DefaultWebCrawlMaxPages
		}
	}
}

func (sc *ScanContext) loadKnowledgeBase() error {
	ApplyConfigDefaults(&sc.Config)
	if sc.Config.RuleFilesOnly {
		sc.EmbedPocs = embed.FS{}
		sc.EmbedActiveFingerprints = embed.FS{}
	} else {
		sc.EmbedPocs = commoncfg.EmbedNucleiPocs
		sc.EmbedActiveFingerprints = commoncfg.EmbedActiveFingerprints
	}

	if err := ValidateLegacyProviderConfig(sc.Config); err != nil {
		return err
	}
	useKnowledgeCache, err := knowledgeIdentityEnabled(sc.Config)
	if err != nil {
		return err
	}
	if useKnowledgeCache {
		snapshot, err := sc.cachedKnowledgeSnapshot()
		if err != nil {
			return err
		}
		sc.knowledge = snapshot
		return nil
	}

	if len(sc.FingerprintDB) == 0 {
		fingerDB, err := loadFingerDB(sc.Config)
		if err != nil {
			return err
		}
		sc.FingerprintDB = fingerDB
	}

	if len(sc.WorkFlowDB) == 0 {
		workflowDB, err := loadWorkflowDB(sc.Config)
		if err != nil {
			return err
		}
		sc.WorkFlowDB = workflowDB
	}

	if len(sc.DirDB) == 0 {
		dirDB, err := loadDirDB(sc.Config)
		if err != nil {
			return err
		}
		sc.DirDB = dirDB
	}

	return nil
}

// ValidateLegacyProviderConfig rejects compatibility-only Provider fields before
// any response store, rule, or network initialization. The fields remain in
// Config solely so old task JSON can be decoded and failed closed.
func ValidateLegacyProviderConfig(cfg Config) error {
	if cfg.Hunter || cfg.Fofa || cfg.Quake || cfg.LowPerceptionMode || cfg.OnlyIPPort || strings.TrimSpace(cfg.APIConfigFilePath) != "" {
		return fmt.Errorf("legacy Provider search configuration is no longer supported; use Argus Server asset discovery")
	}
	return nil
}

func loadFingerDB(cfg Config) ([]FingerPEntity, error) {
	merged := make(map[string][]string)

	if !cfg.RuleFilesOnly {
		if err := mergeStringListYAML(merged, []byte(commoncfg.EmbedFingerData)); err != nil {
			return nil, fmt.Errorf("parse embedded finger db: %w", err)
		}
	}
	if cfg.FingerConfigFilePath != "" {
		if data, err := os.ReadFile(cfg.FingerConfigFilePath); err == nil {
			if err := mergeStringListYAML(merged, data); err != nil {
				return nil, fmt.Errorf("parse finger db %s: %w", cfg.FingerConfigFilePath, err)
			}
		} else if cfg.RuleFilesOnly {
			return nil, fmt.Errorf("read finger db %s: %w", cfg.FingerConfigFilePath, err)
		}
	}

	result := make([]FingerPEntity, 0)
	for productName, rules := range merged {
		for _, rule := range utils.RemoveDuplicateElement(rules) {
			parsed := ddfinger.ParseRule(rule)
			engineRules := make([]RuleData, 0, len(parsed))
			for _, each := range parsed {
				engineRules = append(engineRules, RuleData(each))
			}
			result = append(result, FingerPEntity{
				ProductName: productName,
				AllString:   rule,
				Rule:        engineRules,
			})
		}
	}
	return result, nil
}

func loadWorkflowDB(cfg Config) (map[string]WorkFlowEntity, error) {
	result := make(map[string]WorkFlowEntity)

	if !cfg.RuleFilesOnly {
		if err := mergeWorkflowYAML(result, []byte(commoncfg.EmbedWorkFlowData)); err != nil {
			return nil, fmt.Errorf("parse embedded workflow db: %w", err)
		}
	}
	if cfg.WorkflowYamlPath != "" {
		if data, err := os.ReadFile(cfg.WorkflowYamlPath); err == nil {
			if err := mergeWorkflowYAML(result, data); err != nil {
				return nil, fmt.Errorf("parse workflow db %s: %w", cfg.WorkflowYamlPath, err)
			}
		} else if cfg.RuleFilesOnly {
			return nil, fmt.Errorf("read workflow db %s: %w", cfg.WorkflowYamlPath, err)
		}
	}

	return result, nil
}

func loadDirDB(cfg Config) (map[string][]string, error) {
	result := make(map[string][]string)

	if !cfg.RuleFilesOnly {
		if err := mergeDirYAML(result, []byte(commoncfg.EmbedDirDBData)); err != nil {
			return nil, fmt.Errorf("parse embedded dir db: %w", err)
		}
	}
	if cfg.DirSearchYaml != "" {
		if data, err := os.ReadFile(cfg.DirSearchYaml); err == nil {
			if err := mergeDirYAML(result, data); err != nil {
				return nil, fmt.Errorf("parse dir db %s: %w", cfg.DirSearchYaml, err)
			}
		} else if cfg.RuleFilesOnly {
			return nil, fmt.Errorf("read dir db %s: %w", cfg.DirSearchYaml, err)
		}
	}

	return result, nil
}

func mergeStringListYAML(dst map[string][]string, data []byte) error {
	var raw map[string][]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return err
	}

	for productName, rules := range raw {
		dst[productName] = append(dst[productName], rules...)
		dst[productName] = utils.RemoveDuplicateElement(dst[productName])
	}
	return nil
}

func mergeDirYAML(dst map[string][]string, data []byte) error {
	var raw map[string][]string
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return err
	}

	for productName, paths := range raw {
		for _, p := range paths {
			dst[p] = append(dst[p], productName)
			dst[p] = utils.RemoveDuplicateElement(dst[p])
		}
	}
	return nil
}

type workflowRule struct {
	Type      []string `yaml:"type"`
	Pocs      []string `yaml:"pocs"`
	RiskLevel string   `yaml:"risk_level"`
}

func mergeWorkflowYAML(dst map[string]WorkFlowEntity, data []byte) error {
	var raw map[string]workflowRule
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return err
	}

	for productName, rule := range raw {
		existing := dst[productName]
		for _, entry := range rule.Type {
			switch strings.ToLower(entry) {
			case "root":
				existing.RootType = true
			case "dir":
				existing.DirType = true
			case "base":
				existing.BaseType = true
			case "dir-fallback":
				existing.DirFallback = true
			}
		}
		if arsenalPocRiskRank(rule.RiskLevel) > arsenalPocRiskRank(existing.RiskLevel) {
			existing.RiskLevel = strings.ToLower(strings.TrimSpace(rule.RiskLevel))
		}
		existing.PocsName = append(existing.PocsName, rule.Pocs...)
		existing.PocsName = utils.RemoveDuplicateElement(existing.PocsName)
		dst[productName] = existing
	}
	return nil
}

// arsenalPocRiskRank 将风险等级映射为严重度序（合并多来源 workflow 时取最严格）。
func arsenalPocRiskRank(riskLevel string) int {
	switch strings.ToLower(strings.TrimSpace(riskLevel)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low", "info":
		return 1
	default:
		return 0
	}
}

// pocRequiresSecondConfirmation 与服务端 db.PocRequiresSecondConfirmation 语义一致：
// 风险等级未知或 high 的模板在未预授权时不得进入无人值守执行；info/low/medium 不要求二次确认。
func pocRequiresSecondConfirmation(riskLevel string) bool {
	normalized := strings.ToLower(strings.TrimSpace(riskLevel))
	switch normalized {
	case "info", "low", "medium":
		return false
	default:
		return true
	}
}

// bindAgentContext 无锁上下文绑定。
// 仅加载知识库，不写全局变量，不获取互斥锁，
// 从而允许多个任务完全并行执行。
func bindAgentContext(sc *ScanContext) (func(), error) {
	if sc == nil {
		return func() {}, nil
	}

	if err := sc.loadKnowledgeBase(); err != nil {
		return nil, err
	}

	return func() {}, nil
}

func cloneDirDB(src map[string][]string) map[string][]string {
	if src == nil {
		return nil
	}
	dst := make(map[string][]string, len(src))
	for path, products := range src {
		dst[path] = append([]string(nil), products...)
	}
	return dst
}

func toStructFingerDB(src []FingerPEntity) []structs.FingerPEntity {
	if src == nil {
		return nil
	}
	dst := make([]structs.FingerPEntity, 0, len(src))
	for _, finger := range src {
		rules := make([]structs.RuleData, 0, len(finger.Rule))
		for _, rule := range finger.Rule {
			rules = append(rules, structs.RuleData(rule))
		}
		dst = append(dst, structs.FingerPEntity{
			ProductName:      finger.ProductName,
			AllString:        finger.AllString,
			Rule:             rules,
			IsExposureDetect: finger.IsExposureDetect,
		})
	}
	return dst
}

func toStructWorkflowDB(src map[string]WorkFlowEntity) map[string]structs.WorkFlowEntity {
	if src == nil {
		return nil
	}
	dst := make(map[string]structs.WorkFlowEntity, len(src))
	for key, workflow := range src {
		dst[key] = structs.WorkFlowEntity{
			RootType:    workflow.RootType,
			DirType:     workflow.DirType,
			BaseType:    workflow.BaseType,
			DirFallback: workflow.DirFallback,
			PocsName:    append([]string(nil), workflow.PocsName...),
		}
	}
	return dst
}

func toEngineFingerDB(src []structs.FingerPEntity) []FingerPEntity {
	if src == nil {
		return nil
	}
	dst := make([]FingerPEntity, 0, len(src))
	for _, finger := range src {
		rules := make([]RuleData, 0, len(finger.Rule))
		for _, rule := range finger.Rule {
			rules = append(rules, RuleData(rule))
		}
		dst = append(dst, FingerPEntity{
			ProductName:      finger.ProductName,
			AllString:        finger.AllString,
			Rule:             rules,
			IsExposureDetect: finger.IsExposureDetect,
		})
	}
	return dst
}

func toEngineWorkflowDB(src map[string]structs.WorkFlowEntity) map[string]WorkFlowEntity {
	if src == nil {
		return nil
	}
	dst := make(map[string]WorkFlowEntity, len(src))
	for key, workflow := range src {
		dst[key] = WorkFlowEntity{
			RootType:    workflow.RootType,
			DirType:     workflow.DirType,
			BaseType:    workflow.BaseType,
			DirFallback: workflow.DirFallback,
			PocsName:    append([]string(nil), workflow.PocsName...),
		}
	}
	return dst
}

func toStructURLMap(src map[string]URLEntity) map[string]structs.URLEntity {
	if src == nil {
		return nil
	}
	dst := make(map[string]structs.URLEntity, len(src))
	for rootURL, entity := range src {
		webPaths := make(map[string]structs.UrlPathEntity, len(entity.WebPaths))
		for path, pathEntity := range entity.WebPaths {
			webPaths[path] = structs.UrlPathEntity(pathEntity)
		}
		dst[rootURL] = structs.URLEntity{
			IP:       entity.IP,
			Port:     entity.Port,
			WebPaths: webPaths,
			Cert:     entity.Cert,
		}
	}
	return dst
}

func toEngineURLMap(src map[string]structs.URLEntity) map[string]URLEntity {
	if src == nil {
		return nil
	}
	dst := make(map[string]URLEntity, len(src))
	for rootURL, entity := range src {
		webPaths := make(map[string]UrlPathEntity, len(entity.WebPaths))
		for path, pathEntity := range entity.WebPaths {
			webPaths[path] = UrlPathEntity(pathEntity)
		}
		dst[rootURL] = URLEntity{
			IP:       entity.IP,
			Port:     entity.Port,
			WebPaths: webPaths,
			Cert:     entity.Cert,
		}
	}
	return dst
}

func toStructGoPocResults(src []GoPocsResultType) []structs.GoPocsResultType {
	if src == nil {
		return nil
	}
	dst := make([]structs.GoPocsResultType, 0, len(src))
	for _, result := range src {
		cloned := structs.GoPocsResultType(result)
		cloned.Exchanges = append([]structs.GoPocExchange(nil), result.Exchanges...)
		dst = append(dst, cloned)
	}
	return dst
}

func toEngineGoPocResults(src []structs.GoPocsResultType) []GoPocsResultType {
	if src == nil {
		return nil
	}
	dst := make([]GoPocsResultType, 0, len(src))
	for _, result := range src {
		cloned := GoPocsResultType(result)
		cloned.Exchanges = append([]structs.GoPocExchange(nil), result.Exchanges...)
		dst = append(dst, cloned)
	}
	return dst
}

func toEngineOutputMessage(msg ddout.OutputMessage) OutputMessage {
	return OutputMessage{
		Type:      msg.Type,
		IP:        msg.IP,
		IPs:       append([]string(nil), msg.IPs...),
		Port:      msg.Port,
		Protocol:  msg.Protocol,
		Product:   msg.Product,
		Version:   msg.Version,
		Transport: msg.Transport,
		Web: WebInfo{
			Status:   msg.Web.Status,
			Title:    msg.Web.Title,
			Cert:     msg.Web.Cert,
			Size:     msg.Web.Size,
			Redirect: msg.Web.Redirect,
		},
		Finger: append([]string(nil), msg.Finger...),
		Domain: msg.Domain,
		GoPoc: GoPocsResultType{
			PocName:     msg.GoPoc.PocName,
			Security:    msg.GoPoc.Security,
			Description: msg.GoPoc.Description,
			Target:      msg.GoPoc.Target,
			InfoLeft:    msg.GoPoc.InfoLeft,
			InfoRight:   msg.GoPoc.InfoRight,
			ShowMsg:     msg.GoPoc.ShowMsg,
			Exchanges:   append([]structs.GoPocExchange(nil), msg.GoPoc.Exchanges...),
		},
		URI:           msg.URI,
		City:          msg.City,
		AdditionalMsg: msg.AdditionalMsg,
		Show:          msg.Show,
		Nuclei:        msg.Nuclei,
		Source:        msg.Source,
		CrawlSite:     msg.CrawlSite,
		SensitiveInfo: msg.SensitiveInfo,
	}
}
