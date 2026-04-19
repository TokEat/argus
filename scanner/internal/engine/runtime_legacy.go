package engine

import (
	commoncfg "dddd/scanner/common"
	commonreport "dddd/scanner/common/report"
	"dddd/scanner/ddout"
	"dddd/scanner/internal/arsenal"
	"dddd/scanner/lib/ddfinger"
	"dddd/scanner/structs"
	"dddd/scanner/utils"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

var legacyBindingMu sync.Mutex

func ApplyConfigDefaults(cfg *Config) {
	if cfg.PortScanType == "" {
		cfg.PortScanType = "tcp"
	}
	if cfg.TCPPortScanThreads == 0 {
		if runtime.GOOS == "linux" {
			cfg.TCPPortScanThreads = 4000
		} else {
			cfg.TCPPortScanThreads = 1000
		}
	}
	if cfg.SYNPortScanThreads == 0 {
		cfg.SYNPortScanThreads = 10000
	}
	if cfg.PortsThreshold == 0 {
		cfg.PortsThreshold = 300
	}
	if cfg.TCPPortScanTimeout == 0 {
		cfg.TCPPortScanTimeout = 6
	}
	if cfg.MasscanPath == "" {
		cfg.MasscanPath = "masscan"
	}
	if cfg.GetBannerThreads == 0 {
		cfg.GetBannerThreads = 500
	}
	if cfg.GetBannerTimeout == 0 {
		cfg.GetBannerTimeout = 5
	}
	if cfg.SubdomainBruteForceThreads == 0 {
		cfg.SubdomainBruteForceThreads = 150
	}
	if cfg.HunterPageSize == 0 {
		cfg.HunterPageSize = 100
	}
	if cfg.HunterMaxPageCount == 0 {
		cfg.HunterMaxPageCount = 10
	}
	if cfg.FofaMaxCount == 0 {
		cfg.FofaMaxCount = 100
	}
	if cfg.QuakeSize == 0 {
		cfg.QuakeSize = 100
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
	if cfg.APIConfigFilePath == "" {
		cfg.APIConfigFilePath = "config/api-config.yaml"
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
	if cfg.SubdomainWordListFile == "" {
		cfg.SubdomainWordListFile = "config/subdomains.txt"
	}
	if cfg.Ports == "" {
		cfg.Ports = commoncfg.PortTOP100
	}
	if cfg.LowPerceptionMode {
		cfg.NoDirSearch = true
		if !cfg.Fofa && !cfg.Hunter {
			cfg.Hunter = true
		}
	}
	if !cfg.SkipHostDiscovery && !cfg.TCPPing && cfg.NoICMPPing {
		cfg.SkipHostDiscovery = true
	}
}

func (sc *ScanContext) loadKnowledgeBase() error {
	ApplyConfigDefaults(&sc.Config)
	sc.EmbedPocs = commoncfg.EmbedNucleiPocs

	if err := ensureAPIConfigFile(sc.Config); err != nil {
		return err
	}

	// 优先级 1: 尝试从本地 SQLite (data/arsenal.db) 加载
	if len(sc.FingerprintDB) == 0 && len(sc.WorkFlowDB) == 0 && len(sc.DirDB) == 0 {
		if loaded := sc.tryLoadFromArsenalDB(); loaded {
			return nil
		}
	}

	// 优先级 2: fallback 到内嵌 + 外部 YAML 文件
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

// tryLoadFromArsenalDB 尝试从本地 SQLite 弹药库加载知识库。
// 返回 true 表示成功加载，false 表示需要 fallback。
func (sc *ScanContext) tryLoadFromArsenalDB() bool {
	if err := arsenal.OpenDB(""); err != nil {
		return false
	}
	if !arsenal.IsDBReady() {
		return false
	}

	log.Println("[Arsenal] 从本地弹药库加载规则...")

	// --- 加载指纹 ---
	fingers, err := arsenal.GetAllEnabledFingerprints()
	if err != nil || len(fingers) == 0 {
		return false
	}
	fingerDB := make([]FingerPEntity, 0, len(fingers))
	for _, f := range fingers {
		rules := ddfinger.ParseRule(f.RuleExpr)
		engineRules := make([]RuleData, 0, len(rules))
		for _, r := range rules {
			engineRules = append(engineRules, RuleData(r))
		}
		fingerDB = append(fingerDB, FingerPEntity{
			ProductName: f.ProductName,
			AllString:   f.RuleExpr,
			Rule:        engineRules,
		})
	}
	sc.FingerprintDB = fingerDB

	// --- 加载 Workflow ---
	workflows, err := arsenal.GetAllEnabledWorkflows()
	if err != nil {
		return false
	}
	wfDB := make(map[string]WorkFlowEntity)
	for _, w := range workflows {
		existing := wfDB[w.ProductName]
		switch strings.ToLower(w.MatchType) {
		case "root":
			existing.RootType = true
		case "dir":
			existing.DirType = true
		case "base":
			existing.BaseType = true
		case "dir-fallback":
			existing.DirFallback = true
		}
		// 去重添加 POC 名称
		found := false
		for _, p := range existing.PocsName {
			if p == w.PocName {
				found = true
				break
			}
		}
		if !found {
			existing.PocsName = append(existing.PocsName, w.PocName)
		}
		wfDB[w.ProductName] = existing
	}
	sc.WorkFlowDB = wfDB

	// --- 加载 Dir ---
	probes, err := arsenal.GetAllEnabledDirProbes()
	if err != nil {
		return false
	}
	dirDB := make(map[string][]string)
	for _, p := range probes {
		dirDB[p.Path] = append(dirDB[p.Path], p.ProductName)
		dirDB[p.Path] = utils.RemoveDuplicateElement(dirDB[p.Path])
	}
	sc.DirDB = dirDB

	// --- 导出 POC 到临时目录（供 Nuclei 引擎使用）---
	pocDir, err := exportPocsToTempDir()
	if err == nil && pocDir != "" {
		sc.Config.NucleiTemplate = pocDir
	}

	log.Printf("[Arsenal] 已加载: 指纹 %d, Workflow %d, Dir %d",
		len(sc.FingerprintDB), len(sc.WorkFlowDB), len(sc.DirDB))
	return true
}

// exportPocsToTempDir 将数据库中的 POC 导出到临时目录。
func exportPocsToTempDir() (string, error) {
	pocs, err := arsenal.GetAllEnabledPocs()
	if err != nil || len(pocs) == 0 {
		return "", err
	}

	tmpDir, err := os.MkdirTemp("", "dddd-pocs-*")
	if err != nil {
		return "", fmt.Errorf("创建 POC 临时目录失败: %w", err)
	}

	for _, p := range pocs {
		if p.Content == "" || p.FileName == "" {
			continue
		}
		outPath := filepath.Join(tmpDir, p.FileName)
		_ = os.WriteFile(outPath, []byte(p.Content), 0o644)
	}
	return tmpDir, nil
}

func ensureAPIConfigFile(cfg Config) error {
	needsAPIConfig := cfg.Fofa || cfg.Hunter || cfg.Quake || (cfg.Subdomain && !cfg.NoSubFinder)
	if !needsAPIConfig || cfg.APIConfigFilePath == "" {
		return nil
	}
	if _, err := os.Stat(cfg.APIConfigFilePath); err == nil {
		return nil
	}

	dir := filepath.Dir(cfg.APIConfigFilePath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create api config dir: %w", err)
		}
	}

	if err := os.WriteFile(cfg.APIConfigFilePath, []byte(commoncfg.EmbedAPIConfigData), 0o666); err != nil {
		return fmt.Errorf("write default api config: %w", err)
	}
	return nil
}

func loadFingerDB(cfg Config) ([]FingerPEntity, error) {
	merged := make(map[string][]string)

	if err := mergeStringListYAML(merged, []byte(commoncfg.EmbedFingerData)); err != nil {
		return nil, fmt.Errorf("parse embedded finger db: %w", err)
	}

	if cfg.FingerConfigFilePath != "" {
		if data, err := os.ReadFile(cfg.FingerConfigFilePath); err == nil {
			if err := mergeStringListYAML(merged, data); err != nil {
				return nil, fmt.Errorf("parse finger db %s: %w", cfg.FingerConfigFilePath, err)
			}
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

	if err := mergeWorkflowYAML(result, []byte(commoncfg.EmbedWorkFlowData)); err != nil {
		return nil, fmt.Errorf("parse embedded workflow db: %w", err)
	}

	if cfg.WorkflowYamlPath != "" {
		if data, err := os.ReadFile(cfg.WorkflowYamlPath); err == nil {
			if err := mergeWorkflowYAML(result, data); err != nil {
				return nil, fmt.Errorf("parse workflow db %s: %w", cfg.WorkflowYamlPath, err)
			}
		}
	}

	return result, nil
}

func loadDirDB(cfg Config) (map[string][]string, error) {
	result := make(map[string][]string)

	if err := mergeDirYAML(result, []byte(commoncfg.EmbedDirDBData)); err != nil {
		return nil, fmt.Errorf("parse embedded dir db: %w", err)
	}

	if cfg.DirSearchYaml != "" {
		if data, err := os.ReadFile(cfg.DirSearchYaml); err == nil {
			if err := mergeDirYAML(result, data); err != nil {
				return nil, fmt.Errorf("parse dir db %s: %w", cfg.DirSearchYaml, err)
			}
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
	Type []string `yaml:"type"`
	Pocs []string `yaml:"pocs"`
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
		existing.PocsName = append(existing.PocsName, rule.Pocs...)
		existing.PocsName = utils.RemoveDuplicateElement(existing.PocsName)
		dst[productName] = existing
	}
	return nil
}

func bindLegacyContext(sc *ScanContext) (func(), error) {
	if sc == nil {
		return func() {}, nil
	}

	if err := sc.loadKnowledgeBase(); err != nil {
		return nil, err
	}

	legacyBindingMu.Lock()

	prevConfig := structs.GlobalConfig
	prevEmbedPocs := structs.GlobalEmbedPocs
	prevBannerHMap := structs.GlobalBannerHMap
	prevBodyHMap := structs.GlobalHttpBodyHMap
	prevHeaderHMap := structs.GlobalHttpHeaderHMap
	prevIPPortMap := structs.GlobalIPPortMap
	prevIPDomainMap := structs.GlobalIPDomainMap
	prevURLMap := structs.GlobalURLMap
	prevResultMap := structs.GlobalResultMap
	prevDirFallbackMap := structs.DirFallbackResultMap
	prevGoPocResults := structs.GoPocsResults
	prevFingerprintDB := structs.FingerprintDB
	prevWorkflowDB := structs.WorkFlowDB
	prevDirDB := structs.DirDB
	prevAddScanNum := structs.AddScanNum
	prevAddScanEnd := structs.AddScanEnd
	prevOutputType := ddout.OutputType
	prevOutputFileName := ddout.OutputFileName
	prevSink := ddout.SetOutputSink(func(msg ddout.OutputMessage) {
		if sc.OutputHook != nil {
			sc.OutputHook(toEngineOutputMessage(msg))
		}
	})

	structs.GlobalConfig = structs.Config(sc.Config)
	structs.GlobalEmbedPocs = sc.EmbedPocs
	structs.GlobalBannerHMap = sc.BannerHMap
	structs.GlobalHttpBodyHMap = sc.BodyHMap
	structs.GlobalHttpHeaderHMap = sc.HeaderHMap
	structs.GlobalIPPortMap = sc.IPPortMap
	structs.GlobalIPDomainMap = sc.IPDomainMap
	structs.GlobalURLMap = toStructURLMap(sc.URLMap)
	structs.GlobalResultMap = sc.ResultMap
	structs.DirFallbackResultMap = sc.DirFallbackResultMap
	structs.GoPocsResults = toStructGoPocResults(sc.GoPocsResults)
	structs.FingerprintDB = toStructFingerDB(sc.FingerprintDB)
	structs.WorkFlowDB = toStructWorkflowDB(sc.WorkFlowDB)
	structs.DirDB = cloneDirDB(sc.DirDB)
	structs.AddScanNum = sc.AddScanNum
	structs.AddScanEnd = sc.AddScanEnd
	ddout.OutputType = sc.Config.OutputType
	ddout.OutputFileName = sc.Config.OutputFile
	commonreport.ResetState()

	return func() {
		syncContextFromLegacy(sc)

		ddout.SetOutputSink(prevSink)
		ddout.OutputType = prevOutputType
		ddout.OutputFileName = prevOutputFileName
		structs.GlobalConfig = prevConfig
		structs.GlobalEmbedPocs = prevEmbedPocs
		structs.GlobalBannerHMap = prevBannerHMap
		structs.GlobalHttpBodyHMap = prevBodyHMap
		structs.GlobalHttpHeaderHMap = prevHeaderHMap
		structs.GlobalIPPortMap = prevIPPortMap
		structs.GlobalIPDomainMap = prevIPDomainMap
		structs.GlobalURLMap = prevURLMap
		structs.GlobalResultMap = prevResultMap
		structs.DirFallbackResultMap = prevDirFallbackMap
		structs.GoPocsResults = prevGoPocResults
		structs.FingerprintDB = prevFingerprintDB
		structs.WorkFlowDB = prevWorkflowDB
		structs.DirDB = prevDirDB
		structs.AddScanNum = prevAddScanNum
		structs.AddScanEnd = prevAddScanEnd
		commonreport.ResetState()
		legacyBindingMu.Unlock()
	}, nil
}

// bindAgentContext 轻量级上下文绑定，专用于 Agent 并发模式。
// 不会获取全局互斥锁，不会写入 structs.Global* 全局变量，
// 从而允许多个任务完全并行执行。
func bindAgentContext(sc *ScanContext) (func(), error) {
	if sc == nil {
		return func() {}, nil
	}

	if err := sc.loadKnowledgeBase(); err != nil {
		return nil, err
	}

	// 返回空的 cleanup，无锁无全局状态恢复
	return func() {}, nil
}

func syncLegacyConfigFromContext(sc *ScanContext) {
	if sc == nil {
		return
	}

	structs.GlobalConfig = structs.Config(sc.Config)
}

func syncContextFromLegacy(sc *ScanContext) {
	if sc == nil {
		return
	}

	sc.Config = Config(structs.GlobalConfig)
	sc.IPPortMap = structs.GlobalIPPortMap
	sc.IPDomainMap = structs.GlobalIPDomainMap
	sc.URLMap = toEngineURLMap(structs.GlobalURLMap)
	sc.ResultMap = structs.GlobalResultMap
	sc.DirFallbackResultMap = structs.DirFallbackResultMap
	sc.GoPocsResults = toEngineGoPocResults(structs.GoPocsResults)
	sc.AddScanNum = structs.AddScanNum
	sc.AddScanEnd = structs.AddScanEnd
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
		dst = append(dst, structs.GoPocsResultType(result))
	}
	return dst
}

func toEngineGoPocResults(src []structs.GoPocsResultType) []GoPocsResultType {
	if src == nil {
		return nil
	}
	dst := make([]GoPocsResultType, 0, len(src))
	for _, result := range src {
		dst = append(dst, GoPocsResultType(result))
	}
	return dst
}

func toEngineOutputMessage(msg ddout.OutputMessage) OutputMessage {
	return OutputMessage{
		Type:     msg.Type,
		IP:       msg.IP,
		IPs:      append([]string(nil), msg.IPs...),
		Port:     msg.Port,
		Protocol: msg.Protocol,
		Web: WebInfo{
			Status: msg.Web.Status,
			Title:  msg.Web.Title,
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
		},
		URI:           msg.URI,
		City:          msg.City,
		AdditionalMsg: msg.AdditionalMsg,
		Show:          msg.Show,
		Nuclei:        msg.Nuclei,
	}
}
