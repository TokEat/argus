// Package engine 扫描引擎内核。
//
// Pipeline 是扫描流水线的编排器，从 CLI 入口的 workflow 逻辑提取而来。
// Phase 0.4: import 路径从 common/ 切换到 internal/scanner/
package engine

import (
	"context"
	"dddd/scanner/ddout"
	"dddd/scanner/internal/finger"
	"dddd/scanner/internal/output"
	"dddd/scanner/internal/scanner/cdn"
	"dddd/scanner/internal/scanner/discovery"
	"dddd/scanner/internal/scanner/portscan"
	"dddd/scanner/internal/scanner/protocol"
	"dddd/scanner/internal/scanner/subdomain"
	"dddd/scanner/internal/scanner/web"
	"dddd/scanner/internal/uncover"
	gopoc "dddd/scanner/internal/vuln/gopoc"
	"dddd/scanner/internal/vuln/mapper"
	"dddd/scanner/internal/vuln/nuclei"
	"dddd/scanner/structs"
	"dddd/scanner/utils"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Pipeline 扫描流水线编排器。
type Pipeline struct{}

// Run 执行完整的扫描流水线。
func (p *Pipeline) Run(ctx *ScanContext) error {
	var domains []string
	emit := func(msg structs.OutputMessage) {
		if ctx != nil && ctx.OutputHook != nil {
			ctx.OutputHook(toEngineOutputMessage(msg))
		} else {
			ddout.FormatOutput(msg)
		}
	}
	var urls []string
	var domainPort []string
	var ipPort []string
	var ips []string

	defer gologger.Info().Msg(aurora.BrightGreen("Done!").String())

	// Agent 模式优化：默认跳过 ICMP 存活探测，避免在无 root 权限
	// 的环境下 fallback 到极慢的逐个 ping 子进程模式。
	if ctx != nil && ctx.OutputHook != nil {
		if !ctx.Config.TCPPing {
			ctx.Config.SkipHostDiscovery = true
		}
	}

	// 无锁上下文绑定：仅加载知识库，不写全局变量，不获取互斥锁。
	cleanup, err := bindAgentContext(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	cfg := currentPipelineConfig(ctx)
	enableLocalReports := ctx == nil || ctx.OutputHook == nil

	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	emitPhase(ctx, PhaseSearchEngine, "start", "")
	if err := p.searchEngine(ctx, &cfg); err != nil {
		return err
	}
	emitPhase(ctx, PhaseSearchEngine, "end", "")
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	for _, input := range cfg.Targets {
		inputType := utils.GetInputType(input)
		if inputType == TypeDomain {
			domains = append(domains, input)
			continue
		} else if inputType == TypeDomainPort {
			domainPort = append(domainPort, input)
			continue
		} else if inputType == TypeCIDR {
			for _, ip := range utils.CIDRToIP(input) {
				ips = append(ips, ip.String())
			}
		} else if inputType == TypeIPRange {
			for _, ip := range utils.RangerToIP(input) {
				ips = append(ips, ip.String())
			}
		} else if inputType == TypeIP {
			ips = append(ips, input)
		} else if inputType == TypeIPPort {
			ipPort = append(ipPort, input)
		} else if inputType == TypeURL {
			urls = append(urls, input)
		}
	}

	// 子域名枚举
	if cfg.Subdomain && len(domains) > 0 {
		emitPhase(ctx, PhaseSubdomain, "start", fmt.Sprintf("%d domains", len(domains)))
		subdomains := subdomain.Enumerate(domains, currentSubdomainConfig(ctx, emit))
		for _, each := range subdomains {
			domains = append(domains, each)
		}
		emitPhase(ctx, PhaseSubdomain, "end", fmt.Sprintf("%d domains found", len(domains)))
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}
	domains = utils.RemoveDuplicateElement(domains)

	// CDN 检测
	var cdnDomains []string
	var tIPs []string
	if len(domains) > 0 {
		emitPhase(ctx, PhaseCDN, "start", fmt.Sprintf("%d domains", len(domains)))
		cdnDomains, _, tIPs = cdn.CheckCDNs(
			domains,
			cfg.SubdomainBruteForceThreads,
			ctx.IPDomainMap,
			&ctx.IPDomainMapLock,
			func(msg ddout.OutputMessage) {
				emit(msg)
			},
		)
		for _, each := range tIPs {
			if cfg.AllowLocalAreaDomain && utils.IsLocalIP(each) {
				continue
			}
			ips = append(ips, each)
		}
		emitPhase(ctx, PhaseCDN, "end", fmt.Sprintf("%d cdn, %d ips", len(cdnDomains), len(tIPs)))
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}
	ips = utils.RemoveDuplicateElement(ips)

	// 处理带CDN的域名
	if cfg.AllowCDNAssets {
		for _, cd := range cdnDomains {
			urls = append(urls, "http://"+cd)
			urls = append(urls, "https://"+cd)
		}
	}
	urls = utils.RemoveDuplicateElement(urls)

	// 端口扫描
	if len(ips) > 0 {
		if err := checkPipelineCancelled(ctx); err != nil {
			return err
		}
		if !cfg.SkipHostDiscovery {
			var ICMPAlive []string
			if !cfg.NoICMPPing {
				emitPhase(ctx, PhaseICMP, "start", fmt.Sprintf("%d ips", len(ips)))
				ICMPAlive = discovery.CheckLive(ips, false, emit)
				emitPhase(ctx, PhaseICMP, "end", fmt.Sprintf("%d alive", len(ICMPAlive)))
			}

			var TCPAlive []string
			if cfg.TCPPing {
				var uncheck []string
				for _, ip := range ips {
					index := utils.GetItemInArray(ICMPAlive, ip)
					if index == -1 {
						uncheck = append(uncheck, ip)
					}
				}
				emitPhase(ctx, PhaseTCPPing, "start", fmt.Sprintf("%d ips", len(uncheck)))
				gologger.Info().Msg("TCP存活探测")
				tcpAliveIPPort := portscan.ScanTCP(uncheck, "80,443,3389,445,22",
					cfg.TCPPortScanTimeout, cfg.TCPPortScanThreads, cfg.PortsThreshold, false, emit)
				for _, tIPPort := range tcpAliveIPPort {
					t := strings.Split(tIPPort, ":")
					TCPAlive = append(TCPAlive, t[0])
				}
				emitPhase(ctx, PhaseTCPPing, "end", fmt.Sprintf("%d alive", len(TCPAlive)))
			}

			ips = append(ips, ICMPAlive...)
			ips = append(ips, TCPAlive...)
			ips = utils.RemoveDuplicateElement(ips)
		}
		var tmpIPPort []string

		if cfg.PortScanType == "syn" {
			if !portscan.CheckMasscan(cfg.MasscanPath) {
				gologger.Error().Msg("降级TCP扫描")
				cfg.PortScanType = "tcp"
				setPipelineConfig(ctx, cfg)
			}
		}

		emitPhase(ctx, PhasePortScan, "start", fmt.Sprintf("%d ips, type=%s", len(ips), cfg.PortScanType))
		if cfg.PortScanType == "syn" {
			tmpIPPort = portscan.ScanSYN(ips, cfg.MasscanPath, cfg.SYNPortScanThreads, emit)
		} else {
			tmpIPPort = portscan.ScanTCP(ips, cfg.Ports, cfg.TCPPortScanTimeout, cfg.TCPPortScanThreads, cfg.PortsThreshold, true, emit)
		}

		tmpIPPort = portscan.RemoveFirewall(tmpIPPort, cfg.PortsThreshold)
		emitPhase(ctx, PhasePortScan, "end", fmt.Sprintf("%d open ports", len(tmpIPPort)))

		for _, each := range tmpIPPort {
			ipPort = append(ipPort, each)
		}
		ipPort = utils.RemoveDuplicateElement(ipPort)
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	// 协议识别
	getProtocalInput := ipPort
	for _, each := range domainPort {
		getProtocalInput = append(getProtocalInput, each)
	}
	if len(getProtocalInput) > 0 {
		emitPhase(ctx, PhaseProtocol, "start", fmt.Sprintf("%d targets", len(getProtocalInput)))
		currentProtocolRuntime(ctx, emit).Identify(getProtocalInput, cfg.GetBannerThreads, cfg.GetBannerTimeout)
		emitPhase(ctx, PhaseProtocol, "end", "")
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	cfg = currentPipelineConfig(ctx)

	// HTTP 探测
	for hostPort, service := range currentPipelineIPPortMap(ctx) {
		if service == "http" {
			urls = append(urls, "http://"+hostPort)
		} else if service == "https" {
			urls = append(urls, "https://"+hostPort)
		}
	}
	urls = utils.RemoveDuplicateElement(urls)

	emitPhase(ctx, PhaseHTTPProbe, "start", fmt.Sprintf("%d urls", len(urls)))
	httpx.CallHTTPx(urls, currentWebRuntime(ctx, emit).URLCallback,
		cfg.HTTPProxy,
		cfg.WebThreads,
		cfg.WebTimeout)
	emitPhase(ctx, PhaseHTTPProbe, "end", "")
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	// 域名绑定资产探测
	if !cfg.NoHostBind {
		emitPhase(ctx, PhaseHostBind, "start", "")
		currentWebRuntime(ctx, emit).HostBindCheck(cfg.HTTPProxy, cfg.WebThreads, cfg.WebTimeout)
		emitPhase(ctx, PhaseHostBind, "end", "")
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	var aliveURLs []string
	for rootURL := range currentPipelineURLMap(ctx) {
		aliveURLs = append(aliveURLs, rootURL)
	}

	// 模糊搜索 Poc
	if cfg.PocNameForSearch != "" {
		gologger.AuditTimeLogger("模糊搜索Poc: %v", cfg.PocNameForSearch)
		TargetAndPocsName := make(map[string][]string)
		for _, url := range aliveURLs {
			TargetAndPocsName[url] = []string{}
		}
		if enableLocalReports {
			output.InitReportName()
		}
		addResult, _ := buildNucleiResultHandler(ctx, enableLocalReports)
		nuclei.Call(TargetAndPocsName,
			cfg.HTTPProxy,
			addResult,
			cfg.PocNameForSearch,
			cfg.NoInteractsh,
			currentPipelineEmbedPocs(ctx), cfg.NucleiTemplate, strings.Split(cfg.ExcludeTags, ","),
			strings.Split(cfg.Severities, ","))
		if enableLocalReports {
			output.GenerateHTMLReportFooter()
			output.GenerateAssetReport(cfg.OutputFile)
		}
		if err := checkPipelineCancelled(ctx); err != nil {
			return err
		}
		return nil
	}

	// 目录爆破
	if !cfg.NoDirSearch {
		var checkURLs []string
		for path := range currentPipelineDirDB(ctx) {
			for _, u := range aliveURLs {
				Url := ""
				if u[len(u)-1:] == "/" && path[0:1] == "/" {
					Url = u[:len(u)-1] + path
				} else {
					Url = u + path
				}
				checkURLs = append(checkURLs, Url)
			}
		}
		checkURLs = utils.RemoveDuplicateElement(checkURLs)
		emitPhase(ctx, PhaseDirBrute, "start", fmt.Sprintf("%d urls", len(checkURLs)))
		gologger.Info().Msg("开始主动指纹探测")
		httpx.DirBrute(checkURLs,
			currentWebRuntime(ctx, emit).DirBruteCallback,
			cfg.HTTPProxy,
			cfg.WebThreads,
			cfg.WebTimeout)
		gologger.AuditTimeLogger("主动指纹探测结束")
		emitPhase(ctx, PhaseDirBrute, "end", "")
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	// 指纹识别
	emitPhase(ctx, PhaseFingerprint, "start", "")
	currentFingerRuntime(ctx, emit).Identify()
	emitPhase(ctx, PhaseFingerprint, "end", "")
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	// 合并 dir-fallback 指纹
	resultMap := currentPipelineResultMap(ctx)
	for target, fingers := range currentPipelineDirFallbackResultMap(ctx) {
		existing, ok := resultMap[target]
		if ok {
			for _, f := range fingers {
				if utils.GetItemInArray(existing, f) == -1 {
					existing = append(existing, f)
				}
			}
			resultMap[target] = existing
		} else {
			resultMap[target] = fingers
		}
	}
	setPipelineResultMap(ctx, resultMap)

	if cfg.NoPoc {
		gologger.Info().Msg("跳过漏洞探测")
		return nil
	}

	// 漏洞检测
	if enableLocalReports {
		output.InitReportName()
	}

	var nucleiResults []nucleiOutput.ResultEvent
	TargetAndPocsName, count := mapper.GetPocs(resultMap, currentPipelineWorkflowDB(ctx), cfg.DisableGeneralPoc)
	gologger.Info().Msgf("[Pipeline] Nuclei 映射结果: targets=%d pocs=%d template_path=%s", len(TargetAndPocsName), count, cfg.NucleiTemplate)
	for target, pocs := range TargetAndPocsName {
		gologger.Info().Msgf("[Pipeline]   %s → %v", target, pocs)
	}
	if count > 0 {
		emitPhase(ctx, PhaseNuclei, "start", fmt.Sprintf("%d pocs", count))
		addResult, collector := buildNucleiResultHandler(ctx, enableLocalReports)
		nucleiResults = nuclei.Call(TargetAndPocsName,
			cfg.HTTPProxy,
			addResult,
			"", cfg.NoInteractsh, currentPipelineEmbedPocs(ctx),
			cfg.NucleiTemplate, strings.Split(cfg.ExcludeTags, ","),
			strings.Split(cfg.Severities, ","))
		// 合并：nuclei.Call 返回的结果（CLI 模式） + 回调收集的结果（Agent 模式）
		if collected := collector.snapshot(); len(collected) > 0 {
			nucleiResults = append(nucleiResults, collected...)
		}
		emitPhase(ctx, PhaseNuclei, "end", "")
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	ipPortMap := currentPipelineIPPortMap(ctx)
	telnetTargets := 0
	for _, svc := range ipPortMap {
		if svc == "telnet" {
			telnetTargets++
		}
	}
	emitPhase(ctx, PhaseGoPoc, "start", fmt.Sprintf("telnet=%d, total_services=%d", telnetTargets, len(ipPortMap)))
	var goPocResults []structs.GoPocsResultType

	emitPhase(ctx, "gopoc_telnet_cve", "start", fmt.Sprintf("%d targets", telnetTargets))
	goPocResults = append(goPocResults, gopoc.TelnetCVEOnly(
		ipPortMap,
		cfg.GoPocThreads,
		cfg.Password,
		cfg.PasswordFile,
		emit,
	)...)
	emitPhase(ctx, "gopoc_telnet_cve", "end", fmt.Sprintf("%d results", len(goPocResults)))

	if cfg.GolangPoc {
		emitPhase(ctx, "gopoc_dispatch", "start", fmt.Sprintf("%d services", len(ipPortMap)))
		dispatchResults := gopoc.Dispatch(
			ipPortMap,
			cfg.GoPocThreads,
			cfg.Password,
			cfg.PasswordFile,
			nucleiResults,
			emit,
		)
		goPocResults = append(goPocResults, dispatchResults...)
		emitPhase(ctx, "gopoc_dispatch", "end", fmt.Sprintf("%d results", len(dispatchResults)))
	}
	emitPhase(ctx, PhaseGoPoc, "end", fmt.Sprintf("%d total results", len(goPocResults)))
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	if ctx != nil {
		ctx.GoPocsResults = toEngineGoPocResults(goPocResults)
	}

	if enableLocalReports {
		output.GenerateHTMLReportFooter()
		output.GenerateAssetReport(cfg.OutputFile)
	}

	return nil
}

// searchEngine 调用网络空间搜索引擎获取资产。
func (p *Pipeline) searchEngine(ctx *ScanContext, cfg *Config) error {
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	searchCfg := currentUncoverConfig(ctx)
	searchState, syncBack := newPipelineUncoverState(ctx)
	defer syncBack()

	if cfg.Hunter && !cfg.Fofa {
		cfg.Targets, _ = uncover.HunterSearch(cfg.Targets, searchCfg, searchState)
		setPipelineConfig(ctx, *cfg)
		return checkPipelineCancelled(ctx)
	}
	if cfg.Fofa && !cfg.Hunter {
		cfg.Targets = uncover.FOFASearch(cfg.Targets, searchCfg, searchState)
		setPipelineConfig(ctx, *cfg)
		return checkPipelineCancelled(ctx)
	}
	if cfg.Fofa && cfg.Hunter {
		targets, tIPs := uncover.HunterSearch(cfg.Targets, searchCfg, searchState)
		var querys []string
		for _, i := range tIPs {
			querys = append(querys, "ip=\""+i+"\"")
		}
		querys = utils.RemoveDuplicateElement(querys)
		cfg.Targets = uncover.FOFASearch(querys, searchCfg, searchState)
		cfg.Targets = append(cfg.Targets, targets...)
		cfg.Targets = utils.RemoveDuplicateElement(cfg.Targets)
		setPipelineConfig(ctx, *cfg)
		return checkPipelineCancelled(ctx)
	}
	if cfg.Quake {
		cfg.Targets = uncover.QuakeSearch(cfg.Targets, searchCfg, searchState)
		setPipelineConfig(ctx, *cfg)
	}
	return checkPipelineCancelled(ctx)
}

func checkPipelineCancelled(ctx *ScanContext) error {
	if ctx == nil || ctx.Ctx == nil {
		return nil
	}
	if err := ctx.Ctx.Err(); err != nil {
		if errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		return err
	}
	return nil
}

// emitPhase 安全地触发阶段进度回调。
func emitPhase(ctx *ScanContext, phase, status, message string) {
	if ctx == nil || ctx.PhaseHook == nil {
		return
	}
	ctx.PhaseHook(PhaseEvent{
		Phase:   phase,
		Status:  status,
		Message: message,
	})
}

func currentSubdomainConfig(ctx *ScanContext, emit func(structs.OutputMessage)) subdomain.Config {
	cfg := currentPipelineConfig(ctx)
	return subdomain.Config{
		NoSubdomainBruteForce:      cfg.NoSubdomainBruteForce,
		NoSubFinder:                cfg.NoSubFinder,
		SubdomainBruteForceThreads: cfg.SubdomainBruteForceThreads,
		SubdomainWordListFile:      cfg.SubdomainWordListFile,
		APIConfigFilePath:          cfg.APIConfigFilePath,
		EmitFunc: func(msg ddout.OutputMessage) {
			emit(msg)
		},
	}
}

func currentUncoverConfig(ctx *ScanContext) uncover.Config {
	cfg := currentPipelineConfig(ctx)
	return uncover.Config{
		APIConfigFilePath:          cfg.APIConfigFilePath,
		SubdomainBruteForceThreads: cfg.SubdomainBruteForceThreads,
		HunterPageSize:             cfg.HunterPageSize,
		HunterMaxPageCount:         cfg.HunterMaxPageCount,
		FofaMaxCount:               cfg.FofaMaxCount,
		QuakeSize:                  cfg.QuakeSize,
		LowPerceptionMode:          cfg.LowPerceptionMode,
		OnlyIPPort:                 cfg.OnlyIPPort,
		AllowCDNAssets:             cfg.AllowCDNAssets,
	}
}

// nucleiResultCollector 在 Nuclei 回调中同步收集结果副本。
// Agent 模式下 OutputHook 会把结果推给 gRPC，但 GoPoc 引擎需要
// 本地拿到这些结果来触发联动任务（如 Shiro-Key-Crack）。
type nucleiResultCollector struct {
	mu      sync.Mutex
	results []nucleiOutput.ResultEvent
}

func (c *nucleiResultCollector) add(result nucleiOutput.ResultEvent) {
	c.mu.Lock()
	c.results = append(c.results, result)
	c.mu.Unlock()
}

func (c *nucleiResultCollector) snapshot() []nucleiOutput.ResultEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]nucleiOutput.ResultEvent(nil), c.results...)
}

func buildNucleiResultHandler(ctx *ScanContext, enableLocalReports bool) (func(result nucleiOutput.ResultEvent), *nucleiResultCollector) {
	collector := &nucleiResultCollector{}

	if enableLocalReports || ctx == nil || ctx.OutputHook == nil {
		return func(result nucleiOutput.ResultEvent) {
			output.AddResultByResultEvent(result)
			collector.add(result)
		}, collector
	}

	return func(result nucleiOutput.ResultEvent) {
		payload, err := json.Marshal(result)
		if err != nil {
			return
		}
		show := fmt.Sprintf("[%s] [%s] %v",
			result.TemplateID,
			result.Info.SeverityHolder.Severity.String(),
			result.Matched,
		)
		ctx.OutputHook(OutputMessage{
			Type:   "Nuclei",
			Nuclei: string(payload),
			Show:   show,
		})
		collector.add(result)
	}, collector
}

func newPipelineUncoverState(ctx *ScanContext) (*uncover.State, func()) {
	if ctx == nil {
		return &uncover.State{
			IPPortMap:       structs.GlobalIPPortMap,
			IPPortMapLock:   &structs.GlobalIPPortMapLock,
			IPDomainMap:     structs.GlobalIPDomainMap,
			IPDomainMapLock: &structs.GlobalIPDomainMapLock,
			URLMap:          structs.GlobalURLMap,
			URLMapLock:      &structs.GlobalURLMapLock,
			BannerHMap:      structs.GlobalBannerHMap,
			BodyHMap:        structs.GlobalHttpBodyHMap,
			HeaderHMap:      structs.GlobalHttpHeaderHMap,
		}, func() {}
	}

	state := &uncover.State{
		IPPortMap:       ctx.IPPortMap,
		IPPortMapLock:   &ctx.IPPortMapLock,
		IPDomainMap:     ctx.IPDomainMap,
		IPDomainMapLock: &ctx.IPDomainMapLock,
		URLMap:          toStructURLMap(ctx.URLMap),
		BannerHMap:      ctx.BannerHMap,
		BodyHMap:        ctx.BodyHMap,
		HeaderHMap:      ctx.HeaderHMap,
	}

	// 如果有 OutputHook，将 uncover 的输出路由到当前任务的 Hook。
	if ctx.OutputHook != nil {
		state.EmitFunc = func(msg ddout.OutputMessage) {
			ctx.OutputHook(toEngineOutputMessage(msg))
		}
	}

	return state, func() {
		ctx.URLMap = toEngineURLMap(state.URLMap)
	}
}

func currentPipelineConfig(ctx *ScanContext) Config {
	return ctx.Config
}

func setPipelineConfig(ctx *ScanContext, cfg Config) {
	ctx.Config = cfg
}

func currentPipelineIPPortMap(ctx *ScanContext) map[string]string {
	return ctx.IPPortMap
}

func currentWebRuntime(ctx *ScanContext, emit func(structs.OutputMessage)) *web.Runtime {
	return web.NewRuntime(
		ctx.URLMap,
		&ctx.URLMapLock,
		ctx.IPDomainMap,
		ctx.BodyHMap,
		ctx.HeaderHMap,
		ctx.DirDB,
		ctx.FingerprintDB,
		ctx.WorkFlowDB,
		ctx.DirFallbackResultMap,
		&ctx.DirFallbackResultMapLock,
		emit,
	)
}

func currentFingerRuntime(ctx *ScanContext, emit func(structs.OutputMessage)) *finger.Runtime {
	return finger.NewRuntime(
		ctx.IPPortMap,
		ctx.URLMap,
		ctx.ResultMap,
		ctx.BannerHMap,
		ctx.BodyHMap,
		ctx.HeaderHMap,
		ctx.FingerprintDB,
		emit,
	)
}

func currentProtocolRuntime(ctx *ScanContext, emit func(structs.OutputMessage)) *protocol.Runtime {
	return protocol.NewRuntime(
		ctx.IPPortMap,
		&ctx.IPPortMapLock,
		ctx.BannerHMap,
		emit,
	)
}

func currentPipelineURLMap(ctx *ScanContext) map[string]URLEntity {
	return ctx.URLMap
}

func currentPipelineDirDB(ctx *ScanContext) map[string][]string {
	return ctx.DirDB
}

func currentPipelineResultMap(ctx *ScanContext) map[string][]string {
	return ctx.ResultMap
}

func setPipelineResultMap(ctx *ScanContext, resultMap map[string][]string) {
	ctx.ResultMap = resultMap
}

func currentPipelineDirFallbackResultMap(ctx *ScanContext) map[string][]string {
	return ctx.DirFallbackResultMap
}

func currentPipelineWorkflowDB(ctx *ScanContext) map[string]structs.WorkFlowEntity {
	return ctx.WorkFlowDB
}

func currentPipelineEmbedPocs(ctx *ScanContext) embed.FS {
	return ctx.EmbedPocs
}
