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
	"errors"
	"fmt"
	"strings"

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

	// Agent 模式（ctx != nil 且有 OutputHook）走无锁路径，允许多任务并发。
	// CLI 模式保留全局互斥锁以兌容旧代码。
	var cleanup func()
	var err error
	if ctx != nil && ctx.OutputHook != nil {
		cleanup, err = bindAgentContext(ctx)
	} else {
		cleanup, err = bindLegacyContext(ctx)
	}
	if err != nil {
		return err
	}
	defer cleanup()

	cfg := currentPipelineConfig(ctx)
	enableLocalReports := ctx == nil || ctx.OutputHook == nil
	webRuntime := currentWebRuntime(ctx)
	fingerRuntime := currentFingerRuntime(ctx)

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
		subdomains := subdomain.Enumerate(domains, currentSubdomainConfig(ctx))
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
		cdnDomains, _, tIPs = cdn.CheckCDNs(domains, cfg.SubdomainBruteForceThreads)
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
				ICMPAlive = discovery.CheckLive(ips, false)
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
					cfg.TCPPortScanTimeout, cfg.TCPPortScanThreads, cfg.PortsThreshold, false)
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
			tmpIPPort = portscan.ScanSYN(ips, cfg.MasscanPath, cfg.SYNPortScanThreads)
		} else {
			tmpIPPort = portscan.ScanTCP(ips, cfg.Ports, cfg.TCPPortScanTimeout, cfg.TCPPortScanThreads, cfg.PortsThreshold, true)
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
		currentProtocolRuntime(ctx).Identify(getProtocalInput, cfg.GetBannerThreads, cfg.GetBannerTimeout)
		emitPhase(ctx, PhaseProtocol, "end", "")
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	if ctx != nil {
		syncContextFromLegacy(ctx)
		cfg = currentPipelineConfig(ctx)
	}

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
	httpx.CallHTTPx(urls, webRuntime.URLCallback,
		cfg.HTTPProxy,
		cfg.WebThreads,
		cfg.WebTimeout)
	emitPhase(ctx, PhaseHTTPProbe, "end", "")
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	if ctx != nil {
		syncContextFromLegacy(ctx)
	}

	// 域名绑定资产探测
	if !cfg.NoHostBind {
		emitPhase(ctx, PhaseHostBind, "start", "")
		webRuntime.HostBindCheck(cfg.HTTPProxy, cfg.WebThreads, cfg.WebTimeout)
		if ctx != nil {
			syncContextFromLegacy(ctx)
		}
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
		nuclei.Call(TargetAndPocsName,
			cfg.HTTPProxy,
			output.AddResultByResultEvent,
			cfg.PocNameForSearch,
			cfg.NoInteractsh,
			currentPipelineEmbedPocs(ctx), cfg.NucleiTemplate, strings.Split(cfg.ExcludeTags, ","),
			strings.Split(cfg.Severities, ","))
		if enableLocalReports {
			output.GenerateHTMLReportFooter()
			output.GenerateAssetReport()
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
			webRuntime.DirBruteCallback,
			cfg.HTTPProxy,
			cfg.WebThreads,
			cfg.WebTimeout)
		gologger.AuditTimeLogger("主动指纹探测结束")
		emitPhase(ctx, PhaseDirBrute, "end", "")
		if ctx != nil {
			syncContextFromLegacy(ctx)
		}
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	// 指纹识别
	emitPhase(ctx, PhaseFingerprint, "start", "")
	fingerRuntime.Identify()
	emitPhase(ctx, PhaseFingerprint, "end", "")
	if ctx != nil {
		syncContextFromLegacy(ctx)
	}
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
	if count > 0 {
		emitPhase(ctx, PhaseNuclei, "start", fmt.Sprintf("%d pocs", count))
		nucleiResults = nuclei.Call(TargetAndPocsName,
			cfg.HTTPProxy,
			output.AddResultByResultEvent,
			"", cfg.NoInteractsh, currentPipelineEmbedPocs(ctx),
			cfg.NucleiTemplate, strings.Split(cfg.ExcludeTags, ","),
			strings.Split(cfg.Severities, ","))
		emitPhase(ctx, PhaseNuclei, "end", "")
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	emitPhase(ctx, PhaseGoPoc, "start", "")
	var goPocResults []structs.GoPocsResultType
	goPocResults = append(goPocResults, gopoc.TelnetCVEOnly(
		currentPipelineIPPortMap(ctx),
		cfg.GoPocThreads,
		cfg.Password,
		cfg.PasswordFile,
	)...)

	if cfg.GolangPoc {
		goPocResults = append(goPocResults, gopoc.Dispatch(
			currentPipelineIPPortMap(ctx),
			cfg.GoPocThreads,
			cfg.Password,
			cfg.PasswordFile,
			nucleiResults,
		)...)
	}
	emitPhase(ctx, PhaseGoPoc, "end", "")
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	if ctx != nil {
		ctx.GoPocsResults = toEngineGoPocResults(goPocResults)
	}

	if enableLocalReports {
		output.GenerateHTMLReportFooter()
		output.GenerateAssetReport()
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

func currentSubdomainConfig(ctx *ScanContext) subdomain.Config {
	cfg := currentPipelineConfig(ctx)
	return subdomain.Config{
		NoSubdomainBruteForce:      cfg.NoSubdomainBruteForce,
		NoSubFinder:                cfg.NoSubFinder,
		SubdomainBruteForceThreads: cfg.SubdomainBruteForceThreads,
		SubdomainWordListFile:      cfg.SubdomainWordListFile,
		APIConfigFilePath:          cfg.APIConfigFilePath,
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
	if ctx != nil {
		return ctx.Config
	}
	return Config(structs.GlobalConfig)
}

func setPipelineConfig(ctx *ScanContext, cfg Config) {
	if ctx != nil {
		ctx.Config = cfg
		syncLegacyConfigFromContext(ctx)
		return
	}
	structs.GlobalConfig = structs.Config(cfg)
}

func currentPipelineIPPortMap(ctx *ScanContext) map[string]string {
	if ctx != nil {
		return ctx.IPPortMap
	}
	return structs.GlobalIPPortMap
}

func currentWebRuntime(ctx *ScanContext) *web.Runtime {
	if ctx != nil {
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
		)
	}

	return web.NewRuntime(
		structs.GlobalURLMap,
		&structs.GlobalURLMapLock,
		structs.GlobalIPDomainMap,
		structs.GlobalHttpBodyHMap,
		structs.GlobalHttpHeaderHMap,
		structs.DirDB,
		structs.FingerprintDB,
		structs.WorkFlowDB,
		structs.DirFallbackResultMap,
		&structs.DirFallbackResultMapLock,
	)
}

func currentFingerRuntime(ctx *ScanContext) *finger.Runtime {
	if ctx != nil {
		return finger.NewRuntime(
			ctx.IPPortMap,
			ctx.URLMap,
			ctx.ResultMap,
			ctx.BannerHMap,
			ctx.BodyHMap,
			ctx.HeaderHMap,
			ctx.FingerprintDB,
		)
	}

	return finger.NewRuntime(
		structs.GlobalIPPortMap,
		structs.GlobalURLMap,
		structs.GlobalResultMap,
		structs.GlobalBannerHMap,
		structs.GlobalHttpBodyHMap,
		structs.GlobalHttpHeaderHMap,
		structs.FingerprintDB,
	)
}

func currentProtocolRuntime(ctx *ScanContext) *protocol.Runtime {
	if ctx != nil {
		return protocol.NewRuntime(
			ctx.IPPortMap,
			&ctx.IPPortMapLock,
			ctx.BannerHMap,
		)
	}

	return protocol.NewRuntime(
		structs.GlobalIPPortMap,
		&structs.GlobalIPPortMapLock,
		structs.GlobalBannerHMap,
	)
}

func currentPipelineURLMap(ctx *ScanContext) map[string]URLEntity {
	if ctx != nil {
		return ctx.URLMap
	}
	return structs.GlobalURLMap
}

func currentPipelineDirDB(ctx *ScanContext) map[string][]string {
	if ctx != nil {
		return ctx.DirDB
	}
	return structs.DirDB
}

func currentPipelineResultMap(ctx *ScanContext) map[string][]string {
	if ctx != nil {
		return ctx.ResultMap
	}
	return structs.GlobalResultMap
}

func setPipelineResultMap(ctx *ScanContext, resultMap map[string][]string) {
	if ctx != nil {
		ctx.ResultMap = resultMap
		structs.GlobalResultMap = resultMap
		return
	}
	structs.GlobalResultMap = resultMap
}

func currentPipelineDirFallbackResultMap(ctx *ScanContext) map[string][]string {
	if ctx != nil {
		return ctx.DirFallbackResultMap
	}
	return structs.DirFallbackResultMap
}

func currentPipelineWorkflowDB(ctx *ScanContext) map[string]structs.WorkFlowEntity {
	if ctx != nil {
		return ctx.WorkFlowDB
	}
	return structs.WorkFlowDB
}

func currentPipelineEmbedPocs(ctx *ScanContext) embed.FS {
	if ctx != nil {
		return ctx.EmbedPocs
	}
	return structs.GlobalEmbedPocs
}
