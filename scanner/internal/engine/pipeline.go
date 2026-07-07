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
	"dddd/scanner/structs"
	"dddd/scanner/utils"
	"embed"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx"
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

	// 无锁上下文绑定：仅加载知识库，不写全局变量，不获取互斥锁。
	cleanup, err := bindAgentContext(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	cfg := currentPipelineConfig(ctx)

	// Agent 模式：大网段启用存活预扫描先发现存活主机。
	// 小网段（<=256 IP）直接端口扫描更高效，也避免无 root 环境 ICMP 慢路径拖累任务。
	if ctx != nil && ctx.OutputHook != nil {
		if !cfg.TCPPing && !cfg.SkipHostDiscovery {
			ipCount := estimateIPCount(cfg.Targets)
			if ipCount <= 256 {
				cfg.SkipHostDiscovery = true
				setPipelineConfig(ctx, cfg)
			}
		}
	}
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

			// 存活探测命中时只扫描存活主机；无命中时保留原始目标继续扫描，避免误空跑。
			if len(ICMPAlive) > 0 || len(TCPAlive) > 0 {
				ips = append(ICMPAlive, TCPAlive...)
				ips = utils.RemoveDuplicateElement(ips)
			}
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
	webRuntime := currentWebRuntime(ctx, emit)
	httpx.CallHTTPx(urls, webRuntime.URLCallback,
		cfg.HTTPProxy,
		cfg.WebThreads,
		cfg.WebTimeout)
	if err := p.probeRedirectLocations(ctx, &cfg, webRuntime); err != nil {
		return err
	}
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
		if _, err := runPocSearch(ctx, &cfg, aliveURLs, enableLocalReports); err != nil {
			return err
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

	// WAF 过滤：Safedog / 安全狗 WAF 标题检测。
	for _, entity := range currentPipelineURLMap(ctx) {
		for _, path := range entity.WebPaths {
			title := strings.ToLower(path.Title)
			if strings.Contains(title, "当前网络访问异常") || strings.Contains(title, "请验证是否真人访问") {
				for target := range resultMap {
					if strings.Contains(target, entity.IP) {
						delete(resultMap, target)
						gologger.AuditTimeLogger("[WAF] %s 标题 Safedog → 跳过 Nuclei", target)
					}
				}
			}
		}
	}

	if cfg.NoPoc {
		gologger.Info().Msg("跳过漏洞探测")
		return nil
	}

	// 漏洞检测
	if enableLocalReports {
		output.InitReportName()
	}

	nucleiResults, err := runNucleiPhase(ctx, &cfg, resultMap, enableLocalReports, emit)
	if err != nil {
		return err
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
		if len(cfg.Targets) == 0 {
			return fmt.Errorf("Quake 搜索返回 0 条结果，请检查: 1) API Key 是否已配置 2) 搜索语法是否正确")
		}
	}
	return checkPipelineCancelled(ctx)
}

func (p *Pipeline) probeRedirectLocations(ctx *ScanContext, cfg *Config, webRuntime *web.Runtime) error {
	const maxRedirectLocationPasses = 4

	for pass := 0; pass < maxRedirectLocationPasses; pass++ {
		if err := checkPipelineCancelled(ctx); err != nil {
			return err
		}

		redirectURLs := webRuntime.DrainRedirectURLs()
		if len(redirectURLs) == 0 {
			return nil
		}

		gologger.Info().Msgf("[HTTPProbe] redirect pass=%d targets=%d follow_host_redirects=true", pass+1, len(redirectURLs))
		httpx.CallHTTPxFollowHostRedirects(redirectURLs, webRuntime.URLCallback,
			cfg.HTTPProxy,
			cfg.WebThreads,
			cfg.WebTimeout)
	}
	return nil
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

// estimateIPCount 估算目标 IP 数量，用于决定是否做存活探测。
func estimateIPCount(targets []string) int {
	count := 0
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if strings.Contains(t, "/") {
			_, cidr, err := net.ParseCIDR(t)
			if err == nil {
				ones, bits := cidr.Mask.Size()
				if bits == 32 && ones >= 0 {
					count += 1 << (bits - ones)
				} else {
					count++
				}
				continue
			}
		}
		if strings.Contains(t, "-") {
			ips := utils.RangerToIP(t)
			count += len(ips)
			continue
		}
		count++
	}
	return count
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
