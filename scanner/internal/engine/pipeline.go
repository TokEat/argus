// Package engine 扫描引擎内核。
//
// Pipeline 是扫描流水线的编排器，从 CLI 入口的 workflow 逻辑提取而来。
// Phase 0.4: import 路径从 common/ 切换到 internal/scanner/
package engine

import (
	"context"
	"errors"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/gopocs"
	"github.com/P0lar1ght/argus/scanner/internal/scanner/cdn"
	"github.com/P0lar1ght/argus/scanner/internal/scanner/discovery"
	"github.com/P0lar1ght/argus/scanner/internal/scanner/portscan"
	"github.com/P0lar1ght/argus/scanner/internal/scanner/protocol"
	"github.com/P0lar1ght/argus/scanner/internal/scanner/subdomain"
	"github.com/P0lar1ght/argus/scanner/internal/scanner/web"
	gopoc "github.com/P0lar1ght/argus/scanner/internal/vuln/gopoc"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"net"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx"
	"github.com/projectdiscovery/httpx/runner"
)

// Pipeline 扫描流水线编排器。
type Pipeline struct{}

// httpProbeSession keeps all probe passes for a Pipeline HTTP stage in the
// same target-budgeted session.  The narrow interface makes redirect handling
// testable without reaching the network.
type httpProbeSession interface {
	CallHTTPx(urls []string, callback func(runner.Result), proxy string, threads int)
	CallHTTPxFollowHostRedirects(urls []string, callback func(runner.Result), proxy string, threads int)
	Err() error
	Close()
}

var newHTTPProbeSession = func(parent context.Context, timeout int, visits httpx.URLVisitSet) httpProbeSession {
	return httpx.NewProbeSessionWithURLVisits(parent, timeout, visits)
}

func pipelineHTTPProbeContext(ctx *ScanContext) context.Context {
	if ctx != nil && ctx.Ctx != nil {
		return ctx.Ctx
	}
	return context.Background()
}

func pipelineHTTPURLVisits(ctx *ScanContext) httpx.URLVisitSet {
	if ctx == nil {
		return nil
	}
	return ctx
}

// Run 执行完整的扫描流水线。
func (p *Pipeline) Run(ctx *ScanContext) error {
	var domains []string
	emit := func(msg structs.OutputMessage) {
		dispatchPipelineOutput(ctx, msg)
	}
	var urls []string
	var domainPort []string
	var ipPort []string
	var ips []string

	defer gologger.Info().Msg(aurora.BrightGreen("Done!").String())

	if ctx != nil && ctx.Config.TraceOnly {
		return runStandaloneTrace(ctx, ctx.Config, emit)
	}

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
		if !cfg.TCPPing && !cfg.UDPPing && !cfg.SkipHostDiscovery {
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
	if strings.TrimSpace(cfg.ExecutionMode) != "" {
		switch strings.ToLower(strings.TrimSpace(cfg.ExecutionMode)) {
		case "risk_validation":
			_, err := runRiskValidationPhase(ctx, &cfg, enableLocalReports)
			return err
		case "credential_validation":
			return runCredentialValidationPhase(ctx, &cfg)
		default:
			return fmt.Errorf("unsupported internal execution mode %q", cfg.ExecutionMode)
		}
	}

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
	if cfg.Subdomain && len(domains) > 0 && resumeStageEnabled(ctx, scanplan.StageSubdomainDiscovery) {
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
	if len(domains) > 0 && resumeStageEnabled(ctx, scanplan.StageCDNClassification) {
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
	var confirmedAlive []string
	var udpRecords []structs.ServiceRecord
	udpProbed := false
	if len(ips) > 0 {
		if err := checkPipelineCancelled(ctx); err != nil {
			return err
		}
		if !cfg.SkipHostDiscovery {
			ICMPAlive, TCPAlive := discoverLiveHosts(ctx, cfg, ips, emit)
			// 存活探测命中时只扫描存活主机；无命中时保留原始目标继续扫描，避免误空跑。
			if len(ICMPAlive) > 0 || len(TCPAlive) > 0 {
				ips = discovery.Union(ICMPAlive, TCPAlive)
				confirmedAlive = append([]string(nil), ips...)
			}
		}
		if resumeStageEnabled(ctx, scanplan.StagePortScan) {
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
				tmpIPPort = portscan.ScanSYN(ips, cfg.Ports, cfg.MasscanPath, cfg.SYNPortScanThreads, nil)
			} else {
				tmpIPPort = portscan.ScanTCP(ips, cfg.Ports, cfg.TCPPortScanTimeout, cfg.TCPPortScanThreads, cfg.PortsThreshold, true, nil)
			}

			tmpIPPort = portscan.RemoveFirewall(tmpIPPort, cfg.PortsThreshold)
			if !cfg.NoUDPIdentify {
				udpHosts := protocol.UDPIdentifyHosts(confirmedAlive, tmpIPPort)
				if len(udpHosts) > 0 {
					udpRecords = portscan.ScanUDP(udpHosts, cfg.GetBannerTimeout, cfg.GetBannerThreads, emit)
					udpProbed = true
				}
			}
			emitPhase(ctx, PhasePortScan, "end", fmt.Sprintf("%d tcp, %d udp", len(tmpIPPort), len(udpRecords)))

			for _, each := range tmpIPPort {
				ipPort = append(ipPort, each)
			}
		} else if checkpoint := resumeCheckpoint(ctx, scanplan.StagePortScan); checkpoint != nil {
			ipPort = append(ipPort, checkpoint.OpenPorts...)
		}
		ipPort = utils.RemoveDuplicateElement(ipPort)
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	if cfg.TraceRoute && !cfg.TraceOnly {
		traceHosts := discovery.TraceInputHosts(confirmedAlive, ips, ipPort)
		if len(traceHosts) == 0 {
			gologger.Info().Msg("内网路径探测：没有探活或开放端口作为输入，已跳过")
		} else {
			mapIntranet(traceHosts, emit)
		}
	}

	// 协议识别
	getProtocalInput := ipPort
	for _, each := range domainPort {
		getProtocalInput = append(getProtocalInput, each)
	}
	udpHosts := []string(nil)
	if !cfg.NoUDPIdentify && !udpProbed {
		udpHosts = protocolPhaseUDPHosts(confirmedAlive)
	}
	if resumeStageEnabled(ctx, scanplan.StageProtocolIdentify) && (len(getProtocalInput) > 0 || udpProbed || len(udpHosts) > 0 || ctx.ResumePlan != nil) {
		emitPhase(ctx, PhaseProtocol, "start", fmt.Sprintf("%d targets", len(getProtocalInput)))
		if len(getProtocalInput) > 0 || ctx.ResumePlan != nil {
			currentProtocolRuntime(ctx, emit).Identify(getProtocalInput, cfg.GetBannerThreads, cfg.GetBannerTimeout)
		}
		if udpProbed {
			currentProtocolRuntime(ctx, emit).StoreUDP(udpRecords)
		} else if len(udpHosts) > 0 {
			currentProtocolRuntime(ctx, emit).IdentifyUDP(udpHosts, cfg.GetBannerThreads, cfg.GetBannerTimeout)
		}
		if err := runProtocolCheckPhase(ctx, &cfg, currentPipelineIPPortMap(ctx)); err != nil {
			emitPhase(ctx, PhaseProtocol, "failed", "scoped GoPoc protocol checks failed")
			return err
		}
		emitPhase(ctx, PhaseProtocol, "end", "")
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	cfg = currentPipelineConfig(ctx)
	if !resumeStageEnabled(ctx, scanplan.StageProtocolIdentify) {
		restoreResumeProtocolServices(ctx)
	}

	// HTTP 探测
	for hostPort, service := range currentPipelineIPPortMap(ctx) {
		urls = append(urls, web.ProbeURLs(hostPort, service)...)
	}
	urls = utils.RemoveDuplicateElement(urls)
	httpProbeComplete := true

	if resumeStageEnabled(ctx, scanplan.StageHTTPProbe) {
		emitPhase(ctx, PhaseHTTPProbe, "start", fmt.Sprintf("%d urls", len(urls)))
		webRuntime := currentWebRuntime(ctx, emit)
		var err error
		httpProbeComplete, err = completeHTTPProbePhase(ctx, p.runHTTPProbe(ctx, &cfg, urls, webRuntime))
		if err != nil {
			return err
		}
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	// 域名绑定资产探测
	if !cfg.NoHostBind && resumeStageEnabled(ctx, scanplan.StageHostBinding) {
		emitPhase(ctx, PhaseHostBind, "start", "")
		currentWebRuntime(ctx, emit).HostBindCheck(cfg.HTTPProxy, cfg.WebThreads, cfg.WebTimeout)
		completeHTTPDependentPhase(ctx, PhaseHostBind, httpProbeComplete)
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
		if !httpProbeComplete {
			gologger.Warning().Msg("HTTP probe incomplete; skipping explicit POC search")
			return nil
		}
		gologger.AuditTimeLogger("模糊搜索Poc: %v", cfg.PocNameForSearch)
		if _, err := runPocSearch(ctx, &cfg, aliveURLs, enableLocalReports); err != nil {
			return err
		}
		if err := checkPipelineCancelled(ctx); err != nil {
			return err
		}
		if err := ddout.FlushWEBBlocks(); err != nil {
			return err
		}
		return nil
	}

	if cfg.BehaviorProbe && resumeStageEnabled(ctx, scanplan.StageBehaviorProbe) {
		emitPhase(ctx, PhaseBehaviorProbe, "start", fmt.Sprintf("%d http services", len(aliveURLs)))
		if err := runActiveFingerprintPhase(ctx, &cfg, aliveURLs); err != nil {
			emitPhase(ctx, PhaseBehaviorProbe, "failed", err.Error())
			return err
		}
		completeHTTPDependentPhase(ctx, PhaseBehaviorProbe, httpProbeComplete)
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	// 目录爆破
	if !cfg.NoDirSearch && resumeStageEnabled(ctx, scanplan.StageDirectoryProbe) {
		checkURLs := buildDirProbeURLs(aliveURLs, currentPipelineDirDB(ctx))
		emitPhase(ctx, PhaseDirBrute, "start", fmt.Sprintf("%d urls", len(checkURLs)))
		gologger.AuditTimeLogger("开始主动指纹探测")
		httpx.DirBrute(checkURLs,
			currentWebRuntime(ctx, emit).DirBruteCallback,
			cfg.HTTPProxy,
			cfg.WebThreads,
			cfg.WebTimeout)
		gologger.AuditTimeLogger("主动指纹探测结束")
		completeHTTPDependentPhase(ctx, PhaseDirBrute, httpProbeComplete)
	}
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	// 指纹识别
	if resumeStageEnabled(ctx, scanplan.StageFingerprint) {
		emitPhase(ctx, PhaseFingerprint, "start", "")
		currentFingerRuntime(ctx, emit).Identify()
		completeHTTPDependentPhase(ctx, PhaseFingerprint, httpProbeComplete)
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
	for target, fingers := range resultMap {
		ddout.MergeWEBFingers(target, fingers)
	}
	if err := ddout.FlushWEBBlocks(); err != nil {
		return err
	}

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

	var nucleiResults []gopocs.NucleiResult
	if cfg.NoPoc {
		gologger.Info().Msg("跳过 Nuclei POC")
	} else if !httpProbeComplete {
		gologger.Warning().Msg("HTTP probe incomplete; skipping Nuclei")
	} else {
		var err error
		nucleiResults, err = runNucleiPhase(ctx, &cfg, resultMap, enableLocalReports, emit)
		if err != nil {
			return err
		}
		if err := checkPipelineCancelled(ctx); err != nil {
			return err
		}
	}

	if !cfg.GolangPoc {
		gologger.Info().Msg("跳过 GoPoc")
		return nil
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
	telnetResults, telnetErr := gopoc.TelnetCVEOnly(
		ipPortMap,
		cfg.GoPocThreads,
		cfg.Password,
		cfg.PasswordFile,
		cfg.GoPocModules,
		emit,
	)
	goPocResults = append(goPocResults, telnetResults...)
	if telnetErr != nil {
		emitPhase(ctx, "gopoc_telnet_cve", "failed", "GoPoc execution failed")
		emitPhase(ctx, PhaseGoPoc, "failed", "GoPoc execution failed")
		if ctx != nil {
			ctx.GoPocsResults = toEngineGoPocResults(goPocResults)
		}
		return fmt.Errorf("run Telnet GoPoc dispatcher: %w", telnetErr)
	}
	emitPhase(ctx, "gopoc_telnet_cve", "end", fmt.Sprintf("%d results", len(goPocResults)))

	emitPhase(ctx, "gopoc_dispatch", "start", fmt.Sprintf("%d services", len(ipPortMap)))
	creds := gopocs.DispatchCreds{
		Password: cfg.Password, PasswordFile: cfg.PasswordFile,
		UserAppend: cfg.UserAppend, PasswordAppend: cfg.PasswordAppend, NoBrute: cfg.NoBrute,
		Modules: cfg.GoPocModules,
	}
	var dispatchResults []structs.GoPocsResultType
	var dispatchErr error
	if cfg.MachineOutput {
		dispatchResults, dispatchErr = gopoc.DispatchMachineWithCreds(ipPortMap, resultMap, cfg.GoPocThreads, creds, nucleiResults, emit)
	} else {
		dispatchResults, dispatchErr = gopoc.DispatchWithCreds(ipPortMap, resultMap, cfg.GoPocThreads, creds, nucleiResults, emit)
	}
	goPocResults = append(goPocResults, dispatchResults...)
	if dispatchErr != nil {
		emitPhase(ctx, "gopoc_dispatch", "failed", "GoPoc execution failed")
		emitPhase(ctx, PhaseGoPoc, "failed", "GoPoc execution failed")
		if ctx != nil {
			ctx.GoPocsResults = toEngineGoPocResults(goPocResults)
		}
		return fmt.Errorf("run GoPoc dispatcher: %w", dispatchErr)
	}
	emitPhase(ctx, "gopoc_dispatch", "end", fmt.Sprintf("%d results", len(dispatchResults)))
	emitPhase(ctx, PhaseGoPoc, "end", fmt.Sprintf("%d total results", len(goPocResults)))
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	if ctx != nil {
		ctx.GoPocsResults = toEngineGoPocResults(goPocResults)
	}

	return nil
}

func buildDirProbeURLs(aliveURLs []string, dirDB map[string][]string) []string {
	checkURLs := make([]string, 0, len(aliveURLs)*len(dirDB))
	for rawPath := range dirDB {
		path := strings.TrimSpace(rawPath)
		if path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
			continue
		}
		for _, rawBaseURL := range aliveURLs {
			baseURL := strings.TrimSpace(rawBaseURL)
			if baseURL == "" {
				continue
			}
			checkURLs = append(checkURLs, strings.TrimRight(baseURL, "/")+path)
		}
	}
	return utils.RemoveDuplicateElement(checkURLs)
}

func (p *Pipeline) runHTTPProbe(ctx *ScanContext, cfg *Config, urls []string, webRuntime *web.Runtime) error {
	session := newHTTPProbeSession(pipelineHTTPProbeContext(ctx), cfg.WebTimeout, pipelineHTTPURLVisits(ctx))
	if session == nil {
		return errors.New("http probe session factory returned nil")
	}
	defer session.Close()

	session.CallHTTPx(urls, webRuntime.URLCallback, cfg.HTTPProxy, cfg.WebThreads)
	if err := p.probeRedirectLocations(ctx, cfg, webRuntime, session); err != nil {
		return err
	}
	return session.Err()
}

func completeHTTPProbePhase(ctx *ScanContext, probeErr error) (bool, error) {
	if probeErr == nil {
		if err := checkPipelineCancelled(ctx); err != nil {
			return false, err
		}
		emitPhase(ctx, PhaseHTTPProbe, "end", "")
		return true, nil
	}
	if ctx != nil && ctx.Ctx != nil && ctx.Ctx.Err() != nil {
		return false, probeErr
	}
	if errors.Is(probeErr, context.DeadlineExceeded) {
		emitPhase(ctx, PhaseHTTPProbe, "failed", "target HTTP budget exhausted")
		return false, nil
	}
	return false, probeErr
}

func completeHTTPDependentPhase(ctx *ScanContext, phase string, httpProbeComplete bool) {
	if httpProbeComplete {
		emitPhase(ctx, phase, "end", "")
		return
	}
	emitPhase(ctx, phase, "failed", "upstream HTTP probe incomplete")
}

func (p *Pipeline) probeRedirectLocations(ctx *ScanContext, cfg *Config, webRuntime *web.Runtime, session httpProbeSession) error {
	const maxRedirectLocationPasses = 4

	for pass := 0; pass < maxRedirectLocationPasses; pass++ {
		if err := checkPipelineCancelled(ctx); err != nil {
			return err
		}

		redirectURLs := webRuntime.DrainRedirectURLs()
		if len(redirectURLs) == 0 {
			return nil
		}

		gologger.AuditTimeLogger("[HTTPProbe] redirect pass=%d targets=%d follow_host_redirects=true", pass+1, len(redirectURLs))
		session.CallHTTPxFollowHostRedirects(redirectURLs, webRuntime.URLCallback, cfg.HTTPProxy, cfg.WebThreads)
	}
	return nil
}

var (
	probeARP  = discovery.ProbeARP
	probeICMP = discovery.CheckLive
	probeTCP  = func(ips []string, timeout, threads, threshold int, emit func(ddout.OutputMessage)) []string {
		return discovery.HostsFromIPPorts(portscan.ScanTCP(ips, discovery.TCPProbePorts, timeout, threads, threshold, false, emit))
	}
	probeUDP      = discovery.ProbeUDP
	localLinkNets = discovery.LocalIPv4Nets
	mapIntranet   = discovery.MapIntranet
)

func runStandaloneTrace(ctx *ScanContext, cfg Config, emit func(ddout.OutputMessage)) error {
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}
	hosts := discovery.HostsFromTraceTargets(cfg.Targets)
	if len(hosts) == 0 {
		gologger.Info().Msg("内网路径探测：没有可用的 IPv4 目标，已跳过")
		return nil
	}
	mapIntranet(hosts, emit)
	return checkPipelineCancelled(ctx)
}

func protocolPhaseUDPHosts(confirmedAlive []string) []string {
	return protocol.UDPIdentifyHosts(confirmedAlive, nil)
}

func discoverLiveHosts(ctx *ScanContext, cfg Config, ips []string, emit func(ddout.OutputMessage)) (icmpAlive, extraAlive []string) {
	icmpAlive = checkpointAliveHosts(ctx, scanplan.StageICMPDiscovery)
	extraAlive = checkpointAliveHosts(ctx, scanplan.StageTCPLiveness)
	if len(ips) == 0 {
		return icmpAlive, extraAlive
	}

	doICMP := !cfg.NoICMPPing && resumeStageEnabled(ctx, scanplan.StageICMPDiscovery)
	doTCP := resumeStageEnabled(ctx, scanplan.StageTCPLiveness)
	onLink, _ := discovery.Partition(ips, localLinkNets())
	needARP := len(onLink) > 0 && (doICMP || ((cfg.TCPPing || cfg.UDPPing) && doTCP) || cfg.UDPPing)

	if doICMP {
		emitPhase(ctx, PhaseICMP, "start", fmt.Sprintf("%d ips", len(ips)))
		var arpAlive []string
		if needARP {
			gologger.Info().Msg("ARP存活探测")
			arpAlive, _ = probeARP(onLink, emit)
		}
		icmpTargets := discovery.Difference(ips, arpAlive)
		var icmpOnly []string
		if len(icmpTargets) > 0 {
			icmpOnly = probeICMP(icmpTargets, false, emit)
		}
		icmpAlive = discovery.Union(arpAlive, icmpOnly)
		emitPhase(ctx, PhaseICMP, "end", fmt.Sprintf("%d alive", len(icmpAlive)))
		if remaining := discovery.Difference(ips, icmpAlive); doTCP && len(remaining) > 0 {
			extraAlive = runTCPLiveness(ctx, cfg, remaining, extraAlive, emit)
		}
	} else if cfg.TCPPing && doTCP {
		emitPhase(ctx, PhaseTCPPing, "start", fmt.Sprintf("%d ips", len(ips)))
		if needARP {
			gologger.Info().Msg("ARP存活探测")
			arpAlive, _ := probeARP(onLink, emit)
			icmpAlive = discovery.Union(icmpAlive, arpAlive)
		}
		gologger.Info().Msg("TCP存活探测")
		uncheck := discovery.Difference(ips, icmpAlive)
		if len(uncheck) > 0 {
			extraAlive = discovery.Union(extraAlive, probeTCP(uncheck, cfg.TCPPortScanTimeout, cfg.TCPPortScanThreads, cfg.PortsThreshold, emit))
		}
		emitPhase(ctx, PhaseTCPPing, "end", fmt.Sprintf("%d alive", len(extraAlive)))
	} else if needARP {
		gologger.Info().Msg("ARP存活探测")
		arpAlive, _ := probeARP(onLink, emit)
		icmpAlive = discovery.Union(icmpAlive, arpAlive)
	}

	if cfg.UDPPing {
		remaining := discovery.Difference(ips, discovery.Union(icmpAlive, extraAlive))
		if len(remaining) > 0 {
			gologger.Info().Msg("UDP存活探测")
			wait := time.Duration(cfg.TCPPortScanTimeout) * time.Second
			if wait <= 0 {
				wait = time.Second
			}
			extraAlive = discovery.Union(extraAlive, probeUDP(remaining, wait, cfg.TCPPortScanThreads, emit))
		}
	}
	return icmpAlive, extraAlive
}

func runTCPLiveness(ctx *ScanContext, cfg Config, uncheck, tcpAlive []string, emit func(ddout.OutputMessage)) []string {
	emitPhase(ctx, PhaseTCPPing, "start", fmt.Sprintf("%d ips", len(uncheck)))
	gologger.Info().Msg("TCP存活探测")
	if len(uncheck) > 0 {
		tcpAlive = discovery.Union(tcpAlive, probeTCP(uncheck, cfg.TCPPortScanTimeout, cfg.TCPPortScanThreads, cfg.PortsThreshold, emit))
	}
	emitPhase(ctx, PhaseTCPPing, "end", fmt.Sprintf("%d alive", len(tcpAlive)))
	return tcpAlive
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
	if ctx == nil {
		return
	}
	event := PhaseEvent{
		Phase:   phase,
		Status:  status,
		Message: message,
	}
	if ctx.PhaseObserver != nil {
		ctx.PhaseObserver(event)
	}
	if ctx.PhaseHook != nil {
		ctx.PhaseHook(event)
	}
}

func currentSubdomainConfig(ctx *ScanContext, emit func(structs.OutputMessage)) subdomain.Config {
	cfg := currentPipelineConfig(ctx)
	return subdomain.Config{
		NoSubdomainBruteForce:      cfg.NoSubdomainBruteForce,
		NoSubFinder:                cfg.NoSubFinder,
		SubdomainBruteForceThreads: cfg.SubdomainBruteForceThreads,
		SubdomainBruteforceDepth:   cfg.SubdomainBruteforceDepth,
		SubdomainWordListFile:      cfg.SubdomainWordListFile,
		SubdomainDictionaryWords:   append([]string(nil), cfg.SubdomainDictionaryWords...),
		EmitFunc: func(msg ddout.OutputMessage) {
			emit(msg)
		},
	}
}

func dispatchPipelineOutput(ctx *ScanContext, msg structs.OutputMessage) {
	converted := toEngineOutputMessage(msg)
	if ctx != nil && ctx.OutputObserver != nil {
		ctx.OutputObserver(converted)
	}
	if ctx != nil && ctx.OutputHook != nil {
		ctx.OutputHook(converted)
		return
	}
	ddout.FormatOutput(msg)
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
