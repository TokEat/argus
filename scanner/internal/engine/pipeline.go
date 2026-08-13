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
	"github.com/P0lar1ght/argus/scanner/internal/scanner/cdn"
	"github.com/P0lar1ght/argus/scanner/internal/scanner/discovery"
	"github.com/P0lar1ght/argus/scanner/internal/scanner/portscan"
	"github.com/P0lar1ght/argus/scanner/internal/scanner/subdomain"
	"github.com/P0lar1ght/argus/scanner/internal/scanner/web"
	gopoc "github.com/P0lar1ght/argus/scanner/internal/vuln/gopoc"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"net"
	"strings"

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
	if len(ips) > 0 {
		if err := checkPipelineCancelled(ctx); err != nil {
			return err
		}
		if !cfg.SkipHostDiscovery {
			ICMPAlive := checkpointAliveHosts(ctx, scanplan.StageICMPDiscovery)
			if !cfg.NoICMPPing && resumeStageEnabled(ctx, scanplan.StageICMPDiscovery) {
				emitPhase(ctx, PhaseICMP, "start", fmt.Sprintf("%d ips", len(ips)))
				ICMPAlive = discovery.CheckLive(ips, false, emit)
				emitPhase(ctx, PhaseICMP, "end", fmt.Sprintf("%d alive", len(ICMPAlive)))
			}

			TCPAlive := checkpointAliveHosts(ctx, scanplan.StageTCPLiveness)
			if cfg.TCPPing && resumeStageEnabled(ctx, scanplan.StageTCPLiveness) {
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
				tmpIPPort = portscan.ScanSYN(ips, cfg.Ports, cfg.MasscanPath, cfg.SYNPortScanThreads, emit)
			} else {
				tmpIPPort = portscan.ScanTCP(ips, cfg.Ports, cfg.TCPPortScanTimeout, cfg.TCPPortScanThreads, cfg.PortsThreshold, true, emit)
			}

			tmpIPPort = portscan.RemoveFirewall(tmpIPPort, cfg.PortsThreshold)
			emitPhase(ctx, PhasePortScan, "end", fmt.Sprintf("%d open ports", len(tmpIPPort)))

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

	// 协议识别
	getProtocalInput := ipPort
	for _, each := range domainPort {
		getProtocalInput = append(getProtocalInput, each)
	}
	if resumeStageEnabled(ctx, scanplan.StageProtocolIdentify) && (len(getProtocalInput) > 0 || ctx.ResumePlan != nil) {
		emitPhase(ctx, PhaseProtocol, "start", fmt.Sprintf("%d targets", len(getProtocalInput)))
		currentProtocolRuntime(ctx, emit).Identify(getProtocalInput, cfg.GetBannerThreads, cfg.GetBannerTimeout)
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
		if service == "http" {
			urls = append(urls, "http://"+hostPort)
		} else if service == "https" {
			urls = append(urls, "https://"+hostPort)
		}
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
		return nil
	}

	// 目录爆破
	if !cfg.NoDirSearch && resumeStageEnabled(ctx, scanplan.StageDirectoryProbe) {
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
	if !httpProbeComplete {
		gologger.Warning().Msg("HTTP probe incomplete; skipping risk validation stages")
		return nil
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
	telnetResults, telnetErr := gopoc.TelnetCVEOnly(
		ipPortMap,
		cfg.GoPocThreads,
		cfg.Password,
		cfg.PasswordFile,
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

	if cfg.GolangPoc {
		emitPhase(ctx, "gopoc_dispatch", "start", fmt.Sprintf("%d services", len(ipPortMap)))
		var dispatchResults []structs.GoPocsResultType
		var dispatchErr error
		if cfg.MachineOutput {
			dispatchResults, dispatchErr = gopoc.DispatchMachine(ipPortMap, resultMap, cfg.GoPocThreads, cfg.Password, cfg.PasswordFile, nucleiResults, emit)
		} else {
			dispatchResults, dispatchErr = gopoc.Dispatch(ipPortMap, resultMap, cfg.GoPocThreads, cfg.Password, cfg.PasswordFile, nucleiResults, emit)
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
	}
	emitPhase(ctx, PhaseGoPoc, "end", fmt.Sprintf("%d total results", len(goPocResults)))
	if err := checkPipelineCancelled(ctx); err != nil {
		return err
	}

	if ctx != nil {
		ctx.GoPocsResults = toEngineGoPocResults(goPocResults)
	}

	return nil
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

		gologger.Info().Msgf("[HTTPProbe] redirect pass=%d targets=%d follow_host_redirects=true", pass+1, len(redirectURLs))
		session.CallHTTPxFollowHostRedirects(redirectURLs, webRuntime.URLCallback, cfg.HTTPProxy, cfg.WebThreads)
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
