// Package localplanner executes the standalone CLI scan plan. It consumes
// local result history only and never uploads it.
package localplanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/P0lar1ght/argus/scanner/internal/engine"
	"github.com/P0lar1ght/argus/scanner/internal/localstate"
	"github.com/P0lar1ght/argus/scanner/internal/timing"
	"github.com/P0lar1ght/argus/scanner/utils"
	"github.com/projectdiscovery/gologger"
)

var runTask = engine.RunTask

type execution struct {
	targets     []string
	decision    localstate.TargetDecision
	ruleVersion string
	configHash  string
}

type historySkip struct {
	ip     string
	source string
}

type historyPlanSummary struct {
	inputsFull       int
	inputsPartial    int
	inputsSkipped    int
	assetsPlanned    int
	assetsSkipped    int
	skippedAddresses []historySkip
}

// Execute applies CLI defaults and runs the remaining targets together.
func Execute(ctx *engine.ScanContext, run *localstate.Run) error {
	return ExecuteWithTiming(ctx, run, nil)
}

func ExecuteWithTiming(ctx *engine.ScanContext, run *localstate.Run, recorder *timing.Recorder, outputObservers ...func(engine.OutputMessage)) error {
	if ctx == nil || run == nil {
		return errors.New("local planner requires a scan context and active run")
	}
	originalTargets := append([]string(nil), ctx.Config.Targets...)
	cfg := applyCLISafetyDefaults(ctx.Config)
	ctx.Config = cfg

	policy := localstate.DefaultLocalPolicy()
	ruleVersion := localRuleVersion(ctx)
	configHash := localConfigHash(cfg, policy)
	var history dataResultHistory
	var historyWarnings []string
	if cfg.SkipSeenHistory && !ctx.LocalForceFullScan {
		history, historyWarnings = loadDataResultHistory(dataResultRoot(cfg.OutputFile), cfg.OutputFile)
	}
	run.AddWarnings(historyWarnings...)
	executions, decisions, planSummary := buildExecutions(cfg, history, ruleVersion, configHash, ctx.LocalForceFullScan)
	if err := run.SetTargetDecisions(decisions); err != nil {
		return fmt.Errorf("record CLI target decisions: %w", err)
	}
	run.SetPlanSummary(localstate.PlanSummary{
		InputsFull: planSummary.inputsFull, InputsPartial: planSummary.inputsPartial, InputsSkipped: planSummary.inputsSkipped,
		AssetsPlanned: planSummary.assetsPlanned, AssetsSkipped: planSummary.assetsSkipped,
	})
	logHistorySkips(planSummary)

	var scanErrors []error
	for _, item := range executions {
		ctx.Reset()
		ctx.LocalRunID = run.ID
		ctx.Config = cfg
		ctx.Config.Targets = append([]string(nil), item.targets...)
		ctx.OutputObserver = run.ObserveOutput

		reporter := newStageReporter(run, item.targets, ctx.Config, policy, item.ruleVersion, item.configHash, nil).withTiming(recorder)
		ctx.OutputObserver = func(message engine.OutputMessage) {
			run.ObserveOutput(message)
			reporter.observeOutput(message)
			for _, observer := range outputObservers {
				if observer != nil {
					observer(message)
				}
			}
		}
		ctx.PhaseObserver = reporter.observePhase
		if cfg.TraceOnly {
			gologger.Info().Msgf("[Argus] path: %s", strings.Join(item.targets, ", "))
		} else {
			gologger.Info().Msgf("[Argus] %s scan: %s", item.decision.Action, strings.Join(item.targets, ", "))
		}
		scanErr := runTask(ctx)
		reporter.finalize(scanErr)
		if scanErr != nil {
			scanErrors = append(scanErrors, fmt.Errorf("scan %s: %w", strings.Join(item.targets, ", "), scanErr))
		}
	}
	ctx.Config = cfg
	ctx.Config.Targets = originalTargets
	return errors.Join(scanErrors...)
}

func applyCLISafetyDefaults(cfg engine.Config) engine.Config {
	// Standalone CLI defaults to risk-on: Nuclei POC and GoPoc (including
	// service credential brute force) run unless disabled explicitly with
	// -nopoc / -nogpoc / -nobr. See CLI.md and docs/implementation-status.md.
	if cfg.NoGoPoc {
		cfg.GolangPoc = false
	} else {
		cfg.GolangPoc = true
	}
	return cfg
}

func buildExecutions(cfg engine.Config, history dataResultHistory, ruleVersion, configHash string, force bool) ([]execution, map[string]localstate.TargetDecision, historyPlanSummary) {
	decisions := make(map[string]localstate.TargetDecision, len(cfg.Targets))
	fullTargets := make([]string, 0, len(cfg.Targets))
	seenTargets := make(map[string]struct{}, len(cfg.Targets))
	summary := historyPlanSummary{}
	skipSeen := cfg.SkipSeenHistory && !force
	for _, rawTarget := range cfg.Targets {
		target := strings.TrimSpace(rawTarget)
		stateTarget := localstate.NormalizeTargetForState(target)
		if _, duplicate := seenTargets[stateTarget]; duplicate {
			continue
		}
		seenTargets[stateTarget] = struct{}{}
		decision := localstate.TargetDecision{Action: "full", Reason: "history_asset_missing"}
		if force {
			decision.Reason = "force_full_scan"
		} else if skipSeen {
			planned, skipped := subtractHistoryAssets(target, history)
			if len(skipped) > 0 {
				summary.assetsSkipped += len(skipped)
				summary.skippedAddresses = append(summary.skippedAddresses, skipped...)
			}
			switch {
			case len(planned) == 0 && len(skipped) > 0:
				summary.inputsSkipped++
				decision = localstate.TargetDecision{Action: "skipped", Reason: "history_asset_match:" + skipped[0].source}
				decisions[stateTarget] = decision
				continue
			case len(skipped) > 0:
				summary.inputsPartial++
				decision = localstate.TargetDecision{Action: "partial", Reason: "history_asset_difference"}
				for _, item := range planned {
					if _, duplicate := seenTargets[item]; duplicate {
						continue
					}
					seenTargets[item] = struct{}{}
					fullTargets = append(fullTargets, item)
					summary.assetsPlanned++
				}
				decisions[stateTarget] = decision
				continue
			}
		}
		fullTargets = append(fullTargets, target)
		summary.inputsFull++
		summary.assetsPlanned += targetAssetCount(target)
		decisions[stateTarget] = decision
	}
	executions := make([]execution, 0, 1)
	if len(fullTargets) > 0 {
		executions = append(executions, execution{
			targets: fullTargets, decision: localstate.TargetDecision{Action: "full", Reason: "history_asset_missing"},
			ruleVersion: ruleVersion, configHash: configHash,
		})
	}
	return executions, decisions, summary
}

func subtractHistoryAssets(target string, history dataResultHistory) ([]string, []historySkip) {
	switch utils.GetInputType(target) {
	case engine.TypeIP:
		if source, ok := history.MatchIP(target); ok {
			return nil, []historySkip{{ip: target, source: source}}
		}
	case engine.TypeCIDR:
		if !cidrContainsHistory(target, history) {
			return []string{target}, nil
		}
		return subtractExpandedIPs(utils.CIDRToIP(target), history)
	case engine.TypeIPRange:
		return subtractExpandedIPs(utils.RangerToIP(target), history)
	default:
		if source, ok := history.MatchTarget(target); ok {
			return nil, []historySkip{{ip: firstNonEmpty(targetIP(target), target), source: source}}
		}
	}
	return []string{target}, nil
}

func subtractExpandedIPs(values []net.IP, history dataResultHistory) ([]string, []historySkip) {
	planned := make([]string, 0, len(values))
	skipped := make([]historySkip, 0)
	for _, value := range values {
		ip := value.String()
		if source, ok := history.MatchIP(ip); ok {
			skipped = append(skipped, historySkip{ip: ip, source: source})
			continue
		}
		planned = append(planned, ip)
	}
	return planned, skipped
}

func targetAssetCount(target string) int {
	switch utils.GetInputType(target) {
	case engine.TypeCIDR:
		if _, network, err := net.ParseCIDR(target); err == nil {
			ones, bits := network.Mask.Size()
			if ones >= 0 && bits == 32 {
				return int(uint64(1) << uint(bits-ones))
			}
		}
		return len(utils.CIDRToIP(target))
	case engine.TypeIPRange:
		return len(utils.RangerToIP(target))
	default:
		return 1
	}
}

func cidrContainsHistory(target string, history dataResultHistory) bool {
	_, network, err := net.ParseCIDR(target)
	if err != nil {
		return false
	}
	for value := range history.ipSources {
		if ip := net.ParseIP(value); ip != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func logHistorySkips(summary historyPlanSummary) {
	for _, message := range historySkipMessages(summary) {
		gologger.Info().Msg(message)
	}
}

func historySkipMessages(summary historyPlanSummary) []string {
	if len(summary.skippedAddresses) == 0 {
		return nil
	}
	messages := make([]string, 0, len(summary.skippedAddresses)/24+2)
	const perLine = 24
	for start := 0; start < len(summary.skippedAddresses); start += perLine {
		end := start + perLine
		if end > len(summary.skippedAddresses) {
			end = len(summary.skippedAddresses)
		}
		items := make([]string, 0, end-start)
		for _, skipped := range summary.skippedAddresses[start:end] {
			items = append(items, skipped.ip+" ("+skipped.source+")")
		}
		messages = append(messages, "[Argus] 跳过 datas 历史 IP: "+strings.Join(items, ", "))
	}
	messages = append(messages, fmt.Sprintf("[Argus] datas 历史差集: 跳过=%d, 待扫描=%d", summary.assetsSkipped, summary.assetsPlanned))
	return messages
}

func localRuleVersion(ctx *engine.ScanContext) string {
	if version := strings.TrimSpace(ctx.LocalArsenalVersion); version != "" {
		return version
	}
	items := []string{"argus-network/v1", "argus-protocol/v1", "argus-http/v1"}
	for _, rule := range ctx.FingerprintDB {
		items = append(items, "finger:"+rule.ProductName+"\x00"+rule.AllString)
	}
	for product, paths := range ctx.DirDB {
		for _, path := range paths {
			items = append(items, "dir:"+product+"\x00"+path)
		}
	}
	sort.Strings(items)
	return hashValues(items...)
}

func localConfigHash(cfg engine.Config, policy localstate.LocalPolicy) string {
	semantic := struct {
		Ports                                                                                string
		Subdomain, SkipHostDiscovery, AllowLocalAreaDomain, AllowCDNAssets                   bool
		NoHostBind, NoDirSearch, NoICMPPing, TCPPing, UDPPing, TraceRoute, LowPerceptionMode bool
		PortScanType                                                                         string
		PortScanScatter                                                                    bool
		PortsThreshold, TCPPortScanTimeout, PortScanProbeInterval, GetBannerTimeout, WebTimeout int
		HTTPProxy                                                                            string
		LocalPolicy                                                                          localstate.LocalPolicy
	}{
		Ports: cfg.Ports, Subdomain: cfg.Subdomain, SkipHostDiscovery: cfg.SkipHostDiscovery,
		AllowLocalAreaDomain: cfg.AllowLocalAreaDomain, AllowCDNAssets: cfg.AllowCDNAssets,
		NoHostBind: cfg.NoHostBind, NoDirSearch: cfg.NoDirSearch, NoICMPPing: cfg.NoICMPPing,
		TCPPing: cfg.TCPPing, UDPPing: cfg.UDPPing, TraceRoute: cfg.TraceRoute, LowPerceptionMode: cfg.LowPerceptionMode, PortScanType: cfg.PortScanType,
		PortScanScatter: cfg.PortScanScatter, PortsThreshold: cfg.PortsThreshold, TCPPortScanTimeout: cfg.TCPPortScanTimeout,
		PortScanProbeInterval: cfg.PortScanProbeInterval,
		GetBannerTimeout: cfg.GetBannerTimeout, WebTimeout: cfg.WebTimeout, HTTPProxy: cfg.HTTPProxy,
		LocalPolicy: policy,
	}
	encoded, _ := json.Marshal(semantic)
	return sha256Hex(encoded)
}

func hashValues(values ...string) string {
	digest := sha256.New()
	for _, value := range values {
		_, _ = digest.Write([]byte(fmt.Sprintf("%d:", len(value))))
		_, _ = digest.Write([]byte(value))
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
