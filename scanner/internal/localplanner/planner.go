// Package localplanner executes the standalone CLI scan plan. It consumes
// local result history only and never uploads it.
package localplanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/P0lar1ght/argus/scanner/internal/engine"
	"github.com/P0lar1ght/argus/scanner/internal/localstate"
	"github.com/P0lar1ght/argus/scanner/internal/timing"
	"github.com/projectdiscovery/gologger"
)

var runTask = engine.RunTask

type execution struct {
	targets     []string
	decision    localstate.TargetDecision
	ruleVersion string
	configHash  string
}

// Execute applies safe local defaults, skips targets already present in datas
// history, and executes the remaining targets together.
func Execute(ctx *engine.ScanContext, run *localstate.Run) error {
	return ExecuteWithTiming(ctx, run, nil)
}

func ExecuteWithTiming(ctx *engine.ScanContext, run *localstate.Run, recorder *timing.Recorder, outputObservers ...func(engine.OutputMessage)) error {
	if ctx == nil || run == nil {
		return errors.New("local planner requires a scan context and active run")
	}
	originalTargets := append([]string(nil), ctx.Config.Targets...)
	cfg, explicitRisk := applyCLISafetyDefaults(ctx.Config)
	ctx.Config = cfg

	policy := localstate.DefaultLocalPolicy()
	ruleVersion := localRuleVersion(ctx)
	configHash := localConfigHash(cfg, policy)
	history, historyWarnings := loadDataResultHistory(dataResultRoot(cfg.OutputFile), cfg.OutputFile)
	run.AddWarnings(historyWarnings...)
	executions, decisions := buildExecutions(cfg, history, ruleVersion, configHash, explicitRisk, ctx.LocalForceFullScan)
	if err := run.SetTargetDecisions(decisions); err != nil {
		return fmt.Errorf("record CLI target decisions: %w", err)
	}

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
		gologger.Info().Msgf("[Argus] %s scan: %s", item.decision.Action, strings.Join(item.targets, ", "))
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

func applyCLISafetyDefaults(cfg engine.Config) (engine.Config, bool) {
	explicitRisk := strings.TrimSpace(cfg.PocNameForSearch) != "" || cfg.GolangPoc
	if explicitRisk {
		return cfg, true
	}
	// Ordinary CLI discovery is safe by default. POC and credential checks
	// remain available only through their existing explicit flags.
	cfg.NoPoc = true
	cfg.GolangPoc = false
	cfg.DisableGeneralPoc = true
	cfg.PocNameForSearch = ""
	return cfg, false
}

func buildExecutions(cfg engine.Config, history dataResultHistory, ruleVersion, configHash string, explicitRisk, force bool) ([]execution, map[string]localstate.TargetDecision) {
	decisions := make(map[string]localstate.TargetDecision, len(cfg.Targets))
	fullTargets := make([]string, 0, len(cfg.Targets))
	seenTargets := make(map[string]struct{}, len(cfg.Targets))
	for _, rawTarget := range cfg.Targets {
		target := strings.TrimSpace(rawTarget)
		stateTarget := localstate.NormalizeTargetForState(target)
		if _, duplicate := seenTargets[target]; duplicate {
			continue
		}
		seenTargets[target] = struct{}{}
		decision := localstate.TargetDecision{Action: "full", Reason: "history_asset_missing"}
		if force {
			decision.Reason = "force_full_scan"
		} else if explicitRisk {
			decision.Reason = "explicit_risk_operation"
		} else if source, ok := history.MatchTarget(target); ok {
			decision = localstate.TargetDecision{Action: "skipped", Reason: "history_asset_match:" + source}
			decisions[stateTarget] = decision
			continue
		}
		fullTargets = append(fullTargets, target)
		decisions[stateTarget] = decision
	}
	executions := make([]execution, 0, 1)
	if len(fullTargets) > 0 {
		executions = append(executions, execution{
			targets: fullTargets, decision: localstate.TargetDecision{Action: "full", Reason: "history_asset_missing"},
			ruleVersion: ruleVersion, configHash: configHash,
		})
	}
	return executions, decisions
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
		Ports                                                              string
		Subdomain, SkipHostDiscovery, AllowLocalAreaDomain, AllowCDNAssets bool
		NoHostBind, NoDirSearch, NoICMPPing, TCPPing, LowPerceptionMode    bool
		PortScanType                                                       string
		PortsThreshold, TCPPortScanTimeout, GetBannerTimeout, WebTimeout   int
		HTTPProxy                                                          string
		LocalPolicy                                                        localstate.LocalPolicy
	}{
		Ports: cfg.Ports, Subdomain: cfg.Subdomain, SkipHostDiscovery: cfg.SkipHostDiscovery,
		AllowLocalAreaDomain: cfg.AllowLocalAreaDomain, AllowCDNAssets: cfg.AllowCDNAssets,
		NoHostBind: cfg.NoHostBind, NoDirSearch: cfg.NoDirSearch, NoICMPPing: cfg.NoICMPPing,
		TCPPing: cfg.TCPPing, LowPerceptionMode: cfg.LowPerceptionMode, PortScanType: cfg.PortScanType,
		PortsThreshold: cfg.PortsThreshold, TCPPortScanTimeout: cfg.TCPPortScanTimeout,
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
