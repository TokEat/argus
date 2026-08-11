// Package localplanner executes the conservative internal-fast policy for the
// standalone CLI. It only consumes local TSV history and never uploads it.
package localplanner

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/P0lar1ght/argus/scanner/internal/engine"
	"github.com/P0lar1ght/argus/scanner/internal/localstate"
	"github.com/P0lar1ght/argus/scanner/internal/timing"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/scanner/utils"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
	"github.com/projectdiscovery/gologger"
)

var probeTCP = func(endpoint string, timeout time.Duration) bool {
	connection, err := net.DialTimeout("tcp", endpoint, timeout)
	if err != nil {
		return false
	}
	_ = connection.Close()
	return true
}

type execution struct {
	targets     []string
	plan        *scanplan.ResumePlan
	planHash    string
	decision    localstate.TargetDecision
	reused      []localstate.CoverageRecord
	preflight   []localstate.CoverageRecord
	ruleVersion string
	configHash  string
}

// Execute applies safe local defaults, plans each target, and executes full
// targets together while preserving single-target resume-plan validation.
func Execute(ctx *engine.ScanContext, run *localstate.Run) error {
	return ExecuteWithTiming(ctx, run, nil)
}

func ExecuteWithTiming(ctx *engine.ScanContext, run *localstate.Run, recorder *timing.Recorder) error {
	if ctx == nil || run == nil {
		return errors.New("local planner requires a scan context and active run")
	}
	originalTargets := append([]string(nil), ctx.Config.Targets...)
	cfg, explicitRisk := applyCLISafetyDefaults(ctx.Config)
	ctx.Config = cfg

	policy, err := localstate.LoadLocalPolicy(localstate.Home{Root: ctx.LocalDataRoot})
	if err != nil {
		return fmt.Errorf("load CLI local policy: %w", err)
	}
	snapshot, err := localstate.LoadSnapshot(localstate.Home{Root: ctx.LocalDataRoot})
	if err != nil {
		return fmt.Errorf("load CLI state for planning: %w", err)
	}
	run.AddWarnings(snapshot.Warnings...)
	ruleVersion := localRuleVersion(ctx)
	configHash := localConfigHash(cfg, policy)
	executions, decisions := buildExecutions(cfg, snapshot, policy, ruleVersion, configHash, time.Now().UTC(), explicitRisk, ctx.LocalForceFullScan)
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
		for _, observation := range item.preflight {
			run.ObserveCoverage("executed", "lightweight_revalidation", observation)
		}
		if item.plan != nil {
			if err := engine.ValidateResumePlan(ctx.Config, item.targets, item.ruleVersion, item.planHash, item.plan); err != nil {
				run.AddWarnings(fmt.Sprintf("incremental plan for %s rejected; full scan used: %v", item.targets[0], err))
				item.plan = nil
				item.decision = localstate.TargetDecision{Action: "full", Reason: "resume_plan_rejected"}
				_ = run.SetTargetDecisions(map[string]localstate.TargetDecision{
					localstate.NormalizeTargetForState(item.targets[0]): item.decision,
				})
			} else {
				ctx.ResumePlan = item.plan
				for _, reused := range item.reused {
					run.ObserveCoverage("reused", "valid_local_coverage", reused)
				}
			}
		}

		reporter := newStageReporter(run, item.targets, ctx.Config, policy, item.ruleVersion, item.configHash, ctx.ResumePlan).withTiming(recorder)
		ctx.OutputObserver = func(message engine.OutputMessage) {
			run.ObserveOutput(message)
			reporter.observeOutput(message)
		}
		ctx.PhaseObserver = reporter.observePhase
		gologger.Info().Msgf("[Argus] %s scan: %s", item.decision.Action, strings.Join(item.targets, ", "))
		scanErr := engine.RunTask(ctx)
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

func buildExecutions(cfg engine.Config, snapshot localstate.Snapshot, policy localstate.LocalPolicy, ruleVersion, configHash string, now time.Time, explicitRisk, force bool) ([]execution, map[string]localstate.TargetDecision) {
	decisions := make(map[string]localstate.TargetDecision, len(cfg.Targets))
	fullTargets := make([]string, 0, len(cfg.Targets))
	incremental := make([]execution, 0, len(cfg.Targets))
	coverageByKey := make(map[string]localstate.CoverageRecord, len(snapshot.Coverages))
	for _, coverage := range snapshot.Coverages {
		coverageByKey[coverage.WorkKey] = coverage
	}
	seenTargets := make(map[string]struct{}, len(cfg.Targets))
	for _, rawTarget := range cfg.Targets {
		target := strings.TrimSpace(rawTarget)
		stateTarget := localstate.NormalizeTargetForState(target)
		if _, duplicate := seenTargets[target]; duplicate {
			continue
		}
		seenTargets[target] = struct{}{}
		decision := localstate.TargetDecision{Action: "full", Reason: "no_reusable_coverage"}
		if force {
			decision.Reason = "force_full_scan"
		} else if explicitRisk {
			decision.Reason = "explicit_risk_operation"
		} else if planned, ok := planIncrementalTarget(target, cfg, snapshot.Assets, coverageByKey, policy, ruleVersion, configHash, now); ok {
			decision = localstate.TargetDecision{Action: "incremental", Reason: "known_services_revalidated"}
			planned.decision = decision
			incremental = append(incremental, planned)
			decisions[stateTarget] = decision
			continue
		}
		fullTargets = append(fullTargets, target)
		decisions[stateTarget] = decision
	}
	executions := make([]execution, 0, len(incremental)+1)
	if len(fullTargets) > 0 {
		executions = append(executions, execution{
			targets: fullTargets, decision: localstate.TargetDecision{Action: "full", Reason: "coverage_missing_expired_or_changed"},
			ruleVersion: ruleVersion, configHash: configHash,
		})
	}
	return append(executions, incremental...), decisions
}

func planIncrementalTarget(target string, cfg engine.Config, assets []localstate.AssetRecord, coverageByKey map[string]localstate.CoverageRecord, policy localstate.LocalPolicy, ruleVersion, configHash string, now time.Time) (execution, bool) {
	targetType := utils.GetInputType(target)
	if targetType != structs.TypeIP && targetType != structs.TypeCIDR && targetType != structs.TypeIPRange {
		return execution{}, false
	}
	required, ok := engine.RequiredResumeStages(target, cfg)
	if !ok || len(required) < 2 || required[0] != scanplan.StagePortScan {
		return execution{}, false
	}
	scopeHash := hashValues("internal-fast", target)
	key := scanplan.WorkKey{
		TenantID: scanplan.LocalTenantID, ProjectID: scanplan.LocalProjectID, NetworkZone: scanplan.LocalNetworkZone,
		NormalizedTarget: target, Stage: scanplan.StagePortScan, ScopeHash: scopeHash, ConfigHash: configHash, RuleVersion: ruleVersion,
	}
	workKey, err := key.Digest()
	if err != nil {
		return execution{}, false
	}
	coverage, exists := coverageByKey[workKey]
	if !exists || (coverage.Outcome != "success" && coverage.Outcome != "negative") || coverage.ValidUntil.IsZero() || !coverage.ValidUntil.After(now) {
		return execution{}, false
	}
	openPorts := assetEndpointsForTarget(assets, target)
	preflight, ok := preflightTarget(target, cfg.Ports, openPorts, assetHostsForTarget(assets, target), policy.Revalidation)
	if len(openPorts) > scanplan.MaxCheckpointItems || !ok || !preflight.unchanged || (policy.Revalidation.LivenessEveryRun && !preflight.livenessProbed) {
		return execution{}, false
	}
	checkpoint := scanplan.StageCheckpoint{
		SchemaVersion: scanplan.CheckpointSchemaVersion, Stage: scanplan.StagePortScan, OpenPorts: openPorts,
	}
	checkpointJSON, err := checkpoint.CanonicalJSON()
	if err != nil {
		return execution{}, false
	}
	checkpointHash := sha256Hex(checkpointJSON)
	observationHash := hashValues(coverage.WorkKey, coverage.ContentHash, coverage.ObservedAt.UTC().Format(time.RFC3339Nano), coverage.LastRunID)
	plan := &scanplan.ResumePlan{
		SchemaVersion: scanplan.ResumePlanSchemaVersion,
		TenantID:      scanplan.LocalTenantID, ProjectID: scanplan.LocalProjectID, NetworkZone: scanplan.LocalNetworkZone,
		Target: target, ScopeHash: scopeHash, ConfigHash: configHash, RuleVersion: ruleVersion,
		RequiredStages: required, ReusedStages: []scanplan.Stage{scanplan.StagePortScan},
		ExecutionStages: append([]scanplan.Stage(nil), required[1:]...), StartStage: required[1],
		Checkpoints: []scanplan.ResumeCheckpoint{{
			Stage: scanplan.StagePortScan, WorkKeyHash: coverage.WorkKey,
			CoverageID: syntheticID(coverage.WorkKey), SourceObservationID: syntheticID(observationHash),
			ObservationHash: observationHash, CheckpointHash: checkpointHash, Checkpoint: checkpoint,
		}},
	}
	planHash, err := plan.Digest()
	if err != nil {
		return execution{}, false
	}
	result := execution{
		targets: []string{target}, plan: plan, planHash: planHash, reused: []localstate.CoverageRecord{coverage},
		ruleVersion: ruleVersion, configHash: configHash,
	}
	if policy.Revalidation.LivenessEveryRun {
		outcome := "negative"
		if len(preflight.openEndpoints) > 0 {
			outcome = "success"
		}
		livenessKey := scanplan.WorkKey{
			TenantID: scanplan.LocalTenantID, ProjectID: scanplan.LocalProjectID, NetworkZone: scanplan.LocalNetworkZone,
			NormalizedTarget: target, Stage: scanplan.StageTCPLiveness, ScopeHash: scopeHash, ConfigHash: configHash, RuleVersion: ruleVersion,
		}
		if digest, digestErr := livenessKey.Digest(); digestErr == nil {
			result.preflight = append(result.preflight, localstate.CoverageRecord{
				WorkKey: digest, NormalizedTarget: target, Stage: string(scanplan.StageTCPLiveness),
				ScopeHash: scopeHash, ConfigHash: configHash, RuleVersion: ruleVersion,
				Outcome: outcome, ContentHash: hashValues(preflight.openEndpoints...), ObservedAt: now,
				ValidUntil: now.Add(policy.TTL.Liveness.Value()),
			})
		}
	}
	return result, true
}

type probeExpectation struct {
	compare      bool
	expectedOpen bool
	liveness     bool
}

type preflightResult struct {
	unchanged      bool
	livenessProbed bool
	openEndpoints  []string
}

func preflightTarget(target, configuredPorts string, knownEndpoints, knownHosts []string, policy localstate.LocalRevalidationPolicy) (preflightResult, bool) {
	if len(knownEndpoints) > policy.MaxEndpoints {
		return preflightResult{}, false
	}
	candidates := make(map[string]probeExpectation, len(knownEndpoints)+len(knownHosts)*len(policy.LivenessPorts))
	if policy.KnownServicesEveryRun {
		for _, endpoint := range knownEndpoints {
			candidates[endpoint] = probeExpectation{compare: true, expectedOpen: true}
		}
	}
	if policy.LivenessEveryRun {
		if utils.GetInputType(target) == structs.TypeIP {
			knownHosts = append(knownHosts, target)
		}
		knownHosts = uniqueSorted(knownHosts)
		for _, host := range knownHosts {
			for _, number := range policy.LivenessPorts {
				port := strconv.Itoa(number)
				endpoint := net.JoinHostPort(host, port)
				if existing, exists := candidates[endpoint]; exists {
					existing.liveness = true
					candidates[endpoint] = existing
					continue
				}
				candidates[endpoint] = probeExpectation{compare: portIncluded(configuredPorts, port), expectedOpen: false, liveness: true}
			}
		}
	}
	if len(candidates) > policy.MaxEndpoints {
		return preflightResult{}, false
	}
	type result struct {
		endpoint string
		expect   probeExpectation
		open     bool
	}
	jobs := make(chan string)
	results := make(chan result, len(candidates))
	workers := policy.Concurrency
	if len(candidates) < workers {
		workers = len(candidates)
	}
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for endpoint := range jobs {
				results <- result{endpoint: endpoint, expect: candidates[endpoint], open: probeTCP(endpoint, policy.Timeout.Value())}
			}
		}()
	}
	for endpoint := range candidates {
		jobs <- endpoint
	}
	close(jobs)
	wait.Wait()
	close(results)
	preflight := preflightResult{unchanged: true}
	for item := range results {
		if item.expect.liveness {
			preflight.livenessProbed = true
		}
		if item.open {
			preflight.openEndpoints = append(preflight.openEndpoints, item.endpoint)
		}
		if item.expect.compare && item.expect.expectedOpen != item.open {
			preflight.unchanged = false
		}
	}
	sort.Strings(preflight.openEndpoints)
	return preflight, true
}

func portIncluded(configuredPorts, candidate string) bool {
	wanted, err := strconv.Atoi(candidate)
	if err != nil {
		return false
	}
	for _, item := range strings.Split(configuredPorts, ",") {
		item = strings.TrimSpace(item)
		if item == candidate {
			return true
		}
		bounds := strings.SplitN(item, "-", 2)
		if len(bounds) != 2 {
			continue
		}
		first, firstErr := strconv.Atoi(strings.TrimSpace(bounds[0]))
		last, lastErr := strconv.Atoi(strings.TrimSpace(bounds[1]))
		if firstErr == nil && lastErr == nil && wanted >= first && wanted <= last {
			return true
		}
	}
	return false
}

func assetEndpointsForTarget(assets []localstate.AssetRecord, target string) []string {
	seen := make(map[string]struct{})
	for _, asset := range assets {
		if asset.NetworkZone != scanplan.LocalNetworkZone || asset.AssetType != "ip_port" || !strings.EqualFold(asset.Status, "active") {
			continue
		}
		host, port, err := net.SplitHostPort(asset.NormalizedTarget)
		if err != nil || !targetContainsIP(target, net.ParseIP(host)) {
			continue
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			continue
		}
		seen[net.JoinHostPort(host, port)] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for endpoint := range seen {
		result = append(result, endpoint)
	}
	sort.Strings(result)
	return result
}

func assetHostsForTarget(assets []localstate.AssetRecord, target string) []string {
	hosts := make([]string, 0)
	for _, asset := range assets {
		if asset.NetworkZone != scanplan.LocalNetworkZone || !strings.EqualFold(asset.Status, "active") {
			continue
		}
		host := asset.NormalizedTarget
		if asset.AssetType == "ip_port" {
			parsedHost, _, err := net.SplitHostPort(host)
			if err != nil {
				continue
			}
			host = parsedHost
		} else if asset.AssetType != "ip" {
			continue
		}
		if targetContainsIP(target, net.ParseIP(host)) {
			hosts = append(hosts, host)
		}
	}
	return uniqueSorted(hosts)
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func targetContainsIP(target string, ip net.IP) bool {
	if ip == nil || ip.To4() == nil {
		return false
	}
	switch utils.GetInputType(target) {
	case structs.TypeIP:
		return net.ParseIP(target).Equal(ip)
	case structs.TypeCIDR:
		_, network, err := net.ParseCIDR(target)
		return err == nil && network.Contains(ip)
	case structs.TypeIPRange:
		parts := strings.SplitN(target, "-", 2)
		if len(parts) != 2 {
			return false
		}
		first := net.ParseIP(parts[0]).To4()
		lastText := parts[1]
		if strings.Count(lastText, ".") < 3 {
			prefix := strings.Split(parts[0], ".")
			suffix := strings.Split(lastText, ".")
			if len(prefix) < len(suffix) {
				return false
			}
			lastText = strings.Join(append(prefix[:len(prefix)-len(suffix)], suffix...), ".")
		}
		last := net.ParseIP(lastText).To4()
		value := binary.BigEndian.Uint32(ip.To4())
		return first != nil && last != nil && value >= binary.BigEndian.Uint32(first) && value <= binary.BigEndian.Uint32(last)
	default:
		return false
	}
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

func syntheticID(value string) uint64 {
	digest := sha256.Sum256([]byte(value))
	result := binary.BigEndian.Uint64(digest[:8])
	if result == 0 {
		return 1
	}
	return result
}
