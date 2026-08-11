package engine

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/P0lar1ght/argus/scanner/utils"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
)

// ValidateResumePlan independently reconstructs the stages implied by the
// runtime Config. Server plans are not trusted to decide which stages exist.
func ValidateResumePlan(cfg Config, targets []string, ruleVersion, planHash string, plan *scanplan.ResumePlan) error {
	if plan == nil {
		return errors.New("resume plan is missing")
	}
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("validate resume plan contract: %w", err)
	}
	digest, err := plan.Digest()
	if err != nil || digest != strings.TrimSpace(planHash) {
		return errors.New("resume plan hash does not match its canonical payload")
	}
	if len(targets) != 1 || strings.TrimSpace(targets[0]) != plan.Target {
		return errors.New("resume plan target does not match the assigned single target")
	}
	if strings.TrimSpace(ruleVersion) == "" || strings.TrimSpace(ruleVersion) != plan.RuleVersion {
		return errors.New("resume plan rule version does not match the active Agent rules")
	}
	if strings.TrimSpace(cfg.ExecutionMode) != "" || cfg.OnlyIPPort {
		return errors.New("resume plan is not allowed for risk-validation or IP-only execution modes")
	}
	if !cfg.NoPoc || cfg.GolangPoc || !cfg.DisableGeneralPoc || strings.TrimSpace(cfg.PocNameForSearch) != "" {
		return errors.New("resume plan requires an asset-discovery task with POC execution disabled")
	}
	applyAgentSmallTargetPolicy(&cfg)
	required, ok := resumeStagesForTarget(plan.Target, cfg)
	if !ok || !slices.Equal(required, plan.RequiredStages) {
		return errors.New("resume plan stages do not match the runtime target and config")
	}
	expectedCheckpoints, supported := resumeDependencyCheckpoints(required, plan.StartStage)
	if !supported {
		return fmt.Errorf("resume start stage %q cannot be restored safely", plan.StartStage)
	}
	actualCheckpoints := make([]scanplan.Stage, 0, len(plan.Checkpoints))
	for _, checkpoint := range plan.Checkpoints {
		actualCheckpoints = append(actualCheckpoints, checkpoint.Stage)
	}
	if !slices.Equal(expectedCheckpoints, actualCheckpoints) {
		return errors.New("resume plan checkpoints do not satisfy the execution-stage dependencies")
	}
	return nil
}

func applyAgentSmallTargetPolicy(cfg *Config) {
	if cfg == nil || cfg.TCPPing || cfg.SkipHostDiscovery {
		return
	}
	if estimateIPCount(cfg.Targets) <= 256 {
		cfg.SkipHostDiscovery = true
	}
}

// RequiredResumeStages returns the exact stage order accepted by
// ValidateResumePlan for a target and runtime config. Local and Server
// planners use this helper instead of duplicating Pipeline ordering rules.
func RequiredResumeStages(target string, cfg Config) ([]scanplan.Stage, bool) {
	applyAgentSmallTargetPolicy(&cfg)
	stages, ok := resumeStagesForTarget(target, cfg)
	return append([]scanplan.Stage(nil), stages...), ok
}

func resumeStagesForTarget(target string, cfg Config) ([]scanplan.Stage, bool) {
	common := []scanplan.Stage{scanplan.StageHTTPProbe}
	if !cfg.NoHostBind {
		common = append(common, scanplan.StageHostBinding)
	}
	if !cfg.NoDirSearch {
		common = append(common, scanplan.StageDirectoryProbe)
	}
	common = append(common, scanplan.StageFingerprint)

	switch utils.GetInputType(target) {
	case TypeURL:
		return common, true
	case TypeIP, TypeCIDR, TypeIPRange:
		stages := make([]scanplan.Stage, 0, len(common)+4)
		if !cfg.SkipHostDiscovery && !cfg.NoICMPPing {
			stages = append(stages, scanplan.StageICMPDiscovery)
		}
		if !cfg.SkipHostDiscovery && cfg.TCPPing {
			stages = append(stages, scanplan.StageTCPLiveness)
		}
		stages = append(stages, scanplan.StagePortScan, scanplan.StageProtocolIdentify)
		return append(stages, common...), true
	case TypeDomain:
		stages := make([]scanplan.Stage, 0, len(common)+4)
		if cfg.Subdomain {
			stages = append(stages, scanplan.StageSubdomainDiscovery)
		}
		stages = append(stages, scanplan.StageCDNClassification, scanplan.StagePortScan, scanplan.StageProtocolIdentify)
		return append(stages, common...), true
	case TypeIPPort, TypeDomainPort:
		return append([]scanplan.Stage{scanplan.StageProtocolIdentify}, common...), true
	default:
		return nil, false
	}
}

func resumeDependencyCheckpoints(required []scanplan.Stage, start scanplan.Stage) ([]scanplan.Stage, bool) {
	startIndex := resumeStageIndex(required, start)
	if startIndex < 0 {
		return nil, false
	}
	switch start {
	case scanplan.StageSubdomainDiscovery, scanplan.StageCDNClassification:
		return nil, startIndex == 0
	case scanplan.StageICMPDiscovery:
		return nil, true
	case scanplan.StageTCPLiveness:
		return resumePriorStages(required, startIndex, scanplan.StageICMPDiscovery), true
	case scanplan.StagePortScan:
		return resumePriorStages(required, startIndex, scanplan.StageICMPDiscovery, scanplan.StageTCPLiveness), true
	case scanplan.StageProtocolIdentify:
		if resumeStageIndex(required[:startIndex], scanplan.StagePortScan) >= 0 {
			return []scanplan.Stage{scanplan.StagePortScan}, true
		}
		return nil, true
	case scanplan.StageHTTPProbe:
		if resumeStageIndex(required[:startIndex], scanplan.StageProtocolIdentify) >= 0 {
			return []scanplan.Stage{scanplan.StageProtocolIdentify}, true
		}
		return nil, true
	case scanplan.StageHostBinding, scanplan.StageDirectoryProbe, scanplan.StageFingerprint:
		return nil, false
	default:
		return nil, false
	}
}

func resumePriorStages(required []scanplan.Stage, end int, wanted ...scanplan.Stage) []scanplan.Stage {
	allowed := make(map[scanplan.Stage]struct{}, len(wanted))
	for _, stage := range wanted {
		allowed[stage] = struct{}{}
	}
	var stages []scanplan.Stage
	for _, stage := range required[:end] {
		if _, ok := allowed[stage]; ok {
			stages = append(stages, stage)
		}
	}
	return stages
}

func resumeStageIndex(stages []scanplan.Stage, wanted scanplan.Stage) int {
	for index, stage := range stages {
		if stage == wanted {
			return index
		}
	}
	return -1
}

func resumeStageEnabled(ctx *ScanContext, stage scanplan.Stage) bool {
	if ctx == nil || ctx.ResumePlan == nil {
		return true
	}
	return resumeStageIndex(ctx.ResumePlan.ExecutionStages, stage) >= 0
}

func resumeCheckpoint(ctx *ScanContext, stage scanplan.Stage) *scanplan.StageCheckpoint {
	if ctx == nil || ctx.ResumePlan == nil {
		return nil
	}
	for index := range ctx.ResumePlan.Checkpoints {
		if ctx.ResumePlan.Checkpoints[index].Stage == stage {
			return &ctx.ResumePlan.Checkpoints[index].Checkpoint
		}
	}
	return nil
}

func checkpointAliveHosts(ctx *ScanContext, stages ...scanplan.Stage) []string {
	var hosts []string
	for _, stage := range stages {
		if checkpoint := resumeCheckpoint(ctx, stage); checkpoint != nil {
			hosts = append(hosts, checkpoint.AliveHosts...)
		}
	}
	return utils.RemoveDuplicateElement(hosts)
}

func restoreResumeProtocolServices(ctx *ScanContext) {
	checkpoint := resumeCheckpoint(ctx, scanplan.StageProtocolIdentify)
	if checkpoint == nil {
		return
	}
	ctx.IPPortMapLock.Lock()
	defer ctx.IPPortMapLock.Unlock()
	for _, service := range checkpoint.Services {
		ctx.IPPortMap[service.Endpoint] = service.Protocol
	}
}
