// Package config 配置管理，封装 CLI 参数解析和初始化逻辑。
//
// 当前阶段（Phase 0.3）：此包作为桥接层，底层仍调用 common.Flag()。
// 后续阶段会将 common/flag.go 的逻辑逐步迁入此包。
package config

import (
	"dddd/scanner/common"
	"dddd/scanner/internal/arsenal"
	"dddd/scanner/internal/engine"
	"dddd/scanner/internal/localarsenal"
	"dddd/scanner/internal/localstate"
	"dddd/scanner/internal/timing"
	"fmt"
	"github.com/user/dddd-proto/go/scanplan"
	"os"
)

// PrepareCLIArsenal resolves the fixed offline package before either a scan or
// an arsenal management subcommand. It performs no network access.
func PrepareCLIArsenal(home localstate.Home) (localarsenal.Activation, error) {
	activation, err := localarsenal.Prepare(home.Root)
	if err != nil {
		return localarsenal.Activation{}, err
	}
	arsenal.SetDefaultDBPath(activation.DBPath)
	return activation, nil
}

// InitCLI 解析命令行参数并完成初始化。
// 当前实现为桥接调用 common.Flag()，后续将内联替换。
func InitCLI() (*engine.ScanContext, error) {
	return InitCLIWithTiming(nil)
}

// InitCLIWithTiming is the injectable CLI initializer used by local timing.
func InitCLIWithTiming(recorder *timing.Recorder) (*engine.ScanContext, error) {
	presentation := common.ConfigureCLIPresentation(os.Args[1:])
	if err := common.ValidateCLIOutputType(presentation.OutputType); err != nil {
		return nil, err
	}
	if cliHelpRequested(os.Args[1:]) {
		if err := common.FlagWithError(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("help output completed")
	}
	home, err := localstate.Ensure()
	if err != nil {
		return nil, err
	}
	ruleSpan, _ := beginTiming(recorder, scanplan.TimingRulePrepare, "")
	activation, err := PrepareCLIArsenal(home)
	if err != nil {
		finishTiming(ruleSpan, scanplan.ObservationFailed)
		return nil, err
	}
	if activation.Active {
		common.ConfigureCLIRulePackage(activation.ConfigDir)
	}
	if err := common.FlagWithError(); err != nil {
		finishTiming(ruleSpan, scanplan.ObservationFailed)
		return nil, err
	}
	finishTiming(ruleSpan, scanplan.ObservationSuccess)
	contextSpan, _ := beginTiming(recorder, scanplan.TimingContextInit, "")
	ctx, err := engine.NewScanContextFromLegacyGlobals("cli-local")
	if err != nil {
		finishTiming(contextSpan, scanplan.ObservationFailed)
		return nil, err
	}
	finishTiming(contextSpan, scanplan.ObservationSuccess)
	ctx.LocalDataRoot = home.Root
	ctx.LocalForceFullScan = common.CLIForceFullScan
	ctx.LocalArsenalVersion = activation.RuleVersion
	return ctx, nil
}

func beginTiming(r *timing.Recorder, kind scanplan.TimingKind, stage scanplan.Stage) (*timing.Span, error) {
	if r == nil {
		return nil, nil
	}
	return r.Begin(kind, stage)
}
func finishTiming(span *timing.Span, outcome scanplan.ObservationOutcome) {
	if span != nil {
		_ = span.Finish(outcome)
	}
}

func cliHelpRequested(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}
