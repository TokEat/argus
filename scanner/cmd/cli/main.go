package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/scanner/common"
	"github.com/P0lar1ght/argus/scanner/common/report"
	"github.com/P0lar1ght/argus/scanner/ddout"
	"github.com/P0lar1ght/argus/scanner/internal/arsenal"
	"github.com/P0lar1ght/argus/scanner/internal/config"
	"github.com/P0lar1ght/argus/scanner/internal/localplanner"
	"github.com/P0lar1ght/argus/scanner/internal/localstate"
	"github.com/P0lar1ght/argus/scanner/internal/timing"
	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
)

const (
	exitSuccess  = 0
	exitFailure  = 1
	exitUsage    = 2
	exitCanceled = 130
)

func main() {
	if exitCode := runCLI(); exitCode != exitSuccess {
		os.Exit(exitCode)
	}
}

func runCLI() int {
	if handled, exitCode := dispatchEarlyCLI(os.Args[1:], os.Stdout, os.Stderr); handled {
		return exitCode
	}
	presentation := common.ConfigureCLIPresentation(os.Args[1:])

	recorder := timing.NewRecorder(nil)
	startup, _ := recorder.Begin(scanplan.TimingProcessStartup, "")
	if handled, exitCode := dispatchArsenalCommand(os.Args[1:]); handled {
		return exitCode
	}

	ctx, err := config.InitCLIWithTiming(recorder)
	if err != nil {
		var usageErr *common.CLIUsageError
		if errors.As(err, &usageErr) {
			writeCLIError("invalid arguments", usageErr)
			return exitUsage
		}
		writeCLIError("cli init failed", err)
		return exitFailure
	}
	defer ctx.Close()

	run, err := localstate.StartRun(localstate.Home{Root: ctx.LocalDataRoot}, ctx.Config.Targets)
	if err != nil {
		writeCLIError("cli history init failed", err)
		return exitFailure
	}
	reportSession, err := report.NewSession(report.Options{
		Path:       ctx.Config.ReportName,
		RunID:      run.ID,
		Targets:    ctx.Config.Targets,
		SourceFile: ctx.Config.OutputFile,
		StartedAt:  time.Now(),
	})
	if err != nil {
		_ = run.Finish(err)
		writeCLIError("cli report init failed", err)
		return exitFailure
	}
	defer reportSession.Abort()
	if err := ddout.BeginRun(run.ID); err != nil {
		_ = run.Finish(err)
		writeCLIError("cli output init failed", err)
		return exitFailure
	}
	if startup != nil {
		_ = startup.Finish(scanplan.ObservationSuccess)
	}
	if err := recorder.Bind(run.ID, "cli-local"); err != nil && presentation.Interactive {
		writeCLIError("cli timing bind failed", err)
	}

	stopInterruptWatch := watchInterrupt(ctx.Cancel)
	defer stopInterruptWatch()
	scanErr := localplanner.ExecuteWithTiming(ctx, run, recorder, reportSession.Observe)
	if events, snapshotErr := recorder.Snapshot(); snapshotErr != nil {
		if presentation.Interactive {
			writeCLIError("cli timing snapshot failed", snapshotErr)
		}
	} else {
		for _, event := range events {
			run.ObserveTiming(event)
		}
	}

	historyErr := run.Finish(scanErr)
	if presentation.Interactive {
		for _, warning := range run.Warnings() {
			fmt.Fprintf(os.Stderr, "Argus CLI: history warning: %s\n", warning)
		}
	}

	difference := localstate.DifferenceSummary{}
	var summaryErr error
	if historyErr == nil {
		difference, summaryErr = run.DifferenceSummary()
	}
	if presentation.Interactive && scanErr == nil && historyErr == nil {
		writeInteractiveSummaries(ctx.Config.OutputType, run, difference, summaryErr)
	}

	outputErr := ddout.RunError()
	_, scanStatus := terminalOutcome(scanErr, errors.Join(historyErr, summaryErr, outputErr))
	reportErr := reportSession.Finish(report.Summary{Status: scanStatus, FinishedAt: time.Now()})
	exitCode, status := terminalOutcome(scanErr, errors.Join(historyErr, summaryErr, outputErr, reportErr))
	targets, _, coverage := run.Counts()
	endErr := ddout.EndRun(ddout.RunSummary{
		Status:   status,
		ExitCode: exitCode,
		Counts: ddout.RunCounts{
			Targets: int64(targets), Coverage: int64(coverage),
			AssetsNew: int64(difference.AssetNew), ServicesChanged: int64(difference.ServiceChanged),
			AssetsDisappeared: int64(difference.AssetDisappeared), AssetsNotAssessed: int64(difference.AssetNotAssessed),
			StagesExecuted: int64(difference.StageExecuted), StagesReused: int64(difference.StageReused),
			TargetsFull: int64(difference.FullTargets), TargetsIncremental: int64(difference.IncrementalTargets),
		},
	})
	if endErr != nil {
		writeCLIError("cli output finalize failed", endErr)
	}
	exitCode, _ = terminalOutcome(scanErr, errors.Join(historyErr, summaryErr, outputErr, endErr, reportErr))
	if scanErr != nil && !errors.Is(scanErr, context.Canceled) {
		writeCLIError("pipeline failed", scanErr)
	}
	if historyErr != nil {
		writeCLIError("cli history finalize failed", historyErr)
	}
	if reportErr != nil {
		writeCLIError("cli report finalize failed", reportErr)
	}
	return exitCode
}

func dispatchArsenalCommand(args []string) (bool, int) {
	if len(args) == 0 {
		return false, exitSuccess
	}
	switch args[0] {
	case "help":
		if len(args) > 1 {
			switch args[1] {
			case "finger":
				arsenal.HandleFingerCommand([]string{"--help"})
				return true, exitSuccess
			case "poc":
				arsenal.HandlePocCommand([]string{"--help"})
				return true, exitSuccess
			case "workflow":
				arsenal.HandleWorkflowCommand([]string{"--help"})
				return true, exitSuccess
			}
		}
		os.Args = []string{os.Args[0], "--help"}
		return false, exitSuccess
	case "finger", "poc", "workflow":
		if err := prepareArsenalCommand(args[1:]); err != nil {
			writeCLIError("offline arsenal init failed", err)
			return true, exitFailure
		}
		switch args[0] {
		case "finger":
			arsenal.HandleFingerCommand(args[1:])
		case "poc":
			arsenal.HandlePocCommand(args[1:])
		case "workflow":
			arsenal.HandleWorkflowCommand(args[1:])
		}
		return true, exitSuccess
	}
	return false, exitSuccess
}

func watchInterrupt(cancel context.CancelFunc) func() {
	interrupts := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(interrupts, os.Interrupt)
	go func() {
		select {
		case <-interrupts:
			cancel()
		case <-done:
		}
	}()
	return func() {
		signal.Stop(interrupts)
		close(done)
	}
}

func terminalOutcome(scanErr, otherErr error) (int, string) {
	if cancellationOnly(scanErr) && otherErr == nil {
		return exitCanceled, "canceled"
	}
	if scanErr != nil || otherErr != nil {
		return exitFailure, "failed"
	}
	return exitSuccess, "completed"
}

func cancellationOnly(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if child != nil && !cancellationOnly(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if child := wrapped.Unwrap(); child != nil {
			return cancellationOnly(child)
		}
	}
	return errors.Is(err, context.Canceled)
}

func writeCLIError(label string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Argus CLI: %s: %v\n", label, err)
	}
}

func writeInteractiveSummaries(outputType string, run *localstate.Run, difference localstate.DifferenceSummary, summaryErr error) {
	if summaryErr != nil {
		writeCLIError("cli history summary failed", summaryErr)
	} else if line, ok := formatRunDifferenceSummary(outputType, run.ID, difference); ok {
		fmt.Fprintln(os.Stderr, line)
	}
	if summary, err := run.TimingSummary(); err != nil {
		writeCLIError("cli timing summary failed", err)
	} else if line, ok := formatTimingSummary(outputType, summary); ok {
		fmt.Fprintln(os.Stderr, line)
	}
}

func formatTimingSummary(outputType string, summary localstate.TimingSummary) (string, bool) {
	if !strings.EqualFold(strings.TrimSpace(outputType), "text") || !summary.Available {
		return "", false
	}
	line := fmt.Sprintf("Argus timing: bootstrap=%s rule=%s context=%s stage_sum=%s", formatTimingDuration(summary.Bootstrap), formatTimingDuration(summary.RulePrepare), formatTimingDuration(summary.ContextInit), formatTimingDuration(summary.StageTotal))
	if summary.SlowestStage != "" {
		line += fmt.Sprintf(" slowest_stage=%s (%s)", summary.SlowestStage, formatTimingDuration(summary.SlowestStageDuration))
	}
	return line, true
}

func formatTimingDuration(value time.Duration) string {
	if value > 0 && value < time.Millisecond {
		return "<1ms"
	}
	return value.Round(time.Millisecond).String()
}

func formatRunDifferenceSummary(outputType, runID string, summary localstate.DifferenceSummary) (string, bool) {
	if !strings.EqualFold(strings.TrimSpace(outputType), "text") {
		return "", false
	}
	return fmt.Sprintf(
		"Argus Run %s: assets new=%d changed=%d disappeared=%d not_assessed=%d; stages executed=%d reused=%d; targets full=%d incremental=%d",
		runID, summary.AssetNew, summary.ServiceChanged, summary.AssetDisappeared, summary.AssetNotAssessed,
		summary.StageExecuted, summary.StageReused, summary.FullTargets, summary.IncrementalTargets,
	), true
}

func prepareArsenalCommand(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		return nil
	}
	home, err := localstate.Ensure()
	if err != nil {
		return fmt.Errorf("cli data init: %w", err)
	}
	if _, err := config.PrepareCLIArsenal(home); err != nil {
		return err
	}
	return nil
}
