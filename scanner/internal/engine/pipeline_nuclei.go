package engine

import (
	"crypto/md5"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/P0lar1ght/argus/scanner/gopocs"
	"github.com/P0lar1ght/argus/scanner/internal/output"
	"github.com/P0lar1ght/argus/scanner/internal/vuln/mapper"
	"github.com/P0lar1ght/argus/scanner/internal/vuln/nuclei"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type nucleiCaller func(map[string][]string, string, func(nucleiOutput.ResultEvent), string, bool, bool, embed.FS, string, []string, []string) ([]nucleiOutput.ResultEvent, error)

type limitedNucleiCaller func(map[string][]string, string, func(nucleiOutput.ResultEvent), string, bool, bool, embed.FS, string, []string, []string, nuclei.ExecutionLimits, bool) ([]nucleiOutput.ResultEvent, error)

var (
	callNuclei        nucleiCaller        = nuclei.Call
	callNucleiMachine nucleiCaller        = nuclei.CallMachine
	callNucleiLimited limitedNucleiCaller = nuclei.CallLimited
)

func configuredNucleiCaller(cfg *Config) nucleiCaller {
	if cfg != nil && cfg.MachineOutput {
		return callNucleiMachine
	}
	return callNuclei
}

func normalizedRiskValidationTargets(cfg *Config) (map[string][]string, int, error) {
	if cfg == nil || !strings.EqualFold(strings.TrimSpace(cfg.ExecutionMode), "risk_validation") {
		return nil, 0, fmt.Errorf("risk validation execution mode is required")
	}
	allowedTargets := make(map[string]struct{}, len(cfg.Targets))
	for _, target := range cfg.Targets {
		target = strings.TrimSpace(target)
		if target == "" || strings.ContainsAny(target, "\r\n\x00") {
			return nil, 0, fmt.Errorf("risk validation contains an invalid target")
		}
		allowedTargets[target] = struct{}{}
	}
	if len(allowedTargets) == 0 {
		return nil, 0, fmt.Errorf("risk validation requires confirmed targets")
	}
	if len(cfg.RiskValidationTargets) == 0 {
		return map[string][]string{}, 0, nil
	}

	normalized := make(map[string][]string, len(cfg.RiskValidationTargets))
	total := 0
	for rawTarget, rawPocs := range cfg.RiskValidationTargets {
		target := strings.TrimSpace(rawTarget)
		if _, ok := allowedTargets[target]; !ok {
			return nil, 0, fmt.Errorf("risk validation target %q is outside the dispatched batch", target)
		}
		seen := make(map[string]struct{}, len(rawPocs))
		for _, rawPoc := range rawPocs {
			poc := strings.TrimSpace(strings.ReplaceAll(rawPoc, "\\", "/"))
			clean := path.Clean(poc)
			ext := strings.ToLower(path.Ext(clean))
			if poc == "" || clean != poc || path.IsAbs(clean) || strings.Contains(clean, "/") || (ext != ".yaml" && ext != ".yml") {
				return nil, 0, fmt.Errorf("risk validation POC filename %q is unsafe", rawPoc)
			}
			if _, exists := seen[clean]; exists {
				continue
			}
			seen[clean] = struct{}{}
			normalized[target] = append(normalized[target], clean)
			total++
		}
		if len(normalized[target]) == 0 {
			return nil, 0, fmt.Errorf("risk validation target %q has no confirmed POC", target)
		}
	}
	return normalized, total, nil
}

func validateRiskValidationPocFiles(cfg *Config, targets map[string][]string) error {
	if len(targets) == 0 {
		if len(cfg.RiskValidationPocHashes) != 0 {
			return fmt.Errorf("risk validation contains POC hashes without a Nuclei plan")
		}
		return nil
	}
	if cfg == nil || strings.TrimSpace(cfg.NucleiTemplate) == "" {
		return fmt.Errorf("risk validation requires a materialized POC directory")
	}
	selected := make(map[string]struct{})
	for _, pocs := range targets {
		for _, poc := range pocs {
			selected[poc] = struct{}{}
		}
	}
	if len(cfg.RiskValidationPocHashes) != len(selected) {
		return fmt.Errorf("risk validation POC content hashes do not cover the confirmed selection")
	}
	for poc := range selected {
		expected := strings.ToLower(strings.TrimSpace(cfg.RiskValidationPocHashes[poc]))
		if expected == "" {
			return fmt.Errorf("risk validation POC %q has no confirmed content hash", poc)
		}
		content, err := os.ReadFile(filepath.Join(cfg.NucleiTemplate, poc))
		if err != nil {
			return fmt.Errorf("read confirmed risk validation POC %q: %w", poc, err)
		}
		actual := fmt.Sprintf("%x", md5.Sum(content))
		if actual != expected {
			return fmt.Errorf("risk validation POC %q content changed after confirmation", poc)
		}
	}
	for poc := range cfg.RiskValidationPocHashes {
		if _, exists := selected[poc]; !exists {
			return fmt.Errorf("risk validation contains an unselected POC content hash for %q", poc)
		}
	}
	return nil
}

func runRiskValidationPhase(ctx *ScanContext, cfg *Config, enableLocalReports bool) ([]gopocs.NucleiResult, error) {
	targets, count, err := normalizedRiskValidationTargets(cfg)
	if err != nil {
		return nil, err
	}
	if err := validateRiskValidationPocFiles(cfg, targets); err != nil {
		return nil, err
	}
	goPocTargets, goPocCost, err := normalizedRiskValidationGoPocTargets(cfg)
	if err != nil {
		return nil, err
	}
	if count == 0 && len(goPocTargets) == 0 {
		return nil, fmt.Errorf("risk validation requires a sealed Nuclei or GoPoc plan")
	}
	if strings.TrimSpace(cfg.ValidationBudgetID) == "" || cfg.ValidationTargetConcurrency < 1 || cfg.ValidationRateLimit < 1 || cfg.ValidationRequestBudget < 1 || cfg.ValidationEstimatedRequests < 1 {
		return nil, fmt.Errorf("risk validation requires a positive sealed execution budget")
	}
	if cfg.ValidationEstimatedRequests > cfg.ValidationRequestBudget {
		return nil, fmt.Errorf("risk validation estimate exceeds the sealed request budget")
	}
	var results []nucleiOutput.ResultEvent
	if count > 0 {
		nucleiBudget := cfg.ValidationRequestBudget - goPocCost
		if nucleiBudget < 1 {
			return nil, fmt.Errorf("risk validation leaves no request budget for the sealed Nuclei plan")
		}
		emitPhase(ctx, PhaseNuclei, "start", fmt.Sprintf("%d explicitly confirmed pocs", count))
		addResult, collector := buildNucleiResultHandler(ctx, enableLocalReports)
		var callErr error
		results, callErr = callNucleiLimited(
			targets,
			cfg.HTTPProxy,
			addResult,
			"",
			cfg.NoInteractsh,
			cfg.WAFBypassHeaders,
			currentPipelineEmbedPocs(ctx),
			cfg.NucleiTemplate,
			strings.Split(cfg.ExcludeTags, ","),
			strings.Split(cfg.Severities, ","),
			nuclei.ExecutionLimits{RateLimit: cfg.ValidationRateLimit, TargetConcurrency: cfg.ValidationTargetConcurrency, RequestBudget: nucleiBudget},
			cfg.MachineOutput,
		)
		results = authoritativeNucleiResults(results, collector.snapshot())
		if callErr != nil {
			emitPhase(ctx, PhaseNuclei, "failed", "nuclei execution failed")
			return nil, callErr
		}
		emitPhase(ctx, PhaseNuclei, "end", "")
	}
	if len(goPocTargets) > 0 {
		goPocTargets = activatedRiskGoPocTargets(goPocTargets, results)
	}
	if len(goPocTargets) > 0 {
		emitPhase(ctx, PhaseGoPoc, "start", fmt.Sprintf("%d explicitly confirmed checks", len(goPocTargets)))
		goResults, dispatchErr := gopocs.DispatchGoPocTargets(goPocTargets, cfg.GoPocCatalogSHA256, scanpolicy.GoPocVulnerabilityCheck, cfg.ValidationTargetConcurrency, cfg.ValidationRateLimit, goPocCost, func(message structs.OutputMessage) {
			dispatchPipelineOutput(ctx, message)
		})
		if ctx != nil {
			ctx.GoPocsResults = toEngineGoPocResults(goResults)
		}
		if dispatchErr != nil {
			emitPhase(ctx, PhaseGoPoc, "failed", "scoped GoPoc vulnerability checks failed")
			return nil, dispatchErr
		}
		emitPhase(ctx, PhaseGoPoc, "end", fmt.Sprintf("%d findings", len(goResults)))
	}
	converted := make([]gopocs.NucleiResult, len(results))
	for i, result := range results {
		converted[i] = gopocs.NucleiResult{TemplateID: result.TemplateID, Matched: result.Matched, URL: result.URL}
	}
	return converted, nil
}

func runNucleiPhase(ctx *ScanContext, cfg *Config, resultMap map[string][]string, enableLocalReports bool, emit func(structs.OutputMessage)) ([]gopocs.NucleiResult, error) {
	if cfg.NoPoc {
		return nil, nil
	}
	var nucleiResults []nucleiOutput.ResultEvent
	TargetAndPocsName, count := mapper.GetPocs(resultMap, currentPipelineWorkflowDB(ctx), cfg.DisableGeneralPoc, cfg.WAFSkipOnManyFingerprints)
	gologger.Info().Msgf("[Pipeline] Nuclei 映射结果: targets=%d pocs=%d template_path=%s", len(TargetAndPocsName), count, cfg.NucleiTemplate)
	for target, pocs := range TargetAndPocsName {
		gologger.Info().Msgf("[Pipeline]   %s → %v", target, pocs)
	}
	if count > 0 {
		emitPhase(ctx, PhaseNuclei, "start", fmt.Sprintf("%d pocs", count))
		addResult, collector := buildNucleiResultHandler(ctx, enableLocalReports)
		var callErr error
		nucleiResults, callErr = configuredNucleiCaller(cfg)(TargetAndPocsName,
			cfg.HTTPProxy, addResult,
			"", cfg.NoInteractsh, cfg.WAFBypassHeaders, currentPipelineEmbedPocs(ctx),
			cfg.NucleiTemplate, strings.Split(cfg.ExcludeTags, ","),
			strings.Split(cfg.Severities, ","))
		nucleiResults = authoritativeNucleiResults(nucleiResults, collector.snapshot())
		if callErr != nil {
			emitPhase(ctx, PhaseNuclei, "failed", "nuclei execution failed")
			return nil, callErr
		}
		emitPhase(ctx, PhaseNuclei, "end", "")
	}
	converted := make([]gopocs.NucleiResult, len(nucleiResults))
	for i, r := range nucleiResults {
		converted[i] = gopocs.NucleiResult{TemplateID: r.TemplateID, Matched: r.Matched, URL: r.URL}
	}
	return converted, nil
}

func authoritativeNucleiResults(returned, collected []nucleiOutput.ResultEvent) []nucleiOutput.ResultEvent {
	if len(collected) == 0 {
		return returned
	}
	// The vendored writer both invokes the callback and appends the same event
	// to its return slice. The callback stream is authoritative for reporting,
	// so do not duplicate successful POCs before GoPoc dispatch.
	return collected
}

func runPocSearch(ctx *ScanContext, cfg *Config, aliveURLs []string, enableLocalReports bool) ([]gopocs.NucleiResult, error) {
	TargetAndPocsName := make(map[string][]string)
	for _, url := range aliveURLs {
		TargetAndPocsName[url] = []string{}
	}
	emitPhase(ctx, PhaseNuclei, "start", fmt.Sprintf("%d targets, poc=%s", len(TargetAndPocsName), cfg.PocNameForSearch))
	addResult, _ := buildNucleiResultHandler(ctx, enableLocalReports)
	nucleiResults, callErr := configuredNucleiCaller(cfg)(TargetAndPocsName,
		cfg.HTTPProxy, addResult,
		cfg.PocNameForSearch, cfg.NoInteractsh,
		cfg.WAFBypassHeaders,
		currentPipelineEmbedPocs(ctx), cfg.NucleiTemplate,
		strings.Split(cfg.ExcludeTags, ","), strings.Split(cfg.Severities, ","))
	if callErr != nil {
		emitPhase(ctx, PhaseNuclei, "failed", "nuclei execution failed")
		return nil, callErr
	}
	emitPhase(ctx, PhaseNuclei, "end", "")
	converted := make([]gopocs.NucleiResult, len(nucleiResults))
	for i, r := range nucleiResults {
		converted[i] = gopocs.NucleiResult{TemplateID: r.TemplateID, Matched: r.Matched, URL: r.URL}
	}
	return converted, nil
}

func embedPocs(ep embed.FS) embed.FS { return ep }

type nucleiResultCollector struct {
	mu      sync.Mutex
	results []nucleiOutput.ResultEvent
}

func (c *nucleiResultCollector) add(result nucleiOutput.ResultEvent) {
	c.mu.Lock()
	c.results = append(c.results, result)
	c.mu.Unlock()
}

func (c *nucleiResultCollector) snapshot() []nucleiOutput.ResultEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]nucleiOutput.ResultEvent(nil), c.results...)
}

func buildNucleiResultHandler(ctx *ScanContext, enableLocalReports bool) (func(result nucleiOutput.ResultEvent), *nucleiResultCollector) {
	collector := &nucleiResultCollector{}
	if enableLocalReports || ctx == nil || ctx.OutputHook == nil {
		return func(result nucleiOutput.ResultEvent) {
			output.AddResultByResultEvent(result)
			collector.add(result)
			observeNucleiResult(ctx, result)
		}, collector
	}
	return func(result nucleiOutput.ResultEvent) {
		collector.add(result)
		message, ok := nucleiResultMessage(result)
		if !ok {
			return
		}
		if ctx.OutputObserver != nil {
			ctx.OutputObserver(message)
		}
		ctx.OutputHook(message)
	}, collector
}

func observeNucleiResult(ctx *ScanContext, result nucleiOutput.ResultEvent) {
	if ctx == nil || ctx.OutputObserver == nil {
		return
	}
	if message, ok := nucleiResultMessage(result); ok {
		ctx.OutputObserver(message)
	}
}

func nucleiResultMessage(result nucleiOutput.ResultEvent) (OutputMessage, bool) {
	payload, err := json.Marshal(result)
	if err != nil {
		return OutputMessage{}, false
	}
	show := fmt.Sprintf("[%s] [%s] %v",
		result.TemplateID,
		result.Info.SeverityHolder.Severity.String(),
		result.Matched,
	)
	return OutputMessage{Type: "Nuclei", Nuclei: string(payload), Show: show}, true
}
