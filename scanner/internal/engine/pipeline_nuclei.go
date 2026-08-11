package engine

import (
	"crypto/md5"
	"dddd/scanner/gopocs"
	"dddd/scanner/internal/output"
	"dddd/scanner/internal/vuln/mapper"
	"dddd/scanner/internal/vuln/nuclei"
	"dddd/scanner/structs"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

type nucleiCaller func(map[string][]string, string, func(nucleiOutput.ResultEvent), string, bool, bool, embed.FS, string, []string, []string) []nucleiOutput.ResultEvent

var (
	callNuclei        nucleiCaller = nuclei.Call
	callNucleiMachine nucleiCaller = nuclei.CallMachine
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
	if len(allowedTargets) == 0 || len(cfg.RiskValidationTargets) == 0 {
		return nil, 0, fmt.Errorf("risk validation requires confirmed targets and POCs")
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
	for target := range allowedTargets {
		if len(normalized[target]) == 0 {
			return nil, 0, fmt.Errorf("dispatched target %q is missing from the risk validation plan", target)
		}
	}
	return normalized, total, nil
}

func validateRiskValidationPocFiles(cfg *Config, targets map[string][]string) error {
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
	if enableLocalReports {
		output.InitReportName()
	}
	emitPhase(ctx, PhaseNuclei, "start", fmt.Sprintf("%d explicitly confirmed pocs", count))
	addResult, collector := buildNucleiResultHandler(ctx, enableLocalReports)
	results := configuredNucleiCaller(cfg)(
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
	)
	if collected := collector.snapshot(); len(collected) > 0 {
		results = append(results, collected...)
	}
	emitPhase(ctx, PhaseNuclei, "end", "")
	if enableLocalReports {
		output.GenerateHTMLReportFooter()
		output.GenerateAssetReport(cfg.OutputFile)
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
	if enableLocalReports {
		output.InitReportName()
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
		nucleiResults = configuredNucleiCaller(cfg)(TargetAndPocsName,
			cfg.HTTPProxy, addResult,
			"", cfg.NoInteractsh, cfg.WAFBypassHeaders, currentPipelineEmbedPocs(ctx),
			cfg.NucleiTemplate, strings.Split(cfg.ExcludeTags, ","),
			strings.Split(cfg.Severities, ","))
		if collected := collector.snapshot(); len(collected) > 0 {
			nucleiResults = append(nucleiResults, collected...)
		}
		emitPhase(ctx, PhaseNuclei, "end", "")
	}
	converted := make([]gopocs.NucleiResult, len(nucleiResults))
	for i, r := range nucleiResults {
		converted[i] = gopocs.NucleiResult{TemplateID: r.TemplateID, Matched: r.Matched, URL: r.URL}
	}
	return converted, nil
}

func runPocSearch(ctx *ScanContext, cfg *Config, aliveURLs []string, enableLocalReports bool) ([]gopocs.NucleiResult, error) {
	TargetAndPocsName := make(map[string][]string)
	for _, url := range aliveURLs {
		TargetAndPocsName[url] = []string{}
	}
	if enableLocalReports {
		output.InitReportName()
	}
	emitPhase(ctx, PhaseNuclei, "start", fmt.Sprintf("%d targets, poc=%s", len(TargetAndPocsName), cfg.PocNameForSearch))
	addResult, _ := buildNucleiResultHandler(ctx, enableLocalReports)
	nucleiResults := configuredNucleiCaller(cfg)(TargetAndPocsName,
		cfg.HTTPProxy, addResult,
		cfg.PocNameForSearch, cfg.NoInteractsh,
		cfg.WAFBypassHeaders,
		currentPipelineEmbedPocs(ctx), cfg.NucleiTemplate,
		strings.Split(cfg.ExcludeTags, ","), strings.Split(cfg.Severities, ","))
	emitPhase(ctx, PhaseNuclei, "end", "")
	if enableLocalReports {
		output.GenerateHTMLReportFooter()
		output.GenerateAssetReport(cfg.OutputFile)
	}
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
