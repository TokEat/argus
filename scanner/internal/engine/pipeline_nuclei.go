package engine

import (
	"dddd/scanner/gopocs"
	"dddd/scanner/internal/output"
	"dddd/scanner/internal/vuln/mapper"
	"dddd/scanner/internal/vuln/nuclei"
	"dddd/scanner/structs"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

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
		nucleiResults = nuclei.Call(TargetAndPocsName,
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
	addResult, _ := buildNucleiResultHandler(ctx, enableLocalReports)
	nucleiResults := nuclei.Call(TargetAndPocsName,
		cfg.HTTPProxy, addResult,
		cfg.PocNameForSearch, cfg.NoInteractsh,
		cfg.WAFBypassHeaders,
		currentPipelineEmbedPocs(ctx), cfg.NucleiTemplate,
		strings.Split(cfg.ExcludeTags, ","), strings.Split(cfg.Severities, ","))
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
		}, collector
	}
	return func(result nucleiOutput.ResultEvent) {
		collector.add(result)
		payload, err := json.Marshal(result)
		if err != nil {
			return
		}
		show := fmt.Sprintf("[%s] [%s] %v",
			result.TemplateID,
			result.Info.SeverityHolder.Severity.String(),
			result.Matched,
		)
		ctx.OutputHook(OutputMessage{
			Type:   "Nuclei",
			Nuclei: string(payload),
			Show:   show,
		})
	}, collector
}
