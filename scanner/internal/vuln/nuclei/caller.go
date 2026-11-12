// Package nuclei Nuclei 漏洞扫描封装。
// 桥接层：底层调用 common/callnuclei 的原始实现。
package nuclei

import (
	"embed"
	"github.com/TokEat/argus/scanner/common/callnuclei"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

var callMu sync.Mutex

type ExecutionLimits struct {
	RateLimit         int
	TargetConcurrency int
	RequestBudget     int64
}

// Call 调用 Nuclei 进行漏洞扫描。
func Call(targetAndPocsName map[string][]string,
	httpProxy string,
	addResult func(result output.ResultEvent),
	pocNameForSearch string,
	noInteractsh bool,
	wafBypassHeaders bool,
	embedPocs embed.FS,
	nucleiTemplate string,
	excludeTags []string,
	severities []string,
) ([]output.ResultEvent, error) {
	callMu.Lock()
	defer callMu.Unlock()

	return callnuclei.CallNuclei(targetAndPocsName, httpProxy, addResult,
		pocNameForSearch, noInteractsh, wafBypassHeaders, embedPocs, nucleiTemplate,
		excludeTags, severities)
}

// CallMachine executes the same templates while reserving stdout for the
// standalone CLI's structured output contract.
func CallMachine(targetAndPocsName map[string][]string,
	httpProxy string,
	addResult func(result output.ResultEvent),
	pocNameForSearch string,
	noInteractsh bool,
	wafBypassHeaders bool,
	embedPocs embed.FS,
	nucleiTemplate string,
	excludeTags []string,
	severities []string,
) ([]output.ResultEvent, error) {
	callMu.Lock()
	defer callMu.Unlock()

	return callnuclei.CallNuclei(targetAndPocsName, httpProxy, addResult,
		pocNameForSearch, noInteractsh, wafBypassHeaders, embedPocs, nucleiTemplate,
		excludeTags, severities, callnuclei.Presentation{MachineOutput: true})
}

// CallLimited applies the Server-sealed validation allocation. The target and
// template concurrency share the same allocation so parallel validation
// stages cannot each expand back to Nuclei's much larger defaults.
func CallLimited(targetAndPocsName map[string][]string,
	httpProxy string,
	addResult func(result output.ResultEvent),
	pocNameForSearch string,
	noInteractsh bool,
	wafBypassHeaders bool,
	embedPocs embed.FS,
	nucleiTemplate string,
	excludeTags []string,
	severities []string,
	limits ExecutionLimits,
	machineOutput bool,
) ([]output.ResultEvent, error) {
	callMu.Lock()
	defer callMu.Unlock()

	return callnuclei.CallNuclei(targetAndPocsName, httpProxy, addResult,
		pocNameForSearch, noInteractsh, wafBypassHeaders, embedPocs, nucleiTemplate,
		excludeTags, severities, callnuclei.Presentation{
			MachineOutput: machineOutput, RateLimit: limits.RateLimit,
			BulkSize: limits.TargetConcurrency, TemplateThreads: limits.TargetConcurrency, RequestLimit: limits.RequestBudget,
		})
}

// CallDebug 调用 Nuclei 并启用 MatcherStatus，确保未命中时也能
// 通过 WriteFailure 回调获取 request/response 数据。用于 POC 调试场景。
func CallDebug(targetAndPocsName map[string][]string,
	httpProxy string,
	addResult func(result output.ResultEvent),
	pocNameForSearch string,
	noInteractsh bool,
	wafBypassHeaders bool,
	embedPocs embed.FS,
	nucleiTemplate string,
	excludeTags []string,
	severities []string,
) ([]output.ResultEvent, error) {
	callMu.Lock()
	defer callMu.Unlock()

	return callnuclei.CallNucleiDebug(targetAndPocsName, httpProxy, addResult,
		pocNameForSearch, noInteractsh, wafBypassHeaders, embedPocs, nucleiTemplate,
		excludeTags, severities)
}
