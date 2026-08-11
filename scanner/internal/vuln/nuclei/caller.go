// Package nuclei Nuclei 漏洞扫描封装。
// 桥接层：底层调用 common/callnuclei 的原始实现。
package nuclei

import (
	"dddd/scanner/common/callnuclei"
	"embed"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

var callMu sync.Mutex

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
) []output.ResultEvent {
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
) []output.ResultEvent {
	callMu.Lock()
	defer callMu.Unlock()

	return callnuclei.CallNuclei(targetAndPocsName, httpProxy, addResult,
		pocNameForSearch, noInteractsh, wafBypassHeaders, embedPocs, nucleiTemplate,
		excludeTags, severities, callnuclei.Presentation{MachineOutput: true})
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
) []output.ResultEvent {
	callMu.Lock()
	defer callMu.Unlock()

	return callnuclei.CallNucleiDebug(targetAndPocsName, httpProxy, addResult,
		pocNameForSearch, noInteractsh, wafBypassHeaders, embedPocs, nucleiTemplate,
		excludeTags, severities)
}
