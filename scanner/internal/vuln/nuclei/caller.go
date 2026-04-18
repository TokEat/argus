// Package nuclei Nuclei 漏洞扫描封装。
// 桥接层：底层调用 common/callnuclei 的原始实现。
package nuclei

import (
	"dddd/scanner/common/callnuclei"
	"embed"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Call 调用 Nuclei 进行漏洞扫描。
func Call(targetAndPocsName map[string][]string,
	httpProxy string,
	addResult func(result output.ResultEvent),
	pocNameForSearch string,
	noInteractsh bool,
	embedPocs embed.FS,
	nucleiTemplate string,
	excludeTags []string,
	severities []string,
) []output.ResultEvent {
	return callnuclei.CallNuclei(targetAndPocsName, httpProxy, addResult,
		pocNameForSearch, noInteractsh, embedPocs, nucleiTemplate,
		excludeTags, severities)
}
