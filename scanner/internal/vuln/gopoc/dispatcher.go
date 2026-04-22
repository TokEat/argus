// Package gopoc Go 原生 PoC 引擎。
// 桥接层：底层调用 gopocs 包的原始实现。
package gopoc

import (
	"dddd/scanner/gopocs"
	"dddd/scanner/structs"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Dispatch GoPoc 主调度器。
func Dispatch(ipPortMap map[string]string, goPocThreads int, password string, passwordFile string, nucleiResults []output.ResultEvent, emit func(structs.OutputMessage)) []structs.GoPocsResultType {
	return gopocs.Dispatch(ipPortMap, goPocThreads, password, passwordFile, nucleiResults, emit)
}

// TelnetCVEOnly 高危 CVE 专项检测（不依赖 GoPoc 开关）。
func TelnetCVEOnly(ipPortMap map[string]string, goPocThreads int, password string, passwordFile string, emit func(structs.OutputMessage)) []structs.GoPocsResultType {
	return gopocs.TelnetBypassDispatch(ipPortMap, goPocThreads, password, passwordFile, emit)
}
