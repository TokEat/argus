// Package gopoc Go 原生 PoC 引擎。
// 桥接层：底层调用 gopocs 包的原始实现。
package gopoc

import (
	"github.com/P0lar1ght/argus/scanner/gopocs"
	"github.com/P0lar1ght/argus/scanner/structs"
)

// Dispatch GoPoc 主调度器。
func Dispatch(ipPortMap map[string]string, fingerprints map[string][]string, goPocThreads int, password string, passwordFile string, nucleiResults []gopocs.NucleiResult, emit func(structs.OutputMessage)) ([]structs.GoPocsResultType, error) {
	return gopocs.DispatchScoped(ipPortMap, fingerprints, goPocThreads, password, passwordFile, nucleiResults, emit)
}

// DispatchMachine preserves the GoPoc execution plan while suppressing
// transient terminal output for a standalone machine-readable CLI stream.
func DispatchMachine(ipPortMap map[string]string, fingerprints map[string][]string, goPocThreads int, password string, passwordFile string, nucleiResults []gopocs.NucleiResult, emit func(structs.OutputMessage)) ([]structs.GoPocsResultType, error) {
	return gopocs.DispatchWithPresentationScoped(ipPortMap, fingerprints, goPocThreads, password, passwordFile, nucleiResults, emit, gopocs.Presentation{MachineOutput: true})
}

func DispatchWithCreds(ipPortMap map[string]string, fingerprints map[string][]string, goPocThreads int, creds gopocs.DispatchCreds, nucleiResults []gopocs.NucleiResult, emit func(structs.OutputMessage)) ([]structs.GoPocsResultType, error) {
	return gopocs.DispatchWithPresentationAndCreds(ipPortMap, fingerprints, goPocThreads, creds, nucleiResults, emit, gopocs.Presentation{})
}

func DispatchMachineWithCreds(ipPortMap map[string]string, fingerprints map[string][]string, goPocThreads int, creds gopocs.DispatchCreds, nucleiResults []gopocs.NucleiResult, emit func(structs.OutputMessage)) ([]structs.GoPocsResultType, error) {
	return gopocs.DispatchWithPresentationAndCreds(ipPortMap, fingerprints, goPocThreads, creds, nucleiResults, emit, gopocs.Presentation{MachineOutput: true})
}

// TelnetCVEOnly 高危 CVE 专项检测（不依赖 GoPoc 开关）。
func TelnetCVEOnly(ipPortMap map[string]string, goPocThreads int, password string, passwordFile string, emit func(structs.OutputMessage)) ([]structs.GoPocsResultType, error) {
	return gopocs.TelnetBypassDispatchScoped(ipPortMap, goPocThreads, password, passwordFile, emit)
}
