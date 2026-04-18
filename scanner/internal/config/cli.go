// Package config 配置管理，封装 CLI 参数解析和初始化逻辑。
//
// 当前阶段（Phase 0.3）：此包作为桥接层，底层仍调用 common.Flag()。
// 后续阶段会将 common/flag.go 的逻辑逐步迁入此包。
package config

import (
	"dddd/scanner/common"
	"dddd/scanner/internal/engine"
)

// InitCLI 解析命令行参数并完成初始化。
// 当前实现为桥接调用 common.Flag()，后续将内联替换。
func InitCLI() (*engine.ScanContext, error) {
	common.Flag()
	return engine.NewScanContextFromLegacyGlobals("cli-local")
}
