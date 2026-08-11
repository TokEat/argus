package main

import (
	"dddd/scanner/common"
	"fmt"
	"io"
	"strings"
)

const providerMigrationExitCode = 2

var serverOnlyProviderFlags = map[string]struct{}{
	"hunter":                {},
	"hunter-page-size":      {},
	"hps":                   {},
	"hunter-max-page-count": {},
	"hmpc":                  {},
	"low-perception-mode":   {},
	"lpm":                   {},
	"oip":                   {},
	"fofa":                  {},
	"fofa-max-count":        {},
	"fmc":                   {},
	"quake":                 {},
	"quake-max-count":       {},
	"qmc":                   {},
	"api-config-file":       {},
	"acf":                   {},
}

// dispatchEarlyCLI handles metadata and retired standalone Provider flags
// before Arsenal preparation, local history creation, or scan initialization.
func dispatchEarlyCLI(args []string, stdout, stderr io.Writer) (bool, int) {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(stdout, common.CLIVersionString())
		return true, 0
	}
	if flag, ok := serverOnlyProviderFlag(args); ok {
		fmt.Fprintf(stderr, "Argus CLI: 参数 -%s 已迁移到 Argus Server 的项目“资产测绘”页面；Standalone CLI 只扫描显式授权目标，不再读取 Provider 凭据或执行 FOFA/Hunter/Quake 查询。\n", flag)
		return true, providerMigrationExitCode
	}
	return false, 0
}

func serverOnlyProviderFlag(args []string) (string, bool) {
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		name := strings.TrimLeft(arg, "-")
		if name == "" {
			continue
		}
		if separator := strings.IndexByte(name, '='); separator >= 0 {
			name = name[:separator]
		}
		if _, ok := serverOnlyProviderFlags[name]; ok {
			return name, true
		}
	}
	return "", false
}
