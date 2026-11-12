package common

import (
	"fmt"
	"io"
	"os"
)

var version = "2.0.1"

const cliDescription = "Argus CLI 是面向授权安全测试的离线资产探测工具。默认执行资产发现、Nuclei 与 GoPoc（含口令爆破）；用 -nopoc / -nogpoc / -nobr 关闭对应能力。"

const cliHelpText = `
帮助:
  argus -h
  argus --help
  argus --version

示例:
  argus -a https://example.com
  argus -a 10.0.0.0/24 -nopoc -nogpoc
  argus -a 10.0.0.5 -m ssh,mysql
  argus -tr 192.0.2.9
  argus -tr res.txt`

// CLIVersionString is the stable user-facing version text used by both the
// banner and the early --version path.
func CLIVersionString() string {
	return fmt.Sprintf("Argus CLI v%s", version)
}

func showBanner() {
	writeBanner(os.Stdout)
}

func writeBanner(w io.Writer) {
	fmt.Fprintf(w, `
    _    ____   ____ _   _ ____
   / \  |  _ \ / ___| | | / ___|
  / _ \ | |_) | |  _| | | \___ \
 / ___ \|  _ <| |_| | |_| |___) |
/_/   \_\_| \_\\____|\___/|____/
%s
Command: argus

`, CLIVersionString())
}
