package common

import (
	"fmt"
	"io"
	"os"
)

var version = "2.0.1"

const cliDescription = "Argus CLI 是面向授权安全测试的离线资产探测工具，提供快速内网发现、协议/Web 识别和指纹分析；风险验证仅在显式请求时执行。"

const cliHelpText = `
子命令:
  finger      管理指纹规则库
  poc         管理 POC 规则库
  workflow    管理指纹到 POC 的映射关系

帮助:
  argus help
  argus help finger
  argus help poc
  argus help workflow
  argus finger --help
  argus poc --help
  argus workflow --help
  argus --version

资产测绘:
  FOFA、Hunter、Quake 查询已迁移到 Argus Server 的项目“资产测绘”页面。
  Standalone CLI 只扫描显式授权目标；旧 Provider 参数仅返回迁移提示，不再执行查询。

示例:
  argus -t https://example.com
  argus finger list --product nginx
  argus poc list --severity high
  argus workflow list --product ruoyi`

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
