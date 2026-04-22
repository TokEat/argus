//go:build noembed

package common

import "embed"

// EmbedNucleiPocs 在 noembed 构建模式下为空 FS。
// Agent 模式下 POC 通过 syncRules() 从 Server 拉取到本地 config/pocs/ 目录，
// 无需内嵌到二进制中，可显著减小 Agent 可执行文件体积。
//
// 构建命令: go build -tags noembed ./cmd/agent/
var EmbedNucleiPocs embed.FS
