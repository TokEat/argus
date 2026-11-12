//go:build noembed

package common

import "embed"

// EmbedNucleiPocs 在 noembed 构建模式下为空 FS。
// Agent 模式下 syncRules() 从 Server 拉取 data/arsenal.db 作为传输包，
// 随后物化为本地 config/finger.yaml、config/workflow.yaml、config/dir.yaml、
// config/pocs/、config/dict/ 和 config/subdomains.txt。
// 扫描任务读取本地 config/，无需内嵌到二进制中，可显著减小 Agent 可执行文件体积。
//
// 构建命令: go build -tags noembed ./cmd/agent/
var EmbedNucleiPocs embed.FS

// EmbedActiveFingerprints is materialized from the Server rule package in
// noembed Agent builds.
var EmbedActiveFingerprints embed.FS
