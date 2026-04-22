//go:build !noembed

package common

import "embed"

// EmbedNucleiPocs 内嵌 config/pocs 目录下的所有 Nuclei POC 模板。
// 默认构建（CLI 单机模式）会将 POC 编译进二进制，实现开箱即用。
//
//go:embed config/pocs/*
var EmbedNucleiPocs embed.FS
