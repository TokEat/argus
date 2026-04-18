// Package embed 嵌入资源统一入口。
//
// 当前阶段：资源文件仍物理位于 common/config/ 目录下
// （因为 common/flag.go 的 //go:embed 指令引用的是相对路径）。
// 此包作为外部访问嵌入资源的统一入口。
// 待 common/flag.go 完全迁移到 internal/config/ 后，
// 资源文件将移动到此目录，//go:embed 指令也将更新。
//
// 当前资源清单（位于 common/config/）：
//   - finger.yaml     指纹规则数据库
//   - workflow.yaml    指纹→PoC 工作流映射
//   - dir.yaml         主动探测路径数据库
//   - api-config.yaml  搜索引擎 API 配置
//   - subdomains.txt   子域名字典
//   - pocs/            内嵌 Nuclei PoC 模板
package embed

// 注意：当前阶段不在此包定义 //go:embed 变量。
// 嵌入资源仍通过 common.EmbedXXX 变量访问。
// 后续 Phase 中将统一迁移到此包。
