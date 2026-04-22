// Package output 输出格式化与报告生成。
// 桥接层：底层调用 ddout 和 common/report 的原始实现。
package output

import (
	"dddd/scanner/common/report"
)

// InitReportName 初始化报告文件名。
func InitReportName() {
	report.InitReportName()
}

// GenerateHTMLReportFooter 生成漏洞报告尾部。
func GenerateHTMLReportFooter() {
	report.GenerateHTMLReportFooter()
}

// GenerateAssetReport 生成资产报告。
func GenerateAssetReport(outputFile string) {
	report.GenerateAssetReport(outputFile)
}

// AddResultByResultEvent 添加扫描结果到报告（Nuclei 回调）。
var AddResultByResultEvent = report.AddResultByResultEvent
