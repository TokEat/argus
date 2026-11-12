package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ---- 源定义 ----

type SourceSpec struct {
	Name    string   `json:"name"`
	Repo    string   `json:"repo"` // github.com/org/repo
	Paths   []string `json:"paths"`
	// 源内规则类型: poc / active-fingerprint 原料 / fofa-finger
	Usage string `json:"usage"`
}

type SourceFetch struct {
	Spec   SourceSpec `json:"spec"`
	Dir    string     `json:"dir"`
	SHA    string     `json:"sha"`
	Branch string     `json:"branch"`
	// License 为 LICENSE 文件首行摘要，便于报告归属。
	License string   `json:"license"`
	Files   []string `json:"files"`
	Err     string   `json:"error,omitempty"`
}

type FetchManifest struct {
	FetchedAt time.Time     `json:"fetched_at"`
	Sources   []SourceFetch `json:"sources"`
}

// 收集源清单。许可证字段在 fetch 时从仓库 LICENSE 实测回填。
//
// 已评估但未纳入的源（记录在最终报告中）：
//   - TideSec/TscanPlus：POC 内嵌于发布二进制，仓库内无规则文件
//   - 0x727/FingerPrintHub：nuclei 格式的超集，与 nuclei-templates 高度重叠
//   - sehonn/FingerprintHub：仓库不存在
var sourceCatalog = []SourceSpec{
	{Name: "nuclei-templates", Repo: "github.com/projectdiscovery/nuclei-templates",
		Paths: []string{"http/cves", "http/vulnerabilities", "http/technologies", "http/exposed-panels"}, Usage: "poc+finger"},
	{Name: "afrog", Repo: "github.com/zan8in/afrog",
		Paths: []string{"pocs"}, Usage: "poc"},
	{Name: "xray", Repo: "github.com/chaitin/xray",
		Paths: []string{"pocs"}, Usage: "poc"},
}

// ---- 候选规则 ----

type RuleKind string

const (
	KindPoc      RuleKind = "poc"
	KindFinger   RuleKind = "finger"
	KindActiveFP RuleKind = "active_fingerprint"
)

type Candidate struct {
	Kind    RuleKind `json:"kind"`
	Source  string   `json:"source"`
	License string   `json:"license"`
	SrcPath string   `json:"src_path"`

	ID       string `json:"id"`        // 模板 id / 指纹 id
	FileName string `json:"file_name"` // poc/fp 输出 basename
	Content  string `json:"content"`  // 最终文件内容

	// 元数据（select/dedup/wire 用）
	Severity string   `json:"severity,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Product  string   `json:"product,omitempty"`
	Vendor   string   `json:"vendor,omitempty"`
	CVE      string   `json:"cve,omitempty"`

	// kind=finger
	ProductName string `json:"product_name,omitempty"`
	RuleExpr    string `json:"rule_expr,omitempty"`

	// 流水线结果
	Canon  string `json:"canon,omitempty"`
	Action string `json:"action,omitempty"`
	Reason string `json:"reason,omitempty"`

	// wire 结果
	WireProduct    string  `json:"wire_product,omitempty"`
	WireConfidence float64 `json:"wire_confidence,omitempty"`
}

// ---- 阶段产物 IO ----

func phasePath(workdir, name string) string {
	return filepath.Join(workdir, "phase-"+name+".json")
}

func writePhase(workdir, name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal phase %s: %w", name, err)
	}
	tmp := phasePath(workdir, name) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, phasePath(workdir, name))
}

func readPhase(workdir, name string, v any) error {
	data, err := os.ReadFile(phasePath(workdir, name))
	if err != nil {
		return fmt.Errorf("read phase %s (先运行对应阶段): %w", name, err)
	}
	return json.Unmarshal(data, v)
}

// ---- 计数 ----

type ActionCount struct {
	Added   int `json:"added"`
	Merged  int `json:"merged"`
	Skipped int `json:"skipped"`
	Rejected int `json:"rejected"`
}

func countByAction(cands []Candidate) ActionCount {
	var ac ActionCount
	for _, c := range cands {
		switch c.Action {
		case "added":
			ac.Added++
		case "merged":
			ac.Merged++
		case "skipped":
			ac.Skipped++
		case "rejected":
			ac.Rejected++
		}
	}
	return ac
}
