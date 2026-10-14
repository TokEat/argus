package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// report 聚合 fetch→prune 各阶段 JSON，产出 report.json（机读）与 report.md（人读）：
// 各阶段计数与拒绝/去重原因 TopN、源仓库 SHA+license 归属、合并前后规则数对比、
// workflow 挂载置信度分布、人工复核清单、prune 移除统计。只读，不改 config。

type reportData struct {
	GeneratedAt string            `json:"generated_at"`
	Workdir     string            `json:"workdir"`
	Config      string            `json:"config"`
	Backup      string            `json:"backup,omitempty"`
	Sources     []sourceAttribution `json:"sources"`

	Convert convertSummary `json:"convert"`
	Select  selectSummary  `json:"select"`
	Dedup   dedupSummary   `json:"dedup"`
	Wire    wireSummary    `json:"wire"`
	Merge   mergeResult    `json:"merge"`
	Validate validateSummary `json:"validate"`
	Prune   pruneResult    `json:"prune"`

	Before configCounts `json:"before"`
	After  configCounts `json:"after"`

	ReviewList []MountRow `json:"review_list"` // 人工复核清单（workflow 未自动挂载）
}

type sourceAttribution struct {
	Name    string `json:"name"`
	Repo    string `json:"repo"`
	SHA     string `json:"sha"`
	License string `json:"license"`
	Files   int    `json:"files"`
	Error   string `json:"error,omitempty"`
}

type convertSummary struct {
	CandidatesByKind map[string]int `json:"candidates_by_kind"`
	Candidates       int            `json:"candidates"`
	Rejected         int            `json:"rejected"`
	RejectTop        []kv           `json:"reject_top"`
}

type selectSummary struct {
	Selected int      `json:"selected"`
	Rejected int      `json:"rejected"`
	RejectTop []kv    `json:"reject_top"`
	SafeAFP  int      `json:"safe_active_fp"`
}

type dedupSummary struct {
	ActionCounts map[string]int `json:"action_counts"`
	ReportRows   int            `json:"report_rows"`
	ReasonTop    []kv           `json:"reason_top"`
}

type wireSummary struct {
	Mounts       int     `json:"mounts"`
	Review       int     `json:"review"`
	NewProducts  int     `json:"new_products"`
	HighConf     int     `json:"high_conf"`  // ≥0.9
	MidConf      int     `json:"mid_conf"`   // 0.8-0.9
	AvgConf      float64 `json:"avg_conf"`
	TopProducts  []kv    `json:"top_products"`
}

type validateSummary struct {
	PocOK        int `json:"poc_ok"`
	PocFailed    int `json:"poc_failed"`
	AFPOK        int `json:"afp_ok"`
	AFPFailed    int `json:"afp_failed"`
	AutoEligible int `json:"auto_eligible_total"`
	AutoNew      int `json:"auto_eligible_new"`
	Dangling     int `json:"dangling_refs"`
}

type configCounts struct {
	Pocs            int `json:"pocs"`
	FingerProducts  int `json:"finger_products"`
	FingerExprs     int `json:"finger_exprs"`
	ActiveFP        int `json:"active_fingerprints"`
	WorkflowProducts int `json:"workflow_products"`
	WorkflowRefs    int `json:"workflow_refs"`
}

type kv struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func runReport(opt *options) error {
	r := &reportData{GeneratedAt: nowStamp(), Workdir: opt.workdir, Config: opt.config}

	var fm FetchManifest
	if err := readPhase(opt.workdir, "fetch", &fm); err != nil {
		return err
	}
	for _, s := range fm.Sources {
		r.Sources = append(r.Sources, sourceAttribution{
			Name: s.Spec.Name, Repo: s.Spec.Repo, SHA: s.SHA, License: s.License,
			Files: len(s.Files), Error: s.Err,
		})
	}

	if err := fillConvert(opt, r); err != nil {
		return err
	}
	if err := fillSelect(opt, r); err != nil {
		return err
	}
	if err := fillDedup(opt, r); err != nil {
		return err
	}
	if err := fillWire(opt, r); err != nil {
		return err
	}
	var mr mergeResult
	if err := readPhase(opt.workdir, "merge", &mr); err != nil {
		return err
	}
	r.Merge = mr
	r.Backup = mr.Backup

	var vr validateResult
	if err := readPhase(opt.workdir, "validate", &vr); err != nil {
		return err
	}
	r.Validate = validateSummary{
		PocOK: vr.PocOK, PocFailed: vr.PocFailed,
		AFPOK: vr.AFPOK, AFPFailed: vr.AFPFailed,
		AutoEligible: vr.AutoEligible, AutoNew: vr.AutoNew,
		Dangling: len(vr.DanglingRefs),
	}

	var pr pruneResult
	if err := readPhase(opt.workdir, "prune", &pr); err != nil {
		return err
	}
	r.Prune = pr

	// 合并前（备份）/合并后（磁盘实测）规则数对比
	after, err := measureConfig(opt.config)
	if err != nil {
		return err
	}
	r.After = *after
	if mr.Backup != "" {
		before, err := measureBackup(mr.Backup)
		if err != nil {
			fmt.Printf("  [warn] 备份测量失败（跳过 before 对比）: %v\n", err)
		} else {
			r.Before = *before
		}
	}

	if err := writeReportJSON(opt, r); err != nil {
		return err
	}
	md := renderMarkdown(r)
	if err := os.WriteFile(filepath.Join(opt.workdir, "report.md"), []byte(md), 0o644); err != nil {
		return err
	}
	fmt.Printf("[report] 源 %d · 新增 POC %d · 指纹表达式 %d · 主动指纹 %d · workflow 挂载 %d\n",
		len(r.Sources), r.After.Pocs-r.Before.Pocs, r.Merge.FingerExpr, r.Merge.ActiveFP, r.Merge.Wired)
	fmt.Printf("[report] → %s 与 %s\n", phasePath(opt.workdir, "report"), filepath.Join(opt.workdir, "report.md"))
	return nil
}

func fillConvert(opt *options, r *reportData) error {
	var cr convertResult
	if err := readPhase(opt.workdir, "convert", &cr); err != nil {
		return err
	}
	cs := convertSummary{CandidatesByKind: map[string]int{}, Rejected: len(cr.Rejected)}
	for _, c := range cr.Candidates {
		cs.Candidates++
		cs.CandidatesByKind[string(c.Kind)]++
	}
	cs.RejectTop = topReasons(rowsOf(cr.Rejected), 10)
	r.Convert = cs
	return nil
}

func fillSelect(opt *options, r *reportData) error {
	var sr selectResult
	if err := readPhase(opt.workdir, "select", &sr); err != nil {
		return err
	}
	r.Select = selectSummary{
		Selected: len(sr.Selected), Rejected: len(sr.Rejected),
		RejectTop: topReasons(rowsOf(sr.Rejected), 10), SafeAFP: len(sr.SafeActiveFP),
	}
	return nil
}

func fillDedup(opt *options, r *reportData) error {
	var dd dedupResult
	if err := readPhase(opt.workdir, "dedup", &dd); err != nil {
		return err
	}
	ds := dedupSummary{ActionCounts: map[string]int{}, ReportRows: len(dd.Report)}
	for _, c := range dd.Candidates {
		ds.ActionCounts[c.Action]++
	}
	reasons := map[string]int{}
	for _, row := range dd.Report {
		reasons[row.Reason]++
	}
	ds.ReasonTop = topNMap(reasons, 10)
	r.Dedup = ds
	return nil
}

func fillWire(opt *options, r *reportData) error {
	var wr wireResult
	if err := readPhase(opt.workdir, "wire", &wr); err != nil {
		return err
	}
	ws := wireSummary{Mounts: len(wr.Mounts), Review: len(wr.Review), NewProducts: len(wr.NewProducts)}
	sum := 0.0
	cnt := map[string]int{}
	for _, m := range wr.Mounts {
		sum += m.Confidence
		cnt[m.Product]++
		if m.Confidence >= 0.9 {
			ws.HighConf++
		} else {
			ws.MidConf++
		}
	}
	if len(wr.Mounts) > 0 {
		ws.AvgConf = round3(sum / float64(len(wr.Mounts)))
	}
	ws.TopProducts = topNMap(cnt, 10)
	r.Wire = ws
	r.ReviewList = wr.Review
	return nil
}

// ---- 计数测量 ----

func measureConfig(configDir string) (*configCounts, error) {
	c := &configCounts{}
	pocs, err := filepath.Glob(filepath.Join(configDir, "pocs", "*.yaml"))
	if err != nil {
		return nil, err
	}
	c.Pocs = len(pocs)
	afp, err := filepath.Glob(filepath.Join(configDir, "active-fingerprints", "*.yaml"))
	if err != nil {
		return nil, err
	}
	c.ActiveFP = len(afp)
	fdata, err := os.ReadFile(filepath.Join(configDir, "finger.yaml"))
	if err != nil {
		return nil, err
	}
	fingers := map[string][]string{}
	if err := yaml.Unmarshal(fdata, &fingers); err != nil {
		return nil, err
	}
	c.FingerProducts = len(fingers)
	for _, v := range fingers {
		c.FingerExprs += len(v)
	}
	wdata, err := os.ReadFile(filepath.Join(configDir, "workflow.yaml"))
	if err != nil {
		return nil, err
	}
	wf := map[string]workflowEntry{}
	if err := yaml.Unmarshal(wdata, &wf); err != nil {
		return nil, err
	}
	c.WorkflowProducts = len(wf)
	for _, e := range wf {
		c.WorkflowRefs += len(e.Pocs)
	}
	return c, nil
}

// measureBackup 从 merge 备份 tar 测量合并前规则数（原始武器库）。
func measureBackup(backup string) (*configCounts, error) {
	c := &configCounts{}
	list, err := exec.Command("tar", "tzf", backup).Output()
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(list), "\n") {
		if strings.HasSuffix(line, ".yaml") && strings.Contains(line, "/pocs/") {
			c.Pocs++
		}
		if strings.HasSuffix(line, ".yaml") && strings.Contains(line, "/active-fingerprints/") {
			c.ActiveFP++
		}
	}
	tmp, err := os.MkdirTemp("", "arsenal-report-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	if err := exec.Command("tar", "xzf", backup, "-C", tmp).Run(); err != nil {
		return nil, err
	}
	// 直接定位 finger.yaml / workflow.yaml
	var fdata, wdata []byte
	filepath.WalkDir(tmp, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Name() == "finger.yaml" && fdata == nil {
			fdata, _ = os.ReadFile(p)
		}
		if d.Name() == "workflow.yaml" && wdata == nil {
			wdata, _ = os.ReadFile(p)
		}
		return nil
	})
	if fdata != nil {
		fingers := map[string][]string{}
		if err := yaml.Unmarshal(fdata, &fingers); err == nil {
			c.FingerProducts = len(fingers)
			for _, v := range fingers {
				c.FingerExprs += len(v)
			}
		}
	}
	if wdata != nil {
		wf := map[string]workflowEntry{}
		if err := yaml.Unmarshal(wdata, &wf); err == nil {
			c.WorkflowProducts = len(wf)
			for _, e := range wf {
				c.WorkflowRefs += len(e.Pocs)
			}
		}
	}
	return c, nil
}

// ---- 工具 ----

func nowStamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func writeReportJSON(opt *options, r *reportData) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(phasePath(opt.workdir, "report"), data, 0o644)
}

// rowsOf 提取 RejectRow 的拒绝原因列表。
func rowsOf(rows []RejectRow) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Reason)
	}
	return out
}

func topReasons(reasons []string, n int) []kv {
	m := map[string]int{}
	for _, r := range reasons {
		m[r]++
	}
	return topNMap(m, n)
}

func topNMap(m map[string]int, n int) []kv {
	var rows []kv
	for k, v := range m {
		rows = append(rows, kv{k, v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Key < rows[j].Key
	})
	if len(rows) > n {
		rows = rows[:n]
	}
	return rows
}

func renderMarkdown(r *reportData) string {
	var b strings.Builder
	w := func(format string, a ...interface{}) { fmt.Fprintf(&b, format, a...) }

	w("# 武器库导入总报告\n\n")
	w("生成时间：%s  \n", r.GeneratedAt)
	w("工作目录：`%s`  \n", r.Workdir)
	w("目标配置：`%s`  \n\n", r.Config)

	// 合并前后对比
	w("## 规则数对比（合并前 → 合并后）\n\n")
	w("| 项 | 合并前 | 合并后 | 变化 |\n")
	w("|---|---:|---:|---:|\n")
	w("| POC | %d | %d | +%d |\n", r.Before.Pocs, r.After.Pocs, r.After.Pocs-r.Before.Pocs)
	w("| 指纹产品 | %d | %d | +%d |\n", r.Before.FingerProducts, r.After.FingerProducts, r.After.FingerProducts-r.Before.FingerProducts)
	w("| 指纹表达式 | %d | %d | +%d |\n", r.Before.FingerExprs, r.After.FingerExprs, r.After.FingerExprs-r.Before.FingerExprs)
	w("| 主动指纹 | %d | %d | +%d |\n", r.Before.ActiveFP, r.After.ActiveFP, r.After.ActiveFP-r.Before.ActiveFP)
	w("| workflow 产品 | %d | %d | %+d |\n", r.Before.WorkflowProducts, r.After.WorkflowProducts, r.After.WorkflowProducts-r.Before.WorkflowProducts)
	w("| workflow 引用 | %d | %d | %+d |\n\n", r.Before.WorkflowRefs, r.After.WorkflowRefs, r.After.WorkflowRefs-r.Before.WorkflowRefs)

	// 源仓库归属
	w("## 源仓库与许可证归属\n\n")
	w("| 源 | 仓库 | Commit SHA | License | 文件数 |\n")
	w("|---|---|---|---|---:|\n")
	for _, s := range r.Sources {
		sha := s.SHA
		if len(sha) > 12 {
			sha = sha[:12]
		}
		if s.Error != "" {
			w("| %s | %s | — | — | 失败: %s |\n", s.Name, s.Repo, s.Error)
			continue
		}
		w("| %s | %s | `%s` | %s | %d |\n", s.Name, s.Repo, sha, s.License, s.Files)
	}
	w("\n")

	// 各阶段
	w("## 各阶段计数\n\n")
	w("- **convert**：候选 %d（", r.Convert.Candidates)
	parts := []string{}
	for k, v := range r.Convert.CandidatesByKind {
		parts = append(parts, fmt.Sprintf("%s %d", k, v))
	}
	sort.Strings(parts)
	w("%s），转换拒绝 %d\n", strings.Join(parts, " / "), r.Convert.Rejected)
	w("- **select**：保留 %d，拒绝 %d，safe 主动指纹 %d\n", r.Select.Selected, r.Select.Rejected, r.Select.SafeAFP)
	w("- **dedup**：")
	keys := []string{}
	for k := range r.Dedup.ActionCounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	dparts := []string{}
	for _, k := range keys {
		dparts = append(dparts, fmt.Sprintf("%s %d", k, r.Dedup.ActionCounts[k]))
	}
	w("%s（去重明细 %d 行）\n", strings.Join(dparts, " / "), r.Dedup.ReportRows)
	w("- **wire**：自动挂载 %d，人工复核 %d，新建产品键 %d（高置信≥0.9 %d，中置信 0.8-0.9 %d，均值 %.3f）\n",
		r.Wire.Mounts, r.Wire.Review, r.Wire.NewProducts, r.Wire.HighConf, r.Wire.MidConf, r.Wire.AvgConf)
	w("- **merge**：POC %d（改名 %d），指纹表达式 %d（新产品键 %d），主动指纹 %d，workflow 挂载 %d（新产品键 %d）\n",
		r.Merge.PocFiles, len(r.Merge.RenameMap), r.Merge.FingerExpr, r.Merge.FingerProd, r.Merge.ActiveFP, r.Merge.Wired, r.Merge.NewProds)
	w("- **validate**：POC %d 通过 / %d 失败；主动指纹 %d 通过 / %d 失败；自动放行 %d（新增 %d）；workflow dangling %d\n",
		r.Validate.PocOK, r.Validate.PocFailed, r.Validate.AFPOK, r.Validate.AFPFailed, r.Validate.AutoEligible, r.Validate.AutoNew, r.Validate.Dangling)
	w("- **prune**：移除 POC %d（wordpress helper 依赖 %d，fork DSL 词法 %d），清理 workflow 引用 %d、空产品 %d\n\n",
		r.Prune.RemovedPocs, r.Prune.WordPressHelpers, r.Prune.ForkDSLLexer, r.Prune.RemovedRefs, r.Prune.RemovedProducts)

	if r.Backup != "" {
		w("合并前备份：`%s`\n\n", r.Backup)
	}

	// select 拒绝原因 Top
	w("## select 拒绝原因 Top10\n\n")
	for _, row := range r.Select.RejectTop {
		w("- `%s` — %d\n", row.Key, row.Count)
	}
	w("\n")

	// dedup 原因 Top
	w("## dedup 去重原因 Top10\n\n")
	for _, row := range r.Dedup.ReasonTop {
		w("- `%s` — %d\n", row.Key, row.Count)
	}
	w("\n")

	// wire top products
	w("## 挂载 POC 数最多的产品 Top10\n\n")
	for _, row := range r.Wire.TopProducts {
		w("- `%s` — %d\n", row.Key, row.Count)
	}
	w("\n")

	// 人工复核清单（markdown 截断展示，全量见 report.json）
	const reviewCap = 100
	w("## workflow 人工复核清单（%d 条，未自动挂载）\n\n", len(r.ReviewList))
	if len(r.ReviewList) == 0 {
		w("（无）\n\n")
	} else {
		if len(r.ReviewList) > reviewCap {
			w("> 仅展示前 %d 条，全量见 `phase-report.json` 的 `review_list`。\n\n", reviewCap)
		}
		w("| POC | 候选产品 | 置信度 | 依据 | 匹配来源 |\n")
		w("|---|---|---:|---|---|\n")
		show := r.ReviewList
		if len(show) > reviewCap {
			show = show[:reviewCap]
		}
		for _, m := range show {
			w("| %s | %s | %.3f | %s | %s |\n", m.POC, m.Product, m.Confidence, m.Evidence, m.MatchedBy)
		}
		w("\n")
	}

	return b.String()
}
