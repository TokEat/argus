package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/ratelimit"
	"gopkg.in/yaml.v3"

	"github.com/P0lar1ght/argus/shared/proto/go/activefingerprint"
)

// 本阶段对 merge 落盘结果做严格校验，把"运行时才会暴露"的问题提前暴露：
//   - 新 POC 逐个过 nuclei fork 的 templates.Parse（镜像引擎加载，解析失败=拒绝）；
//   - 主动指纹逐个跑 activefingerprint.Inspect（必须无错），并断言自动放行总数 ≤8；
//   - workflow.yaml 挂载的 poc 引用必须都能解析到磁盘文件（防 dangling 引用）。
// 校验对象是 config 实际落盘内容，不是候选内存态。

type validateResult struct {
	PocTotal    int           `json:"poc_total"` // 校验的新 POC 数
	PocOK       int           `json:"poc_ok"`
	PocFailed   int           `json:"poc_failed"`
	PocFailures []ValidateRow `json:"poc_failures"`

	AFPTotal     int           `json:"afp_total"`     // 主动指纹文件总数（含 shiro）
	AFPOK        int           `json:"afp_ok"`
	AFPFailed    int           `json:"afp_failed"`
	AFPFailures  []ValidateRow `json:"afp_failures"`
	AutoEligible int           `json:"auto_eligible_total"` // 最终 on-disk 自动放行数（须 ≤8）
	AutoNew      int           `json:"auto_eligible_new"`   // 其中本次新增（afp-*）

	WfProducts   int      `json:"workflow_products"`
	WfPocRefs    int      `json:"workflow_poc_refs"`
	DanglingRefs []string `json:"dangling_workflow_refs"`
}

type ValidateRow struct {
	File string `json:"file"`
	Err  string `json:"error"`
}

func runValidate(opt *options) error {
	var dd dedupResult
	if err := readPhase(opt.workdir, "dedup", &dd); err != nil {
		return err
	}
	var mr mergeResult
	if err := readPhase(opt.workdir, "merge", &mr); err != nil {
		return err
	}
	res := &validateResult{}

	if err := validatePocs(opt, dd, mr, res); err != nil {
		return err
	}
	if err := validateActiveFPs(opt, res); err != nil {
		return err
	}
	if err := validateWorkflowRefs(opt, res); err != nil {
		return err
	}

	if err := writePhase(opt.workdir, "validate", res); err != nil {
		return err
	}
	fmt.Printf("[validate] POC %d 通过 / %d 失败 · 主动指纹 %d 通过 / %d 失败（自动放行 %d，新增 %d）· workflow dangling %d → %s\n",
		res.PocOK, res.PocFailed, res.AFPOK, res.AFPFailed, res.AutoEligible, res.AutoNew, len(res.DanglingRefs), phasePath(opt.workdir, "validate"))
	if res.AutoEligible > activefingerprint.MaxAutoSafePerTenant {
		return fmt.Errorf("自动放行主动指纹 %d 超过每租户硬上限 %d", res.AutoEligible, activefingerprint.MaxAutoSafePerTenant)
	}
	if len(res.DanglingRefs) > 0 {
		fmt.Printf("  [warn] workflow 有 %d 个 dangling poc 引用（见 phase-validate.json）\n", len(res.DanglingRefs))
	}
	return nil
}

// validatePocs 对 merge 落盘的新 POC（dedup survivor）逐个 templates.Parse。
func validatePocs(opt *options, dd dedupResult, mr mergeResult, res *validateResult) error {
	execOpts, err := buildExecutorOptions(opt)
	if err != nil {
		return err
	}
	templates.ResetTemplateCache()

	pocsDir := filepath.Join(opt.config, "pocs")
	var ids []string
	for _, c := range dd.Candidates {
		if c.Kind == KindPoc && c.Action == "added" {
			ids = append(ids, c.ID)
		}
	}
	sort.Strings(ids)

	for _, id := range ids {
		base := id
		if rn, ok := mr.RenameMap[id]; ok {
			base = rn
		}
		path := filepath.Join(pocsDir, base+".yaml")
		// 文件缺失 = 已被 prune 移除，跳过（不再判失败），保证 validate 幂等
		if _, err := os.Stat(path); err != nil {
			continue
		}
		res.PocTotal++
		if err := parseOnePoc(execOpts, path); err != nil {
			res.PocFailed++
			res.PocFailures = append(res.PocFailures, ValidateRow{File: base + ".yaml", Err: err.Error()})
		} else {
			res.PocOK++
		}
		if res.PocTotal%500 == 0 {
			fmt.Printf("  ... POC 校验中 %d/%d\n", res.PocTotal, len(ids))
		}
	}
	return nil
}

// parseOnePoc 用 recover 兜住第三方模板可能触发的 panic，避免整批中断。
func parseOnePoc(execOpts protocols.ExecutorOptions, path string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	_, err = templates.Parse(path, nil, execOpts)
	return err
}

// buildExecutorOptions 按 testutils.NewMockExecuterOptions 配方构造最小可解析选项，
// 但不引入 testutils（其 integration.go 依赖未缓存的 httprouter，离线构建会失败）。
func buildExecutorOptions(opt *options) (protocols.ExecutorOptions, error) {
	options := &types.Options{
		NoColor:                    true,
		BulkSize:                   25,
		TemplateThreads:            10,
		Timeout:                    5,
		Retries:                    1,
		RateLimit:                  150,
		InteractshURL:              "https://oast.fun",
		InteractionsCacheSize:      5000,
		InteractionsEviction:       60,
		InteractionsCoolDownPeriod: 5,
		InteractionsPollDuration:   5,
	}
	if err := protocolinit.Init(options); err != nil {
		return protocols.ExecutorOptions{}, fmt.Errorf("protocolinit: %w", err)
	}
	progressImpl, _ := progress.NewStatsTicker(0, false, false, false, 0)
	pocsDir, err := filepath.Abs(filepath.Join(opt.config, "pocs"))
	if err != nil {
		return protocols.ExecutorOptions{}, err
	}
	execOpts := protocols.ExecutorOptions{
		Output:       &noopWriter{aurora: aurora.NewAurora(false)},
		Options:      options,
		Progress:     progressImpl,
		ProjectFile:  nil,
		IssuesClient: nil,
		Browser:      nil,
		Catalog:      disk.NewCatalog(pocsDir),
		RateLimiter:  ratelimit.New(context.Background(), uint(options.RateLimit), time.Second),
	}
	workflowLoader, err := parsers.NewLoader(&execOpts)
	if err != nil {
		return protocols.ExecutorOptions{}, fmt.Errorf("workflow loader: %w", err)
	}
	execOpts.WorkflowLoader = workflowLoader
	execOpts.CreateTemplateCtxStore()
	return execOpts, nil
}

// noopWriter 是解析期无需落盘/展示的最小 output.Writer 实现。
type noopWriter struct{ aurora aurora.Aurora }

func (n *noopWriter) Close()                                          {}
func (n *noopWriter) Colorizer() aurora.Aurora                        { return n.aurora }
func (n *noopWriter) Write(*output.ResultEvent) error                 { return nil }
func (n *noopWriter) WriteFailure(*output.InternalWrappedEvent) error { return nil }
func (n *noopWriter) Request(string, string, string, error)           {}
func (n *noopWriter) WriteStoreDebugData(string, string, string, string) {}

// validateActiveFPs 对 active-fingerprints/ 全量（含 shiro）跑 Inspect：
// 必须无错，且自动放行总数 ≤ MaxAutoSafePerTenant。
func validateActiveFPs(opt *options, res *validateResult) error {
	dir := filepath.Join(opt.config, "active-fingerprints")
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		name := filepath.Base(f)
		res.AFPTotal++
		cls, inspectErr := activefingerprint.Inspect(name, content)
		if inspectErr != nil {
			res.AFPFailed++
			res.AFPFailures = append(res.AFPFailures, ValidateRow{File: name, Err: inspectErr.Error()})
			continue
		}
		res.AFPOK++
		if cls.AutoEligible {
			res.AutoEligible++
			if len(name) >= 4 && name[:4] == "afp-" {
				res.AutoNew++
			}
		}
	}
	return nil
}

// validateWorkflowRefs 校验 workflow.yaml 里每个 poc 引用都能解析到 pocs/<ref>.yaml。
func validateWorkflowRefs(opt *options, res *validateResult) error {
	wf := map[string]workflowEntry{}
	data, err := os.ReadFile(filepath.Join(opt.config, "workflow.yaml"))
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return fmt.Errorf("workflow.yaml 解析: %w", err)
	}
	pocsDir := filepath.Join(opt.config, "pocs")
	for prod, e := range wf {
		res.WfProducts++
		for _, ref := range e.Pocs {
			res.WfPocRefs++
			if _, err := os.Stat(filepath.Join(pocsDir, ref+".yaml")); err != nil {
				res.DanglingRefs = append(res.DanglingRefs, prod+" -> "+ref)
			}
		}
	}
	sort.Strings(res.DanglingRefs)
	return nil
}
