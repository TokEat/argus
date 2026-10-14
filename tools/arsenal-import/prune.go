package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// prune 把 validate 判为解析失败的 POC 从 config 移除并清理 workflow.yaml 引用：
//   - 删 config/pocs/<file>（主要是依赖未导入 helpers/wordpress/*.txt 的插件探测模板，
//     及个别 fork DSL 词法器解析不了的 native 模板——它们在 argus 运行时同样是死规则）；
//   - 从 workflow.yaml 各产品 pocs 列表摘掉这些引用，清空后无剩余 poc 的产品条目一并删除；
//   - 回写 phase-dedup.json：被剪候选 Action 改为 rejected（下游 validate/report 视为未入库）。
// config 已先经 merge 备份，prune 只动校验失败的文件，安全可回滚（恢复备份即可）。

type pruneResult struct {
	RemovedPocs      int      `json:"removed_pocs"`
	RemovedRefs      int      `json:"removed_workflow_refs"`
	RemovedProducts  int      `json:"removed_empty_products"`
	Files            []string `json:"files"`
	WordPressHelpers int      `json:"wordpress_helper_deps"`
	ForkDSLLexer     int      `json:"fork_dsl_lexer"`
}

func runPrune(opt *options) error {
	var vr validateResult
	if err := readPhase(opt.workdir, "validate", &vr); err != nil {
		return err
	}
	if len(vr.PocFailures) == 0 {
		fmt.Println("[prune] 无校验失败 POC，无需移除")
		return writePhase(opt.workdir, "prune", &pruneResult{})
	}
	res := &pruneResult{Files: []string{}}

	// 1) 删除失败 POC 文件，记录 basename（无扩展）供 workflow 清理
	pruned := map[string]bool{}
	for _, f := range vr.PocFailures {
		base := strings.TrimSuffix(f.File, ".yaml")
		pruned[base] = true
		res.Files = append(res.Files, f.File)
		if strings.Contains(f.Err, "could not parse payloads") {
			res.WordPressHelpers++
		} else {
			res.ForkDSLLexer++
		}
		if err := os.Remove(filepath.Join(opt.config, "pocs", f.File)); err != nil && !os.IsNotExist(err) {
			return err
		}
		res.RemovedPocs++
	}
	sort.Strings(res.Files)

	// 2) 清理 workflow.yaml 引用
	if err := pruneWorkflowRefs(opt, pruned, res); err != nil {
		return err
	}

	// 3) 回写 dedup 阶段：被剪候选标记 rejected
	if err := markPrunedInDedup(opt, pruned); err != nil {
		return err
	}

	if err := writePhase(opt.workdir, "prune", res); err != nil {
		return err
	}
	fmt.Printf("[prune] 移除 POC %d（wordpress helper 依赖 %d，fork DSL 词法 %d），清理 workflow 引用 %d、空产品 %d → %s\n",
		res.RemovedPocs, res.WordPressHelpers, res.ForkDSLLexer, res.RemovedRefs, res.RemovedProducts, phasePath(opt.workdir, "prune"))
	return nil
}

func pruneWorkflowRefs(opt *options, pruned map[string]bool, res *pruneResult) error {
	wfPath := filepath.Join(opt.config, "workflow.yaml")
	data, err := os.ReadFile(wfPath)
	if err != nil {
		return err
	}
	wf := map[string]workflowEntry{}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return fmt.Errorf("workflow.yaml 解析: %w", err)
	}
	out := map[string]workflowEntry{}
	for prod, e := range wf {
		kept := e.Pocs[:0]
		for _, ref := range e.Pocs {
			if pruned[ref] {
				res.RemovedRefs++
				continue
			}
			kept = append(kept, ref)
		}
		if len(kept) == 0 {
			res.RemovedProducts++
			continue
		}
		e.Pocs = kept
		out[prod] = e
	}
	data, err = yaml.Marshal(out)
	if err != nil {
		return err
	}
	return os.WriteFile(wfPath, data, 0o644)
}

func markPrunedInDedup(opt *options, pruned map[string]bool) error {
	var dd dedupResult
	if err := readPhase(opt.workdir, "dedup", &dd); err != nil {
		return err
	}
	changed := false
	for i := range dd.Candidates {
		c := &dd.Candidates[i]
		if c.Kind == KindPoc && c.Action == "added" && pruned[c.ID] {
			c.Action = "rejected"
			c.Reason = "validate: nuclei parse failed (pruned)"
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return writePhase(opt.workdir, "dedup", &dd)
}
