package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// 本阶段把 survivor 合并入 --config（先 tar 备份）。POC 写 pocs/<id>.yaml（命名冲突
// 改名 <id>-<source>.yaml 并记映射）；finger.yaml 新表达式挂到归一化后的现有产品键
// （≥阈值归并，绝不丢现有条目）；主动指纹写 active-fingerprints/；workflow.yaml 按
// wire 方案挂载（产品键经同一 resolveKey 归并，保证 workflow 键 == finger.yaml 键）。

type mergeResult struct {
	Backup     string            `json:"backup"`
	PocFiles   int               `json:"poc_files"`
	RenameMap  map[string]string `json:"rename_map"` // poc id → 落盘 basename
	FingerExpr int               `json:"finger_exprs"`
	FingerProd int               `json:"finger_new_products"`
	ActiveFP   int               `json:"active_fp"`
	Wired      int               `json:"workflow_mounted"`
	NewProds   int               `json:"workflow_new_products"`
}

// workflowEntry 对应 workflow.yaml 单产品节点。
type workflowEntry struct {
	Type []string `yaml:"type"`
	Pocs []string `yaml:"pocs"`
}

// 产品键归并阈值：新指纹产品名与现有 finger.yaml 键的 token 相似度 ≥ 该值则归并到现有键。
const mergeKeyThreshold = 0.85

func runMerge(opt *options) error {
	var dd dedupResult
	if err := readPhase(opt.workdir, "dedup", &dd); err != nil {
		return err
	}
	var wr wireResult
	if err := readPhase(opt.workdir, "wire", &wr); err != nil {
		return err
	}
	backup, err := backupConfig(opt)
	if err != nil {
		return err
	}
	res := &mergeResult{Backup: backup, RenameMap: map[string]string{}}

	existFingers := loadExistingFingers(opt.config)
	resolve := newKeyResolver(existFingers)

	// 1) POC 落盘
	pocs := []Candidate{}
	for _, c := range dd.Candidates {
		if c.Kind == KindPoc && c.Action == "added" {
			pocs = append(pocs, c)
		}
	}
	sort.Slice(pocs, func(i, j int) bool { return pocs[i].ID < pocs[j].ID })
	if err := writePocs(opt, pocs, res); err != nil {
		return err
	}

	// 2) 主动指纹落盘
	if err := writeActiveFPs(opt, dd, res); err != nil {
		return err
	}

	// 3) finger.yaml 合并
	if err := mergeFingerYAML(opt, dd, existFingers, resolve, res); err != nil {
		return err
	}

	// 4) workflow.yaml 按 wire 方案挂载
	if err := mergeWorkflow(opt, wr, resolve, res); err != nil {
		return err
	}

	if err := writePhase(opt.workdir, "merge", res); err != nil {
		return err
	}
	fmt.Printf("[merge] 备份 %s\n", backup)
	fmt.Printf("[merge] POC %d（改名 %d）· 指纹表达式 %d（新产品键 %d）· 主动指纹 %d · workflow 挂载 %d（新产品键 %d）→ %s\n",
		res.PocFiles, len(res.RenameMap), res.FingerExpr, res.FingerProd, res.ActiveFP, res.Wired, res.NewProds, phasePath(opt.workdir, "merge"))
	return nil
}

func backupConfig(opt *options) (string, error) {
	ts := time.Now().Format("20060102-150405")
	out := filepath.Join(opt.workdir, "..", "arsenal-import-backup-"+ts+".tar.gz")
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", err
	}
	cmd := exec.Command("tar", "czf", abs, "-C", filepath.Dir(opt.config), filepath.Base(opt.config))
	if combined, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("备份失败: %v: %s", err, combined)
	}
	return abs, nil
}

// writePocs 写 POC 文件，冲突改名 <id>-<source>(-N)。renameMap 记录 id→basename。
func writePocs(opt *options, pocs []Candidate, res *mergeResult) error {
	used := map[string]bool{}
	files, _ := filepath.Glob(filepath.Join(opt.config, "pocs", "*.yaml"))
	for _, f := range files {
		used[strings.TrimSuffix(filepath.Base(f), ".yaml")] = true
	}
	for _, c := range pocs {
		name := c.ID
		if used[name] {
			name = c.ID + "-" + c.Source
			for n := 2; used[name]; n++ {
				name = fmt.Sprintf("%s-%s-%d", c.ID, c.Source, n)
			}
		}
		used[name] = true
		if name != c.ID {
			res.RenameMap[c.ID] = name
		}
		if err := os.WriteFile(filepath.Join(opt.config, "pocs", name+".yaml"), []byte(c.Content), 0o644); err != nil {
			return err
		}
		res.PocFiles++
	}
	return nil
}

func writeActiveFPs(opt *options, dd dedupResult, res *mergeResult) error {
	for _, c := range dd.Candidates {
		if c.Kind != KindActiveFP || c.Action != "added" {
			continue
		}
		if err := os.WriteFile(filepath.Join(opt.config, "active-fingerprints", c.FileName), []byte(c.Content), 0o644); err != nil {
			return err
		}
		res.ActiveFP++
	}
	return nil
}

// mergeFingerYAML 把新增指纹表达式挂到归一化后的产品键（现有键优先），绝不丢现有条目。
func mergeFingerYAML(opt *options, dd dedupResult, exist map[string][]string, resolve *keyResolver, res *mergeResult) error {
	add := map[string][]string{} // finalKey → 新表达式
	for _, c := range dd.Candidates {
		if c.Kind != KindFinger || c.Action != "added" {
			continue
		}
		key := resolve.resolve(c.ProductName)
		expr := strings.TrimSpace(c.RuleExpr)
		// 同键下去重（防与现有或已收表达式重复）
		dup := false
		for _, e := range append(exist[key], add[key]...) {
			if fofaExactEqual(e, expr) {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		add[key] = append(add[key], expr)
		res.FingerExpr++
	}
	// 应用：新键计数 + 追加
	newKeys := map[string]bool{}
	for key, exprs := range add {
		if _, ok := exist[key]; !ok {
			newKeys[key] = true
		}
		exist[key] = append(exist[key], exprs...)
	}
	res.FingerProd = len(newKeys)
	data, err := yaml.Marshal(exist)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(opt.config, "finger.yaml"), data, 0o644)
}

// fofaExactEqual 规范化后比较两条 fofa 表达式是否等价（小写去空白）。
func fofaExactEqual(a, b string) bool {
	return strings.ToLower(strings.Join(strings.Fields(a), "")) == strings.ToLower(strings.Join(strings.Fields(b), ""))
}

// mergeWorkflow 按 wire 方案把 POC 挂到产品（产品键经 resolveKey 归并，与 finger.yaml 一致）。
func mergeWorkflow(opt *options, wr wireResult, resolve *keyResolver, res *mergeResult) error {
	wf := map[string]*workflowEntry{}
	data, err := os.ReadFile(filepath.Join(opt.config, "workflow.yaml"))
	if err == nil {
		if err := yaml.Unmarshal(data, &wf); err != nil {
			return fmt.Errorf("workflow.yaml 解析: %w", err)
		}
	}
	newProds := map[string]bool{}
	for _, m := range wr.Mounts {
		// 用落盘 basename（处理过改名）作为 poc 引用
		pocRef := m.POC
		pocBase := strings.TrimSuffix(m.POC, ".yaml")
		if rn, ok := res.RenameMap[pocBase]; ok {
			pocRef = rn
		}
		key := resolve.resolve(m.Product)
		e, ok := wf[key]
		if !ok {
			e = &workflowEntry{Type: []string{"root"}}
			wf[key] = e
			newProds[key] = true
		}
		if !inStrSlice(e.Pocs, pocRef) {
			e.Pocs = append(e.Pocs, pocRef)
			res.Wired++
		}
	}
	res.NewProds = len(newProds)
	// map[string]*workflowEntry → 输出需 map[string]workflowEntry，yaml 才能正确序列化
	out := map[string]workflowEntry{}
	for k, v := range wf {
		out[k] = *v
	}
	data, err = yaml.Marshal(out)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(opt.config, "workflow.yaml"), data, 0o644)
}

func inStrSlice(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// ---- 产品键归并 ----

// keyResolver 把新指纹产品名归并到现有 finger.yaml 键（token 相似度≥阈值），
// 无匹配则返回原名。workflow 与 finger.yaml 共用，保证两文件产品键一致。
type keyResolver struct {
	idx *productIndex
}

func newKeyResolver(exist map[string][]string) *keyResolver {
	idx := &productIndex{post: map[string][]int{}}
	for prod := range exist {
		toks := uniqueSorted(tokenizeProduct(prod))
		if len(toks) == 0 {
			continue
		}
		ki := len(idx.keys)
		idx.keys = append(idx.keys, prod)
		idx.toks = append(idx.toks, toks)
		idx.origin = append(idx.origin, "existing")
		for _, t := range toks {
			idx.post[t] = append(idx.post[t], ki)
		}
	}
	return &keyResolver{idx: idx}
}

func (r *keyResolver) resolve(name string) string {
	toks := uniqueSorted(tokenizeProduct(name))
	if len(toks) == 0 {
		return name
	}
	key, conf, _, ok := r.idx.bestMatch(toks)
	if ok && conf >= mergeKeyThreshold {
		return key
	}
	return name
}
