package main

import (
	"fmt"
	"sort"
	"strings"
)

// 本阶段做深度语义去重：POC 按请求归一+matcher 签名精确哈希 + token Jaccard 近重复；
// fofa 按原子集合 Jaccard 近重复。对现有库（config/pocs + finger.yaml）与批内双向去重。
// 策略：精确重复→跳过；同产品近重复→保留高 severity（POC）/保留一条（fofa）；
// 跨产品 fofa 精确重复→保留首个 + 报告别名候选。

type dedupResult struct {
	Candidates []Candidate `json:"candidates"` // 全部，Action ∈ added/skipped/merged
	Report     []DedupRow  `json:"report"`     // 被去重样本明细
}

type DedupRow struct {
	Kind       string  `json:"kind"`
	ID         string  `json:"id"`
	Action     string  `json:"action"` // skipped / merged / alias
	DupOf      string  `json:"dup_of,omitempty"`
	Similarity float64 `json:"similarity,omitempty"`
	Reason     string  `json:"reason"`
}

func runDedup(opt *options) error {
	var sel selectResult
	if err := readPhase(opt.workdir, "select", &sel); err != nil {
		return err
	}
	res := &dedupResult{}
	pocs, fingers, afps := partition(sel.Selected)
	dedupPOC(opt, pocs, res)
	dedupFinger(opt, fingers, res)
	// 主动指纹只有 7 个 safe 精选名额内，无需近重复；直接放行。
	for i := range afps {
		afps[i].Action = "added"
		res.Candidates = append(res.Candidates, afps[i])
	}
	if err := writePhase(opt.workdir, "dedup", res); err != nil {
		return err
	}
	ac := countByAction(res.Candidates)
	fmt.Printf("[dedup] added=%d merged=%d skipped=%d (近重复对 %d) → %s\n",
		ac.Added, ac.Merged, ac.Skipped, len(res.Report), phasePath(opt.workdir, "dedup"))
	return printDedupSummary(res.Report)
}

func partition(cands []Candidate) (pocs, fingers, afps []Candidate) {
	for _, c := range cands {
		switch c.Kind {
		case KindPoc:
			pocs = append(pocs, c)
		case KindFinger:
			fingers = append(fingers, c)
		case KindActiveFP:
			afps = append(afps, c)
		}
	}
	return
}

func printDedupSummary(rep []DedupRow) error {
	byReason := map[string]int{}
	for _, r := range rep {
		byReason[r.Reason]++
	}
	type kv struct {
		reason string
		n      int
	}
	var rows []kv
	for reason, n := range byReason {
		rows = append(rows, kv{reason, n})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].n > rows[j].n })
	fmt.Println("\n去重原因 Top10:")
	for i, row := range rows {
		if i >= 10 {
			break
		}
		fmt.Printf("  %5d  %s\n", row.n, row.reason)
	}
	return nil
}

// ---- POC 去重 ----

func dedupPOC(opt *options, pocs []Candidate, res *dedupResult) {
	// 稳定序：severity 降序 → 源优先级 → 原顺序，保证组内保留最优者
	order := append([]Candidate(nil), pocs...)
	sort.SliceStable(order, func(i, j int) bool {
		si, sj := severityRank(order[i].Severity), severityRank(order[j].Severity)
		if si != sj {
			return si > sj
		}
		return sourceRank(order[i].Source) > sourceRank(order[j].Source)
	})

	type doc struct {
		key      string // batch 用 candidate index（字符串化）或 existing 文件名
		existing bool
		canon    string
		tokens   []string
	}
	var docs []doc
	docIsExisting := []bool{}
	docBatchIdx := []int{} // batch 数组下标；existing 为 -1

	// 现有库 doc
	exist := loadExistingPocs(opt.config)
	// 规范化 existing 文件名→无扩展（对齐 candidate.FileName 无扩展习惯）
	for fn, ec := range exist {
		docs = append(docs, doc{key: strings.TrimSuffix(fn, ".yaml"), existing: true, canon: ec.canon, tokens: ec.tokens})
		docIsExisting = append(docIsExisting, true)
		docBatchIdx = append(docBatchIdx, -1)
	}
	// batch doc（保序，便于精确去重"保留首个"）
	batchCanon := make([]string, len(order))
	for i, c := range order {
		t, err := parseNucleiTemplate([]byte(c.Content))
		canon, toks, _ := "", []string(nil), false
		if err == nil {
			canon, toks, _ = pocCanon(t)
		}
		batchCanon[i] = canon
		docs = append(docs, doc{key: fmt.Sprint(i), existing: false, canon: canon, tokens: toks})
		docIsExisting = append(docIsExisting, false)
		docBatchIdx = append(docBatchIdx, i)
	}
	nDocs := len(docs)

	// 1) 精确去重：canon 串 → 首个 doc 下标
	exactOwner := map[string]int{}
	exactDup := make([]int, nDocs) // 重复的指向保留者；唯一/保留者为 -1
	for i := range nDocs {
		exactDup[i] = -1
	}
	for i := range nDocs {
		if docIsExisting[i] {
			if _, seen := exactOwner[docs[i].canon]; !seen {
				exactOwner[docs[i].canon] = i
			}
			continue // existing 只作基准，不做重复标记
		}
		if owner, seen := exactOwner[docs[i].canon]; seen {
			exactDup[i] = owner
		} else {
			exactOwner[docs[i].canon] = i
		}
	}

	// 2) 近重复：仅在未被精确判重的 batch doc 与全部 existing 之间找 Jaccard 对
	alive := make([]bool, nDocs)
	tokenSets := make([][]string, nDocs)
	for i := range nDocs {
		alive[i] = docIsExisting[i] || exactDup[i] == -1
		tokenSets[i] = docs[i].tokens
	}
	pairs := findNearDupPairs(tokenSets, alive, opt.nearDupPoc)
	parent := newUF(nDocs)
	for _, p := range pairs {
		parent.union(p[0], p[1])
	}

	// 3) 汇总：组内保留优先级最高的 batch doc（existing 组内 batch 全部跳过）
	groupBest := map[int]int{} // root → 最优 batch doc（无 batch 则 -1）
	bestIsExisting := map[int]bool{}
	for i := range nDocs {
		if !alive[i] {
			continue
		}
		root := parent.find(i)
		if docIsExisting[i] {
			bestIsExisting[root] = true // 组内出现 existing 则 batch 不重复入库
			continue
		}
		if cur, ok := groupBest[root]; !ok || batchBetter(order, docBatchIdx[i], docBatchIdx[cur]) {
			groupBest[root] = i
		}
	}

	batchAction := make([]string, len(order))
	batchDupOf := make([]string, len(order))
	batchSim := make([]float64, len(order))
	batchReason := make([]string, len(order))
	for i := range nDocs {
		bi := docBatchIdx[i]
		if bi < 0 {
			continue // existing
		}
		if owner := exactDup[i]; owner >= 0 {
			batchAction[bi] = "skipped"
			batchReason[bi] = "exact dup"
			if docs[owner].existing {
				batchDupOf[bi] = "existing:" + docs[owner].key
			} else {
				batchDupOf[bi] = order[docBatchIdx[owner]].ID
			}
			batchSim[bi] = 1.0
			continue
		}
		root := parent.find(i)
		if bestIsExisting[root] {
			batchAction[bi] = "skipped"
			batchReason[bi] = "near dup of existing"
			batchSim[bi] = bestSim(tokenSets, i, root, groupBest)
			continue
		}
		if best, ok := groupBest[root]; ok && docBatchIdx[best] != bi {
			batchAction[bi] = "merged"
			batchReason[bi] = "near dup (same detection)"
			batchDupOf[bi] = order[docBatchIdx[best]].ID
			batchSim[bi] = bestSim(tokenSets, i, root, groupBest)
		}
	}

	for i, c := range order {
		c.Canon = batchCanon[i]
		switch batchAction[i] {
		case "skipped":
			c.Action = "skipped"
		case "merged":
			c.Action = "merged"
		default:
			c.Action = "added"
		}
		c.Reason = batchReason[i]
		res.Candidates = append(res.Candidates, c)
		if batchAction[i] == "skipped" || batchAction[i] == "merged" {
			res.Report = append(res.Report, DedupRow{
				Kind: "poc", ID: c.ID, Action: batchAction[i],
				DupOf: batchDupOf[i], Similarity: round3(batchSim[i]), Reason: batchReason[i],
			})
		}
	}
}

func batchBetter(order []Candidate, a, b int) bool {
	// a 是否优于 b：severity → 源优先级（a 排前即优）
	sa, sb := severityRank(order[a].Severity), severityRank(order[b].Severity)
	if sa != sb {
		return sa > sb
	}
	return sourceRank(order[a].Source) > sourceRank(order[b].Source)
}

func bestSim(tokenSets [][]string, i, root int, groupBest map[int]int) float64 {
	best := groupBest[root]
	if best < 0 || best >= len(tokenSets) {
		return 0
	}
	return jaccard(toSet(tokenSets[i]), toSet(tokenSets[best]))
}

// severityRank / sourceRank 数值大者优。
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func sourceRank(s string) int {
	switch s {
	case "nuclei-templates":
		return 3
	case "afrog":
		return 2
	case "xray":
		return 1
	default:
		return 0
	}
}

// ---- fofa 去重 ----

func dedupFinger(opt *options, fingers []Candidate, res *dedupResult) {
	exist := loadExistingFingers(opt.config)
	// 全局精确串集合：canon → 首个产品（现有库 + 已收 batch）
	exactOwner := map[string]string{}
	existAtoms := map[string][][]string{} // 产品 → 现有表达式原子集合
	for prod, exprs := range exist {
		for _, e := range exprs {
			canon, toks, ok := fofaCanon(e)
			if !ok {
				continue
			}
			if _, seen := exactOwner[canon]; !seen {
				exactOwner[canon] = "existing:" + prod
			}
			existAtoms[prod] = append(existAtoms[prod], toks)
		}
	}

	// 按产品分块，块内对 batch 表达式做（近）重复检测
	byProduct := map[string][]int{}
	for i, c := range fingers {
		byProduct[c.ProductName] = append(byProduct[c.ProductName], i)
	}

	for prod, idxs := range byProduct {
		// 块内 doc：现有同产品表达式 + batch 表达式
		var docTokens [][]string
		var docExisting []bool
		var docBatch []int // batch 下标，existing 为 -1
		for _, ea := range existAtoms[prod] {
			docTokens = append(docTokens, ea)
			docExisting = append(docExisting, true)
			docBatch = append(docBatch, -1)
		}
		candCanon := make([]string, len(idxs))
		candOK := make([]bool, len(idxs))
		for j, ci := range idxs {
			canon, toks, ok := fofaCanon(fingers[ci].RuleExpr)
			candCanon[j], candOK[j] = canon, ok
			docTokens = append(docTokens, toks)
			docExisting = append(docExisting, false)
			docBatch = append(docBatch, j)
		}
		n := len(docTokens)
		alive := make([]bool, n)
		for k := range n {
			alive[k] = true
		}
		pairs := findNearDupPairs(docTokens, alive, opt.nearDupFinger)

		// 精确去重 + 近重复合并
		keptCanon := map[string]bool{} // 本块内已保留的 canon
		nearCovered := make([]bool, len(idxs))
		// 与现有表达式近重复（Jaccard≥阈值）的 batch 下标集合
		nearDupExisting := map[int]bool{}
		for _, p := range pairs {
			a, b := p[0], p[1]
			aEx, bEx := docExisting[a], docExisting[b]
			if aEx && bEx {
				continue
			}
			if aEx != bEx {
				batchSide := a
				if aEx {
					batchSide = b
				}
				nearDupExisting[docBatch[batchSide]] = true
			} else { // batch-batch 近重复：保留原子更多者
				ja, jb := docBatch[a], docBatch[b]
				if len(docTokens[a]) < len(docTokens[b]) {
					nearCovered[ja] = true
				} else {
					nearCovered[jb] = true
				}
			}
		}

		for j, ci := range idxs {
			c := fingers[ci]
			c.Canon = candCanon[j]
			if !candOK[j] {
				c.Action, c.Reason = "skipped", "finger canon failed"
			} else if owner, seen := exactOwner[candCanon[j]]; seen {
				if owner == "existing:"+prod || strings.HasPrefix(owner, "existing:") {
					if owner != "existing:"+prod {
						c.Action, c.Reason = "skipped", "cross-product alias of "+owner
						res.Report = append(res.Report, DedupRow{Kind: "finger", ID: c.ID, Action: "alias", DupOf: owner, Similarity: 1, Reason: c.Reason})
					} else {
						c.Action, c.Reason = "skipped", "exact dup of existing"
					}
				} else {
					c.Action, c.Reason = "skipped", "exact dup of batch "+owner
				}
			} else if keptCanon[candCanon[j]] {
				c.Action, c.Reason = "skipped", "exact dup in batch"
			} else if nearDupExisting[j] {
				c.Action, c.Reason = "skipped", "near dup of existing"
			} else if nearCovered[j] {
				c.Action, c.Reason = "merged", "near dup in batch (fewer atoms)"
			} else {
				c.Action = "added"
				keptCanon[candCanon[j]] = true
				exactOwner[candCanon[j]] = prod
			}
			res.Candidates = append(res.Candidates, c)
			if c.Action == "skipped" || c.Action == "merged" {
				res.Report = append(res.Report, DedupRow{Kind: "finger", ID: c.ID, Action: c.Action, Reason: c.Reason})
			}
		}
	}
}

// ---- 近重复引擎 ----

type uf struct{ p []int }

func newUF(n int) *uf {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	return &uf{p}
}

func (u *uf) find(x int) int {
	for u.p[x] != x {
		u.p[x] = u.p[u.p[x]]
		x = u.p[x]
	}
	return x
}

func (u *uf) union(a, b int) {
	if ra, rb := u.find(a), u.find(b); ra != rb {
		u.p[rb] = ra
	}
}

func toSet(ts []string) map[string]bool {
	m := make(map[string]bool, len(ts))
	for _, t := range ts {
		m[t] = true
	}
	return m
}

func jaccard(a, b map[string]bool) float64 {
	big, small := a, b
	if len(a) < len(b) {
		big, small = b, a
	}
	inter := 0
	for t := range small {
		if big[t] {
			inter++
		}
	}
	union := len(a) + len(b) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

// findNearDupPairs 在 alive 的 doc 间找 Jaccard≥threshold 的无序对。
// 用倒排索引 + 文档频率上限剪枝，避免 O(N²)；minOverlap 要求至少共享 2 个可用 token。
const (
	maxDF      = 40
	minOverlap = 2
)

func findNearDupPairs(tokenSets [][]string, alive []bool, threshold float64) [][2]int {
	n := len(tokenSets)
	df := map[string]int{}
	for i := range n {
		if !alive[i] {
			continue
		}
		for _, t := range uniqueSorted(tokenSets[i]) {
			df[t]++
		}
	}
	posting := map[string][]int{}
	for i := range n {
		if !alive[i] {
			continue
		}
		for _, t := range uniqueSorted(tokenSets[i]) {
			if df[t] >= minOverlap && df[t] <= maxDF {
				posting[t] = append(posting[t], i)
			}
		}
	}
	co := map[[2]int]int{}
	for _, list := range posting {
		for a := 0; a < len(list); a++ {
			for b := a + 1; b < len(list); b++ {
				co[[2]int{list[a], list[b]}]++
			}
		}
	}
	sets := make([]map[string]bool, n)
	for i := range n {
		sets[i] = toSet(tokenSets[i])
	}
	var pairs [][2]int
	for p, c := range co {
		if c < minOverlap {
			continue
		}
		if jaccard(sets[p[0]], sets[p[1]]) >= threshold {
			pairs = append(pairs, p)
		}
	}
	return pairs
}

func round3(f float64) float64 {
	return float64(int(f*1000+0.5)) / 1000
}
