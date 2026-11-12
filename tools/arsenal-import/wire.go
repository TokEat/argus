package main

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// 本阶段把 survivor POC 挂到"有指纹的产品"下（POC 只有挂进 workflow.yaml 对应
// 产品 pocs 列表才会被指纹驱动执行）。匹配目标 = 现有 finger.yaml 产品键 ∪ 批内
// 新增指纹 ProductName。置信度 = token 包含度/Jaccard 混合分，≥阈值自动挂载，
// 低置信进人工复核清单。只产出挂载方案（phase JSON），不直接改 config——
// 所有 config 写入集中在 merge 阶段（先备份）。

type wireResult struct {
	Mounts      []MountRow `json:"mounts"`       // 自动挂载（置信度≥阈值）
	Review      []MountRow `json:"review"`       // 低置信/无法推导 → 人工复核
	NewProducts []string   `json:"new_products"` // 需新建的产品键（现有 finger.yaml 无）
}

type MountRow struct {
	POC        string  `json:"poc"`
	Product    string  `json:"product"`
	Confidence float64 `json:"confidence"`
	Evidence   string  `json:"evidence"`  // 推导依据（metadata.product/vendor 或 tags）
	MatchedBy  string  `json:"matched_by"` // existing:<key> / batch:<productname>
}

func runWire(opt *options) error {
	var dd dedupResult
	if err := readPhase(opt.workdir, "dedup", &dd); err != nil {
		return err
	}
	idx := buildProductIndex(opt, dd)
	res := &wireResult{}
	for _, c := range dd.Candidates {
		if c.Kind != KindPoc || c.Action != "added" {
			continue
		}
		pocToks, evidence := derivePOCProductTokens(c)
		if len(pocToks) == 0 {
			res.Review = append(res.Review, MountRow{POC: c.ID, Evidence: "no product derivable", MatchedBy: "none"})
			continue
		}
		prod, conf, matchedBy, ok := idx.bestMatch(pocToks)
		row := MountRow{POC: c.ID, Product: prod, Confidence: round3(conf), Evidence: evidence, MatchedBy: matchedBy}
		if !ok || conf < opt.wireConfidence {
			row.Product = prod // 可能空
			res.Review = append(res.Review, row)
			continue
		}
		res.Mounts = append(res.Mounts, row)
		if matchedBy == "batch" {
			res.NewProducts = append(res.NewProducts, prod)
		}
	}
	res.NewProducts = uniqueSorted(res.NewProducts)
	sort.Slice(res.Mounts, func(i, j int) bool { return res.Mounts[i].POC < res.Mounts[j].POC })
	if err := writePhase(opt.workdir, "wire", res); err != nil {
		return err
	}
	fmt.Printf("[wire] 自动挂载 %d，人工复核 %d，新建产品键 %d → %s\n",
		len(res.Mounts), len(res.Review), len(res.NewProducts), phasePath(opt.workdir, "wire"))
	return printWireSummary(res)
}

func printWireSummary(res *wireResult) error {
	byConf := map[string]int{"high(≥0.9)": 0, "mid(0.8-0.9)": 0}
	for _, m := range res.Mounts {
		if m.Confidence >= 0.9 {
			byConf["high(≥0.9)"]++
		} else {
			byConf["mid(0.8-0.9)"]++
		}
	}
	fmt.Printf("  置信度分布: ≥0.9 %d 个，0.8-0.9 %d 个\n", byConf["high(≥0.9)"], byConf["mid(0.8-0.9)"])
	// 挂载数最多的产品 top10
	cnt := map[string]int{}
	for _, m := range res.Mounts {
		cnt[m.Product]++
	}
	type kv struct {
		p string
		n int
	}
	var rows []kv
	for p, n := range cnt {
		rows = append(rows, kv{p, n})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].n > rows[j].n })
	fmt.Println("  挂载 POC 数最多的产品 Top10:")
	for i, r := range rows {
		if i >= 10 {
			break
		}
		fmt.Printf("    %4d  %s\n", r.n, r.p)
	}
	return nil
}

// ---- 产品索引 ----

type productIndex struct {
	keys   []string          // 归一产品键（existing finger.yaml + 批内新增指纹）
	toks   [][]string        // 每个键的 token 集
	post   map[string][]int  // token → 键下标（倒排）
	origin []string          // 每个键的来源：existing / batch
}

func tokenizeProduct(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func buildProductIndex(opt *options, dd dedupResult) *productIndex {
	idx := &productIndex{post: map[string][]int{}}
	seen := map[string]bool{}
	add := func(key, origin string) {
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		toks := uniqueSorted(tokenizeProduct(key))
		if len(toks) == 0 {
			return
		}
		idx.keys = append(idx.keys, key)
		idx.toks = append(idx.toks, toks)
		idx.origin = append(idx.origin, origin)
		for _, t := range toks {
			idx.post[t] = append(idx.post[t], len(idx.keys)-1)
		}
	}
	for prod := range loadExistingFingers(opt.config) {
		add(prod, "existing")
	}
	// 批内新增指纹（action=added）的产品键——挂载目标，保证 POC 挂到有指纹的产品
	for _, c := range dd.Candidates {
		if c.Kind == KindFinger && c.Action == "added" {
			add(c.ProductName, "batch")
		}
	}
	return idx
}

// bestMatch 用倒排找候选键，按 0.7*包含度+0.3*Jaccard 打分；要求至少命中一个
// 区分性 token（长度≥4），避免被 server/panel/cms 这类泛词带偏。返回最优键与分数。
func (idx *productIndex) bestMatch(pocToks []string) (string, float64, string, bool) {
	pocSet := toSet(pocToks)
	cand := map[int]bool{}
	for _, t := range pocToks {
		for _, ki := range idx.post[t] {
			cand[ki] = true
		}
	}
	best, bestScore, bestJ := -1, 0.0, 0.0
	for ki := range cand {
		inter := 0
		distinctive := false
		for t := range pocSet {
			if inSlice(idx.toks[ki], t) {
				inter++
				if len(t) >= 4 {
					distinctive = true
				}
			}
		}
		if inter == 0 || !distinctive {
			continue
		}
		containment := float64(inter) / float64(len(pocSet))
		union := len(pocSet) + len(idx.toks[ki]) - inter
		j := float64(inter) / float64(union)
		score := 0.7*containment + 0.3*j
		if score > bestScore || (score == bestScore && j > bestJ) {
			best, bestScore, bestJ = ki, score, j
		}
	}
	if best < 0 {
		return "", 0, "", false
	}
	return idx.keys[best], bestScore, idx.origin[best], true
}

func inSlice(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// derivePOCProductTokens 从 metadata.product/vendor 推导产品 token；缺失时退到
// tech 类 tag。返回 token 集与依据说明。
func derivePOCProductTokens(c Candidate) ([]string, string) {
	var toks []string
	if p := strings.TrimSpace(c.Product); p != "" {
		toks = append(toks, tokenizeProduct(p)...)
	}
	if v := strings.TrimSpace(c.Vendor); v != "" {
		toks = append(toks, tokenizeProduct(v)...)
	}
	if len(toks) > 0 {
		return uniqueSorted(toks), "metadata:" + firstNonEmpty(c.Product, c.Vendor)
	}
	var tagToks []string
	for _, t := range c.Tags {
		if isTechProductTag(t) {
			tagToks = append(tagToks, tokenizeProduct(t)...)
		}
	}
	if len(tagToks) > 0 {
		return uniqueSorted(tagToks), "tags:" + strings.Join(c.Tags, ",")
	}
	return nil, ""
}

// isTechProductTag 判断是否可作为产品推导依据的技术类 tag（排除泛化/非产品词）。
func isTechProductTag(t string) bool {
	lt := strings.ToLower(strings.TrimSpace(t))
	if len(lt) < 3 {
		return false
	}
	generic := map[string]bool{
		"vuln": true, "cve": true, "rce": true, "sqli": true, "xss": true, "lfi": true,
		"ssrf": true, "exposure": true, "disclosure": true, "detect": true, "tech": true,
		"panel": true, "discovery": true, "intrusive": true, "authenticated": true,
		"default": true, "login": true, "unauth": true, "edb": true, "packetstorm": true,
	}
	if generic[lt] {
		return false
	}
	// 排除年份类 cve2024 之类
	if strings.HasPrefix(lt, "cve20") {
		return false
	}
	return true
}
