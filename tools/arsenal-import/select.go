package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/P0lar1ght/argus/scanner/lib/ddfinger"
)

// 本阶段对 convert 候选做精选门控：severity/目录/tag/可转换性/治理安全。
// 主动指纹打分精选 ≤cap 个提升 safe 档（auto-safe 每租户硬上限 8，shiro 已占 1）。
// 治理默认值会把缺失 execution-class 的模板当 detection 放行（rule_catalog.go:888），
// 所以"绝不发 exploit"必须由本阶段把 intrusive/OOB 类挡在库外。

type selectResult struct {
	Selected     []Candidate `json:"selected"`
	Rejected     []RejectRow `json:"rejected"`
	SafeActiveFP []string    `json:"safe_active_fp"` // 提升为 safe 档的主动指纹 id
}

var (
	noiseTags   = map[string]bool{"dos": true, "ddos": true, "fuzz": true, "fuzzing": true, "iot": true}
	oobTags     = map[string]bool{"oast": true, "oob": true, "interactsh": true}
	exploitTags = map[string]bool{"intrusive": true} // nuclei 官方副作用标记=exploit 类
)

// ddfinger SingleCheck 支持的全部键（parse.go）；之外键产出的原子永不匹配，视为非法。
var fofaValidKeys = map[string]bool{
	"body": true, "title": true, "header": true, "server": true, "cert": true,
	"port": true, "protocol": true, "path": true, "body_hash": true,
	"icon_hash": true, "status": true, "content_type": true, "banner": true, "type": true,
}

func runSelect(opt *options) error {
	var conv convertResult
	if err := readPhase(opt.workdir, "convert", &conv); err != nil {
		return err
	}
	res := selectResult{}
	var afp []Candidate
	for _, c := range conv.Candidates {
		switch c.Kind {
		case KindPoc:
			if reason := pocGate(c); reason != "" {
				res.Rejected = append(res.Rejected, RejectRow{c.Source, c.SrcPath, reason})
				continue
			}
			res.Selected = append(res.Selected, c)
		case KindFinger:
			if err := validateFofaExpr(c.RuleExpr); err != nil {
				res.Rejected = append(res.Rejected, RejectRow{c.Source, c.SrcPath, "finger: " + err.Error()})
				continue
			}
			res.Selected = append(res.Selected, c)
		case KindActiveFP:
			afp = append(afp, c)
		}
	}
	res.SafeActiveFP = pickSafeActiveFP(afp, opt.activeFPCap, &res)

	if err := writePhase(opt.workdir, "select", res); err != nil {
		return err
	}
	fmt.Printf("[select] 保留 %d，拒绝 %d（safe 主动指纹 %d）→ %s\n",
		len(res.Selected), len(res.Rejected), len(res.SafeActiveFP), phasePath(opt.workdir, "select"))
	return printRejectSummary(res.Rejected)
}

// pocGate 返回非空字符串即拒绝原因。门控顺序：功能可用 → 治理安全 → 噪声 → severity。
func pocGate(c Candidate) string {
	tags := map[string]bool{}
	for _, t := range c.Tags {
		tags[strings.ToLower(t)] = true
	}
	// OOB 依赖：argus 未配置 interactsh 服务端，必假阴性
	if strings.Contains(c.Content, "{{interactsh-url") || strings.Contains(c.Content, "{{interactsh") {
		return "oob: interactsh dependency"
	}
	for t := range oobTags {
		if tags[t] {
			return "oob: tag " + t
		}
	}
	// exploit 类（nuclei intrusive 副作用标记，与 detection-only 治理冲突）
	for t := range exploitTags {
		if tags[t] {
			return "exploit-class: intrusive tag"
		}
	}
	for t := range noiseTags {
		if tags[t] {
			return "noise tag: " + t
		}
	}
	sev := strings.ToLower(strings.TrimSpace(c.Severity))
	switch sev {
	case "medium", "high", "critical":
		return ""
	case "info", "low", "":
		// 低危/info 仅当产品识别目录（指纹驱动 workflow 的主动确认 POC）
		if isProductIdentDir(c.SrcPath) {
			return ""
		}
		return "severity below threshold: " + sev
	default:
		return "unknown severity: " + sev
	}
}

func isProductIdentDir(srcPath string) bool {
	return strings.HasPrefix(srcPath, "http/exposed-panels/") || strings.HasPrefix(srcPath, "http/technologies/")
}

// validateFofaExpr 校验 fofa 表达式可被 ddfinger 忠实执行。括号不平衡会让
// ddfinger 的 boolEval gologger.Fatal（os.Exit），必须先自查；键白名单保证
// 解析出的原子在 SingleCheck 里真的有分支处理。
func validateFofaExpr(expr string) error {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return fmt.Errorf("empty expr")
	}
	if strings.Count(expr, "(") != strings.Count(expr, ")") {
		return fmt.Errorf("unbalanced parens")
	}
	atoms := ddfinger.ParseRule(expr)
	if len(atoms) == 0 {
		return fmt.Errorf("no parseable atoms")
	}
	for _, a := range atoms {
		if !fofaValidKeys[a.Key] {
			return fmt.Errorf("unknown key %q", a.Key)
		}
	}
	return nil
}

// pickSafeActiveFP 精选 ≤cap 个主动指纹提升 safe：按产品分组取组内最优
// （matcher 越多/含 status 越精确），组间按分数取前 cap 个不同产品。
func pickSafeActiveFP(afp []Candidate, capN int, res *selectResult) []string {
	type scored struct {
		c     Candidate
		score int
	}
	byProduct := map[string][]scored{}
	for _, c := range afp {
		pn := c.ProductName
		if pn == "" {
			pn = firstNonEmpty(c.Product, c.ID)
		}
		byProduct[pn] = append(byProduct[pn], scored{c, scoreActiveFP(c)})
	}
	var winners []scored
	for _, group := range byProduct {
		sort.Slice(group, func(i, j int) bool { return group[i].score > group[j].score })
		winners = append(winners, group[0])
	}
	sort.Slice(winners, func(i, j int) bool { return winners[i].score > winners[j].score })
	if len(winners) > capN {
		winners = winners[:capN]
	}
	var safeIDs []string
	for _, w := range winners {
		c := w.c
		c.Content = strings.Replace(c.Content, "argus-auto-profile: controlled", "argus-auto-profile: safe", 1)
		res.Selected = append(res.Selected, c)
		safeIDs = append(safeIDs, c.ID)
	}
	chosen := map[string]bool{}
	for _, id := range safeIDs {
		chosen[id] = true
	}
	for _, c := range afp {
		if !chosen[c.ID] {
			res.Rejected = append(res.Rejected, RejectRow{c.Source, c.SrcPath, "active-fp over quota (safe cap)"})
		}
	}
	return safeIDs
}

// scoreActiveFP 以 matcher 规模近似识别精度：word*1 + regex*2 + status*3。
func scoreActiveFP(c Candidate) int {
	t, err := parseNucleiTemplate([]byte(c.Content))
	if err != nil || len(t.AllHTTP()) == 0 {
		return 0
	}
	score := 0
	for _, m := range t.AllHTTP()[0].Matchers {
		score += len(m.Words) + 2*len(m.Regex) + 3*len(m.Status)
	}
	return score
}
