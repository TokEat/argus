package main

import "testing"

func TestMaskValue(t *testing.T) {
	cases := map[string]string{
		`/a/{{id}}/123`:  `/a/{}/n`,
		`/User/Login`:    `/user/login`,
		`{{BaseURL}}/x`: `{}/x`,
	}
	for in, want := range cases {
		if got := maskValue(in); got != want {
			t.Errorf("maskValue(%q)=%q want %q", in, got, want)
		}
	}
}

func TestPOCCanonDedup(t *testing.T) {
	// 同检测逻辑、仅路径 ID 与 matcher 大小写不同 → 同一精确规范串
	a := `id: x1
info: {name: a, severity: high}
http:
  - method: get
    path: ["/user/123/profile"]
    matchers:
      - type: word
        part: body
        words: ["Admin Panel"]
`
	b := `id: x2
info: {name: b, severity: low}
http:
  - method: GET
    path: ["/user/456/profile"]
    matchers:
      - type: word
        part: body
        words: ["admin panel"]
`
	ta, err := parseNucleiTemplate([]byte(a))
	if err != nil {
		t.Fatal(err)
	}
	tb, _ := parseNucleiTemplate([]byte(b))
	ca, _, oka := pocCanon(ta)
	cb, _, okb := pocCanon(tb)
	if !oka || !okb {
		t.Fatal("canon failed")
	}
	if ca != cb {
		t.Errorf("期望归一为同一规范形:\nA=%q\nB=%q", ca, cb)
	}
}

func TestPOCCanonDistinct(t *testing.T) {
	// 不同 matcher 词 → 不同规范形（不误判重复）
	mk := func(word string) string {
		return "id: z\ninfo: {name: z, severity: high}\nhttp:\n  - path: [\"/a\"]\n    matchers:\n      - type: word\n        part: body\n        words: [\"" + word + "\"]\n"
	}
	t1, _ := parseNucleiTemplate([]byte(mk("login success")))
	t2, _ := parseNucleiTemplate([]byte(mk("logout success")))
	c1, _, _ := pocCanon(t1)
	c2, _, _ := pocCanon(t2)
	if c1 == c2 {
		t.Error("不同检测词不应同规范形")
	}
}

func TestFofaCanon(t *testing.T) {
	// 大小写/空白差异 → 同一精确串；原子集合归一
	// ddfinger 只认小写键（大写会被截断），故用小写 status
	ex, toks, ok := fofaCanon(` body="AbC"  && status="200" `)
	if !ok {
		t.Fatal("fofaCanon failed")
	}
	if ex != `body="abc"&&status="200"` {
		t.Errorf("exact=%q", ex)
	}
	if len(toks) != 2 || toks[0] != `body=abc` || toks[1] != `status=200` {
		t.Errorf("toks=%v", toks)
	}
}

func TestJaccard(t *testing.T) {
	a := map[string]bool{"x": true, "y": true, "z": true}
	b := map[string]bool{"x": true, "y": true, "w": true}
	if got := jaccard(a, b); got < 0.49 || got > 0.51 {
		t.Errorf("jaccard=%v want 0.5", got)
	}
	if got := jaccard(a, a); got != 1.0 {
		t.Errorf("自相似应 1.0, got %v", got)
	}
}

func TestFindNearDupPairs(t *testing.T) {
	sets := [][]string{
		{"a", "b", "c"},
		{"a", "b", "c"},        // 与 0 全同
		{"a", "b"},             // 与 0 相似 0.66
		{"x", "y", "z"},        // 无关
		{"a", "b", "c", "extra"}, // 与 0 相似 0.75
	}
	alive := []bool{true, true, true, true, true}
	pairs := findNearDupPairs(sets, alive, 0.85)
	// 阈值 0.85：仅 (0,1) 全同命中
	if len(pairs) != 1 || pairs[0] != [2]int{0, 1} {
		t.Errorf("pairs=%v 期望仅 [[0 1]]", pairs)
	}
}
