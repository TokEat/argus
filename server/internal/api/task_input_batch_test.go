package api

import "testing"

func TestBatchSizeForTargetType(t *testing.T) {
	cases := map[string]int{
		"url":         50,
		"domain":      50,
		"domain_port": 200,
		"ip":          50,
		"ip_port":     200,
		"cidr":        2,
		"ip_range":    2,
		"osint":       100,
		"unknown":     100,
	}
	for typ, want := range cases {
		if got := batchSizeForTargetType(typ); got != want {
			t.Errorf("batchSizeForTargetType(%q) = %d, want %d", typ, got, want)
		}
	}
}

func TestBatchTargetsOfTypeChunking(t *testing.T) {
	mk := func(n int) []string {
		s := make([]string, n)
		for i := range s {
			s[i] = "t"
		}
		return s
	}
	type tc struct {
		typ         string
		count       int
		wantBatches int
		wantLast    int // 最后一批的目标数
	}
	for _, c := range []tc{
		{"ip", 250, 5, 50},       // 250/50
		{"url", 169, 4, 19},      // 169/50 -> 50+50+50+19
		{"domain", 120, 3, 20},   // 120/50 -> 50+50+20
		{"ip_port", 200, 1, 200}, // 恰好一批
		{"cidr", 25, 13, 1},      // 25/2 -> 12*2 + 1
	} {
		batches := batchTargetsOfType(mk(c.count), c.typ, "")
		if len(batches) != c.wantBatches {
			t.Errorf("%s %d: got %d batches, want %d", c.typ, c.count, len(batches), c.wantBatches)
			continue
		}
		if last := len(batches[len(batches)-1].Targets); last != c.wantLast {
			t.Errorf("%s %d: last batch %d targets, want %d", c.typ, c.count, last, c.wantLast)
		}
	}
}
