package agent

import (
	"errors"
	"testing"
)

func TestMemGuardThresholds(t *testing.T) {
	cases := []struct {
		name     string
		used     float64
		err      error
		wantSoft bool
		wantHard bool
	}{
		{name: "below both", used: 50, wantSoft: false, wantHard: false},
		{name: "over soft only", used: 85, wantSoft: true, wantHard: false},
		{name: "over both", used: 95, wantSoft: true, wantHard: true},
		{name: "at soft boundary", used: 80, wantSoft: true, wantHard: false},
		{name: "read failure never blocks", used: 0, err: errors.New("boom"), wantSoft: false, wantHard: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := &memGuard{
				softPct: 80,
				hardPct: 90,
				read: func() (float64, error) {
					return tc.used, tc.err
				},
			}
			if got := g.overSoft(); got != tc.wantSoft {
				t.Errorf("overSoft() = %v, want %v", got, tc.wantSoft)
			}
			if got := g.overHard(); got != tc.wantHard {
				t.Errorf("overHard() = %v, want %v", got, tc.wantHard)
			}
		})
	}
}

func TestMemEnvPct(t *testing.T) {
	t.Setenv("ARGUS_MEM_TEST_PCT", "73")
	if got := memEnvPct("ARGUS_MEM_TEST_PCT", 80); got != 73 {
		t.Errorf("explicit value: got %v, want 73", got)
	}
	t.Setenv("ARGUS_MEM_TEST_PCT", "bogus")
	if got := memEnvPct("ARGUS_MEM_TEST_PCT", 80); got != 80 {
		t.Errorf("invalid value should fall back: got %v, want 80", got)
	}
	t.Setenv("ARGUS_MEM_TEST_PCT", "250")
	if got := memEnvPct("ARGUS_MEM_TEST_PCT", 80); got != 80 {
		t.Errorf("out-of-range value should fall back: got %v, want 80", got)
	}
	if got := memEnvPct("ARGUS_MEM_TEST_UNSET", 80); got != 80 {
		t.Errorf("unset should use default: got %v, want 80", got)
	}
}
