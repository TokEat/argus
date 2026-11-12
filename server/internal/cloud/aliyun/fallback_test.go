package aliyun

import (
	"testing"
)

func TestGenerateFallbackTypes(t *testing.T) {
	tests := []struct {
		input    string
		wantLen  int
		wantFirst string
	}{
		{"ecs.c6.large", 5, "ecs.c7.large"},
		{"ecs.g6.xlarge", 5, "ecs.g7.xlarge"},
		{"ecs.r6.2xlarge", 5, "ecs.r7.2xlarge"},
		{"ecs.c7.large", 4, "ecs.c8y.large"},   // c7 already in list, skip self
		{"ecs.n4.small", 2, "ecs.n5.small"},     // unknown family, gen+1/+2
	}

	for _, tt := range tests {
		got := generateFallbackTypes(tt.input)
		if len(got) != tt.wantLen {
			t.Errorf("generateFallbackTypes(%q) = %v (len=%d), want len=%d", tt.input, got, len(got), tt.wantLen)
			continue
		}
		if got[0] != tt.wantFirst {
			t.Errorf("generateFallbackTypes(%q)[0] = %q, want %q", tt.input, got[0], tt.wantFirst)
		}
	}

	// Edge cases
	if got := generateFallbackTypes("invalid"); got != nil {
		t.Errorf("generateFallbackTypes('invalid') = %v, want nil", got)
	}
	if got := generateFallbackTypes("ecs.c6"); got != nil {
		t.Errorf("generateFallbackTypes('ecs.c6') = %v, want nil", got)
	}
}
