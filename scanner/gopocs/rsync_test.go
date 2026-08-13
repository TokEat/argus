package gopocs

import "testing"

func TestMaskPasswordRedactsNonEmptyValues(t *testing.T) {
	if got := maskPassword(""); got != "<empty>" {
		t.Fatalf("expected empty password marker, got %q", got)
	}
	if got := maskPassword("secret"); got != "[REDACTED]" {
		t.Fatalf("expected password to be redacted, got %q", got)
	}
}
