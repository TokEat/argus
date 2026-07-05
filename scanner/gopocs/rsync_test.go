package gopocs

import "testing"

func TestMaskPasswordPreservesNonEmptyValues(t *testing.T) {
	if got := maskPassword(""); got != "<empty>" {
		t.Fatalf("expected empty password marker, got %q", got)
	}
	if got := maskPassword("secret"); got != "secret" {
		t.Fatalf("expected password evidence to be preserved, got %q", got)
	}
}
