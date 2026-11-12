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

func TestMaskUsernameRedactsNonEmptyValues(t *testing.T) {
	if got := maskUsername(""); got != "<empty>" {
		t.Fatalf("expected empty username marker, got %q", got)
	}
	if got := maskUsername("administrator"); got != "[REDACTED]" {
		t.Fatalf("expected username to be redacted, got %q", got)
	}
}
