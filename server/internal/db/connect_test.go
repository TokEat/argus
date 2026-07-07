package db

import (
	"strings"
	"testing"
)

func TestDefaultPostgresDSNDoesNotUseWeakPassword(t *testing.T) {
	dsn := normalizePostgresDSN("")
	if strings.Contains(dsn, "password=root") {
		t.Fatalf("default PostgreSQL DSN must not use weak password: %q", dsn)
	}
}
