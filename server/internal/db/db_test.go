package db

import "testing"

func TestIsPostgresDSN(t *testing.T) {
	tests := []struct {
		dsn  string
		want bool
	}{
		{dsn: "", want: false},
		{dsn: "data/dddd.db", want: false},
		{dsn: "postgres://user:pass@localhost:5432/dddd", want: true},
		{dsn: "host=localhost user=postgres dbname=dddd", want: true},
	}

	for _, tc := range tests {
		if got := isPostgresDSN(tc.dsn); got != tc.want {
			t.Fatalf("isPostgresDSN(%q) = %v, want %v", tc.dsn, got, tc.want)
		}
	}
}
