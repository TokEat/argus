package db

import "testing"

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"":          "Unknown",
		"info":      "Info",
		" Info ":    "Info",
		"HIGH":      "High",
		"critical":  "Critical",
		"medium":    "Medium",
		"low":       "Low",
		"undefined": "Unknown",
	}
	for input, want := range cases {
		if got := normalizeSeverity(input); got != want {
			t.Fatalf("normalizeSeverity(%q) = %q, want %q", input, got, want)
		}
	}
}
