package formatter

import "testing"

func TestCLINoColorStripsEmbeddedANSI(t *testing.T) {
	formatter := NewCLI(true)
	data, err := formatter.Format(&LogEvent{Message: "\x1b[31merror\x1b[0m", Metadata: map[string]string{"target": "\x1b[36mloopback\x1b[0m"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "error target=loopback"; got != want {
		t.Fatalf("Format() = %q, want %q", got, want)
	}
}
