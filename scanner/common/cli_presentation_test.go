package common

import "testing"

func TestPresentationForArgsUsesMachineModeForJSONAndNonTTY(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		stdoutTTY   bool
		output      string
		interactive bool
	}{
		{name: "tty text", stdoutTTY: true, output: "text", interactive: true},
		{name: "redirected text", stdoutTTY: false, output: "text", interactive: false},
		{name: "short separated json", args: []string{"-ot", "json"}, stdoutTTY: true, output: "json", interactive: false},
		{name: "short equals json", args: []string{"-ot=json"}, stdoutTTY: true, output: "json", interactive: false},
		{name: "long separated json", args: []string{"--output-type", "json"}, stdoutTTY: true, output: "json", interactive: false},
		{name: "long equals json", args: []string{"--output-type=json"}, stdoutTTY: true, output: "json", interactive: false},
		{name: "last output flag wins", args: []string{"-ot", "json", "--output-type=text"}, stdoutTTY: true, output: "text", interactive: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := PresentationForArgs(test.args, test.stdoutTTY)
			if got.OutputType != test.output || got.Interactive != test.interactive {
				t.Fatalf("presentation = %#v, want output=%q interactive=%v", got, test.output, test.interactive)
			}
			if got.ShowBanner != test.interactive || got.NoColor == test.interactive || got.SuppressInfo == test.interactive {
				t.Fatalf("presentation policy = %#v", got)
			}
		})
	}
}

func TestValidateCLIOutputType(t *testing.T) {
	for _, outputType := range []string{"text", "json"} {
		if err := ValidateCLIOutputType(outputType); err != nil {
			t.Fatalf("ValidateCLIOutputType(%q) = %v", outputType, err)
		}
	}
	if _, ok := ValidateCLIOutputType("ndjson").(*CLIUsageError); !ok {
		t.Fatalf("invalid output type error is not CLIUsageError: %T", ValidateCLIOutputType("ndjson"))
	}
}
