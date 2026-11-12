package structs

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigMachinePresentationNeverEntersTaskJSON(t *testing.T) {
	encoded, err := json.Marshal(Config{Targets: []string{"127.0.0.1"}, MachineOutput: true, TraceOnly: true, ShowPocMap: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"MachineOutput", "machine_output", "TraceOnly", "trace_only", "ShowPocMap", "show_poc_map"} {
		if strings.Contains(string(encoded), leak) {
			t.Fatalf("CLI-only field leaked into task JSON (%s): %s", leak, encoded)
		}
	}
}
