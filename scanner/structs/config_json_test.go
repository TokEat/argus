package structs

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigMachinePresentationNeverEntersTaskJSON(t *testing.T) {
	encoded, err := json.Marshal(Config{Targets: []string{"127.0.0.1"}, MachineOutput: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "MachineOutput") || strings.Contains(string(encoded), "machine_output") {
		t.Fatalf("CLI presentation leaked into task JSON: %s", encoded)
	}
}
