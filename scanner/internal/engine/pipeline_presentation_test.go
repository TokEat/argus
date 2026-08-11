package engine

import (
	"reflect"
	"testing"
)

func TestConfiguredNucleiCallerKeepsAgentDefaultAndSelectsCLIMachineMode(t *testing.T) {
	if got, want := reflect.ValueOf(configuredNucleiCaller(&Config{})).Pointer(), reflect.ValueOf(callNuclei).Pointer(); got != want {
		t.Fatalf("default config selected machine Nuclei caller")
	}
	if got, want := reflect.ValueOf(configuredNucleiCaller(&Config{MachineOutput: true})).Pointer(), reflect.ValueOf(callNucleiMachine).Pointer(); got != want {
		t.Fatalf("machine config did not select machine Nuclei caller")
	}
}
