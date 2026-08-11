package localstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadLocalPolicyCreatesDefaultsAndPreservesEdits(t *testing.T) {
	home := Home{Root: filepath.Join(t.TempDir(), "argus-data")}
	policy, err := LoadLocalPolicy(home)
	if err != nil {
		t.Fatal(err)
	}
	if policy.TTL.Port.Value() != time.Hour || policy.TTL.Protocol.Value() != 6*time.Hour || policy.TTL.RiskValidation.Value() != 24*time.Hour {
		t.Fatalf("default TTL policy = %#v", policy.TTL)
	}
	path := filepath.Join(home.Root, LocalPolicyFileName)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	custom := strings.Replace(string(contents), "port: 1h0m0s", "port: 90m", 1)
	if custom == string(contents) {
		t.Fatalf("default policy did not contain readable port TTL: %s", contents)
	}
	if err := os.WriteFile(path, []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err = LoadLocalPolicy(home)
	if err != nil {
		t.Fatal(err)
	}
	if policy.TTL.Port.Value() != 90*time.Minute {
		t.Fatalf("custom port TTL = %s", policy.TTL.Port.Value())
	}
}

func TestLoadLocalPolicyRejectsUnknownOrUnsafeValues(t *testing.T) {
	for _, test := range []struct {
		name, mutate string
	}{
		{name: "unknown", mutate: "unexpected: true\n"},
		{name: "missing_boolean", mutate: "revalidation:\n    known_services_every_run: true\n    timeout: 200ms\n    concurrency: 64\n    max_endpoints: 512\n    liveness_ports: [80]\n"},
		{name: "timeout", mutate: "revalidation:\n    liveness_every_run: true\n    known_services_every_run: true\n    timeout: 1ms\n    concurrency: 64\n    max_endpoints: 512\n    liveness_ports: [80]\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := Home{Root: filepath.Join(t.TempDir(), "argus-data")}
			if _, err := LoadLocalPolicy(home); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(home.Root, LocalPolicyFileName)
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "unknown" {
				contents = append(contents, []byte(test.mutate)...)
			} else {
				start := strings.Index(string(contents), "revalidation:\n")
				if start < 0 {
					t.Fatal("revalidation block missing")
				}
				contents = append(contents[:start], []byte(test.mutate)...)
			}
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadLocalPolicy(home); err == nil {
				t.Fatal("invalid policy was accepted")
			}
		})
	}
}
