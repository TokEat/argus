package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/P0lar1ght/argus/scanner/structs"
)

func validCredentialConfig() Config {
	return Config{
		ExecutionMode: "credential_validation",
		Targets:       []string{"192.0.2.10:22"},
		CredentialValidationTargets: []structs.CredentialValidationTarget{{
			Endpoint: "192.0.2.10:22", Service: "ssh", Plugin: "SSH-Crack",
			Eligibility: "protocol", ObservationSHA256: strings.Repeat("a", 64),
		}},
		CredentialPairLimit: 50_000,
		CredentialBundle:    []structs.UserPasswd{{UserName: "incremental", Password: "secret"}},
		GoPocThreads:        1,
	}
}

func TestPipelineCredentialValidationRunsOnlySealedCredentialPhase(t *testing.T) {
	original := dispatchCredentialTargets
	t.Cleanup(func() { dispatchCredentialTargets = original })
	called := false
	dispatchCredentialTargets = func(targets []structs.CredentialValidationTarget, bundle []structs.UserPasswd, pairLimit, threads int, emit func(structs.OutputMessage)) ([]structs.GoPocsResultType, error) {
		called = true
		if len(targets) != 1 || targets[0].Plugin != "SSH-Crack" || len(bundle) != 1 || pairLimit != 50_000 {
			t.Fatalf("unexpected sealed credential dispatch: targets=%+v bundle=%+v limit=%d", targets, bundle, pairLimit)
		}
		return nil, nil
	}
	var phases []PhaseEvent
	ctx := &ScanContext{
		Config: validCredentialConfig(), Ctx: context.Background(),
		OutputHook: func(OutputMessage) {}, PhaseHook: func(event PhaseEvent) { phases = append(phases, event) },
	}
	if err := (&Pipeline{}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("credential dispatcher was not called")
	}
	if len(phases) != 2 || phases[0].Phase != PhaseCredentialValidation || phases[0].Status != "start" || phases[1].Status != "end" {
		t.Fatalf("credential mode emitted unexpected phases: %+v", phases)
	}
}

func TestCredentialValidationPlanRejectsUnsealedOrUnsafeTargets(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"outside dispatched batch", func(cfg *Config) { cfg.Targets = []string{"192.0.2.11:22"} }},
		{"http service", func(cfg *Config) { cfg.CredentialValidationTargets[0].Service = "http" }},
		{"non credential plugin", func(cfg *Config) { cfg.CredentialValidationTargets[0].Plugin = "SMB-MS17-010" }},
		{"invalid observation", func(cfg *Config) { cfg.CredentialValidationTargets[0].ObservationSHA256 = "bad" }},
		{"bundle over limit", func(cfg *Config) {
			cfg.CredentialPairLimit = 1
			cfg.CredentialBundle = append(cfg.CredentialBundle, structs.UserPasswd{})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validCredentialConfig()
			test.mutate(&cfg)
			if _, _, err := normalizedCredentialValidationTargets(&cfg); err == nil {
				t.Fatal("unsafe credential plan was accepted")
			}
		})
	}
}

func TestCredentialValidationPropagatesDispatcherFailure(t *testing.T) {
	original := dispatchCredentialTargets
	t.Cleanup(func() { dispatchCredentialTargets = original })
	want := errors.New("credential runner failed")
	dispatchCredentialTargets = func([]structs.CredentialValidationTarget, []structs.UserPasswd, int, int, func(structs.OutputMessage)) ([]structs.GoPocsResultType, error) {
		return nil, want
	}
	ctx := &ScanContext{Config: validCredentialConfig(), Ctx: context.Background()}
	if err := (&Pipeline{}).Run(ctx); !errors.Is(err, want) {
		t.Fatalf("Pipeline.Run error = %v, want %v", err, want)
	}
}
