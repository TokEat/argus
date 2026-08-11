package engine

import "testing"

func TestLegacyProviderConfigFailsBeforeContextInitialization(t *testing.T) {
	for _, cfg := range []Config{{Hunter: true}, {Fofa: true}, {Quake: true}, {LowPerceptionMode: true}, {OnlyIPPort: true}, {APIConfigFilePath: "config/api-config.yaml"}} {
		if _, err := NewScanContext(cfg); err == nil {
			t.Fatalf("legacy provider configuration %+v initialized", cfg)
		}
	}
}
