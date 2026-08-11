package engine

import (
	"testing"

	"github.com/P0lar1ght/argus/shared/proto/go/scanplan"
)

func TestCanonicalStageForEveryPipelinePhase(t *testing.T) {
	tests := map[string]scanplan.Stage{
		PhaseSearchEngine: scanplan.StageSearchEngine,
		PhaseSubdomain:    scanplan.StageSubdomainDiscovery,
		PhaseCDN:          scanplan.StageCDNClassification,
		PhaseICMP:         scanplan.StageICMPDiscovery,
		PhaseTCPPing:      scanplan.StageTCPLiveness,
		PhasePortScan:     scanplan.StagePortScan,
		PhaseProtocol:     scanplan.StageProtocolIdentify,
		PhaseHTTPProbe:    scanplan.StageHTTPProbe,
		PhaseHostBind:     scanplan.StageHostBinding,
		PhaseDirBrute:     scanplan.StageDirectoryProbe,
		PhaseFingerprint:  scanplan.StageFingerprint,
		PhaseNuclei:       scanplan.StageRiskValidation,
		PhaseGoPoc:        scanplan.StageRiskValidation,
	}
	for phase, want := range tests {
		got, ok := CanonicalStageForPhase(phase)
		if !ok || got != want {
			t.Fatalf("CanonicalStageForPhase(%q)=(%q,%v), want (%q,true)", phase, got, ok, want)
		}
	}
	if _, ok := CanonicalStageForPhase("future_phase"); ok {
		t.Fatal("unknown Pipeline phase was silently accepted")
	}
}
