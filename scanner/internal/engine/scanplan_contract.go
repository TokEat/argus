package engine

import "github.com/P0lar1ght/argus/shared/proto/go/scanplan"

// CanonicalStageForPhase bridges legacy Pipeline phase names to the stable
// cross-component ScanPlan contract. Multiple legacy POC phase names collapse
// into risk_validation because POC execution is isolated from discovery plans.
func CanonicalStageForPhase(phase string) (scanplan.Stage, bool) {
	switch phase {
	case PhaseSubdomain:
		return scanplan.StageSubdomainDiscovery, true
	case PhaseCDN:
		return scanplan.StageCDNClassification, true
	case PhaseICMP:
		return scanplan.StageICMPDiscovery, true
	case PhaseTCPPing:
		return scanplan.StageTCPLiveness, true
	case PhasePortScan:
		return scanplan.StagePortScan, true
	case PhaseProtocol:
		return scanplan.StageProtocolIdentify, true
	case PhaseHTTPProbe:
		return scanplan.StageHTTPProbe, true
	case PhaseHostBind:
		return scanplan.StageHostBinding, true
	case PhaseDirBrute:
		return scanplan.StageDirectoryProbe, true
	case PhaseFingerprint:
		return scanplan.StageFingerprint, true
	case PhaseNuclei, PhaseGoPoc, "gopoc_telnet_cve", "gopoc_dispatch":
		return scanplan.StageRiskValidation, true
	case PhaseCredentialValidation:
		return scanplan.StageCredentialValidation, true
	default:
		return "", false
	}
}
