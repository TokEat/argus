package scanplan

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func validPlan(scenario Scenario, stages []StagePlan) Plan {
	return Plan{
		SchemaVersion: SchemaVersion,
		Scenario:      scenario,
		TenantID:      "tenant-a",
		ProjectID:     "project-a",
		NetworkZone:   PublicNetworkZone,
		Targets:       []string{"https://example.test"},
		ScopeHash:     "scope-v1",
		ConfigHash:    "config-v1",
		RuleVersion:   "rules-v1",
		Stages:        stages,
	}
}

func TestAllScenariosHaveValidPlans(t *testing.T) {
	tests := []Plan{
		validPlan(ScenarioExternalMap, []StagePlan{
			{Stage: StageSubdomainDiscovery},
			{Stage: StageCDNClassification, DependsOn: []Stage{StageSubdomainDiscovery}},
			{Stage: StagePortScan, DependsOn: []Stage{StageCDNClassification}},
			{Stage: StageProtocolIdentify, DependsOn: []Stage{StagePortScan}},
			{Stage: StageHTTPProbe, DependsOn: []Stage{StageProtocolIdentify}},
			{Stage: StageFingerprint, DependsOn: []Stage{StageHTTPProbe}},
		}),
		validPlan(ScenarioInternalFast, []StagePlan{
			{Stage: StageICMPDiscovery},
			{Stage: StageTCPLiveness},
			{Stage: StagePortScan, DependsOn: []Stage{StageICMPDiscovery, StageTCPLiveness}},
			{Stage: StageProtocolIdentify, DependsOn: []Stage{StagePortScan}},
			{Stage: StageHTTPProbe, DependsOn: []Stage{StageProtocolIdentify}},
			{Stage: StageFingerprint, DependsOn: []Stage{StageHTTPProbe}},
		}),
		validPlan(ScenarioInternalServer, []StagePlan{
			{Stage: StageICMPDiscovery},
			{Stage: StageTCPLiveness},
			{Stage: StagePortScan, DependsOn: []Stage{StageICMPDiscovery, StageTCPLiveness}},
			{Stage: StageProtocolIdentify, DependsOn: []Stage{StagePortScan}},
			{Stage: StageHTTPProbe, DependsOn: []Stage{StageProtocolIdentify}},
			{Stage: StageHostBinding, DependsOn: []Stage{StageHTTPProbe}},
			{Stage: StageDirectoryProbe, DependsOn: []Stage{StageHTTPProbe}},
			{Stage: StageFingerprint, DependsOn: []Stage{StageHostBinding, StageDirectoryProbe}},
		}),
		validPlan(ScenarioRiskValidation, []StagePlan{{Stage: StageRiskValidation, Force: true}}),
		validPlan(ScenarioCredentialValidation, []StagePlan{{Stage: StageCredentialValidation, Force: true}}),
	}
	for _, plan := range tests {
		if err := plan.Validate(); err != nil {
			t.Fatalf("scenario %s is not expressible: %v", plan.Scenario, err)
		}
	}
}

func TestPlanValidationRejectsUnsafeOrAmbiguousGraphs(t *testing.T) {
	tests := []struct {
		name string
		plan Plan
	}{
		{
			name: "risk stage in asset discovery",
			plan: validPlan(ScenarioExternalMap, []StagePlan{{Stage: StageRiskValidation}}),
		},
		{
			name: "discovery stage in risk validation",
			plan: validPlan(ScenarioRiskValidation, []StagePlan{{Stage: StageHTTPProbe}, {Stage: StageRiskValidation}}),
		},
		{
			name: "risk validation without force",
			plan: validPlan(ScenarioRiskValidation, []StagePlan{{Stage: StageRiskValidation}}),
		},
		{
			name: "cycle",
			plan: validPlan(ScenarioInternalFast, []StagePlan{
				{Stage: StagePortScan, DependsOn: []Stage{StageProtocolIdentify}},
				{Stage: StageProtocolIdentify, DependsOn: []Stage{StagePortScan}},
			}),
		},
		{
			name: "duplicate target",
			plan: func() Plan {
				plan := validPlan(ScenarioInternalFast, []StagePlan{{Stage: StagePortScan}})
				plan.Targets = append(plan.Targets, plan.Targets[0])
				return plan
			}(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.plan.Validate(); err == nil {
				t.Fatal("invalid plan was accepted")
			}
		})
	}
}

func validWorkKey() WorkKey {
	return WorkKey{
		TenantID: "tenant-a", ProjectID: "project-a", NetworkZone: PublicNetworkZone,
		NormalizedTarget: "https://example.test", Stage: StageHTTPProbe,
		ScopeHash: "scope-v1", ConfigHash: "config-v1", RuleVersion: "rules-v1",
	}
}

func TestWorkKeyDigestIsStableAndCoversEveryDimension(t *testing.T) {
	base := validWorkKey()
	baseDigest, err := base.Digest()
	if err != nil || len(baseDigest) != 64 {
		t.Fatalf("base digest=%q err=%v", baseDigest, err)
	}
	mutations := []func(*WorkKey){
		func(key *WorkKey) { key.TenantID = "tenant-b" },
		func(key *WorkKey) { key.ProjectID = "project-b" },
		func(key *WorkKey) { key.NetworkZone = "private-a" },
		func(key *WorkKey) { key.NormalizedTarget = "https://other.test" },
		func(key *WorkKey) { key.Stage = StageFingerprint },
		func(key *WorkKey) { key.ScopeHash = "scope-v2" },
		func(key *WorkKey) { key.ConfigHash = "config-v2" },
		func(key *WorkKey) { key.RuleVersion = "rules-v2" },
	}
	for index, mutate := range mutations {
		changed := base
		mutate(&changed)
		digest, err := changed.Digest()
		if err != nil {
			t.Fatalf("mutation %d: %v", index, err)
		}
		if digest == baseDigest {
			t.Fatalf("mutation %d did not change WorkKey digest", index)
		}
	}
}

func TestRiskValidationWorkKeyRequiresPocAndEndpointHashes(t *testing.T) {
	key := validWorkKey()
	key.Stage = StageRiskValidation
	if _, err := key.Digest(); err == nil {
		t.Fatal("risk validation WorkKey without POC dimensions was accepted")
	}
	key.POCSetHash = "pocs-v1"
	key.EndpointContentHash = "endpoint-v1"
	digest, err := key.Digest()
	if err != nil {
		t.Fatalf("valid risk validation WorkKey rejected: %v", err)
	}
	key.POCSetHash = "pocs-v2"
	changedDigest, err := key.Digest()
	if err != nil || changedDigest == digest {
		t.Fatalf("POC set change did not change digest: before=%q after=%q err=%v", digest, changedDigest, err)
	}
	key.Stage = StageHTTPProbe
	if _, err := key.Digest(); err == nil {
		t.Fatal("POC dimensions were accepted for a non-POC stage")
	}
}

func TestCredentialValidationWorkKeyRequiresCredentialAndObservationHashes(t *testing.T) {
	key := validWorkKey()
	key.Stage = StageCredentialValidation
	if _, err := key.Digest(); err == nil {
		t.Fatal("credential validation WorkKey without credential dimensions was accepted")
	}
	key.CredentialSetHash = "credentials-v1"
	key.ServiceObservationHash = "service-v1"
	digest, err := key.Digest()
	if err != nil {
		t.Fatalf("valid credential validation WorkKey rejected: %v", err)
	}
	key.ServiceObservationHash = "service-v2"
	changedDigest, err := key.Digest()
	if err != nil || changedDigest == digest {
		t.Fatalf("service observation change did not change digest: before=%q after=%q err=%v", digest, changedDigest, err)
	}
	key.Stage = StageProtocolIdentify
	if _, err := key.Digest(); err == nil {
		t.Fatal("credential dimensions were accepted for a non-credential stage")
	}
}

func TestObservationAndCoverageValidation(t *testing.T) {
	now := time.Now().UTC()
	observation := Observation{
		SchemaVersion: SchemaVersion,
		WorkKey:       validWorkKey(),
		Outcome:       ObservationNegative,
		ObservedAt:    now,
		ContentHash:   "content-v1",
	}
	if err := observation.Validate(); err != nil {
		t.Fatalf("valid observation rejected: %v", err)
	}
	failed := observation
	failed.Outcome = ObservationFailed
	if err := failed.Validate(); err == nil {
		t.Fatal("failed observation without error evidence was accepted")
	}
	validUntil := now.Add(time.Hour)
	coverage := Coverage{
		SchemaVersion: SchemaVersion,
		WorkKey:       validWorkKey(),
		Status:        CoverageComplete,
		Outcome:       ObservationNegative,
		StartedAt:     now.Add(-time.Second),
		FinishedAt:    now,
		ValidUntil:    &validUntil,
	}
	if err := coverage.Validate(); err != nil {
		t.Fatalf("valid coverage rejected: %v", err)
	}
	coverage.Outcome = ObservationFailed
	if err := coverage.Validate(); err == nil {
		t.Fatal("failed observation was accepted as complete coverage")
	}
	coverage.Outcome = ObservationNegative
	coverage.Status = CoverageInvalidated
	if err := coverage.Validate(); err == nil {
		t.Fatal("invalidated coverage without a reason was accepted")
	}
}

func TestStageObservationEventRequiresTerminalEvidenceWithoutTrustDimensions(t *testing.T) {
	now := time.Now().UTC()
	event := StageObservationEvent{
		SchemaVersion: SchemaVersion,
		EventID:       "event-a",
		AttemptID:     "attempt-a",
		AgentID:       "agent-a",
		Stage:         StageHTTPProbe,
		Outcome:       ObservationNegative,
		Targets:       []string{"https://example.test"},
		ConfigHash:    "config-a",
		RuleVersion:   "rules-a",
		StartedAt:     now.Add(-time.Second),
		FinishedAt:    now,
		ContentHash:   "content-a",
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("valid stage event rejected: %v", err)
	}
	failed := event
	failed.Outcome = ObservationFailed
	if err := failed.Validate(); err == nil {
		t.Fatal("failed stage event without reason was accepted")
	}
	skipped := event
	skipped.Outcome = ObservationSkipped
	skipped.ErrorCode = "not_applicable"
	if err := skipped.Validate(); err != nil {
		t.Fatalf("skipped stage event with a reason rejected: %v", err)
	}
	duplicateTarget := event
	duplicateTarget.Targets = append(duplicateTarget.Targets, duplicateTarget.Targets[0])
	if err := duplicateTarget.Validate(); err == nil {
		t.Fatal("stage event with duplicate targets was accepted")
	}
}

func TestStageCheckpointValidation(t *testing.T) {
	checkpoint := StageCheckpoint{
		SchemaVersion: CheckpointSchemaVersion,
		Stage:         StageProtocolIdentify,
		Services: []ServiceCheckpoint{
			{Endpoint: "10.0.0.1:22", Protocol: "ssh"},
			{Endpoint: "10.0.0.1:443", Protocol: "https"},
		},
	}
	if _, err := checkpoint.CanonicalJSON(); err != nil {
		t.Fatalf("valid checkpoint rejected: %v", err)
	}
	unsorted := checkpoint
	unsorted.Services = []ServiceCheckpoint{
		{Endpoint: "10.0.0.1:443", Protocol: "https"},
		{Endpoint: "10.0.0.1:22", Protocol: "ssh"},
	}
	if err := unsorted.Validate(); err == nil {
		t.Fatal("unsorted checkpoint was accepted")
	}
	wrongShape := checkpoint
	wrongShape.URLs = []string{"https://10.0.0.1:443"}
	if err := wrongShape.Validate(); err == nil {
		t.Fatal("protocol checkpoint with HTTP data was accepted")
	}
	credentials := StageCheckpoint{SchemaVersion: CheckpointSchemaVersion, Stage: StageHTTPProbe, URLs: []string{"https://user:password@example.test"}}
	if err := credentials.Validate(); err == nil {
		t.Fatal("checkpoint URL with credentials was accepted")
	}
}

func TestStageObservationCheckpointRequiresSingleSuccessfulTarget(t *testing.T) {
	now := time.Now().UTC()
	event := StageObservationEvent{
		SchemaVersion: SchemaVersion, EventID: "event-a", AttemptID: "attempt-a", AgentID: "agent-a",
		Stage: StagePortScan, Outcome: ObservationSuccess, Targets: []string{"10.0.0.1"},
		ConfigHash: "config-a", RuleVersion: "rules-a", StartedAt: now.Add(-time.Second), FinishedAt: now,
		ContentHash: "content-a",
		Checkpoint:  &StageCheckpoint{SchemaVersion: CheckpointSchemaVersion, Stage: StagePortScan, OpenPorts: []string{"10.0.0.1:443"}},
	}
	if err := event.Validate(); err != nil {
		t.Fatalf("valid checkpoint event rejected: %v", err)
	}
	event.Targets = append(event.Targets, "10.0.0.2")
	if err := event.Validate(); err == nil {
		t.Fatal("multi-target checkpoint event was accepted")
	}
	event.Targets = event.Targets[:1]
	event.Outcome = ObservationFailed
	event.ErrorCode = "failed"
	if err := event.Validate(); err == nil {
		t.Fatal("failed checkpoint event was accepted")
	}
}

func TestStageCheckpointIsBoundToAssignedTarget(t *testing.T) {
	portCheckpoint := StageCheckpoint{SchemaVersion: CheckpointSchemaVersion, Stage: StagePortScan, OpenPorts: []string{"10.0.0.8:22"}}
	if err := portCheckpoint.ValidateForTarget("10.0.0.0/24"); err != nil {
		t.Fatalf("in-scope CIDR checkpoint rejected: %v", err)
	}
	if err := portCheckpoint.ValidateForTarget("10.0.1.0/24"); err == nil {
		t.Fatal("out-of-scope CIDR checkpoint accepted")
	}
	httpCheckpoint := StageCheckpoint{SchemaVersion: CheckpointSchemaVersion, Stage: StageHTTPProbe, URLs: []string{"https://example.test:443/login"}}
	if err := httpCheckpoint.ValidateForTarget("https://example.test"); err != nil {
		t.Fatalf("same-authority URL checkpoint rejected: %v", err)
	}
	httpCheckpoint.URLs = []string{"https://other.test/login"}
	if err := httpCheckpoint.ValidateForTarget("https://example.test"); err == nil {
		t.Fatal("cross-host URL checkpoint accepted")
	}
	domainCheckpoint := StageCheckpoint{SchemaVersion: CheckpointSchemaVersion, Stage: StageSubdomainDiscovery, Domains: []string{"api.example.test"}}
	if err := domainCheckpoint.ValidateForTarget("example.test"); err != nil {
		t.Fatalf("subdomain checkpoint rejected: %v", err)
	}
	domainCheckpoint.Domains = []string{"example.invalid"}
	if err := domainCheckpoint.ValidateForTarget("example.test"); err == nil {
		t.Fatal("unrelated domain checkpoint accepted")
	}
	protocolCheckpoint := StageCheckpoint{SchemaVersion: CheckpointSchemaVersion, Stage: StageProtocolIdentify, Services: []ServiceCheckpoint{{Endpoint: "10.0.0.8:443", Protocol: "https"}}}
	if err := protocolCheckpoint.ValidateForTarget("example.test"); err == nil {
		t.Fatal("domain target accepted an unattributed resolved-IP checkpoint")
	}
}

func TestResumePlanRequiresOrderedPartitionAndBoundEvidence(t *testing.T) {
	checkpoint := StageCheckpoint{
		SchemaVersion: CheckpointSchemaVersion,
		Stage:         StagePortScan,
		OpenPorts:     []string{"10.0.0.8:443"},
	}
	encoded, err := checkpoint.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	checkpointDigest := sha256.Sum256(encoded)
	validHash := hex.EncodeToString(checkpointDigest[:])
	plan := ResumePlan{
		SchemaVersion: ResumePlanSchemaVersion,
		TenantID:      "tenant-a", ProjectID: "project-a", NetworkZone: "private:corp", Target: "10.0.0.8",
		ScopeHash: "scope-v1", ConfigHash: "config-v1", RuleVersion: "rules-v1",
		RequiredStages:  []Stage{StagePortScan, StageProtocolIdentify, StageHTTPProbe, StageFingerprint},
		ReusedStages:    []Stage{StagePortScan},
		ExecutionStages: []Stage{StageProtocolIdentify, StageHTTPProbe, StageFingerprint},
		StartStage:      StageProtocolIdentify,
		Checkpoints: []ResumeCheckpoint{{
			Stage: StagePortScan, WorkKeyHash: validHash, CoverageID: 7, SourceObservationID: 9,
			ObservationHash: validHash, CheckpointHash: validHash, Checkpoint: checkpoint,
		}},
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("valid resume plan rejected: %v", err)
	}
	if digest, err := plan.Digest(); err != nil || len(digest) != 64 {
		t.Fatalf("resume plan digest=%q err=%v", digest, err)
	}

	nonPrefix := plan
	nonPrefix.ReusedStages = []Stage{StagePortScan, StageHTTPProbe}
	nonPrefix.ExecutionStages = []Stage{StageProtocolIdentify, StageFingerprint}
	if err := nonPrefix.Validate(); err == nil {
		t.Fatal("non-prefix resume partition was accepted")
	}

	wrongTarget := plan
	wrongTarget.Target = "10.0.1.8"
	if err := wrongTarget.Validate(); err == nil {
		t.Fatal("out-of-target resume evidence was accepted")
	}

	mutated := plan
	mutated.Checkpoints = append([]ResumeCheckpoint(nil), plan.Checkpoints...)
	mutated.Checkpoints[0].Checkpoint.OpenPorts = []string{"10.0.0.8:80"}
	if err := mutated.Validate(); err == nil {
		t.Fatal("resume checkpoint hash mismatch was accepted")
	}
}

func TestResumePlanAllowsExplicitFullFallback(t *testing.T) {
	plan := ResumePlan{
		SchemaVersion: ResumePlanSchemaVersion,
		TenantID:      "tenant-a", ProjectID: "project-a", NetworkZone: PublicNetworkZone, Target: "https://example.test",
		ScopeHash: "scope-v1", ConfigHash: "config-v1", RuleVersion: "rules-v1",
		RequiredStages:  []Stage{StageHTTPProbe, StageFingerprint},
		ExecutionStages: []Stage{StageHTTPProbe, StageFingerprint},
		StartStage:      StageHTTPProbe,
		FallbackReason:  "http_content_not_replayable",
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("safe full fallback plan rejected: %v", err)
	}
}
