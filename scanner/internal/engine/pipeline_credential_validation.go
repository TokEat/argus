package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/P0lar1ght/argus/scanner/gopocs"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/shared/proto/go/scanpolicy"
)

var dispatchCredentialTargets = gopocs.DispatchCredentialTargets

func normalizedCredentialValidationTargets(cfg *Config) ([]structs.CredentialValidationTarget, int, error) {
	if cfg == nil || !strings.EqualFold(strings.TrimSpace(cfg.ExecutionMode), "credential_validation") {
		return nil, 0, fmt.Errorf("credential validation execution mode is required")
	}
	limit := cfg.CredentialPairLimit
	if limit == 0 {
		limit = scanpolicy.DefaultCredentialPairLimit
	}
	if limit < 1 || limit > scanpolicy.MaximumCredentialPairLimit {
		return nil, 0, fmt.Errorf("credential pair limit must be between 1 and %d", scanpolicy.MaximumCredentialPairLimit)
	}
	if len(cfg.CredentialBundle) > limit {
		return nil, 0, fmt.Errorf("credential bundle contains %d pairs, exceeding limit %d", len(cfg.CredentialBundle), limit)
	}
	if strings.TrimSpace(cfg.ValidationBudgetID) == "" || cfg.ValidationTargetConcurrency < 1 || cfg.ValidationRateLimit < 1 || cfg.ValidationRequestBudget < 1 || cfg.ValidationEstimatedRequests < 1 {
		return nil, 0, errors.New("credential validation requires a positive sealed execution budget")
	}
	if cfg.ValidationEstimatedRequests > cfg.ValidationRequestBudget {
		return nil, 0, errors.New("credential validation estimate exceeds the sealed request budget")
	}
	if cfg.GoPocThreads < 1 || cfg.GoPocThreads > cfg.ValidationTargetConcurrency {
		return nil, 0, errors.New("credential validation concurrency exceeds the sealed allocation")
	}
	allowedTargets := make(map[string]struct{}, len(cfg.Targets))
	for _, target := range cfg.Targets {
		target = strings.TrimSpace(target)
		if target == "" || strings.ContainsAny(target, "\r\n\x00") {
			return nil, 0, errors.New("credential validation contains an invalid dispatched target")
		}
		allowedTargets[target] = struct{}{}
	}
	if len(allowedTargets) == 0 || len(cfg.CredentialValidationTargets) == 0 {
		return nil, 0, errors.New("credential validation requires a sealed service plan")
	}
	seen := make(map[string]struct{}, len(cfg.CredentialValidationTargets))
	targets := append([]structs.CredentialValidationTarget(nil), cfg.CredentialValidationTargets...)
	if int64(len(targets)) > cfg.ValidationRequestBudget/int64(limit) {
		return nil, 0, errors.New("credential validation target plan exceeds the sealed request budget")
	}
	for i := range targets {
		target := &targets[i]
		target.Endpoint = strings.TrimSpace(target.Endpoint)
		target.Service = strings.ToLower(strings.TrimSpace(target.Service))
		target.Plugin = strings.TrimSpace(target.Plugin)
		target.Eligibility = strings.ToLower(strings.TrimSpace(target.Eligibility))
		target.ObservationSHA256 = strings.ToLower(strings.TrimSpace(target.ObservationSHA256))
		if _, ok := allowedTargets[target.Endpoint]; !ok {
			return nil, 0, fmt.Errorf("credential target %q is outside the dispatched batch", target.Endpoint)
		}
		_, port, err := net.SplitHostPort(target.Endpoint)
		if err != nil {
			return nil, 0, fmt.Errorf("credential target %q must be host:port", target.Endpoint)
		}
		parsedPort, err := strconv.Atoi(port)
		if err != nil || parsedPort < 1 || parsedPort > 65535 {
			return nil, 0, fmt.Errorf("credential target %q has invalid port", target.Endpoint)
		}
		if err := gopocs.CredentialPluginEligible(target.Plugin, target.Service, port, target.Eligibility); err != nil {
			return nil, 0, err
		}
		decoded, err := hex.DecodeString(target.ObservationSHA256)
		if err != nil || len(decoded) != sha256.Size {
			return nil, 0, fmt.Errorf("credential target %q has invalid observation sha256", target.Endpoint)
		}
		key := strings.ToLower(target.Endpoint) + "\x00" + target.Plugin
		if _, duplicate := seen[key]; duplicate {
			return nil, 0, fmt.Errorf("duplicate credential target %q for plugin %q", target.Endpoint, target.Plugin)
		}
		seen[key] = struct{}{}
	}
	for target := range allowedTargets {
		covered := false
		for _, planned := range targets {
			if planned.Endpoint == target {
				covered = true
				break
			}
		}
		if !covered {
			return nil, 0, fmt.Errorf("dispatched target %q is missing from the credential plan", target)
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Endpoint == targets[j].Endpoint {
			return targets[i].Plugin < targets[j].Plugin
		}
		return targets[i].Endpoint < targets[j].Endpoint
	})
	return targets, limit, nil
}

func runCredentialValidationPhase(ctx *ScanContext, cfg *Config) error {
	targets, limit, err := normalizedCredentialValidationTargets(cfg)
	if err != nil {
		return err
	}
	emitPhase(ctx, PhaseCredentialValidation, "start", fmt.Sprintf("%d authorized service checks", len(targets)))
	results, dispatchErr := dispatchCredentialTargets(targets, cfg.CredentialBundle, limit, cfg.GoPocThreads, cfg.ValidationRateLimit, func(message structs.OutputMessage) {
		dispatchPipelineOutput(ctx, message)
	})
	ctx.GoPocsResults = toEngineGoPocResults(results)
	if dispatchErr != nil {
		emitPhase(ctx, PhaseCredentialValidation, "failed", "credential validation failed")
		return dispatchErr
	}
	emitPhase(ctx, PhaseCredentialValidation, "end", fmt.Sprintf("%d findings", len(results)))
	return nil
}
