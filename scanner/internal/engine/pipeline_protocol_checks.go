package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/TokEat/argus/scanner/gopocs"
	"github.com/TokEat/argus/scanner/structs"
	"github.com/TokEat/argus/shared/proto/go/scanpolicy"
)

var dispatchProtocolCheckTargets = gopocs.DispatchGoPocTargets

func runProtocolCheckPhase(ctx *ScanContext, cfg *Config, services map[string]string) error {
	if cfg == nil || !cfg.ProtocolCheckEnabled {
		return nil
	}
	if cfg.ProtocolCheckTargetLimit < 1 || cfg.ProtocolCheckTargetLimit > scanpolicy.MaximumGoPocTargets || cfg.ProtocolCheckRateLimit < 1 || cfg.ProtocolCheckRequestBudget < 1 {
		return fmt.Errorf("protocol checks require a positive sealed target and request budget")
	}
	keys := make([]string, 0, len(services))
	for endpoint := range services {
		keys = append(keys, endpoint)
	}
	sort.Strings(keys)
	targets := make([]scanpolicy.GoPocTarget, 0)
	for _, endpoint := range keys {
		host, rawPort, err := net.SplitHostPort(endpoint)
		if err != nil || strings.TrimSpace(host) == "" {
			continue
		}
		port, err := strconv.Atoi(rawPort)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		service := strings.ToLower(strings.TrimSpace(services[endpoint]))
		observation := sha256.Sum256([]byte(strings.Join([]string{endpoint, service, strconv.Itoa(port)}, "\x00")))
		targets = append(targets, scanpolicy.GoPocTargetsForEndpoint(endpoint, service, port, hex.EncodeToString(observation[:]), scanpolicy.GoPocProtocolCheck)...)
		if len(targets) > cfg.ProtocolCheckTargetLimit {
			return fmt.Errorf("protocol check plan exceeds the sealed target limit")
		}
	}
	if len(targets) == 0 {
		return nil
	}
	_, err := dispatchProtocolCheckTargets(targets, cfg.GoPocCatalogSHA256, scanpolicy.GoPocProtocolCheck, cfg.GoPocThreads, cfg.ProtocolCheckRateLimit, cfg.ProtocolCheckRequestBudget, func(message structs.OutputMessage) {
		dispatchPipelineOutput(ctx, message)
	})
	return err
}
