package engine

import (
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/P0lar1ght/argus/scanner/internal/vuln/nuclei"
	"github.com/P0lar1ght/argus/scanner/structs"
	"github.com/P0lar1ght/argus/shared/proto/go/activefingerprint"
	"github.com/projectdiscovery/gologger"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func runActiveFingerprintPhase(ctx *ScanContext, cfg *Config, aliveURLs []string) error {
	if cfg == nil || !cfg.BehaviorProbe {
		return nil
	}
	files, products, err := validatedActiveFingerprintFiles(cfg)
	if err != nil {
		return err
	}
	if len(files) == 0 || len(aliveURLs) == 0 {
		return nil
	}
	urls := canonicalBehaviorTargets(aliveURLs)
	estimate := int64(len(files) * len(urls))
	if cfg.BehaviorProbeRequestBudget < estimate {
		return fmt.Errorf("active fingerprint estimate %d exceeds sealed request budget %d", estimate, cfg.BehaviorProbeRequestBudget)
	}
	gologger.Info().Msgf("[BehaviorProbe] running %d reviewed safe active-fingerprint templates on %d targets (not POC)", len(files), len(urls))
	targets := make(map[string][]string, len(urls))
	for _, target := range urls {
		targets[target] = append([]string(nil), files...)
	}
	var (
		matchedMu sync.Mutex
		matched   []nucleiOutput.ResultEvent
	)
	callback := func(result nucleiOutput.ResultEvent) {
		matchedMu.Lock()
		matched = append(matched, result)
		matchedMu.Unlock()
	}
	threads := cfg.WebThreads
	if threads < 1 {
		threads = 1
	}
	if threads > 32 {
		threads = 32
	}
	_, err = callNucleiLimited(targets, cfg.HTTPProxy, callback, "", true, false,
		currentPipelineEmbedActiveFingerprints(ctx), cfg.ActiveFingerprintTemplate, nil, nil,
		nuclei.ExecutionLimits{RateLimit: threads, TargetConcurrency: threads, RequestBudget: cfg.BehaviorProbeRequestBudget}, cfg.MachineOutput)
	if err != nil {
		return err
	}
	matchedMu.Lock()
	results := append([]nucleiOutput.ResultEvent(nil), matched...)
	matchedMu.Unlock()
	emitted := make(map[string]struct{}, len(results))
	for _, result := range results {
		fileName := filepath.Base(strings.TrimSpace(result.TemplatePath))
		product := products[fileName]
		if product == "" {
			product = products[strings.TrimSpace(result.TemplateID)]
		}
		if product == "" {
			continue
		}
		uri := strings.TrimSpace(result.Matched)
		if uri == "" {
			uri = strings.TrimSpace(result.URL)
		}
		key := product + "\x00" + uri
		if _, exists := emitted[key]; exists {
			continue
		}
		emitted[key] = struct{}{}
		dispatchPipelineOutput(ctx, structs.OutputMessage{
			Type: "Active-Finger", URI: uri, Finger: []string{product},
			AdditionalMsg: "[behavior-probe:" + strings.TrimSuffix(fileName, filepath.Ext(fileName)) + "]",
		})
	}
	return nil
}

func validatedActiveFingerprintFiles(cfg *Config) ([]string, map[string]string, error) {
	if strings.TrimSpace(cfg.ActiveFingerprintTemplate) == "" {
		return nil, nil, fmt.Errorf("active fingerprint template directory is required")
	}
	if len(cfg.ActiveFingerprintHashes) == 0 && len(cfg.ActiveFingerprintProducts) == 0 {
		return nil, map[string]string{}, nil
	}
	if len(cfg.ActiveFingerprintHashes) == 0 || len(cfg.ActiveFingerprintProducts) == 0 {
		return nil, nil, fmt.Errorf("active fingerprint requires a sealed file and product plan")
	}
	if len(cfg.ActiveFingerprintHashes) > activefingerprint.MaxAutoSafePerTenant || len(cfg.ActiveFingerprintProducts) != len(cfg.ActiveFingerprintHashes) {
		return nil, nil, fmt.Errorf("active fingerprint sealed plan is inconsistent or exceeds %d templates", activefingerprint.MaxAutoSafePerTenant)
	}
	files := make([]string, 0, len(cfg.ActiveFingerprintHashes))
	products := make(map[string]string, len(cfg.ActiveFingerprintHashes))
	ids := make(map[string]string, len(cfg.ActiveFingerprintHashes))
	for rawName, expectedHash := range cfg.ActiveFingerprintHashes {
		name := filepath.Base(strings.TrimSpace(rawName))
		if name != rawName || (filepath.Ext(name) != ".yaml" && filepath.Ext(name) != ".yml") {
			return nil, nil, fmt.Errorf("active fingerprint filename %q is unsafe", rawName)
		}
		product := strings.TrimSpace(cfg.ActiveFingerprintProducts[name])
		if product == "" {
			return nil, nil, fmt.Errorf("active fingerprint %q has no sealed product", name)
		}
		content, err := os.ReadFile(filepath.Join(cfg.ActiveFingerprintTemplate, name))
		if err != nil {
			return nil, nil, fmt.Errorf("read active fingerprint %q: %w", name, err)
		}
		classification, err := activefingerprint.Inspect(name, content)
		if err != nil || !classification.AutoEligible || classification.Product != product {
			return nil, nil, fmt.Errorf("active fingerprint %q no longer matches its automatic execution contract", name)
		}
		if other, duplicate := ids[classification.ID]; duplicate {
			return nil, nil, fmt.Errorf("active fingerprints %q and %q use duplicate template id %q", other, name, classification.ID)
		}
		ids[classification.ID] = name
		actual := fmt.Sprintf("%x", sha256.Sum256(content))
		if !strings.EqualFold(strings.TrimSpace(expectedHash), actual) {
			return nil, nil, fmt.Errorf("active fingerprint %q content changed after task creation", name)
		}
		files = append(files, name)
		products[name] = product
		products[classification.ID] = product
	}
	sort.Strings(files)
	return files, products, nil
}

func canonicalBehaviorTargets(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			continue
		}
		parsed.Scheme = strings.ToLower(parsed.Scheme)
		parsed.Host = strings.ToLower(parsed.Host)
		parsed.Path = ""
		parsed.RawPath = ""
		parsed.RawQuery = ""
		parsed.Fragment = ""
		value = parsed.String()
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
