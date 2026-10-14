// Package scanpolicy defines the user-facing, versioned scan policy shared by
// Argus control-plane clients, Server, and Agents. It deliberately excludes
// scanner implementation paths, output files, and other host-local settings.
package scanpolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

const (
	SchemaVersion               = "argus.scan-policy/v1"
	DefaultCredentialPairLimit  = 50_000
	MaximumCredentialPairLimit  = 100_000
	MaximumCustomPorts          = 65_535
	MaximumDictionaryReferences = 32
	DefaultPacingIntervalMillis = 500
	MinimumPacingIntervalMillis = 50
	MaximumPacingIntervalMillis = 5000
	DefaultWebCrawlMaxDepth     = 2
	DefaultWebCrawlMaxPages     = 50
	MaximumWebCrawlMaxDepth     = 5
	MaximumWebCrawlMaxPages     = 500
	MaximumWebCrawlPathAppLimit = 5
)

type Preset string

const (
	PresetQuick    Preset = "quick"
	PresetStandard Preset = "standard"
	PresetDeep     Preset = "deep"
	PresetCustom   Preset = "custom"
)

func (p Preset) Valid() bool {
	switch p {
	case PresetQuick, PresetStandard, PresetDeep, PresetCustom:
		return true
	default:
		return false
	}
}

type PortProfile string

const (
	PortProfileCommon100 PortProfile = "common-100"
	PortProfileTop1000   PortProfile = "top-1000"
	PortProfileAll       PortProfile = "all"
	PortProfileCustom    PortProfile = "custom"
)

func (p PortProfile) Valid() bool {
	switch p {
	case PortProfileCommon100, PortProfileTop1000, PortProfileAll, PortProfileCustom:
		return true
	default:
		return false
	}
}

type ScanMethod string

const (
	ScanMethodTCP ScanMethod = "tcp"
	ScanMethodSYN ScanMethod = "syn"
)

func (m ScanMethod) Valid() bool { return m == ScanMethodTCP || m == ScanMethodSYN }

type Intensity string

const (
	IntensityLow      Intensity = "low"
	IntensityBalanced Intensity = "balanced"
	IntensityHigh     Intensity = "high"
)

func (i Intensity) Valid() bool {
	switch i {
	case IntensityLow, IntensityBalanced, IntensityHigh:
		return true
	default:
		return false
	}
}

// ScanPacing is the low-and-slow port scan option: probes to the same target
// are scattered across time with a minimum per-target interval so security
// appliances with per-IP rate thresholds are less likely to auto-block the
// scanner. Disabled by default; enabling trades throughput for stealth.
type ScanPacing struct {
	Enabled        bool `json:"enabled"`
	IntervalMillis int  `json:"interval_millis"`
}

func (p ScanPacing) Valid() error {
	if !p.Enabled {
		return nil
	}
	if p.IntervalMillis < MinimumPacingIntervalMillis || p.IntervalMillis > MaximumPacingIntervalMillis {
		return fmt.Errorf("pacing interval_millis must be between %d and %d", MinimumPacingIntervalMillis, MaximumPacingIntervalMillis)
	}
	return nil
}

// DispatchStrategy selects how SubTasks reach agents. controller_push routes
// each SubTask to a specific alive agent under controller control (k8s-style
// scheduling with load balancing); agent_claim keeps the legacy first-come
// shared-queue pull model. It is a scheduling concern, not scan content, so it
// is deliberately kept out of Policy and Hash (unlike Preset/PortProfile).
type DispatchStrategy string

const (
	DispatchStrategyControllerPush DispatchStrategy = "controller_push"
	DispatchStrategyAgentClaim     DispatchStrategy = "agent_claim"
)

func (s DispatchStrategy) Valid() bool {
	switch s {
	case DispatchStrategyControllerPush, DispatchStrategyAgentClaim:
		return true
	default:
		return false
	}
}

// NormalizeDispatchStrategy resolves empty/invalid values to def. Stored task
// rows keep an empty strategy to mean "inherit the global default at read
// time", so upgrades never hard-flip pre-existing rows.
func NormalizeDispatchStrategy(s DispatchStrategy, def DispatchStrategy) DispatchStrategy {
	if s.Valid() {
		return s
	}
	return def
}

// dispatchStrategyDefaultEnv overrides the process-wide default dispatch
// strategy. It exists so tests can pin the legacy pull model while production
// defaults to controller-push.
const dispatchStrategyDefaultEnv = "ARGUS_DISPATCH_STRATEGY_DEFAULT"

var defaultDispatchStrategy = DispatchStrategyFromEnv()

// DispatchStrategyFromEnv reads the configured default, falling back to
// controller_push when the env var is empty or unrecognized.
func DispatchStrategyFromEnv() DispatchStrategy {
	switch raw := DispatchStrategy(strings.ToLower(strings.TrimSpace(os.Getenv(dispatchStrategyDefaultEnv)))); raw {
	case DispatchStrategyAgentClaim:
		return DispatchStrategyAgentClaim
	default:
		return DispatchStrategyControllerPush
	}
}

// DefaultDispatchStrategy returns the process-wide default used when a task
// row stores an empty dispatch_strategy.
func DefaultDispatchStrategy() DispatchStrategy { return defaultDispatchStrategy }

// SetDefaultDispatchStrategy overrides the process-wide default. Tests use it
// to pin a strategy; passing an invalid value is ignored.
func SetDefaultDispatchStrategy(s DispatchStrategy) {
	if s.Valid() {
		defaultDispatchStrategy = s
	}
}

type Capabilities struct {
	SubdomainDiscovery          bool `json:"subdomain_discovery"`
	SubdomainBruteforce         bool `json:"subdomain_bruteforce"`
	AllowCDNAssets              bool `json:"allow_cdn_assets"`
	AllowPrivateResolvedDomains bool `json:"allow_private_resolved_domains"`
	HostBinding                 bool `json:"host_binding"`
	BehaviorProbe               bool `json:"behavior_probe"`
	DirectoryProbe              bool `json:"directory_probe"`
	RiskValidation              bool `json:"risk_validation"`
	CredentialValidation        bool `json:"credential_validation"`
	WebCrawl                    bool `json:"web_crawl"`
	SensitiveInfo               bool `json:"sensitive_info"`
}

// WebCrawlPolicy bounds proactive same-host:port page crawling. Crawling is
// strictly scoped to the seed host:port; cross-port / sibling-subdomain links
// are reported as related-asset candidates but never fetched.
type WebCrawlPolicy struct {
	MaxDepth int `json:"max_depth,omitempty"`
	MaxPages int `json:"max_pages,omitempty"`
	// PathAppLimit caps per-host:port path-prefix app / hidden-endpoint
	// candidates mined from crawled JS/HTML (0=disabled, no profiling cost).
	PathAppLimit int `json:"path_app_limit,omitempty"`
}

// AIControlPolicy gates the optional server-side AI analysis (worth /
// semantic-dedup / structured extraction) for the two content features. Each
// sub-switch additionally requires a globally configured LLM; when off or
// unconfigured the feature degrades to basic regex/hash extraction.
type AIControlPolicy struct {
	Crawl         bool `json:"crawl,omitempty"`
	SensitiveInfo bool `json:"sensitive_info,omitempty"`
}

type Selector struct {
	Match    map[string][]string `json:"match,omitempty"`
	NotMatch map[string][]string `json:"not_match,omitempty"`
}

type DictionaryRef struct {
	ID       string `json:"id"`
	Revision int    `json:"revision"`
	SHA256   string `json:"sha256"`
	Count    int    `json:"count"`
}

type CredentialPolicy struct {
	UsernameBooks []DictionaryRef `json:"username_books,omitempty"`
	PasswordBooks []DictionaryRef `json:"password_books,omitempty"`
	PairLimit     int             `json:"pair_limit"`
}

// SubdomainPolicy binds project-scoped immutable wordlist revisions. The
// referenced values are always additive to Scanner's built-in wordlist.
type SubdomainPolicy struct {
	Wordlists       []DictionaryRef `json:"wordlists,omitempty"`
	BruteforceDepth int             `json:"bruteforce_depth,omitempty"`
}

type Authorization struct {
	ValidationConfirmed bool `json:"validation_confirmed"`
}

type Policy struct {
	SchemaVersion string           `json:"schema_version"`
	Preset        Preset           `json:"preset"`
	PortProfile   PortProfile      `json:"port_profile"`
	CustomPorts   string           `json:"custom_ports,omitempty"`
	ScanMethod    ScanMethod       `json:"scan_method"`
	Intensity     Intensity        `json:"intensity"`
	Pacing        *ScanPacing      `json:"pacing,omitempty"`
	Capabilities  Capabilities      `json:"capabilities"`
	Selector      Selector          `json:"selector,omitempty"`
	Subdomains    SubdomainPolicy   `json:"subdomains"`
	Credentials   CredentialPolicy  `json:"credentials"`
	Authorization Authorization     `json:"authorization"`
	WebCrawl      WebCrawlPolicy    `json:"web_crawl,omitempty"`
	AIControl     AIControlPolicy   `json:"ai_control,omitempty"`
}

func PresetPolicy(preset Preset) (Policy, error) {
	policy := Policy{
		SchemaVersion: SchemaVersion,
		Preset:        preset,
		ScanMethod:    ScanMethodTCP,
		Credentials:   CredentialPolicy{PairLimit: DefaultCredentialPairLimit},
	}
	switch preset {
	case PresetQuick:
		policy.PortProfile = PortProfileCommon100
		policy.Intensity = IntensityLow
		policy.Capabilities.SubdomainDiscovery = true
	case PresetStandard:
		policy.PortProfile = PortProfileTop1000
		policy.Intensity = IntensityBalanced
		policy.Capabilities.SubdomainDiscovery = true
		policy.Capabilities.BehaviorProbe = true
		policy.Capabilities.RiskValidation = true
	case PresetDeep:
		policy.PortProfile = PortProfileAll
		policy.Intensity = IntensityHigh
		policy.Capabilities.SubdomainDiscovery = true
		policy.Capabilities.SubdomainBruteforce = true
		policy.Subdomains.BruteforceDepth = 2
		policy.Capabilities.HostBinding = true
		policy.Capabilities.BehaviorProbe = true
		policy.Capabilities.DirectoryProbe = true
		policy.Capabilities.RiskValidation = true
	case PresetCustom:
		policy.PortProfile = PortProfileCustom
		policy.Intensity = IntensityBalanced
	default:
		return Policy{}, fmt.Errorf("unsupported scan preset %q", preset)
	}
	return policy, nil
}

// Normalize validates a policy and returns its canonical representation.
// Port profile, transport method, and intensity are immutable preset traits;
// capabilities are explicit user choices. The UI seeds its checkboxes from the
// preset defaults, so an unticked capability here means "do not run that stage"
// and must never be replaced by a preset default (an all-false Capabilities is a
// legitimate choice, not an omission). Because a bool struct cannot distinguish
// "field omitted" from "explicitly false", capabilities are taken verbatim.
func Normalize(input Policy) (Policy, error) {
	if input.SchemaVersion == "" {
		input.SchemaVersion = SchemaVersion
	}
	if input.SchemaVersion != SchemaVersion {
		return Policy{}, fmt.Errorf("unsupported scan policy schema %q", input.SchemaVersion)
	}
	if !input.Preset.Valid() {
		return Policy{}, fmt.Errorf("unsupported scan preset %q", input.Preset)
	}
	if input.Preset != PresetCustom {
		expected, _ := PresetPolicy(input.Preset)
		expected.Selector = input.Selector
		expected.Authorization = input.Authorization
		expected.Pacing = input.Pacing
		expected.Subdomains.Wordlists = input.Subdomains.Wordlists
		if input.Subdomains.BruteforceDepth != 0 {
			expected.Subdomains.BruteforceDepth = input.Subdomains.BruteforceDepth
		}
		expected.Credentials = input.Credentials
		expected.Capabilities = input.Capabilities
		expected.WebCrawl = input.WebCrawl
		expected.AIControl = input.AIControl
		if expected.Credentials.PairLimit == 0 {
			expected.Credentials.PairLimit = DefaultCredentialPairLimit
		}
		if input.PortProfile != "" && input.PortProfile != expected.PortProfile ||
			input.CustomPorts != "" ||
			input.ScanMethod != "" && input.ScanMethod != expected.ScanMethod ||
			input.Intensity != "" && input.Intensity != expected.Intensity {
			return Policy{}, errors.New("preset overrides require preset=custom")
		}
		input = expected
	}
	if !input.PortProfile.Valid() {
		return Policy{}, fmt.Errorf("unsupported port profile %q", input.PortProfile)
	}
	if !input.ScanMethod.Valid() {
		return Policy{}, fmt.Errorf("unsupported scan method %q", input.ScanMethod)
	}
	if !input.Intensity.Valid() {
		return Policy{}, fmt.Errorf("unsupported scan intensity %q", input.Intensity)
	}
	if input.Pacing != nil {
		pacing := *input.Pacing
		if !pacing.Enabled {
			input.Pacing = nil
		} else {
			if pacing.IntervalMillis == 0 {
				pacing.IntervalMillis = DefaultPacingIntervalMillis
			}
			if err := pacing.Valid(); err != nil {
				return Policy{}, err
			}
			input.Pacing = &pacing
		}
	}
	if input.PortProfile == PortProfileCustom {
		ports, err := NormalizePorts(input.CustomPorts)
		if err != nil {
			return Policy{}, err
		}
		input.CustomPorts = ports
	} else if strings.TrimSpace(input.CustomPorts) != "" {
		return Policy{}, errors.New("custom_ports is valid only with the custom port profile")
	}
	if input.Capabilities.SubdomainBruteforce && !input.Capabilities.SubdomainDiscovery {
		return Policy{}, errors.New("subdomain bruteforce requires subdomain discovery")
	}
	if !input.Capabilities.SubdomainBruteforce && len(input.Subdomains.Wordlists) > 0 {
		return Policy{}, errors.New("subdomain dictionary references require subdomain bruteforce")
	}
	if input.Capabilities.SubdomainBruteforce {
		if input.Subdomains.BruteforceDepth == 0 {
			input.Subdomains.BruteforceDepth = 1
		}
		if input.Subdomains.BruteforceDepth < 1 || input.Subdomains.BruteforceDepth > 4 {
			return Policy{}, errors.New("subdomain bruteforce depth must be between 1 and 4")
		}
	} else if input.Subdomains.BruteforceDepth != 0 {
		return Policy{}, errors.New("subdomain bruteforce depth requires subdomain bruteforce")
	}
	if len(input.Subdomains.Wordlists) > MaximumDictionaryReferences {
		return Policy{}, fmt.Errorf("subdomain policy allows at most %d dictionary references", MaximumDictionaryReferences)
	}
	if (input.Capabilities.RiskValidation || input.Capabilities.CredentialValidation) && !input.Authorization.ValidationConfirmed {
		return Policy{}, errors.New("POC or credential validation requires one explicit authorization confirmation")
	}
	if !input.Capabilities.WebCrawl && (input.WebCrawl.MaxDepth != 0 || input.WebCrawl.MaxPages != 0) {
		return Policy{}, errors.New("web_crawl bounds require the web_crawl capability")
	}
	if input.Capabilities.WebCrawl {
		if input.WebCrawl.MaxDepth == 0 {
			input.WebCrawl.MaxDepth = DefaultWebCrawlMaxDepth
		}
		if input.WebCrawl.MaxPages == 0 {
			input.WebCrawl.MaxPages = DefaultWebCrawlMaxPages
		}
		if input.WebCrawl.MaxDepth < 1 || input.WebCrawl.MaxDepth > MaximumWebCrawlMaxDepth {
			return Policy{}, fmt.Errorf("web_crawl max_depth must be between 1 and %d", MaximumWebCrawlMaxDepth)
		}
		if input.WebCrawl.MaxPages < 1 || input.WebCrawl.MaxPages > MaximumWebCrawlMaxPages {
			return Policy{}, fmt.Errorf("web_crawl max_pages must be between 1 and %d", MaximumWebCrawlMaxPages)
		}
		if input.WebCrawl.PathAppLimit < 0 || input.WebCrawl.PathAppLimit > MaximumWebCrawlPathAppLimit {
			return Policy{}, fmt.Errorf("web_crawl path_app_limit must be between 0 and %d", MaximumWebCrawlPathAppLimit)
		}
	}
	if input.AIControl.Crawl && !input.Capabilities.WebCrawl {
		return Policy{}, errors.New("ai_control.crawl requires the web_crawl capability")
	}
	if input.AIControl.SensitiveInfo && !input.Capabilities.SensitiveInfo {
		return Policy{}, errors.New("ai_control.sensitive_info requires the sensitive_info capability")
	}
	if input.Credentials.PairLimit == 0 {
		input.Credentials.PairLimit = DefaultCredentialPairLimit
	}
	if input.Credentials.PairLimit < 1 || input.Credentials.PairLimit > MaximumCredentialPairLimit {
		return Policy{}, fmt.Errorf("credential pair limit must be between 1 and %d", MaximumCredentialPairLimit)
	}
	if !input.Capabilities.CredentialValidation && (len(input.Credentials.UsernameBooks) > 0 || len(input.Credentials.PasswordBooks) > 0) {
		return Policy{}, errors.New("credential dictionary references require credential validation")
	}
	if len(input.Credentials.UsernameBooks) > MaximumDictionaryReferences || len(input.Credentials.PasswordBooks) > MaximumDictionaryReferences {
		return Policy{}, fmt.Errorf("credential policy allows at most %d references per dictionary kind", MaximumDictionaryReferences)
	}
	var err error
	input.Selector.Match, err = normalizeSelector(input.Selector.Match)
	if err != nil {
		return Policy{}, fmt.Errorf("normalize selector match: %w", err)
	}
	input.Selector.NotMatch, err = normalizeSelector(input.Selector.NotMatch)
	if err != nil {
		return Policy{}, fmt.Errorf("normalize selector not_match: %w", err)
	}
	input.Credentials.UsernameBooks = append([]DictionaryRef(nil), input.Credentials.UsernameBooks...)
	input.Credentials.PasswordBooks = append([]DictionaryRef(nil), input.Credentials.PasswordBooks...)
	input.Subdomains.Wordlists = append([]DictionaryRef(nil), input.Subdomains.Wordlists...)
	input.Subdomains.Wordlists, err = normalizeDictionaryRefs(input.Subdomains.Wordlists)
	if err != nil {
		return Policy{}, fmt.Errorf("normalize subdomain wordlists: %w", err)
	}
	input.Credentials.UsernameBooks, err = normalizeDictionaryRefs(input.Credentials.UsernameBooks)
	if err != nil {
		return Policy{}, fmt.Errorf("normalize username books: %w", err)
	}
	input.Credentials.PasswordBooks, err = normalizeDictionaryRefs(input.Credentials.PasswordBooks)
	if err != nil {
		return Policy{}, fmt.Errorf("normalize password books: %w", err)
	}
	return input, nil
}

func Hash(policy Policy) (string, error) {
	normalized, err := Normalize(policy)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func NormalizePorts(raw string) (string, error) {
	seen := make(map[int]struct{})
	for _, token := range strings.Split(raw, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		parts := strings.Split(token, "-")
		if len(parts) > 2 {
			return "", fmt.Errorf("invalid port token %q", token)
		}
		start, err := parsePort(parts[0])
		if err != nil {
			return "", err
		}
		end := start
		if len(parts) == 2 {
			end, err = parsePort(parts[1])
			if err != nil {
				return "", err
			}
		}
		if start > end {
			return "", fmt.Errorf("invalid descending port range %q", token)
		}
		for port := start; port <= end; port++ {
			seen[port] = struct{}{}
			if len(seen) > MaximumCustomPorts {
				return "", errors.New("custom port set exceeds 65535 ports")
			}
		}
	}
	if len(seen) == 0 {
		return "", errors.New("custom port profile requires at least one port")
	}
	ports := make([]int, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	parts := make([]string, len(ports))
	for i, port := range ports {
		parts[i] = fmt.Sprint(port)
	}
	return strings.Join(parts, ","), nil
}

func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", raw)
	}
	return port, nil
}

func normalizeSelector(values map[string][]string) (map[string][]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	normalized := make(map[string][]string, len(values))
	for rawKey, rawValues := range values {
		key := strings.TrimSpace(rawKey)
		if key == "" || strings.ContainsAny(key, "\r\n\x00") {
			return nil, errors.New("selector contains an invalid key")
		}
		seen := make(map[string]struct{})
		for _, rawValue := range rawValues {
			value := strings.TrimSpace(rawValue)
			if value == "" || strings.ContainsAny(value, "\r\n\x00") {
				return nil, fmt.Errorf("selector %q contains an invalid value", key)
			}
			seen[value] = struct{}{}
		}
		if len(seen) == 0 {
			return nil, fmt.Errorf("selector %q requires at least one value", key)
		}
		items := make([]string, 0, len(seen))
		for value := range seen {
			items = append(items, value)
		}
		sort.Strings(items)
		normalized[key] = items
	}
	return normalized, nil
}

func normalizeDictionaryRefs(refs []DictionaryRef) ([]DictionaryRef, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(refs))
	for i := range refs {
		ref := &refs[i]
		ref.ID = strings.TrimSpace(ref.ID)
		ref.SHA256 = strings.ToLower(strings.TrimSpace(ref.SHA256))
		if ref.ID == "" || strings.ContainsAny(ref.ID, "\r\n\x00") || ref.Revision < 1 || ref.Count < 0 {
			return nil, errors.New("dictionary reference contains invalid metadata")
		}
		decoded, err := hex.DecodeString(ref.SHA256)
		if err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("dictionary %q has an invalid sha256", ref.ID)
		}
		key := ref.ID + "\x00" + fmt.Sprint(ref.Revision)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("duplicate dictionary reference %q revision %d", ref.ID, ref.Revision)
		}
		seen[key] = struct{}{}
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].ID == refs[j].ID {
			return refs[i].Revision < refs[j].Revision
		}
		return refs[i].ID < refs[j].ID
	})
	return refs, nil
}
