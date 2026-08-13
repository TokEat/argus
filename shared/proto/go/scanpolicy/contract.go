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

type Capabilities struct {
	SubdomainDiscovery          bool `json:"subdomain_discovery"`
	SubdomainBruteforce         bool `json:"subdomain_bruteforce"`
	AllowCDNAssets              bool `json:"allow_cdn_assets"`
	AllowPrivateResolvedDomains bool `json:"allow_private_resolved_domains"`
	HostBinding                 bool `json:"host_binding"`
	DirectoryProbe              bool `json:"directory_probe"`
	RiskValidation              bool `json:"risk_validation"`
	CredentialValidation        bool `json:"credential_validation"`
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
	Capabilities  Capabilities     `json:"capabilities"`
	Selector      Selector         `json:"selector,omitempty"`
	Credentials   CredentialPolicy `json:"credentials"`
	Authorization Authorization    `json:"authorization"`
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
		policy.Capabilities.RiskValidation = true
	case PresetDeep:
		policy.PortProfile = PortProfileAll
		policy.Intensity = IntensityHigh
		policy.Capabilities.SubdomainDiscovery = true
		policy.Capabilities.SubdomainBruteforce = true
		policy.Capabilities.HostBinding = true
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
// capability checkboxes are explicit user choices layered on those defaults.
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
		expected.Credentials = input.Credentials
		if input.Capabilities != (Capabilities{}) {
			expected.Capabilities = input.Capabilities
		}
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
	if (input.Capabilities.RiskValidation || input.Capabilities.CredentialValidation) && !input.Authorization.ValidationConfirmed {
		return Policy{}, errors.New("POC or credential validation requires one explicit authorization confirmation")
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
