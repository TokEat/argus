// Package activefingerprint defines the governed Nuclei template contract used
// for active product identification. It deliberately separates storage
// compatibility from automatic-execution eligibility.
package activefingerprint

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	RuleKind               = "active-fingerprint"
	AutoProfileSafe        = "safe"
	AutoProfileControlled  = "controlled"
	MaxAutoSafePerTenant   = 8
	MaxSameOriginRedirects = 2
	MaxTemplateBytes       = 1 << 20
)

var templateIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type Classification struct {
	ID              string   `json:"id"`
	Product         string   `json:"product"`
	DeclaredProfile string   `json:"declared_profile,omitempty"`
	ComputedProfile string   `json:"computed_profile"`
	AutoEligible    bool     `json:"auto_eligible"`
	MaxRequests     int      `json:"max_requests"`
	Reasons         []string `json:"reasons,omitempty"`
}

type templateDocument struct {
	ID   string `yaml:"id"`
	Info struct {
		Metadata map[string]interface{} `yaml:"metadata"`
	} `yaml:"info"`
	HTTP       []httpRequest `yaml:"http"`
	Requests   []httpRequest `yaml:"requests"`
	DNS        interface{}   `yaml:"dns"`
	Network    interface{}   `yaml:"network"`
	Headless   interface{}   `yaml:"headless"`
	Code       interface{}   `yaml:"code"`
	Javascript interface{}   `yaml:"javascript"`
	File       interface{}   `yaml:"file"`
}

type httpRequest struct {
	Method        string                 `yaml:"method"`
	Path          []string               `yaml:"path"`
	Raw           []string               `yaml:"raw"`
	Body          string                 `yaml:"body"`
	Headers       map[string]string      `yaml:"headers"`
	Payloads      map[string]interface{} `yaml:"payloads"`
	Attack        string                 `yaml:"attack"`
	Fuzzing       []interface{}          `yaml:"fuzzing"`
	Race          bool                   `yaml:"race"`
	Unsafe        bool                   `yaml:"unsafe"`
	Redirects     bool                   `yaml:"redirects"`
	HostRedirects bool                   `yaml:"host-redirects"`
	MaxRedirects  int                    `yaml:"max-redirects"`
	Matchers      []interface{}          `yaml:"matchers"`
}

var forbiddenAutomaticHeaders = map[string]struct{}{
	"authorization":       {},
	"proxy-authorization": {},
	"host":                {},
	"connection":          {},
	"content-length":      {},
	"transfer-encoding":   {},
	"upgrade":             {},
	"forwarded":           {},
	"x-forwarded-for":     {},
	"x-forwarded-host":    {},
	"x-forwarded-proto":   {},
	"x-real-ip":           {},
}

// Inspect validates one independently versioned active-fingerprint YAML file
// and computes whether it may execute automatically during asset discovery.
// Controlled HTTP templates remain maintainable/debuggable but are not auto
// eligible. Non-HTTP protocol templates are rejected for the V1 rule kind.
func Inspect(fileName string, source []byte) (Classification, error) {
	result := Classification{ComputedProfile: AutoProfileControlled, MaxRequests: 1}
	cleanName := filepath.Base(strings.TrimSpace(fileName))
	if cleanName != fileName || strings.ContainsAny(cleanName, `/\`) || hasControl(cleanName) || (filepath.Ext(cleanName) != ".yaml" && filepath.Ext(cleanName) != ".yml") {
		return result, errors.New("active fingerprint requires a flat .yaml or .yml filename")
	}
	if len(source) == 0 {
		return result, errors.New("active fingerprint source is empty")
	}
	if len(source) > MaxTemplateBytes {
		return result, fmt.Errorf("active fingerprint source exceeds %d bytes", MaxTemplateBytes)
	}

	var doc templateDocument
	if err := yaml.Unmarshal(source, &doc); err != nil {
		return result, fmt.Errorf("parse active fingerprint YAML: %w", err)
	}
	var topLevel map[string]yaml.Node
	if err := yaml.Unmarshal(source, &topLevel); err != nil {
		return result, fmt.Errorf("parse active fingerprint YAML keys: %w", err)
	}
	for _, protocol := range []string{"dns", "network", "tcp", "ssl", "websocket", "whois", "headless", "code", "javascript", "file"} {
		if _, present := topLevel[protocol]; present {
			return result, errors.New("active fingerprint V1 supports HTTP/HTTPS Nuclei templates only")
		}
	}
	result.ID = strings.TrimSpace(doc.ID)
	if !templateIDPattern.MatchString(result.ID) {
		return result, errors.New("active fingerprint id must use 1-128 ASCII letters, numbers, dot, underscore, or dash")
	}
	result.Product = metadataString(doc.Info.Metadata, "argus-product", "argus_product")
	if result.Product == "" || !utf8.ValidString(result.Product) || utf8.RuneCountInString(result.Product) > 128 || hasControl(result.Product) {
		return result, errors.New("active fingerprint info.metadata.argus-product must be a printable 1-128 character value")
	}
	if kind := metadataString(doc.Info.Metadata, "argus-rule-kind", "argus_rule_kind"); kind != RuleKind {
		return result, fmt.Errorf("active fingerprint info.metadata.argus-rule-kind must be %q", RuleKind)
	}
	result.DeclaredProfile = strings.ToLower(metadataString(doc.Info.Metadata, "argus-auto-profile", "argus_auto_profile"))
	if rawMax := metadataString(doc.Info.Metadata, "max-request", "max_request"); rawMax != "" {
		parsed, parseErr := strconv.Atoi(rawMax)
		if parseErr != nil || parsed <= 0 {
			return result, errors.New("active fingerprint info.metadata.max-request must be a positive integer")
		}
		result.MaxRequests = parsed
	}
	requests := append(append([]httpRequest(nil), doc.HTTP...), doc.Requests...)
	if len(requests) == 0 {
		return result, errors.New("active fingerprint requires an http request")
	}
	result.Reasons = automaticSafetyReasons(requests, source, result.MaxRequests, topLevel)
	result.AutoEligible = len(result.Reasons) == 0
	if result.AutoEligible {
		result.ComputedProfile = AutoProfileSafe
	}
	return result, nil
}

func automaticSafetyReasons(requests []httpRequest, source []byte, maxRequests int, topLevel map[string]yaml.Node) []string {
	reasons := make(map[string]struct{})
	add := func(reason string) { reasons[reason] = struct{}{} }
	if len(requests) != 1 || maxRequests != 1 {
		add("automatic execution requires exactly one request")
	}
	lowerSource := strings.ToLower(string(source))
	if strings.Contains(lowerSource, "interactsh") {
		add("OAST/interactsh is not allowed for automatic execution")
	}
	for _, reason := range automaticSurfaceReasons(topLevel) {
		add(reason)
	}
	for _, request := range requests {
		method := strings.ToUpper(strings.TrimSpace(request.Method))
		if method != http.MethodGet && method != http.MethodHead {
			add("automatic execution allows GET or HEAD only")
		}
		if len(request.Raw) > 0 || strings.TrimSpace(request.Body) != "" {
			add("raw requests and request bodies are not allowed for automatic execution")
		}
		if len(request.Payloads) > 0 || strings.TrimSpace(request.Attack) != "" || len(request.Fuzzing) > 0 || request.Race || request.Unsafe {
			add("payload, fuzzing, race, and unsafe features are not allowed for automatic execution")
		}
		if len(request.Path) != 1 || !safeBaseURLPath(request.Path) {
			add("automatic execution requires one same-origin BaseURL path")
		}
		if request.Redirects || request.MaxRedirects < 0 || request.MaxRedirects > MaxSameOriginRedirects {
			add("automatic execution permits at most two same-origin host redirects")
		}
		if len(request.Matchers) == 0 {
			add("automatic execution requires a matcher")
		}
		for name, value := range request.Headers {
			normalized := strings.ToLower(strings.TrimSpace(name))
			if _, forbidden := forbiddenAutomaticHeaders[normalized]; forbidden || strings.Contains(normalized, "\r") || strings.Contains(normalized, "\n") || strings.Contains(value, "\r") || strings.Contains(value, "\n") {
				add("automatic execution contains a forbidden or malformed header")
			}
		}
	}
	out := make([]string, 0, len(reasons))
	for reason := range reasons {
		out = append(out, reason)
	}
	sort.Strings(out)
	return out
}

func automaticSurfaceReasons(topLevel map[string]yaml.Node) []string {
	allowedTopLevel := map[string]struct{}{"id": {}, "info": {}, "http": {}, "requests": {}}
	allowedRequestFields := map[string]struct{}{
		"method": {}, "path": {}, "headers": {}, "matchers": {}, "matchers-condition": {},
		"redirects": {}, "host-redirects": {}, "max-redirects": {}, "name": {},
	}
	reasons := make(map[string]struct{})
	for key := range topLevel {
		if _, allowed := allowedTopLevel[strings.ToLower(strings.TrimSpace(key))]; !allowed {
			reasons["automatic execution does not allow additional top-level Nuclei capabilities"] = struct{}{}
		}
	}
	for _, section := range []string{"http", "requests"} {
		node, exists := topLevel[section]
		if !exists {
			continue
		}
		if node.Kind == yaml.AliasNode && node.Alias != nil {
			node = *node.Alias
		}
		if node.Kind != yaml.SequenceNode {
			continue
		}
		for _, request := range node.Content {
			if request.Kind == yaml.AliasNode && request.Alias != nil {
				request = request.Alias
			}
			if request.Kind != yaml.MappingNode {
				continue
			}
			for i := 0; i+1 < len(request.Content); i += 2 {
				key := strings.ToLower(strings.TrimSpace(request.Content[i].Value))
				if _, allowed := allowedRequestFields[key]; !allowed {
					reasons["automatic execution does not allow additional HTTP request capabilities"] = struct{}{}
				}
			}
		}
	}
	out := make([]string, 0, len(reasons))
	for reason := range reasons {
		out = append(out, reason)
	}
	sort.Strings(out)
	return out
}

func safeBaseURLPath(paths []string) bool {
	if len(paths) != 1 {
		return false
	}
	value := strings.TrimSpace(paths[0])
	if !strings.HasPrefix(value, "{{BaseURL}}") {
		return false
	}
	remainder := strings.TrimPrefix(value, "{{BaseURL}}")
	return remainder == "" || strings.HasPrefix(remainder, "/") || strings.HasPrefix(remainder, "?")
}

func metadataString(metadata map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := metadata[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case string:
			return strings.TrimSpace(typed)
		case int:
			return strconv.Itoa(typed)
		case int64:
			return strconv.FormatInt(typed, 10)
		case uint64:
			return strconv.FormatUint(typed, 10)
		default:
			return strings.TrimSpace(fmt.Sprint(typed))
		}
	}
	return ""
}

func hasControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}
