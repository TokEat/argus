// Package assetdiscovery contains control-plane asset discovery providers.
// Provider credentials stay in the Server process; this package does not
// persist them or expose an HTTP handler.
package assetdiscovery

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	fofaProvider           = "fofa"
	fofaSearchEndpoint     = "https://fofa.info/api/v1/search/all"
	fofaResponseLimit      = int64(8 << 20)
	fofaQueryTimeout       = 30 * time.Second
	DefaultFOFAResultLimit = 100
	MaxFOFAResultLimit     = 10000
	MaxFOFAQueryBytes      = 4096
	fofaMaxCredentialBytes = 4096
	fofaFields             = "host,protocol,title,icp,ip,port,domain"
	fofaMaxPages           = 100000
)

var protocolPattern = regexp.MustCompile(`^[a-z][a-z0-9+.-]{0,31}$`)

var (
	// ErrInvalidFOFARequest identifies caller-controlled validation failures.
	ErrInvalidFOFARequest = errors.New("invalid fofa request")
	// ErrFOFAUnavailable identifies transport failures and upstream 5xx errors.
	ErrFOFAUnavailable = errors.New("fofa is unavailable")
	// ErrFOFARejected identifies an authenticated provider rejection or quota response.
	ErrFOFARejected = errors.New("fofa rejected the query")
	// ErrInvalidFOFAResponse identifies malformed or over-budget provider output.
	ErrInvalidFOFAResponse = errors.New("invalid fofa response")
)

// FOFACredential is supplied by a tenant-authorized Server caller. It must not
// be serialized into a scan task, log entry, audit detail, or discovery result.
type FOFACredential struct {
	Email string
	Key   string
}

// FOFAQuery is one bounded provider query. A zero Limit uses the safe default;
// a zero Page fetches the first page only.
type FOFAQuery struct {
	Expression string
	Limit      int
	Page       int
}

// Asset is a normalized discovery candidate. Authorization and project-scope
// filtering happen in a later control-plane layer before targets are persisted
// or dispatched to an Agent.
type Asset struct {
	Target     string `json:"target"`
	IP         string `json:"ip,omitempty"`
	Port       int    `json:"port"`
	Domain     string `json:"domain,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Title      string `json:"title,omitempty"`
	ICP        string `json:"icp,omitempty"`
	Country    string `json:"country,omitempty"`
	City       string `json:"city,omitempty"`
	Company    string `json:"company,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	Source     string `json:"source"`
}

// Result contains only normalized provider output and bounded accounting. Raw
// responses and credentials are deliberately excluded. Page and PageSize
// report the provider page actually fetched, so callers never need to guess
// provider-specific page-size limits.
type Result struct {
	Provider      string  `json:"provider"`
	ProviderTotal int     `json:"provider_total"`
	SkippedRows   int     `json:"skipped_rows"`
	Truncated     bool    `json:"truncated"`
	Page          int     `json:"page,omitempty"`
	PageSize      int     `json:"page_size,omitempty"`
	Assets        []Asset `json:"assets"`
}

// FOFAClient is the Server-side FOFA provider client.
type FOFAClient struct {
	httpClient    *http.Client
	endpoint      string
	responseLimit int64
	queryTimeout  time.Duration
}

// NewFOFAClient builds a client that rejects redirects so credentials carried
// in FOFA query parameters cannot be forwarded to another origin.
func NewFOFAClient(client *http.Client) *FOFAClient {
	if client == nil {
		client = &http.Client{}
	}
	clone := *client
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if clone.Timeout <= 0 || clone.Timeout > fofaQueryTimeout {
		clone.Timeout = fofaQueryTimeout
	}
	return &FOFAClient{
		httpClient:    &clone,
		endpoint:      fofaSearchEndpoint,
		responseLimit: fofaResponseLimit,
		queryTimeout:  fofaQueryTimeout,
	}
}

type fofaResponse struct {
	Error   bool       `json:"error"`
	Size    int        `json:"size"`
	Results [][]string `json:"results"`
}

// Search queries FOFA without persisting or logging credentials. Transport and
// provider errors are intentionally sanitized because net/http errors may echo
// the full URL, including FOFA's email/key query parameters.
func (c *FOFAClient) Search(ctx context.Context, credential FOFACredential, query FOFAQuery) (Result, error) {
	result := Result{Provider: fofaProvider, Assets: []Asset{}}
	if c == nil || c.httpClient == nil {
		return result, fmt.Errorf("%w: client is not initialized", ErrInvalidFOFARequest)
	}
	if ctx == nil {
		return result, fmt.Errorf("%w: context is required", ErrInvalidFOFARequest)
	}
	email, key, expression, limit, page, err := validateFOFAInput(credential, query)
	if err != nil {
		return result, err
	}

	requestContext, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestContext, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return result, fmt.Errorf("%w: build request", ErrInvalidFOFARequest)
	}
	params := req.URL.Query()
	params.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(expression)))
	params.Set("email", email)
	params.Set("key", key)
	params.Set("page", strconv.Itoa(page))
	params.Set("size", strconv.Itoa(limit))
	params.Set("fields", fofaFields)
	params.Set("full", "false")
	req.URL.RawQuery = params.Encode()
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Argus-Server/asset-discovery")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if requestContext.Err() != nil {
			return result, fmt.Errorf("fofa request stopped: %w", requestContext.Err())
		}
		return result, ErrFOFAUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if resp.StatusCode >= http.StatusInternalServerError {
			return result, fmt.Errorf("%w: HTTP status %d", ErrFOFAUnavailable, resp.StatusCode)
		}
		return result, fmt.Errorf("%w: HTTP status %d", ErrFOFARejected, resp.StatusCode)
	}

	body, err := readBoundedResponse(resp.Body, c.responseLimit, ErrInvalidFOFAResponse)
	if err != nil {
		return result, err
	}
	var providerResponse fofaResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&providerResponse); err != nil {
		return result, fmt.Errorf("%w: decode JSON", ErrInvalidFOFAResponse)
	}
	if err := ensureJSONEOF(decoder, ErrInvalidFOFAResponse); err != nil {
		return result, err
	}
	if providerResponse.Error {
		return result, ErrFOFARejected
	}
	if providerResponse.Size < 0 {
		return result, fmt.Errorf("%w: negative result size", ErrInvalidFOFAResponse)
	}

	result.Page = page
	result.PageSize = limit
	result.ProviderTotal = providerResponse.Size
	rows := providerResponse.Results
	if len(rows) > limit {
		rows = rows[:limit]
	}
	result.Truncated = providerResponse.Size > (page-1)*limit+len(rows)
	assetsByTarget := make(map[string]Asset, len(rows))
	for _, row := range rows {
		asset, ok := normalizeFOFARow(row)
		if !ok {
			result.SkippedRows++
			continue
		}
		if existing, duplicate := assetsByTarget[asset.Target]; duplicate {
			assetsByTarget[asset.Target] = mergeAsset(existing, asset)
			continue
		}
		assetsByTarget[asset.Target] = asset
	}
	result.Assets = make([]Asset, 0, len(assetsByTarget))
	for _, asset := range assetsByTarget {
		result.Assets = append(result.Assets, asset)
	}
	sort.Slice(result.Assets, func(i, j int) bool {
		return result.Assets[i].Target < result.Assets[j].Target
	})
	return result, nil
}

func validateFOFAInput(credential FOFACredential, query FOFAQuery) (string, string, string, int, int, error) {
	email := strings.TrimSpace(credential.Email)
	key := strings.TrimSpace(credential.Key)
	expression := strings.TrimSpace(query.Expression)
	if email == "" || key == "" {
		return "", "", "", 0, 0, fmt.Errorf("%w: credential is incomplete", ErrInvalidFOFARequest)
	}
	if len(email) > fofaMaxCredentialBytes || len(key) > fofaMaxCredentialBytes ||
		!utf8.ValidString(email) || !utf8.ValidString(key) || !strings.Contains(email, "@") || hasControl(email) || hasControl(key) {
		return "", "", "", 0, 0, fmt.Errorf("%w: credential is malformed", ErrInvalidFOFARequest)
	}
	if expression == "" {
		return "", "", "", 0, 0, fmt.Errorf("%w: query is empty", ErrInvalidFOFARequest)
	}
	if len(expression) > MaxFOFAQueryBytes || !utf8.ValidString(expression) || strings.ContainsAny(expression, "\r\n\x00") {
		return "", "", "", 0, 0, fmt.Errorf("%w: query is malformed", ErrInvalidFOFARequest)
	}
	limit := query.Limit
	if limit == 0 {
		limit = DefaultFOFAResultLimit
	}
	if limit < 1 || limit > MaxFOFAResultLimit {
		return "", "", "", 0, 0, fmt.Errorf("%w: result limit must be between 1 and %d", ErrInvalidFOFARequest, MaxFOFAResultLimit)
	}
	page := query.Page
	if page == 0 {
		page = 1
	}
	if page < 1 || page > fofaMaxPages {
		return "", "", "", 0, 0, fmt.Errorf("%w: page must be between 1 and %d", ErrInvalidFOFARequest, fofaMaxPages)
	}
	return email, key, expression, limit, page, nil
}

func readBoundedResponse(reader io.Reader, limit int64, invalidResponseError error) ([]byte, error) {
	if invalidResponseError == nil {
		invalidResponseError = ErrInvalidFOFAResponse
	}
	if limit <= 0 {
		return nil, fmt.Errorf("%w: response budget is invalid", invalidResponseError)
	}
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read body", invalidResponseError)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: response exceeds the allowed size", invalidResponseError)
	}
	return body, nil
}

func ensureJSONEOF(decoder *json.Decoder, invalidResponseError error) error {
	if invalidResponseError == nil {
		invalidResponseError = ErrInvalidFOFAResponse
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON data", invalidResponseError)
	}
	return nil
}

func normalizeFOFARow(row []string) (Asset, bool) {
	if len(row) < 7 {
		return Asset{}, false
	}
	host := strings.TrimSpace(row[0])
	protocol := strings.ToLower(strings.TrimSpace(row[1]))
	title := cleanMetadata(row[2])
	icp := cleanMetadata(row[3])
	ip := normalizeIP(row[4])
	port, err := strconv.Atoi(strings.TrimSpace(row[5]))
	if err != nil || port < 1 || port > 65535 || !protocolPattern.MatchString(protocol) {
		return Asset{}, false
	}
	domain := normalizeDomain(row[6])
	target := normalizeProviderTarget(host, protocol, ip, port, domain)
	if target == "" {
		return Asset{}, false
	}
	return Asset{
		Target: target, IP: ip, Port: port, Domain: domain,
		Protocol: protocol, Title: title, ICP: icp, Source: fofaProvider,
	}, true
}

func normalizeProviderTarget(rawHost, protocol, ip string, port int, domain string) string {
	if protocol == "http" || protocol == "https" {
		host := normalizeHostFromProvider(rawHost)
		if normalizeIP(host) != "" && domain != "" {
			host = domain
		}
		if host == "" {
			host = domain
		}
		if host == "" {
			host = ip
		}
		if host == "" {
			return ""
		}
		return protocol + "://" + net.JoinHostPort(host, strconv.Itoa(port))
	}
	if ip != "" {
		return net.JoinHostPort(ip, strconv.Itoa(port))
	}
	host := normalizeHostFromProvider(rawHost)
	if host == "" {
		host = domain
	}
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func normalizeHostFromProvider(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\r\n\x00") {
		return ""
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.User != nil {
			return ""
		}
		return normalizeHost(parsed.Hostname())
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return normalizeHost(host)
	}
	return normalizeHost(raw)
}

func normalizeHost(raw string) string {
	if ip := normalizeIP(raw); ip != "" {
		return ip
	}
	return normalizeDomain(raw)
}

func normalizeIP(raw string) string {
	parsed := net.ParseIP(strings.Trim(strings.TrimSpace(raw), "[]"))
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

func normalizeDomain(raw string) string {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if domain == "" || len(domain) > 253 || strings.ContainsAny(domain, "\r\n\x00/@") {
		return ""
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return ""
			}
		}
	}
	return domain
}

func cleanMetadata(raw string) string {
	value := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(raw, "\r", " "), "\n", " "))
	if len(value) > 1024 {
		value = value[:1024]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value
}

func mergeAsset(existing, candidate Asset) Asset {
	existing.IP = stableNonEmpty(existing.IP, candidate.IP)
	existing.Domain = stableNonEmpty(existing.Domain, candidate.Domain)
	existing.Protocol = stableNonEmpty(existing.Protocol, candidate.Protocol)
	existing.Title = stableNonEmpty(existing.Title, candidate.Title)
	existing.ICP = stableNonEmpty(existing.ICP, candidate.ICP)
	existing.Country = stableNonEmpty(existing.Country, candidate.Country)
	existing.City = stableNonEmpty(existing.City, candidate.City)
	existing.Company = stableNonEmpty(existing.Company, candidate.Company)
	if existing.StatusCode == 0 || (candidate.StatusCode != 0 && candidate.StatusCode < existing.StatusCode) {
		existing.StatusCode = candidate.StatusCode
	}
	return existing
}

func stableNonEmpty(left, right string) string {
	if left == "" {
		return right
	}
	if right != "" && right < left {
		return right
	}
	return left
}

func hasControl(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}
	return false
}
