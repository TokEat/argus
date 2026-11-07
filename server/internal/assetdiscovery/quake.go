package assetdiscovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	quakeProvider            = "quake"
	quakeSearchEndpoint      = "https://quake.360.net/api/v3/search/quake_service"
	quakeResponseLimit       = int64(8 << 20)
	quakeQueryTimeout        = 30 * time.Second
	DefaultQuakeResultLimit  = 100
	MaxQuakeResultLimit      = 500
	MaxQuakeQueryBytes       = 4096
	quakeMaxCredentialBytes  = 4096
	quakeMaxURLsPerRow       = 32
	quakeMaxNormalizedAssets = 2000
	quakeMaxPages            = 100000
)

var (
	// ErrInvalidQuakeRequest identifies caller-controlled validation failures.
	ErrInvalidQuakeRequest = errors.New("invalid quake request")
	// ErrQuakeUnavailable identifies transport failures and upstream 5xx errors.
	ErrQuakeUnavailable = errors.New("quake is unavailable")
	// ErrQuakeRejected identifies an authenticated provider rejection or quota response.
	ErrQuakeRejected = errors.New("quake rejected the query")
	// ErrInvalidQuakeResponse identifies malformed or over-budget provider output.
	ErrInvalidQuakeResponse = errors.New("invalid quake response")
)

// QuakeCredential is supplied by a tenant-authorized Server caller. The token
// must not be serialized into a task, log entry, audit detail, or result.
type QuakeCredential struct {
	Token string
}

// QuakeQuery is one bounded provider query. A zero Limit uses the safe default;
// a zero Page fetches the first page only.
type QuakeQuery struct {
	Expression string
	Limit      int
	Page       int
}

// QuakeClient is the Server-side Quake provider client.
type QuakeClient struct {
	httpClient    *http.Client
	endpoint      string
	responseLimit int64
	queryTimeout  time.Duration
}

// NewQuakeClient builds a client that rejects redirects so X-QuakeToken is
// never forwarded to a different request target.
func NewQuakeClient(client *http.Client) *QuakeClient {
	if client == nil {
		client = &http.Client{}
	}
	clone := *client
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if clone.Timeout <= 0 || clone.Timeout > quakeQueryTimeout {
		clone.Timeout = quakeQueryTimeout
	}
	return &QuakeClient{
		httpClient:    &clone,
		endpoint:      quakeSearchEndpoint,
		responseLimit: quakeResponseLimit,
		queryTimeout:  quakeQueryTimeout,
	}
}

type quakeRequest struct {
	Query       string   `json:"query"`
	Start       int      `json:"start"`
	Size        int      `json:"size"`
	Latest      bool     `json:"latest"`
	IgnoreCache bool     `json:"ignore_cache"`
	Include     []string `json:"include"`
}

type quakeResponse struct {
	Code json.RawMessage     `json:"code"`
	Data []quakeResponseItem `json:"data"`
	Meta struct {
		Pagination struct {
			Total int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
}

type quakeResponseItem struct {
	Service struct {
		Name string `json:"name"`
		HTTP struct {
			Host  string   `json:"host"`
			Title string   `json:"title"`
			URLs  []string `json:"http_load_url"`
		} `json:"http"`
	} `json:"service"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// Search queries Quake once without the legacy account/VIP preflight. A
// minimal explicit include list allows restricted accounts to fall back to
// IP:port assets while preventing the response schema from expanding silently.
func (c *QuakeClient) Search(ctx context.Context, credential QuakeCredential, query QuakeQuery) (Result, error) {
	result := Result{Provider: quakeProvider, Assets: []Asset{}}
	if c == nil || c.httpClient == nil {
		return result, fmt.Errorf("%w: client is not initialized", ErrInvalidQuakeRequest)
	}
	if ctx == nil {
		return result, fmt.Errorf("%w: context is required", ErrInvalidQuakeRequest)
	}
	token, expression, limit, page, err := validateQuakeInput(credential, query)
	if err != nil {
		return result, err
	}

	payload, err := json.Marshal(quakeRequest{
		Query: expression, Start: (page - 1) * limit, Size: limit, Latest: false, IgnoreCache: true,
		// http_load_url is optional response data, not a supported include selector.
		// Host and service name preserve endpoint normalization when it is absent.
		Include: []string{"ip", "port", "service.name", "service.http.host", "service.http.title"},
	})
	if err != nil {
		return result, fmt.Errorf("%w: encode request", ErrInvalidQuakeRequest)
	}
	requestContext, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return result, fmt.Errorf("%w: build request", ErrInvalidQuakeRequest)
	}
	request.Header.Set("X-QuakeToken", token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "Argus-Server/asset-discovery")

	response, err := c.httpClient.Do(request)
	if err != nil {
		if requestContext.Err() != nil {
			return result, fmt.Errorf("quake request stopped: %w", requestContext.Err())
		}
		return result, ErrQuakeUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = readBoundedResponse(response.Body, minInt64(c.responseLimit, 4096), ErrInvalidQuakeResponse)
		if response.StatusCode >= http.StatusInternalServerError {
			return result, fmt.Errorf("%w: HTTP status %d", ErrQuakeUnavailable, response.StatusCode)
		}
		return result, fmt.Errorf("%w: HTTP status %d", ErrQuakeRejected, response.StatusCode)
	}

	body, err := readBoundedResponse(response.Body, c.responseLimit, ErrInvalidQuakeResponse)
	if err != nil {
		return result, err
	}
	var providerResponse quakeResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&providerResponse); err != nil {
		return result, fmt.Errorf("%w: decode JSON", ErrInvalidQuakeResponse)
	}
	if err := ensureJSONEOF(decoder, ErrInvalidQuakeResponse); err != nil {
		return result, err
	}
	success, validCode := quakeResponseCodeSucceeded(providerResponse.Code)
	if !validCode {
		return result, fmt.Errorf("%w: invalid provider code", ErrInvalidQuakeResponse)
	}
	if !success {
		return result, ErrQuakeRejected
	}
	if providerResponse.Meta.Pagination.Total < 0 {
		return result, fmt.Errorf("%w: negative result total", ErrInvalidQuakeResponse)
	}

	rows := providerResponse.Data
	result.Page = page
	result.PageSize = limit
	result.ProviderTotal = providerResponse.Meta.Pagination.Total
	if result.ProviderTotal > 0 && len(rows) == 0 {
		return result, fmt.Errorf("%w: empty result set before advertised total", ErrInvalidQuakeResponse)
	}
	if result.ProviderTotal < len(rows) {
		result.ProviderTotal = len(rows)
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	offset := (page - 1) * limit
	if result.ProviderTotal > offset+len(rows) {
		result.Truncated = true
	}

	maxAssets := limit * 4
	if maxAssets > quakeMaxNormalizedAssets {
		maxAssets = quakeMaxNormalizedAssets
	}
	assetsByTarget := make(map[string]Asset, len(rows))
	for _, row := range rows {
		assets, rowTruncated := normalizeQuakeRow(row)
		if rowTruncated {
			result.Truncated = true
		}
		if len(assets) == 0 {
			result.SkippedRows++
			continue
		}
		for _, asset := range assets {
			if existing, duplicate := assetsByTarget[asset.Target]; duplicate {
				assetsByTarget[asset.Target] = mergeAsset(existing, asset)
				continue
			}
			if len(assetsByTarget) >= maxAssets {
				result.Truncated = true
				break
			}
			assetsByTarget[asset.Target] = asset
		}
		if len(assetsByTarget) >= maxAssets {
			break
		}
	}
	return finalizeQuakeResult(result, assetsByTarget), nil
}

func validateQuakeInput(credential QuakeCredential, query QuakeQuery) (string, string, int, int, error) {
	token := strings.TrimSpace(credential.Token)
	expression := strings.TrimSpace(query.Expression)
	if token == "" || len(token) > quakeMaxCredentialBytes || !utf8.ValidString(token) || hasControl(token) {
		return "", "", 0, 0, fmt.Errorf("%w: credential is malformed", ErrInvalidQuakeRequest)
	}
	if expression == "" {
		return "", "", 0, 0, fmt.Errorf("%w: query is empty", ErrInvalidQuakeRequest)
	}
	if len(expression) > MaxQuakeQueryBytes || !utf8.ValidString(expression) || strings.ContainsAny(expression, "\r\n\x00") {
		return "", "", 0, 0, fmt.Errorf("%w: query is malformed", ErrInvalidQuakeRequest)
	}
	limit := query.Limit
	if limit == 0 {
		limit = DefaultQuakeResultLimit
	}
	if limit < 1 || limit > MaxQuakeResultLimit {
		return "", "", 0, 0, fmt.Errorf("%w: result limit must be between 1 and %d", ErrInvalidQuakeRequest, MaxQuakeResultLimit)
	}
	page := query.Page
	if page == 0 {
		page = 1
	}
	// Cap the offset so page * limit stays a small positive integer even when
	// both fields come from the caller.
	if page < 1 || page > quakeMaxPages {
		return "", "", 0, 0, fmt.Errorf("%w: page must be between 1 and %d", ErrInvalidQuakeRequest, quakeMaxPages)
	}
	return token, expression, limit, page, nil
}

func quakeResponseCodeSucceeded(raw json.RawMessage) (bool, bool) {
	value := strings.TrimSpace(string(raw))
	if value == "" || value == "null" {
		return false, false
	}
	var numeric int
	if err := json.Unmarshal(raw, &numeric); err == nil {
		return numeric == 0, true
	}
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		parsed, err := strconv.Atoi(strings.TrimSpace(text))
		if err == nil {
			return parsed == 0, true
		}
	}
	return false, false
}

func normalizeQuakeRow(row quakeResponseItem) ([]Asset, bool) {
	if row.Port < 1 || row.Port > 65535 {
		return nil, false
	}
	ip := normalizeIP(row.IP)
	host := normalizeHostFromProvider(row.Service.HTTP.Host)
	domain := ""
	if normalizeIP(host) == "" {
		domain = normalizeDomain(host)
	}
	baseProtocol := normalizeQuakeProtocol(row.Service.Name)
	title := cleanQuakeMetadata(row.Service.HTTP.Title)
	assetsByTarget := make(map[string]Asset)
	urls := row.Service.HTTP.URLs
	truncated := len(urls) > quakeMaxURLsPerRow
	if truncated {
		urls = urls[:quakeMaxURLsPerRow]
	}
	for _, rawURL := range urls {
		protocol := baseProtocol
		assetDomain := domain
		if parsed, err := url.Parse(strings.TrimSpace(rawURL)); err == nil && (strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https")) {
			protocol = strings.ToLower(parsed.Scheme)
		}
		if rawHost := normalizeHostFromProvider(rawURL); normalizeIP(rawHost) == "" {
			if normalized := normalizeDomain(rawHost); normalized != "" {
				assetDomain = normalized
			}
		}
		if protocol != "http" && protocol != "https" {
			continue
		}
		target := normalizeProviderTarget(rawURL, protocol, ip, row.Port, assetDomain)
		if target == "" {
			continue
		}
		assetsByTarget[target] = Asset{
			Target: target, IP: ip, Port: row.Port, Domain: assetDomain,
			Protocol: protocol, Title: title, Source: quakeProvider,
		}
	}
	if len(assetsByTarget) == 0 {
		protocol := baseProtocol
		if protocol != "" && !protocolPattern.MatchString(protocol) {
			protocol = ""
		}
		target := normalizeProviderTarget("", protocol, ip, row.Port, domain)
		if target != "" {
			assetsByTarget[target] = Asset{
				Target: target, IP: ip, Port: row.Port, Domain: domain,
				Protocol: protocol, Title: title, Source: quakeProvider,
			}
		}
	}
	assets := make([]Asset, 0, len(assetsByTarget))
	for _, asset := range assetsByTarget {
		assets = append(assets, asset)
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].Target < assets[j].Target })
	return assets, truncated
}

func normalizeQuakeProtocol(raw string) string {
	protocol := strings.ToLower(strings.TrimSpace(raw))
	if protocol == "http/ssl" {
		return "https"
	}
	if protocolPattern.MatchString(protocol) {
		return protocol
	}
	return ""
}

func cleanQuakeMetadata(raw string) string {
	if strings.Contains(raw, "暂无权限") {
		return ""
	}
	return cleanMetadata(raw)
}

func finalizeQuakeResult(result Result, assetsByTarget map[string]Asset) Result {
	result.Assets = make([]Asset, 0, len(assetsByTarget))
	for _, asset := range assetsByTarget {
		result.Assets = append(result.Assets, asset)
	}
	sort.Slice(result.Assets, func(i, j int) bool {
		return result.Assets[i].Target < result.Assets[j].Target
	})
	return result
}
