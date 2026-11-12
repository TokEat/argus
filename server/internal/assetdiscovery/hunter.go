package assetdiscovery

import (
	"bytes"
	"context"
	"encoding/base64"
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
	hunterProvider             = "hunter"
	hunterSearchEndpoint       = "https://hunter.qianxin.com/openApi/search"
	hunterResponseLimit        = int64(8 << 20)
	hunterQueryTimeout         = 30 * time.Second
	DefaultHunterResultLimit   = 100
	MaxHunterResultLimit       = 1000
	DefaultHunterPageSize      = 100
	MaxHunterPageSize          = 100
	MaxHunterQueryBytes        = 4096
	hunterMaxPages             = 10
	hunterMaxCredentialBytes   = 4096
	hunterSearchWebAndServices = "3"
)

var (
	// ErrInvalidHunterRequest identifies caller-controlled validation failures.
	ErrInvalidHunterRequest = errors.New("invalid hunter request")
	// ErrHunterUnavailable identifies transport failures and upstream 5xx errors.
	ErrHunterUnavailable = errors.New("hunter is unavailable")
	// ErrHunterRejected identifies an authenticated provider rejection or quota response.
	ErrHunterRejected = errors.New("hunter rejected the query")
	// ErrInvalidHunterResponse identifies malformed or over-budget provider output.
	ErrInvalidHunterResponse = errors.New("invalid hunter response")
)

// HunterCredential is supplied by a tenant-authorized Server caller. It must
// not be serialized into a scan task, log entry, audit detail, or result.
type HunterCredential struct {
	APIKey string
}

// HunterQuery is one bounded provider query. Zero values use safe defaults.
// PageSize is an internal provider tuning value; public APIs should generally
// expose only Limit and let the Server select the page size. A zero Page keeps
// the aggregate behavior (fetch from the first page up to Limit); Page > 0
// fetches exactly that provider page.
type HunterQuery struct {
	Expression string
	Limit      int
	PageSize   int
	Page       int
}

// HunterClient is the Server-side Hunter provider client.
type HunterClient struct {
	httpClient    *http.Client
	endpoint      string
	responseLimit int64
	queryTimeout  time.Duration
}

// NewHunterClient builds a client that rejects redirects so the API key in the
// query string cannot be forwarded to a different origin.
func NewHunterClient(client *http.Client) *HunterClient {
	if client == nil {
		client = &http.Client{}
	}
	clone := *client
	clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if clone.Timeout <= 0 || clone.Timeout > hunterQueryTimeout {
		clone.Timeout = hunterQueryTimeout
	}
	return &HunterClient{
		httpClient:    &clone,
		endpoint:      hunterSearchEndpoint,
		responseLimit: hunterResponseLimit,
		queryTimeout:  hunterQueryTimeout,
	}
}

type hunterResponse struct {
	Code int                `json:"code"`
	Data hunterResponseData `json:"data"`
}

type hunterResponseData struct {
	Items []hunterResponseItem `json:"arr"`
	Total int                  `json:"total"`
}

type hunterResponseItem struct {
	URL        string `json:"url"`
	IP         string `json:"ip"`
	Port       int    `json:"port"`
	Domain     string `json:"domain"`
	Protocol   string `json:"protocol"`
	City       string `json:"city"`
	Company    string `json:"company"`
	StatusCode int    `json:"status_code"`
	Title      string `json:"web_title"`
	Country    string `json:"country"`
}

// Search queries Hunter without logging or persisting the API key, raw query,
// raw response, or banner. One timeout and one byte budget cover all pages.
func (c *HunterClient) Search(ctx context.Context, credential HunterCredential, query HunterQuery) (Result, error) {
	result := Result{Provider: hunterProvider, Assets: []Asset{}}
	if c == nil || c.httpClient == nil {
		return result, fmt.Errorf("%w: client is not initialized", ErrInvalidHunterRequest)
	}
	if ctx == nil {
		return result, fmt.Errorf("%w: context is required", ErrInvalidHunterRequest)
	}
	apiKey, expression, limit, pageSize, page, err := validateHunterInput(credential, query)
	if err != nil {
		return result, err
	}

	requestContext, cancel := context.WithTimeout(ctx, c.queryTimeout)
	defer cancel()
	if page > 0 {
		return c.searchOnePage(requestContext, apiKey, expression, page, pageSize)
	}

	remainingResponseBytes := c.responseLimit
	processedRows := 0
	assetsByTarget := make(map[string]Asset, limit)
	maxPages := (limit + pageSize - 1) / pageSize

	for curPage := 1; curPage <= maxPages && processedRows < limit; curPage++ {
		if remainingResponseBytes <= 0 {
			return result, fmt.Errorf("%w: total response budget exhausted", ErrInvalidHunterResponse)
		}
		providerResponse, responseBytes, requestErr := c.searchPage(requestContext, apiKey, expression, curPage, pageSize, remainingResponseBytes)
		if requestErr != nil {
			return result, requestErr
		}
		remainingResponseBytes -= responseBytes
		if providerResponse.Data.Total < 0 {
			return result, fmt.Errorf("%w: negative result total", ErrInvalidHunterResponse)
		}
		if providerResponse.Data.Total > result.ProviderTotal {
			result.ProviderTotal = providerResponse.Data.Total
		}

		rows := providerResponse.Data.Items
		if result.ProviderTotal == 0 {
			if len(rows) != 0 {
				return result, fmt.Errorf("%w: rows returned with zero total", ErrInvalidHunterResponse)
			}
			return result, nil
		}
		if len(rows) == 0 {
			return result, fmt.Errorf("%w: pagination ended before advertised total", ErrInvalidHunterResponse)
		}
		if processedRows+len(rows) > result.ProviderTotal {
			return result, fmt.Errorf("%w: page rows exceed advertised total", ErrInvalidHunterResponse)
		}

		remainingRows := limit - processedRows
		if len(rows) > remainingRows {
			rows = rows[:remainingRows]
			result.Truncated = true
		}
		for _, row := range rows {
			asset, ok := normalizeHunterRow(row)
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
		processedRows += len(rows)

		if processedRows >= result.ProviderTotal {
			return finalizeHunterResult(result, assetsByTarget), nil
		}
		if processedRows >= limit {
			result.Truncated = true
			return finalizeHunterResult(result, assetsByTarget), nil
		}
		if len(providerResponse.Data.Items) < pageSize {
			return result, fmt.Errorf("%w: short page before advertised total", ErrInvalidHunterResponse)
		}
	}

	if processedRows < result.ProviderTotal {
		result.Truncated = true
	}
	return finalizeHunterResult(result, assetsByTarget), nil
}

// searchOnePage fetches exactly one specified provider page with the validated
// page size, so control-plane callers can browse results page by page like the
// official Hunter web UI. Truncated reports whether the advertised total is
// still beyond this page.
func (c *HunterClient) searchOnePage(ctx context.Context, apiKey, expression string, page, pageSize int) (Result, error) {
	result := Result{Provider: hunterProvider, Assets: []Asset{}, Page: page, PageSize: pageSize}
	providerResponse, _, requestErr := c.searchPage(ctx, apiKey, expression, page, pageSize, c.responseLimit)
	if requestErr != nil {
		return result, requestErr
	}
	if providerResponse.Data.Total < 0 {
		return result, fmt.Errorf("%w: negative result total", ErrInvalidHunterResponse)
	}
	result.ProviderTotal = providerResponse.Data.Total
	rows := providerResponse.Data.Items
	if result.ProviderTotal == 0 {
		if len(rows) != 0 {
			return result, fmt.Errorf("%w: rows returned with zero total", ErrInvalidHunterResponse)
		}
		return result, nil
	}
	if len(rows) == 0 {
		return result, fmt.Errorf("%w: pagination ended before advertised total", ErrInvalidHunterResponse)
	}
	if len(rows) > pageSize {
		rows = rows[:pageSize]
	}
	offset := (page - 1) * pageSize
	if offset+len(rows) > result.ProviderTotal {
		return result, fmt.Errorf("%w: page rows exceed advertised total", ErrInvalidHunterResponse)
	}

	assetsByTarget := make(map[string]Asset, len(rows))
	for _, row := range rows {
		asset, ok := normalizeHunterRow(row)
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
	result.Truncated = result.ProviderTotal > offset+len(rows)
	return finalizeHunterResult(result, assetsByTarget), nil
}

func (c *HunterClient) searchPage(ctx context.Context, apiKey, expression string, page, pageSize int, responseLimit int64) (hunterResponse, int64, error) {
	var providerResponse hunterResponse
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return providerResponse, 0, fmt.Errorf("%w: build request", ErrInvalidHunterRequest)
	}
	params := request.URL.Query()
	params.Set("api-key", apiKey)
	params.Set("search", base64.URLEncoding.EncodeToString([]byte(expression)))
	params.Set("page", strconv.Itoa(page))
	params.Set("page_size", strconv.Itoa(pageSize))
	params.Set("is_web", hunterSearchWebAndServices)
	request.URL.RawQuery = params.Encode()
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "Argus-Server/asset-discovery")

	response, err := c.httpClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return providerResponse, 0, fmt.Errorf("hunter request stopped: %w", ctx.Err())
		}
		return providerResponse, 0, ErrHunterUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = readBoundedResponse(response.Body, minInt64(responseLimit, 4096), ErrInvalidHunterResponse)
		if response.StatusCode >= http.StatusInternalServerError {
			return providerResponse, 0, fmt.Errorf("%w: HTTP status %d", ErrHunterUnavailable, response.StatusCode)
		}
		return providerResponse, 0, fmt.Errorf("%w: HTTP status %d", ErrHunterRejected, response.StatusCode)
	}

	body, err := readBoundedResponse(response.Body, responseLimit, ErrInvalidHunterResponse)
	if err != nil {
		return providerResponse, 0, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&providerResponse); err != nil {
		return providerResponse, int64(len(body)), fmt.Errorf("%w: decode JSON", ErrInvalidHunterResponse)
	}
	if err := ensureJSONEOF(decoder, ErrInvalidHunterResponse); err != nil {
		return providerResponse, int64(len(body)), err
	}
	if providerResponse.Code != http.StatusOK {
		return providerResponse, int64(len(body)), ErrHunterRejected
	}
	return providerResponse, int64(len(body)), nil
}

func validateHunterInput(credential HunterCredential, query HunterQuery) (string, string, int, int, int, error) {
	apiKey := strings.TrimSpace(credential.APIKey)
	expression := strings.TrimSpace(query.Expression)
	if apiKey == "" || len(apiKey) > hunterMaxCredentialBytes || !utf8.ValidString(apiKey) || hasControl(apiKey) {
		return "", "", 0, 0, 0, fmt.Errorf("%w: credential is malformed", ErrInvalidHunterRequest)
	}
	if expression == "" {
		return "", "", 0, 0, 0, fmt.Errorf("%w: query is empty", ErrInvalidHunterRequest)
	}
	if len(expression) > MaxHunterQueryBytes || !utf8.ValidString(expression) || strings.ContainsAny(expression, "\r\n\x00") {
		return "", "", 0, 0, 0, fmt.Errorf("%w: query is malformed", ErrInvalidHunterRequest)
	}

	limit := query.Limit
	if limit == 0 {
		limit = DefaultHunterResultLimit
	}
	if limit < 1 || limit > MaxHunterResultLimit {
		return "", "", 0, 0, 0, fmt.Errorf("%w: result limit must be between 1 and %d", ErrInvalidHunterRequest, MaxHunterResultLimit)
	}
	pageSize := query.PageSize
	if pageSize == 0 {
		pageSize = DefaultHunterPageSize
	}
	if pageSize < 1 || pageSize > MaxHunterPageSize {
		return "", "", 0, 0, 0, fmt.Errorf("%w: page size must be between 1 and %d", ErrInvalidHunterRequest, MaxHunterPageSize)
	}
	if pageSize > limit {
		pageSize = limit
	}
	page := query.Page
	if page < 0 {
		return "", "", 0, 0, 0, fmt.Errorf("%w: page must not be negative", ErrInvalidHunterRequest)
	}
	if page > 0 {
		// A single page fetch obeys the same provider contract as the
		// aggregate mode: at most hunterMaxPages pages of the chosen page size.
		if page > hunterMaxPages {
			return "", "", 0, 0, 0, fmt.Errorf("%w: page must not exceed %d", ErrInvalidHunterRequest, hunterMaxPages)
		}
		return apiKey, expression, limit, pageSize, page, nil
	}
	if (limit+pageSize-1)/pageSize > hunterMaxPages {
		return "", "", 0, 0, 0, fmt.Errorf("%w: query would exceed %d pages", ErrInvalidHunterRequest, hunterMaxPages)
	}
	return apiKey, expression, limit, pageSize, 0, nil
}

func normalizeHunterRow(row hunterResponseItem) (Asset, bool) {
	ip := normalizeIP(row.IP)
	domain := normalizeDomain(row.Domain)
	protocol := strings.ToLower(strings.TrimSpace(row.Protocol))
	if protocol == "" {
		if parsed, err := url.Parse(strings.TrimSpace(row.URL)); err == nil {
			protocol = strings.ToLower(parsed.Scheme)
		}
	}
	if row.Port < 1 || row.Port > 65535 || !protocolPattern.MatchString(protocol) {
		return Asset{}, false
	}
	if domain == "" {
		host := normalizeHostFromProvider(row.URL)
		if normalizeIP(host) == "" {
			domain = normalizeDomain(host)
		}
	}
	target := normalizeProviderTarget(row.URL, protocol, ip, row.Port, domain)
	if target == "" {
		return Asset{}, false
	}
	statusCode := row.StatusCode
	if statusCode < 100 || statusCode > 599 {
		statusCode = 0
	}
	return Asset{
		Target: target, IP: ip, Port: row.Port, Domain: domain,
		Protocol: protocol, Title: cleanMetadata(row.Title), Country: cleanMetadata(row.Country),
		City: cleanMetadata(row.City), Company: cleanMetadata(row.Company), StatusCode: statusCode,
		Source: hunterProvider,
	}, true
}

func finalizeHunterResult(result Result, assetsByTarget map[string]Asset) Result {
	result.Assets = make([]Asset, 0, len(assetsByTarget))
	for _, asset := range assetsByTarget {
		result.Assets = append(result.Assets, asset)
	}
	sort.Slice(result.Assets, func(i, j int) bool {
		return result.Assets[i].Target < result.Assets[j].Target
	})
	return result
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}
