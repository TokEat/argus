package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/P0lar1ght/argus/server/internal/assetdiscovery"
	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

const (
	assetDiscoveryPreviewSchema = "argus.asset-discovery-query-preview/v1"
	assetDiscoveryRequestLimit  = int64(16 << 10)
	assetDiscoveryConfigLimit   = 1 << 20
	assetDiscoveryAuditTimeout  = 2 * time.Second
)

var (
	errAPIProviderConfigUnavailable = errors.New("API provider config unavailable")
	errFOFACredentialUnavailable    = errors.New("fofa credential unavailable")
)

func assetDiscoveryRequestBodyLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := strings.TrimSuffix(c.Request.URL.Path, "/")
		if c.Request.Method == http.MethodPost && strings.HasPrefix(path, "/api/v1/projects/") &&
			isAssetDiscoveryQueryPath(path) && c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, assetDiscoveryRequestLimit)
		}
		c.Next()
	}
}

func isAssetDiscoveryQueryPath(path string) bool {
	return strings.HasSuffix(path, "/asset-discovery/fofa/query") ||
		strings.HasSuffix(path, "/asset-discovery/hunter/query") ||
		strings.HasSuffix(path, "/asset-discovery/quake/query") ||
		(strings.Contains(path, "/asset-discovery/queries/") && strings.HasSuffix(path, "/notebook-items"))
}

type projectDiscoveryQueryRequest struct {
	Expression string `json:"expression"`
	Limit      int    `json:"limit"`
}

type projectDiscoveryQueryResponse struct {
	SchemaVersion string                 `json:"schema_version"`
	ProjectID     string                 `json:"project_id"`
	AuditID       uint                   `json:"audit_id"`
	Provider      string                 `json:"provider"`
	ProviderTotal int                    `json:"provider_total"`
	SkippedRows   int                    `json:"skipped_rows"`
	Truncated     bool                   `json:"truncated"`
	Assets        []assetdiscovery.Asset `json:"assets"`
}

type tenantFOFACredential struct {
	Credential assetdiscovery.FOFACredential
	Version    int
	ConfigHash string
}

func queryProjectFOFAPreview(c *gin.Context) {
	project, ok := requireProjectAccess(c, c.Param("id"))
	if !ok {
		return
	}

	request, err := decodeProjectDiscoveryQueryRequest(c, assetdiscovery.MaxFOFAQueryBytes, assetdiscovery.DefaultFOFAResultLimit, assetdiscovery.MaxFOFAResultLimit)
	if err != nil {
		status := http.StatusBadRequest
		if errors.As(err, new(*http.MaxBytesError)) {
			status = http.StatusRequestEntityTooLarge
		}
		audit := newAssetDiscoveryAudit(c, project.ID, "fofa", request, "failed", "invalid_request", time.Now())
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return
		}
		c.JSON(status, gin.H{"error": "invalid asset discovery request"})
		return
	}

	startedAt := time.Now()
	audit := newAssetDiscoveryAudit(c, project.ID, "fofa", request, "failed", "", startedAt)
	credential, err := loadTenantFOFACredential(currentTenantID(c))
	if err != nil {
		audit.ErrorCode = "credential_unavailable"
		audit.DurationMS = time.Since(startedAt).Milliseconds()
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "FOFA is not configured for this tenant"})
		return
	}
	audit.ConfigVersion = credential.Version
	audit.ConfigHash = credential.ConfigHash

	provider := routerRuntime().AssetDiscoveryFOFA
	if provider == nil {
		audit.ErrorCode = "provider_unavailable"
		audit.DurationMS = time.Since(startedAt).Milliseconds()
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "FOFA is unavailable"})
		return
	}

	result, searchErr := provider.Search(c.Request.Context(), credential.Credential, assetdiscovery.FOFAQuery{
		Expression: request.Expression,
		Limit:      request.Limit,
	})
	audit.DurationMS = time.Since(startedAt).Milliseconds()
	if searchErr != nil {
		status, code, message := classifyFOFAQueryError(searchErr)
		audit.ErrorCode = code
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return
		}
		c.JSON(status, gin.H{"error": message})
		return
	}
	completeProjectDiscoveryPreview(c, project.ID, request, result, audit)
}

func decodeProjectDiscoveryQueryRequest(c *gin.Context, maxQueryBytes, defaultLimit, maxLimit int) (projectDiscoveryQueryRequest, error) {
	var request projectDiscoveryQueryRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, assetDiscoveryRequestLimit)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return request, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return request, errors.New("expected one JSON object")
	}

	request.Expression = strings.TrimSpace(request.Expression)
	if request.Expression == "" || len(request.Expression) > maxQueryBytes ||
		!utf8.ValidString(request.Expression) || strings.ContainsAny(request.Expression, "\r\n\x00") {
		return request, errors.New("invalid query expression")
	}
	if request.Limit == 0 {
		request.Limit = defaultLimit
	}
	if request.Limit < 1 || request.Limit > maxLimit {
		return request, errors.New("invalid query limit")
	}
	return request, nil
}

func loadTenantFOFACredential(tenantID string) (tenantFOFACredential, error) {
	var result tenantFOFACredential
	providerConfig, err := loadTenantAPIProviderConfig(tenantID, "fofa")
	if err != nil {
		return result, errFOFACredentialUnavailable
	}
	for _, entry := range providerConfig.Keys {
		parts := strings.SplitN(strings.TrimSpace(entry), ":", 2)
		if len(parts) != 2 {
			continue
		}
		email := strings.TrimSpace(parts[0])
		key := strings.TrimSpace(parts[1])
		if !validFOFACredentialPart(email, true) || !validFOFACredentialPart(key, false) {
			continue
		}
		return tenantFOFACredential{
			Credential: assetdiscovery.FOFACredential{Email: email, Key: key},
			Version:    providerConfig.Version,
			ConfigHash: providerConfig.ConfigHash,
		}, nil
	}
	return result, errFOFACredentialUnavailable
}

type tenantAPIProviderConfig struct {
	Keys       []string
	Version    int
	ConfigHash string
}

func loadTenantAPIProviderConfig(tenantID, provider string) (tenantAPIProviderConfig, error) {
	var result tenantAPIProviderConfig
	if db.DB == nil {
		return result, errAPIProviderConfigUnavailable
	}
	arsenal, err := db.FindTenantArsenalByTypeAndFile(tenantID, "apiconfig", "api-config.yaml")
	if err != nil || !strings.EqualFold(strings.TrimSpace(arsenal.State), "Approved") {
		return result, errAPIProviderConfigUnavailable
	}
	content := strings.TrimSpace(arsenal.Content)
	if content == "" || len(content) > assetDiscoveryConfigLimit || !utf8.ValidString(content) {
		return result, errAPIProviderConfigUnavailable
	}

	var providers map[string][]string
	decoder := yaml.NewDecoder(strings.NewReader(content))
	if err := decoder.Decode(&providers); err != nil || providers == nil {
		return result, errAPIProviderConfigUnavailable
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return result, errAPIProviderConfigUnavailable
	}
	keys, ok := providers[strings.ToLower(strings.TrimSpace(provider))]
	if !ok || len(keys) == 0 || len(keys) > 1000 {
		return result, errAPIProviderConfigUnavailable
	}
	digest := sha256.Sum256([]byte(content))
	return tenantAPIProviderConfig{
		Keys: append([]string(nil), keys...), Version: arsenal.Version, ConfigHash: hex.EncodeToString(digest[:]),
	}, nil
}

func validFOFACredentialPart(value string, email bool) bool {
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) {
		return false
	}
	if email && !strings.Contains(value, "@") {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func newAssetDiscoveryAudit(c *gin.Context, projectID, provider string, request projectDiscoveryQueryRequest, status, errorCode string, startedAt time.Time) *db.AssetDiscoveryAudit {
	digest := sha256.Sum256([]byte(strings.TrimSpace(request.Expression)))
	return &db.AssetDiscoveryAudit{
		TenantID:       currentTenantID(c),
		ProjectID:      projectID,
		Provider:       provider,
		Action:         "query_preview",
		OperatorID:     currentUserID(c),
		QueryHash:      hex.EncodeToString(digest[:]),
		RequestedLimit: request.Limit,
		Status:         status,
		ErrorCode:      errorCode,
		DurationMS:     time.Since(startedAt).Milliseconds(),
		CreatedAt:      time.Now(),
	}
}

func saveAssetDiscoveryAudit(audit *db.AssetDiscoveryAudit) bool {
	if db.DB == nil || audit == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), assetDiscoveryAuditTimeout)
	defer cancel()
	return db.DB.WithContext(ctx).Create(audit).Error == nil
}

func classifyFOFAQueryError(err error) (int, string, string) {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return http.StatusGatewayTimeout, "provider_timeout", "FOFA query timed out"
	case errors.Is(err, assetdiscovery.ErrInvalidFOFARequest):
		return http.StatusBadRequest, "invalid_request", "invalid FOFA query"
	case errors.Is(err, assetdiscovery.ErrFOFARejected):
		return http.StatusBadGateway, "provider_rejected", "FOFA rejected the query"
	case errors.Is(err, assetdiscovery.ErrInvalidFOFAResponse):
		return http.StatusBadGateway, "invalid_provider_response", "FOFA returned an invalid response"
	default:
		return http.StatusBadGateway, "provider_unavailable", "FOFA is unavailable"
	}
}
