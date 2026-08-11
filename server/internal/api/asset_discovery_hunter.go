package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/user/dddd-server/internal/assetdiscovery"
)

var errHunterCredentialUnavailable = errors.New("hunter credential unavailable")

type tenantHunterCredential struct {
	Credential assetdiscovery.HunterCredential
	Version    int
	ConfigHash string
}

func queryProjectHunterPreview(c *gin.Context) {
	project, ok := requireProjectAccess(c, c.Param("id"))
	if !ok {
		return
	}

	request, err := decodeProjectDiscoveryQueryRequest(c, assetdiscovery.MaxHunterQueryBytes, assetdiscovery.DefaultHunterResultLimit, assetdiscovery.MaxHunterResultLimit)
	if err != nil {
		status := http.StatusBadRequest
		if errors.As(err, new(*http.MaxBytesError)) {
			status = http.StatusRequestEntityTooLarge
		}
		audit := newAssetDiscoveryAudit(c, project.ID, "hunter", request, "failed", "invalid_request", time.Now())
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return
		}
		c.JSON(status, gin.H{"error": "invalid asset discovery request"})
		return
	}

	startedAt := time.Now()
	audit := newAssetDiscoveryAudit(c, project.ID, "hunter", request, "failed", "", startedAt)
	credential, err := loadTenantHunterCredential(currentTenantID(c))
	if err != nil {
		audit.ErrorCode = "credential_unavailable"
		audit.DurationMS = time.Since(startedAt).Milliseconds()
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Hunter is not configured for this tenant"})
		return
	}
	audit.ConfigVersion = credential.Version
	audit.ConfigHash = credential.ConfigHash

	provider := routerRuntime().AssetDiscoveryHunter
	if provider == nil {
		audit.ErrorCode = "provider_unavailable"
		audit.DurationMS = time.Since(startedAt).Milliseconds()
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Hunter is unavailable"})
		return
	}

	result, searchErr := provider.Search(c.Request.Context(), credential.Credential, assetdiscovery.HunterQuery{
		Expression: request.Expression,
		Limit:      request.Limit,
	})
	audit.DurationMS = time.Since(startedAt).Milliseconds()
	if searchErr != nil {
		status, code, message := classifyHunterQueryError(searchErr)
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

func loadTenantHunterCredential(tenantID string) (tenantHunterCredential, error) {
	var result tenantHunterCredential
	providerConfig, err := loadTenantAPIProviderConfig(tenantID, "hunter")
	if err != nil {
		return result, errHunterCredentialUnavailable
	}
	for _, entry := range providerConfig.Keys {
		apiKey := strings.TrimSpace(entry)
		if apiKey == "" || len(apiKey) > 4096 || !utf8.ValidString(apiKey) || hasControlCharacters(apiKey) {
			continue
		}
		return tenantHunterCredential{
			Credential: assetdiscovery.HunterCredential{APIKey: apiKey},
			Version:    providerConfig.Version,
			ConfigHash: providerConfig.ConfigHash,
		}, nil
	}
	return result, errHunterCredentialUnavailable
}

func hasControlCharacters(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}
	return false
}

func classifyHunterQueryError(err error) (int, string, string) {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return http.StatusGatewayTimeout, "provider_timeout", "Hunter query timed out"
	case errors.Is(err, assetdiscovery.ErrInvalidHunterRequest):
		return http.StatusBadRequest, "invalid_request", "invalid Hunter query"
	case errors.Is(err, assetdiscovery.ErrHunterRejected):
		return http.StatusBadGateway, "provider_rejected", "Hunter rejected the query"
	case errors.Is(err, assetdiscovery.ErrInvalidHunterResponse):
		return http.StatusBadGateway, "invalid_provider_response", "Hunter returned an invalid response"
	default:
		return http.StatusBadGateway, "provider_unavailable", "Hunter is unavailable"
	}
}
