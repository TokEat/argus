package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/P0lar1ght/argus/server/internal/assetdiscovery"
	"github.com/gin-gonic/gin"
)

var errQuakeCredentialUnavailable = errors.New("quake credential unavailable")

type tenantQuakeCredential struct {
	Credential assetdiscovery.QuakeCredential
	Version    int
	ConfigHash string
}

func queryProjectQuakePreview(c *gin.Context) {
	project, ok := requireProjectAccess(c, c.Param("id"))
	if !ok {
		return
	}

	request, err := decodeProjectDiscoveryQueryRequest(c, assetdiscovery.MaxQuakeQueryBytes, assetdiscovery.DefaultQuakeResultLimit, assetdiscovery.MaxQuakeResultLimit)
	if err != nil {
		status := http.StatusBadRequest
		if errors.As(err, new(*http.MaxBytesError)) {
			status = http.StatusRequestEntityTooLarge
		}
		audit := newAssetDiscoveryAudit(c, project.ID, "quake", request, "failed", "invalid_request", time.Now())
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return
		}
		c.JSON(status, gin.H{"error": "invalid asset discovery request"})
		return
	}

	startedAt := time.Now()
	audit := newAssetDiscoveryAudit(c, project.ID, "quake", request, "failed", "", startedAt)
	expression, ok := loadDiscoverySnapshotExpression(c, project.ID, "quake", request, audit, startedAt)
	if !ok {
		return
	}
	credential, err := loadTenantQuakeCredential(currentTenantID(c))
	if err != nil {
		audit.ErrorCode = "credential_unavailable"
		audit.DurationMS = time.Since(startedAt).Milliseconds()
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Quake is not configured for this tenant"})
		return
	}
	audit.ConfigVersion = credential.Version
	audit.ConfigHash = credential.ConfigHash

	provider := routerRuntime().AssetDiscoveryQuake
	if provider == nil {
		audit.ErrorCode = "provider_unavailable"
		audit.DurationMS = time.Since(startedAt).Milliseconds()
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Quake is unavailable"})
		return
	}

	result, searchErr := provider.Search(c.Request.Context(), credential.Credential, assetdiscovery.QuakeQuery{
		Expression: expression,
		Limit:      request.Limit,
		Page:       request.Page,
	})
	audit.DurationMS = time.Since(startedAt).Milliseconds()
	if searchErr != nil {
		status, code, message := classifyQuakeQueryError(searchErr)
		audit.ErrorCode = code
		if !saveAssetDiscoveryAudit(audit) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to record asset discovery audit"})
			return
		}
		c.JSON(status, gin.H{"error": message})
		return
	}
	completeProjectDiscoveryQuery(c, project.ID, request, result, audit)
}

func loadTenantQuakeCredential(tenantID string) (tenantQuakeCredential, error) {
	var result tenantQuakeCredential
	providerConfig, err := loadTenantAPIProviderConfig(tenantID, "quake")
	if err != nil {
		return result, errQuakeCredentialUnavailable
	}
	for _, entry := range providerConfig.Keys {
		token := strings.TrimSpace(entry)
		if token == "" || len(token) > 4096 || !utf8.ValidString(token) || hasControlCharacters(token) {
			continue
		}
		return tenantQuakeCredential{
			Credential: assetdiscovery.QuakeCredential{Token: token},
			Version:    providerConfig.Version,
			ConfigHash: providerConfig.ConfigHash,
		}, nil
	}
	return result, errQuakeCredentialUnavailable
}

func classifyQuakeQueryError(err error) (int, string, string) {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return http.StatusGatewayTimeout, "provider_timeout", "Quake query timed out"
	case errors.Is(err, assetdiscovery.ErrInvalidQuakeRequest):
		return http.StatusBadRequest, "invalid_request", "invalid Quake query"
	case errors.Is(err, assetdiscovery.ErrQuakeRejected):
		return http.StatusBadGateway, "provider_rejected", "Quake rejected the query"
	case errors.Is(err, assetdiscovery.ErrInvalidQuakeResponse):
		return http.StatusBadGateway, "invalid_provider_response", "Quake returned an invalid response"
	default:
		return http.StatusBadGateway, "provider_unavailable", "Quake is unavailable"
	}
}
