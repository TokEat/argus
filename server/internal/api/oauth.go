package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/P0lar1ght/argus/server/internal/db"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	oauthScope           = "argus"
	oauthCursorClientID  = "cursor"
	oauthAccessTokenTTL  = time.Hour
	oauthRefreshTokenTTL = 30 * 24 * time.Hour
	oauthAuthCodeTTL     = 2 * time.Minute
)

// Seeded public client for Cursor; other MCP clients use DCR plus RFC 8252 loopback.
var oauthCursorRedirects = []string{
	"http://127.0.0.1:8787/callback",
	"http://localhost:8787/callback",
	"https://www.cursor.com/agents/mcp/oauth/callback",
	"cursor://anysphere.cursor-mcp/oauth/callback",
}

var oauthKnownHTTPSRedirectHosts = map[string]bool{
	"www.cursor.com": true,
	"cursor.com":     true,
}

var oauthPrivateRedirectSchemes = map[string]bool{
	"cursor":          true,
	"vscode":          true,
	"vscode-insiders": true,
}

var oauthLoginPage = template.Must(template.New("oauth-login").Parse(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Argus MCP 登录</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0f1419; color: #e7ecf3; display: flex; min-height: 100vh; align-items: center; justify-content: center; margin: 0; }
    form { background: #1b232d; padding: 28px; border-radius: 12px; width: 360px; box-shadow: 0 12px 40px rgba(0,0,0,.35); }
    h1 { font-size: 20px; margin: 0 0 8px; }
    p { color: #9aa8b8; font-size: 13px; margin: 0 0 18px; }
    label { display: block; font-size: 12px; margin: 12px 0 6px; color: #c5d0dc; }
    input { width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 8px; border: 1px solid #314155; background: #10161d; color: #e7ecf3; }
    button { width: 100%; margin-top: 18px; padding: 10px 12px; border: 0; border-radius: 8px; background: #3b82f6; color: white; font-weight: 600; cursor: pointer; }
    .err { color: #fca5a5; font-size: 13px; margin-bottom: 12px; }
  </style>
</head>
<body>
  <form method="post" action="/oauth/authorize" autocomplete="on">
    <h1>授权 Argus MCP</h1>
    <p>使用现有 Argus 账号登录。MCP 客户端不会把 JWT 写进配置文件。</p>
    {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
    <label for="username">用户名</label>
    <input id="username" name="username" value="{{.Username}}" required autofocus>
    <label for="password">密码</label>
    <input id="password" name="password" type="password" required>
    <input type="hidden" name="client_id" value="{{.ClientID}}">
    <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
    <input type="hidden" name="state" value="{{.State}}">
    <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
    <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
    <input type="hidden" name="resource" value="{{.Resource}}">
    <input type="hidden" name="scope" value="{{.Scope}}">
    <input type="hidden" name="response_type" value="code">
    <button type="submit">登录并授权</button>
  </form>
</body>
</html>`))

type oauthAuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
	Scope               string
	ResponseType        string
	Username            string
	Error               string
}

func publicAPIBase() string {
	base := strings.TrimRight(strings.TrimSpace(routerRuntime().PublicBaseURL), "/")
	if base == "" {
		return "http://127.0.0.1:8085"
	}
	return base
}

func mcpResourceURI() string {
	return publicAPIBase() + "/mcp"
}

func oauthIssuer() string {
	return publicAPIBase()
}

func oauthProtectedResourceMetadataURL() string {
	return publicAPIBase() + "/.well-known/oauth-protected-resource/mcp"
}

func mcpWWWAuthenticate() string {
	return fmt.Sprintf(`Bearer resource_metadata=%q, scope=%q`, oauthProtectedResourceMetadataURL(), oauthScope)
}

func registerOAuthRoutes(r *gin.Engine) {
	r.GET("/.well-known/oauth-protected-resource", oauthProtectedResourceMetadata)
	r.GET("/.well-known/oauth-protected-resource/mcp", oauthProtectedResourceMetadata)
	r.GET("/.well-known/oauth-authorization-server", oauthAuthorizationServerMetadata)
	r.GET("/.well-known/openid-configuration", oauthAuthorizationServerMetadata)
	r.GET("/oauth/authorize", oauthAuthorizeGet)
	r.POST("/oauth/authorize", oauthAuthorizePost)
	r.POST("/oauth/token", oauthToken)
	r.POST("/oauth/register", oauthRegister)
}

func oauthProtectedResourceMetadata(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"resource":                 mcpResourceURI(),
		"authorization_servers":    []string{oauthIssuer()},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{oauthScope},
	})
}

func oauthAuthorizationServerMetadata(c *gin.Context) {
	issuer := oauthIssuer()
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                         issuer,
		"authorization_endpoint":                         issuer + "/oauth/authorize",
		"token_endpoint":                                 issuer + "/oauth/token",
		"registration_endpoint":                          issuer + "/oauth/register",
		"scopes_supported":                               []string{oauthScope},
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"authorization_response_iss_parameter_supported": true,
		"require_pkce":                                   true,
	})
}

func parseOAuthAuthorizeRequest(c *gin.Context) oauthAuthorizeRequest {
	values := c.Request.URL.Query()
	if c.Request.Method == http.MethodPost {
		_ = c.Request.ParseForm()
		values = c.Request.PostForm
	}
	return oauthAuthorizeRequest{
		ClientID:            strings.TrimSpace(values.Get("client_id")),
		RedirectURI:         strings.TrimSpace(values.Get("redirect_uri")),
		State:               values.Get("state"),
		CodeChallenge:       strings.TrimSpace(values.Get("code_challenge")),
		CodeChallengeMethod: strings.TrimSpace(values.Get("code_challenge_method")),
		Resource:            strings.TrimSpace(values.Get("resource")),
		Scope:               strings.TrimSpace(values.Get("scope")),
		ResponseType:        strings.TrimSpace(values.Get("response_type")),
		Username:            strings.TrimSpace(values.Get("username")),
	}
}

func oauthAuthorizeGet(c *gin.Context) {
	req := parseOAuthAuthorizeRequest(c)
	if err := validateOAuthAuthorizeRequest(&req); err != nil {
		oauthAuthorizeError(c, req, err)
		return
	}
	writeOAuthLoginPage(c, http.StatusOK, req)
}

func oauthAuthorizePost(c *gin.Context) {
	req := parseOAuthAuthorizeRequest(c)
	if err := validateOAuthAuthorizeRequest(&req); err != nil {
		oauthAuthorizeError(c, req, err)
		return
	}
	password := ""
	if c.Request.PostForm != nil {
		password = c.Request.PostForm.Get("password")
	}
	identity, err := authenticateArgusUser(req.Username, password)
	if err != nil {
		req.Error = "用户名或密码不正确，或账号已停用。"
		writeOAuthLoginPage(c, http.StatusUnauthorized, req)
		return
	}
	if err := denyIfTenantMCPBlocked(identity.TenantID, req.ClientID); err != nil {
		req.Error = tenantMCPDenyMessage(err)
		writeOAuthLoginPage(c, http.StatusForbidden, req)
		return
	}
	code, err := issueOAuthAuthorizationCode(req, identity)
	if err != nil {
		oauthAuthorizeError(c, req, err)
		return
	}
	target, err := url.Parse(req.RedirectURI)
	if err != nil {
		oauthAuthorizeError(c, req, errInvalidOAuthRequest)
		return
	}
	q := target.Query()
	q.Set("code", code)
	if req.State != "" {
		q.Set("state", req.State)
	}
	q.Set("iss", oauthIssuer())
	target.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, target.String())
}

var (
	errInvalidOAuthRequest = errors.New("invalid_request")
	errOAuthServerError    = errors.New("server_error")
)

func validateOAuthAuthorizeRequest(req *oauthAuthorizeRequest) error {
	if req == nil {
		return errInvalidOAuthRequest
	}
	normalizeOAuthAuthorizeRequest(req)
	if req.ResponseType != "" && req.ResponseType != "code" {
		return errInvalidOAuthRequest
	}
	if req.ClientID == "" || req.RedirectURI == "" || req.CodeChallenge == "" {
		return errInvalidOAuthRequest
	}
	if !strings.EqualFold(req.CodeChallengeMethod, "S256") {
		return errInvalidOAuthRequest
	}
	if req.Resource != mcpResourceURI() {
		return errInvalidOAuthRequest
	}
	client, err := loadOAuthClient(req.ClientID)
	if err != nil {
		return errInvalidOAuthRequest
	}
	if !oauthRedirectAllowed(req.RedirectURI) || !clientAllowsRedirect(client, req.RedirectURI) {
		return errInvalidOAuthRequest
	}
	return nil
}

func normalizeOAuthAuthorizeRequest(req *oauthAuthorizeRequest) {
	if strings.TrimSpace(req.CodeChallengeMethod) == "" {
		req.CodeChallengeMethod = "S256"
	}
	if canonical, ok := canonicalMCPResource(req.Resource); ok {
		req.Resource = canonical
	}
}

func canonicalMCPResource(resource string) (string, bool) {
	want := strings.TrimRight(mcpResourceURI(), "/")
	resource = strings.TrimRight(strings.TrimSpace(resource), "/")
	if resource == "" || resource == want {
		return mcpResourceURI(), true
	}
	return "", false
}

func oauthAuthorizeError(c *gin.Context, req oauthAuthorizeRequest, err error) {
	if req.RedirectURI != "" && oauthRedirectAllowed(req.RedirectURI) {
		if target, parseErr := url.Parse(req.RedirectURI); parseErr == nil {
			q := target.Query()
			q.Set("error", err.Error())
			if req.State != "" {
				q.Set("state", req.State)
			}
			q.Set("iss", oauthIssuer())
			target.RawQuery = q.Encode()
			c.Redirect(http.StatusFound, target.String())
			return
		}
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
}

func tenantMCPDenyMessage(err error) string {
	if errors.Is(err, errTenantMCPClientBlocked) {
		return "该 MCP 客户端已对本租户禁用。"
	}
	return "本租户已关闭 MCP 接入。"
}

func writeOAuthLoginPage(c *gin.Context, status int, req oauthAuthorizeRequest) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)
	_ = oauthLoginPage.Execute(c.Writer, req)
}

func issueOAuthAuthorizationCode(req oauthAuthorizeRequest, identity argusIdentity) (string, error) {
	if err := ensureBuiltinOAuthClients(); err != nil {
		return "", errOAuthServerError
	}
	code := randomOAuthToken()
	row := db.OAuthAuthorizationCode{
		CodeHash:      sha256Hex(code),
		ClientID:      req.ClientID,
		RedirectURI:   req.RedirectURI,
		Resource:      req.Resource,
		CodeChallenge: req.CodeChallenge,
		UserID:        identity.UserID,
		TenantID:      identity.TenantID,
		Role:          identity.Role,
		RoleBase:      identity.RoleBase,
		ExpAuthorized: identity.ExpAuthorized,
		ExpiresAt:     time.Now().Add(oauthAuthCodeTTL),
	}
	if err := db.DB.Create(&row).Error; err != nil {
		return "", errOAuthServerError
	}
	return code, nil
}

func oauthToken(c *gin.Context) {
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	grant := strings.TrimSpace(c.Request.PostForm.Get("grant_type"))
	switch grant {
	case "authorization_code":
		oauthTokenAuthorizationCode(c)
	case "refresh_token":
		oauthTokenRefresh(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}
}

func oauthTokenAuthorizationCode(c *gin.Context) {
	form := c.Request.PostForm
	clientID := strings.TrimSpace(form.Get("client_id"))
	code := strings.TrimSpace(form.Get("code"))
	redirectURI := strings.TrimSpace(form.Get("redirect_uri"))
	verifier := strings.TrimSpace(form.Get("code_verifier"))
	resource := strings.TrimSpace(form.Get("resource"))
	if clientID == "" || code == "" || redirectURI == "" || verifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	canonical, ok := canonicalMCPResource(resource)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_target"})
		return
	}
	resource = canonical
	if _, err := loadOAuthClient(clientID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}
	var row db.OAuthAuthorizationCode
	if err := db.DB.Where("code_hash = ?", sha256Hex(code)).First(&row).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	if row.UsedAt != nil || now.After(row.ExpiresAt) || row.ClientID != clientID || row.RedirectURI != redirectURI || row.Resource != resource {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	if pkceS256(verifier) != row.CodeChallenge {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	result := db.DB.Model(&db.OAuthAuthorizationCode{}).
		Where("code_hash = ? AND used_at IS NULL", row.CodeHash).
		Update("used_at", now)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	if result.RowsAffected != 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	if err := denyIfTenantMCPBlocked(row.TenantID, clientID); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "access_denied"})
		return
	}
	identity := argusIdentity{
		UserID:        row.UserID,
		TenantID:      row.TenantID,
		Role:          row.Role,
		RoleBase:      row.RoleBase,
		ExpAuthorized: row.ExpAuthorized,
	}
	writeOAuthTokenResponse(c, clientID, resource, identity)
}

func oauthTokenRefresh(c *gin.Context) {
	form := c.Request.PostForm
	clientID := strings.TrimSpace(form.Get("client_id"))
	refresh := strings.TrimSpace(form.Get("refresh_token"))
	resource := strings.TrimSpace(form.Get("resource"))
	if clientID == "" || refresh == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	canonical, ok := canonicalMCPResource(resource)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_target"})
		return
	}
	resource = canonical
	if _, err := loadOAuthClient(clientID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}
	var row db.OAuthRefreshToken
	if err := db.DB.Where("token_hash = ?", sha256Hex(refresh)).First(&row).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	now := time.Now()
	if row.ClientID != clientID || row.Resource != resource || now.After(row.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	if err := denyIfTenantMCPBlocked(row.TenantID, clientID); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "access_denied"})
		return
	}
	if row.RevokedAt != nil {
		db.DB.Model(&db.OAuthRefreshToken{}).
			Where("client_id = ? AND user_id = ? AND revoked_at IS NULL", row.ClientID, row.UserID).
			Update("revoked_at", now)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	if err := db.DB.Model(&row).Update("revoked_at", now).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	identity := argusIdentity{
		UserID:        row.UserID,
		TenantID:      row.TenantID,
		Role:          row.Role,
		RoleBase:      row.RoleBase,
		ExpAuthorized: row.ExpAuthorized,
	}
	writeOAuthTokenResponse(c, clientID, resource, identity)
}

func writeOAuthTokenResponse(c *gin.Context, clientID, resource string, identity argusIdentity) {
	access, err := signMCPOAuthAccessToken(identity, clientID, resource)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	refresh := randomOAuthToken()
	row := db.OAuthRefreshToken{
		TokenHash:     sha256Hex(refresh),
		ClientID:      clientID,
		UserID:        identity.UserID,
		TenantID:      identity.TenantID,
		Role:          identity.Role,
		RoleBase:      identity.RoleBase,
		ExpAuthorized: identity.ExpAuthorized,
		Resource:      resource,
		ExpiresAt:     time.Now().Add(oauthRefreshTokenTTL),
	}
	if err := db.DB.Create(&row).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(oauthAccessTokenTTL.Seconds()),
		"refresh_token": refresh,
		"scope":         oauthScope,
	})
}

func signMCPOAuthAccessToken(identity argusIdentity, clientID, resource string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"tenant_id":      identity.TenantID,
		"role":           identity.Role,
		"role_base":      identity.RoleBase,
		"user_id":        identity.UserID,
		"exp_authorized": identity.ExpAuthorized,
		"aud":            resource,
		"client_id":      clientID,
		"token_use":      "access",
		"exp":            time.Now().Add(oauthAccessTokenTTL).Unix(),
	})
	return token.SignedString(currentJWTSecret())
}

func oauthRegister(c *gin.Context) {
	var req struct {
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		ClientName              string   `json:"client_name"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.RedirectURIs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client_metadata"})
		return
	}
	method := strings.TrimSpace(req.TokenEndpointAuthMethod)
	if method != "" && method != "none" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client_metadata"})
		return
	}
	for _, redirect := range req.RedirectURIs {
		if !oauthRedirectAllowed(strings.TrimSpace(redirect)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri"})
			return
		}
	}
	payload, _ := json.Marshal(req.RedirectURIs)
	client := db.OAuthClient{
		ClientID:     uuid.NewString(),
		RedirectURIs: string(payload),
		Public:       true,
	}
	if err := db.DB.Create(&client).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"client_id":                  client.ClientID,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_name":                strings.TrimSpace(req.ClientName),
	})
}

func ensureBuiltinOAuthClients() error {
	payload, _ := json.Marshal(oauthCursorRedirects)
	client := db.OAuthClient{
		ClientID:     oauthCursorClientID,
		RedirectURIs: string(payload),
		Public:       true,
	}
	return db.DB.Where("client_id = ?", oauthCursorClientID).Attrs(client).FirstOrCreate(&client).Error
}

func loadOAuthClient(clientID string) (db.OAuthClient, error) {
	if err := ensureBuiltinOAuthClients(); err != nil {
		return db.OAuthClient{}, err
	}
	var client db.OAuthClient
	if err := db.DB.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return db.OAuthClient{}, errInvalidOAuthRequest
		}
		return db.OAuthClient{}, err
	}
	if !client.Public {
		return db.OAuthClient{}, errInvalidOAuthRequest
	}
	return client, nil
}

func clientAllowsRedirect(client db.OAuthClient, redirect string) bool {
	var uris []string
	if json.Unmarshal([]byte(client.RedirectURIs), &uris) != nil {
		return false
	}
	for _, item := range uris {
		if oauthRedirectsMatch(strings.TrimSpace(item), redirect) {
			return true
		}
	}
	return false
}

func oauthRedirectAllowed(redirect string) bool {
	if len(redirect) == 0 || len(redirect) > 2048 {
		return false
	}
	parsed, err := url.Parse(redirect)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Fragment != "" || strings.Contains(parsed.Path, "..") {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	switch scheme {
	case "http":
		return isOAuthLoopbackHost(host)
	case "https":
		if isOAuthLoopbackHost(host) {
			return true
		}
		return oauthKnownHTTPSRedirectHosts[host] && strings.HasPrefix(parsed.Path, "/")
	default:
		return oauthPrivateRedirectSchemes[scheme] && parsed.Path != ""
	}
}

func oauthRedirectsMatch(registered, requested string) bool {
	if registered == requested {
		return true
	}
	left, errLeft := url.Parse(registered)
	right, errRight := url.Parse(requested)
	if errLeft != nil || errRight != nil {
		return false
	}
	if !isOAuthLoopbackURL(left) || !isOAuthLoopbackURL(right) {
		return false
	}
	return oauthRedirectPath(left) == oauthRedirectPath(right) && left.RawQuery == right.RawQuery
}

func isOAuthLoopbackURL(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	return (scheme == "http" || scheme == "https") && isOAuthLoopbackHost(parsed.Hostname())
}

func isOAuthLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func oauthRedirectPath(parsed *url.URL) string {
	if parsed == nil || parsed.Path == "" {
		return "/"
	}
	return parsed.Path
}

func jwtAudiences(claims jwt.MapClaims) []string {
	switch value := claims["aud"].(type) {
	case string:
		if strings.TrimSpace(value) != "" {
			return []string{value}
		}
	case []interface{}:
		out := make([]string, 0, len(value))
		for _, item := range value {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" && text != "<nil>" {
				out = append(out, text)
			}
		}
		return out
	case []string:
		return value
	}
	return nil
}

func tokenAllowsAPI(claims jwt.MapClaims) bool {
	audiences := jwtAudiences(claims)
	if len(audiences) == 0 {
		return true
	}
	resource := mcpResourceURI()
	for _, audience := range audiences {
		if audience == resource {
			return true
		}
	}
	return false
}

func tokenAllowsMCP(claims jwt.MapClaims) bool {
	resource := mcpResourceURI()
	for _, audience := range jwtAudiences(claims) {
		if audience == resource {
			return true
		}
	}
	return false
}

func randomOAuthToken() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
