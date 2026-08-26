package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func newOAuthTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	setupAITestDB(t)
	gin.SetMode(gin.TestMode)
	router := NewRouter(RouterDependencies{PublicBaseURL: "http://oauth.example"})
	ts := httptest.NewServer(router)
	t.Cleanup(ts.Close)
	deps := *routerRuntime()
	deps.PublicBaseURL = ts.URL
	ConfigureRouterDependencies(deps)
	t.Cleanup(func() {
		ConfigureRouterDependencies(RouterDependencies{})
	})
	return ts
}

func TestOAuthMetadataDescribesPKCEAndResource(t *testing.T) {
	ts := newOAuthTestServer(t)
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), ts.URL+"/mcp") {
			t.Fatalf("%s: status=%d body=%s", path, resp.StatusCode, body)
		}
	}
	resp, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("GET authorization-server: %v", err)
	}
	defer resp.Body.Close()
	var meta map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if meta["issuer"] != ts.URL || meta["authorization_response_iss_parameter_supported"] != true {
		t.Fatalf("unexpected AS metadata: %#v", meta)
	}
	methods, _ := json.Marshal(meta["code_challenge_methods_supported"])
	if !strings.Contains(string(methods), "S256") {
		t.Fatalf("missing S256: %s", methods)
	}
	oidc, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET openid-configuration: %v", err)
	}
	defer oidc.Body.Close()
	if oidc.StatusCode != http.StatusOK {
		t.Fatalf("openid-configuration status=%d", oidc.StatusCode)
	}
}

func TestOAuthLoopbackRedirectPolicy(t *testing.T) {
	allowed := []string{
		"http://127.0.0.1:39053/callback/BKj9umzr4ef_",
		"http://localhost:51111/oauth/callback",
		"http://[::1]:8080/callback",
		"https://www.cursor.com/agents/mcp/oauth/callback",
		"cursor://anysphere.cursor-mcp/oauth/callback",
		"vscode://vscode.github-authentication/did-authenticate",
	}
	for _, redirect := range allowed {
		if !oauthRedirectAllowed(redirect) {
			t.Fatalf("expected allowed redirect %s", redirect)
		}
	}
	rejected := []string{
		"https://evil.example/cb",
		"http://192.168.1.8/callback",
		"http://example.com:8787/callback",
		"javascript:alert(1)",
		"file:///etc/passwd",
	}
	for _, redirect := range rejected {
		if oauthRedirectAllowed(redirect) {
			t.Fatalf("expected rejected redirect %s", redirect)
		}
	}
	if !oauthRedirectsMatch("http://127.0.0.1:1111/callback/x", "http://localhost:2222/callback/x") {
		t.Fatal("RFC 8252 loopback should ignore port and treat localhost as loopback")
	}
	if oauthRedirectsMatch("http://127.0.0.1:1111/callback", "http://127.0.0.1:1111/callback/other") {
		t.Fatal("loopback path must still match")
	}
}

func TestOAuthDCRAcceptsGenericMCPClients(t *testing.T) {
	ts := newOAuthTestServer(t)
	resp, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{"redirect_uris":["http://127.0.0.1:39053/callback/codex-id"],"token_endpoint_auth_method":"none","client_name":"Codex","grant_types":["authorization_code","refresh_token"]}`))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", resp.StatusCode, body)
	}
	var created map[string]interface{}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatalf("decode register: %v", err)
	}
	clientID, _ := created["client_id"].(string)
	if clientID == "" {
		t.Fatal("missing client_id")
	}

	user := seedLoginUser(t, uniqueLoginUsername("mcp-dcr"), "secret", "default", "operator")
	verifier := oauthTestVerifier(t)
	redirect := "http://localhost:39053/callback/codex-id"
	form := url.Values{
		"response_type":  {"code"},
		"client_id":      {clientID},
		"redirect_uri":   {redirect},
		"code_challenge": {pkceS256(verifier)},
		"scope":          {"read write"},
		"state":          {"csrf-state"},
		"username":       {user.Username},
		"password":       {"secret"},
	}
	httpClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	authResp, err := httpClient.PostForm(ts.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		raw, _ := io.ReadAll(authResp.Body)
		t.Fatalf("authorize status=%d body=%s", authResp.StatusCode, raw)
	}
	location, err := url.Parse(authResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("missing code in %s", location)
	}
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	}
	tokenResp, err := http.PostForm(ts.URL+"/oauth/token", tokenForm)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token status=%d body=%s", tokenResp.StatusCode, raw)
	}
}

func TestOAuthAuthorizeRejectsPlainPKCEAndUnknownRedirect(t *testing.T) {
	ts := newOAuthTestServer(t)
	resource := ts.URL + "/mcp"
	plain := ts.URL + "/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"cursor"},
		"redirect_uri":          {"http://127.0.0.1:8787/callback"},
		"code_challenge":        {"abc"},
		"code_challenge_method": {"plain"},
		"resource":              {resource},
	}.Encode()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(plain)
	if err != nil {
		t.Fatalf("plain PKCE: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "invalid_request") {
		t.Fatalf("plain PKCE should redirect with invalid_request, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	bad := ts.URL + "/oauth/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {"cursor"},
		"redirect_uri":          {"https://evil.example/callback"},
		"code_challenge":        {"abc"},
		"code_challenge_method": {"S256"},
		"resource":              {resource},
	}.Encode()
	resp, err = http.Get(bad)
	if err != nil {
		t.Fatalf("bad redirect: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("evil redirect should not be followed, status=%d body=%s", resp.StatusCode, body)
	}
}

func TestOAuthAuthorizationCodeAndRefresh(t *testing.T) {
	ts := newOAuthTestServer(t)
	user := seedLoginUser(t, uniqueLoginUsername("oauth"), "secret", "default", "operator")
	verifier := oauthTestVerifier(t)
	code := completeOAuthLogin(t, ts, user.Username, "secret", verifier)
	tokens := exchangeOAuthCode(t, ts, code, verifier)
	if tokens["token_type"] != "Bearer" || tokens["access_token"] == "" || tokens["refresh_token"] == "" {
		t.Fatalf("unexpected token response: %#v", tokens)
	}

	replay := exchangeOAuthCodeRaw(t, ts, code, verifier)
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("code replay status=%d", replay.StatusCode)
	}
	replay.Body.Close()

	access := tokens["access_token"].(string)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`))
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("MCP initialize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "argus-mcp") {
		t.Fatalf("MCP initialize status=%d body=%s", resp.StatusCode, body)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"cursor"},
		"refresh_token": {tokens["refresh_token"].(string)},
		"resource":      {ts.URL + "/mcp"},
	}
	refreshResp, err := http.PostForm(ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	var refreshed map[string]interface{}
	if err := json.NewDecoder(refreshResp.Body).Decode(&refreshed); err != nil {
		t.Fatalf("decode refresh: %v", err)
	}
	refreshResp.Body.Close()
	if refreshResp.StatusCode != http.StatusOK || refreshed["refresh_token"] == "" || refreshed["refresh_token"] == tokens["refresh_token"] {
		t.Fatalf("expected rotated refresh token, got %#v", refreshed)
	}
	reuse, err := http.PostForm(ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("refresh reuse: %v", err)
	}
	reuse.Body.Close()
	if reuse.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh reuse status=%d", reuse.StatusCode)
	}
}

func TestMCPRejectsUILoginTokenAndChallengesWithoutBearer(t *testing.T) {
	ts := newOAuthTestServer(t)
	user := seedLoginUser(t, uniqueLoginUsername("ui"), "secret", "default", "operator")
	login := loginForTest(t, `{"username":"`+user.Username+`","password":"secret"}`)
	claims := decodeLoginClaims(t, login)
	if _, exists := claims["aud"]; exists {
		t.Fatalf("UI login token must not set aud: %#v", claims)
	}
	uiToken := struct {
		Token string `json:"token"`
	}{}
	if err := json.Unmarshal(login.Body.Bytes(), &uiToken); err != nil {
		t.Fatalf("decode ui token: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+uiToken.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("UI token to MCP: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("UI token must not access /mcp, status=%d", resp.StatusCode)
	}

	challenge, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("unauthenticated MCP: %v", err)
	}
	auth := challenge.Header.Get("WWW-Authenticate")
	challenge.Body.Close()
	if challenge.StatusCode != http.StatusUnauthorized || !strings.Contains(auth, "resource_metadata=") || !strings.Contains(auth, "/.well-known/oauth-protected-resource/mcp") {
		t.Fatalf("missing MCP challenge: status=%d www=%s", challenge.StatusCode, auth)
	}

	apiReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/stats", nil)
	apiReq.Header.Set("Authorization", "Bearer "+uiToken.Token)
	apiResp, err := http.DefaultClient.Do(apiReq)
	if err != nil {
		t.Fatalf("UI token API: %v", err)
	}
	apiResp.Body.Close()
	if apiResp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("UI login token should still call /api/v1, status=%d", apiResp.StatusCode)
	}
}

func TestOAuthTokenRejectsWrongClientAndVerifier(t *testing.T) {
	ts := newOAuthTestServer(t)
	user := seedLoginUser(t, uniqueLoginUsername("oauth-bad"), "secret", "default", "operator")
	verifier := oauthTestVerifier(t)
	code := completeOAuthLogin(t, ts, user.Username, "secret", verifier)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"not-cursor"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:8787/callback"},
		"code_verifier": {verifier},
		"resource":      {ts.URL + "/mcp"},
	}
	resp, err := http.PostForm(ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("wrong client: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong client_id status=%d", resp.StatusCode)
	}
	badVerifier := exchangeOAuthCodeRaw(t, ts, code, "not-the-verifier-value-0123456789abcdef")
	badVerifier.Body.Close()
	if badVerifier.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong verifier status=%d", badVerifier.StatusCode)
	}
}

func TestOAuthTokenKeepsTenantIsolation(t *testing.T) {
	ts := newOAuthTestServer(t)
	userA := seedLoginUser(t, uniqueLoginUsername("oauth-a"), "secret", "tenant-a", "admin")
	userB := seedLoginUser(t, uniqueLoginUsername("oauth-b"), "secret", "tenant-b", "admin")
	verifierA := oauthTestVerifier(t)
	verifierB := oauthTestVerifier(t)
	codeA := completeOAuthLogin(t, ts, userA.Username, "secret", verifierA)
	codeB := completeOAuthLogin(t, ts, userB.Username, "secret", verifierB)
	stolen := exchangeOAuthCodeRaw(t, ts, codeB, verifierA)
	stolen.Body.Close()
	if stolen.StatusCode != http.StatusBadRequest {
		t.Fatalf("tenant A must not redeem tenant B code with A's verifier, status=%d", stolen.StatusCode)
	}
	tokensA := exchangeOAuthCode(t, ts, codeA, verifierA)
	tokensB := exchangeOAuthCode(t, ts, codeB, verifierB)
	if decodeOAuthAccessTenant(t, tokensA["access_token"].(string)) != "tenant-a" {
		t.Fatalf("token A tenant mismatch")
	}
	if decodeOAuthAccessTenant(t, tokensB["access_token"].(string)) != "tenant-b" {
		t.Fatalf("token B tenant mismatch")
	}
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+tokensA["access_token"].(string))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list users status=%d body=%s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), userB.Username) {
		t.Fatalf("tenant A token listed tenant B user")
	}
	if !strings.Contains(string(body), userA.Username) {
		t.Fatalf("tenant A token missing own user")
	}
}

func TestOAuthRegisterRejectsUnlistedRedirect(t *testing.T) {
	ts := newOAuthTestServer(t)
	resp, err := http.Post(ts.URL+"/oauth/register", "application/json", strings.NewReader(`{"redirect_uris":["https://evil.example/cb"],"token_endpoint_auth_method":"none"}`))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "invalid_redirect_uri") {
		t.Fatalf("expected invalid_redirect_uri, status=%d body=%s", resp.StatusCode, body)
	}
}

func TestMCPStreamableHTTPListsToolsWithOAuthToken(t *testing.T) {
	ts := newOAuthTestServer(t)
	user := seedLoginUser(t, uniqueLoginUsername("mcp"), "secret", "default", "admin")
	verifier := oauthTestVerifier(t)
	code := completeOAuthLogin(t, ts, user.Username, "secret", verifier)
	tokens := exchangeOAuthCode(t, ts, code, verifier)
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "argus-oauth-test", Version: "0.1.0"}, nil)
	session, err := client.Connect(context.Background(), &sdkmcp.StreamableClientTransport{
		Endpoint:             ts.URL + "/mcp",
		HTTPClient:           oauthHTTPClient(tokens["access_token"].(string)),
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("connect MCP: %v", err)
	}
	defer session.Close()
	if got := session.InitializeResult().ProtocolVersion; got != "2026-07-28" {
		t.Fatalf("protocol version = %q", got)
	}
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(result.Tools) != 7 {
		t.Fatalf("expected 7 tools, got %d", len(result.Tools))
	}
}

func oauthHTTPClient(token string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		req.Header.Set("Authorization", "Bearer "+token)
		return http.DefaultTransport.RoundTrip(req)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func oauthTestVerifier(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func decodeOAuthAccessTenant(t *testing.T, access string) string {
	t.Helper()
	token, err := jwt.Parse(access, func(token *jwt.Token) (interface{}, error) {
		return currentJWTSecret(), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || !token.Valid {
		t.Fatalf("parse access token: %v", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("unexpected claims type %T", token.Claims)
	}
	tenant, _ := claims["tenant_id"].(string)
	return tenant
}

func completeOAuthLogin(t *testing.T, ts *httptest.Server, username, password, verifier string) string {
	t.Helper()
	form := url.Values{
		"response_type":         {"code"},
		"client_id":             {"cursor"},
		"redirect_uri":          {"http://127.0.0.1:8787/callback"},
		"code_challenge":        {pkceS256(verifier)},
		"code_challenge_method": {"S256"},
		"resource":              {ts.URL + "/mcp"},
		"state":                 {"csrf-state"},
		"username":              {username},
		"password":              {password},
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.PostForm(ts.URL+"/oauth/authorize", form)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status=%d body=%s", resp.StatusCode, body)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if location.Query().Get("iss") != ts.URL || location.Query().Get("state") != "csrf-state" {
		t.Fatalf("missing iss/state: %s", location)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("missing code in %s", location)
	}
	return code
}

func exchangeOAuthCode(t *testing.T, ts *httptest.Server, code, verifier string) map[string]interface{} {
	t.Helper()
	resp := exchangeOAuthCodeRaw(t, ts, code, verifier)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token status=%d body=%s", resp.StatusCode, body)
	}
	var tokens map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	return tokens
}

func exchangeOAuthCodeRaw(t *testing.T, ts *httptest.Server, code, verifier string) *http.Response {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"cursor"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:8787/callback"},
		"code_verifier": {verifier},
		"resource":      {ts.URL + "/mcp"},
	}
	resp, err := http.PostForm(ts.URL+"/oauth/token", form)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	return resp
}
