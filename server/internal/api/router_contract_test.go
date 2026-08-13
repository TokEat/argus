package api

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAPIV1RouteContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewRouter(RouterDependencies{})

	routes := make([]string, 0, len(router.Routes()))
	for _, route := range router.Routes() {
		if strings.HasPrefix(route.Path, "/api/v1/") {
			routes = append(routes, route.Method+" "+route.Path)
		}
	}
	sort.Strings(routes)

	if len(routes) != 249 {
		t.Fatalf("API v1 route count = %d, want 249\n%s", len(routes), strings.Join(routes, "\n"))
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(routes, "\n")+"\n")))
	const expected = "0dd868ae868e42b7a337f4ab5b011eb24f072a3c8ac233a012348108c533bcfe"
	if digest != expected {
		t.Fatalf("API v1 route contract hash = %s, want %s\n%s", digest, expected, strings.Join(routes, "\n"))
	}
}

func TestNewRouterKeepsTenantAndRBACMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/projects", nil)

	NewRouter(RouterDependencies{}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/v1/projects without credentials status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}
