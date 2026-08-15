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

	if len(routes) != 231 {
		t.Fatalf("API v1 route count = %d, want 231\n%s", len(routes), strings.Join(routes, "\n"))
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(routes, "\n")+"\n")))
	const expected = "9a8f8a9e29467e02235af5c14f61fb5d2b95a7c79fe6d9fb4bcbe18b56bccd0c"
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
