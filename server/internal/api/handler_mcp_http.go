package api

import (
	"net/http"
	"strings"

	argusmcp "github.com/P0lar1ght/argus/mcp"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerMCPHTTP(r *gin.Engine) {
	handler := sdkmcp.NewStreamableHTTPHandler(func(req *http.Request) *sdkmcp.Server {
		token := bearerToken(req.Header.Get("Authorization"))
		return argusmcp.NewServer(publicAPIBase(), token)
	}, &sdkmcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	serve := func(c *gin.Context) {
		if !authenticateMCPRequest(c) {
			return
		}
		handler.ServeHTTP(c.Writer, c.Request)
	}
	r.Any("/mcp", serve)
	r.Any("/mcp/*path", serve)
}

func authenticateMCPRequest(c *gin.Context) bool {
	tokenString := bearerToken(c.GetHeader("Authorization"))
	if tokenString == "" {
		writeMCPUnauthorized(c)
		return false
	}
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrTokenUnverifiable
		}
		return currentJWTSecret(), nil
	})
	if err != nil || !token.Valid {
		writeMCPUnauthorized(c)
		return false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !tokenAllowsMCP(claims) {
		writeMCPUnauthorized(c)
		return false
	}
	applyJWTClaims(c, claims)
	return true
}

func writeMCPUnauthorized(c *gin.Context) {
	c.Header("WWW-Authenticate", mcpWWWAuthenticate())
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid MCP access token"})
}

func bearerToken(header string) string {
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}

func applyJWTClaims(c *gin.Context, claims jwt.MapClaims) {
	c.Set("tenant", claims["tenant_id"])
	if role, ok := claims["role"].(string); ok {
		c.Set("role", role)
	} else {
		c.Set("role", "admin")
	}
	if uid, ok := claims["user_id"].(string); ok {
		c.Set("user_id", uid)
	}
	if expAuthorized, ok := claims["exp_authorized"].(bool); ok {
		c.Set("exp_authorized", expAuthorized)
	} else {
		c.Set("exp_authorized", false)
	}
}
