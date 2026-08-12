package mcp

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

func AuthenticateHTTP(token string, next http.Handler) http.Handler {
	expected := []byte(strings.TrimSpace(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		provided := ""
		if strings.HasPrefix(header, "Bearer ") {
			provided = strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		}
		if len(expected) == 0 || subtle.ConstantTimeCompare([]byte(provided), expected) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
