package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,80}$`)

const maxCanaryHits = 1024

type hit struct {
	At        time.Time `json:"at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type store struct {
	mu   sync.Mutex
	ttl  time.Duration
	hits map[string]hit
}

func main() {
	ttl := 5 * time.Minute
	if raw := strings.TrimSpace(os.Getenv("ARGUS_EXP_CANARY_TTL")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed < time.Second || parsed > time.Hour {
			log.Fatal("ARGUS_EXP_CANARY_TTL must be between 1s and 1h")
		}
		ttl = parsed
	}
	s := &store{ttl: ttl, hits: map[string]hit{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("GET /hit/{token}", s.record)
	mux.HandleFunc("GET /status/{token}", s.status)
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second}
	log.Printf("Argus EXP lab Canary listening on :8080 (ttl=%s)", ttl)
	log.Fatal(server.ListenAndServe())
}

func (s *store) record(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !tokenPattern.MatchString(token) {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.cleanup(now)
	value, exists := s.hits[token]
	if !exists && len(s.hits) >= maxCanaryHits {
		s.mu.Unlock()
		http.Error(w, "canary capacity exceeded", http.StatusTooManyRequests)
		return
	}
	if !exists {
		value = hit{At: now, ExpiresAt: now.Add(s.ttl)}
		s.hits[token] = value
	}
	s.mu.Unlock()
	writeJSON(w, map[string]any{"accepted": true, "first_hit": !exists, "at": value.At, "expires_at": value.ExpiresAt})
}

func (s *store) status(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !tokenPattern.MatchString(token) {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	s.cleanup(now)
	value, exists := s.hits[token]
	s.mu.Unlock()
	response := map[string]any{"hit": exists}
	if exists {
		response["at"] = value.At
		response["expires_at"] = value.ExpiresAt
	}
	writeJSON(w, response)
}

func (s *store) cleanup(now time.Time) {
	for token, value := range s.hits {
		if !now.Before(value.ExpiresAt) {
			delete(s.hits, token)
		}
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
