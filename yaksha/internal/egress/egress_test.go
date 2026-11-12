package egress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestValidateExactTargets(t *testing.T) {
	for _, value := range []string{"https://example.invalid:443", "tcp://10.0.0.8:22"} {
		if err := ValidateTargets([]string{value}); err != nil {
			t.Fatalf("%s: %v", value, err)
		}
	}
	for _, value := range []string{"https://example.invalid", "https://example.invalid:443/path", "ftp://example.invalid:21", "tcp://host:22?x=1"} {
		if err := ValidateTargets([]string{value}); err == nil {
			t.Fatalf("expected %s to fail", value)
		}
	}
}

func TestDuplicateTargetsRejected(t *testing.T) {
	if err := ValidateTargets([]string{"tcp://host.invalid:22", "tcp://host.invalid:22"}); err == nil {
		t.Fatal("expected duplicate target error")
	}
}

func TestHTTPRedirectRechecksExactTarget(t *testing.T) {
	var destinationHits atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		destinationHits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", destination.URL+"/final")
		w.WriteHeader(http.StatusFound)
	}))
	defer source.Close()

	client := NewDirectClient(nil, true)
	_, err := client.HTTPGet(context.Background(), source.URL+"/start", []string{source.URL})
	if err == nil || !strings.Contains(err.Error(), "redirect target is not authorized") || destinationHits.Load() != 0 {
		t.Fatalf("error=%v destination_hits=%d", err, destinationHits.Load())
	}
	result, err := client.HTTPGet(context.Background(), source.URL+"/start", []string{source.URL, destination.URL})
	if err != nil || result.StatusCode != http.StatusOK || result.Body != "ok" || destinationHits.Load() != 1 {
		t.Fatalf("result=%#v error=%v destination_hits=%d", result, err, destinationHits.Load())
	}
}
