package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCanaryRecordsFirstHitAndExpires(t *testing.T) {
	s := &store{ttl: 20 * time.Millisecond, hits: map[string]hit{}}
	token := "ARGUS_CANARY_1234567890"
	recordRequest := httptest.NewRequest(http.MethodGet, "/hit/"+token, nil).WithContext(t.Context())
	recordRequest.SetPathValue("token", token)
	record := httptest.NewRecorder()
	s.record(record, recordRequest)
	if record.Code != http.StatusOK {
		t.Fatalf("record status=%d body=%s", record.Code, record.Body.String())
	}

	statusRequest := httptest.NewRequest(http.MethodGet, "/status/"+token, nil)
	statusRequest.SetPathValue("token", token)
	status := httptest.NewRecorder()
	s.status(status, statusRequest)
	var value map[string]any
	if err := json.Unmarshal(status.Body.Bytes(), &value); err != nil || value["hit"] != true {
		t.Fatalf("status=%s err=%v", status.Body.String(), err)
	}
	time.Sleep(25 * time.Millisecond)
	status = httptest.NewRecorder()
	s.status(status, statusRequest)
	if err := json.Unmarshal(status.Body.Bytes(), &value); err != nil || value["hit"] != false {
		t.Fatalf("expired status=%s err=%v", status.Body.String(), err)
	}
}

func TestCanaryRejectsInvalidToken(t *testing.T) {
	s := &store{ttl: time.Minute, hits: map[string]hit{}}
	request := httptest.NewRequest(http.MethodGet, "/hit/short", nil)
	request.SetPathValue("token", "short")
	response := httptest.NewRecorder()
	s.record(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestCanaryRejectsNewTokensAtCapacity(t *testing.T) {
	s := &store{ttl: time.Minute, hits: make(map[string]hit, maxCanaryHits)}
	now := time.Now().UTC()
	for i := 0; i < maxCanaryHits; i++ {
		s.hits[fmt.Sprintf("ARGUS_CANARY_%04d", i)] = hit{At: now, ExpiresAt: now.Add(time.Minute)}
	}
	request := httptest.NewRequest(http.MethodGet, "/hit/ARGUS_CANARY_OVERFLOW", nil)
	request.SetPathValue("token", "ARGUS_CANARY_OVERFLOW")
	response := httptest.NewRecorder()
	s.record(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d", response.Code)
	}
}
