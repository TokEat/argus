package output

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
)

func TestCollectRequestResponsePacketsPreservesAllDebugSteps(t *testing.T) {
	event := map[string]interface{}{
		"request":       "main request",
		"response":      "main response",
		"request_bad":   "ignored",
		"response_-1":   "ignored",
		"unrelated_100": "ignored",
	}
	const stepCount = 25
	for index := 0; index < stepCount; index++ {
		event[fmt.Sprintf("request_%d", index)] = fmt.Sprintf("request-step-%d", index)
		event[fmt.Sprintf("response_%d", index)] = fmt.Sprintf("response-step-%d", index)
	}

	packets := collectRequestResponsePackets(event)
	if len(packets) != stepCount {
		t.Fatalf("packet count = %d, want %d", len(packets), stepCount)
	}
	for index := 0; index < stepCount; index++ {
		pair := packets[index]
		if pair.Request != fmt.Sprintf("request-step-%d", index) || pair.Response != fmt.Sprintf("response-step-%d", index) {
			t.Fatalf("packet[%d] = %#v", index, pair)
		}
	}
}

func TestStandardWriterWriteFailurePreservesAllPacketStepsAndCURLCommand(t *testing.T) {
	previousCallback := AddResultCallback
	ResultsLock.Lock()
	previousResults := append([]ResultEvent(nil), Results...)
	Results = nil
	ResultsLock.Unlock()
	AddResultCallback = func(ResultEvent) {}
	t.Cleanup(func() {
		AddResultCallback = previousCallback
		ResultsLock.Lock()
		Results = previousResults
		ResultsLock.Unlock()
	})

	sink := &testWriteCloser{}
	writer, err := NewWriter(
		WithJson(true, true),
		WithMatcherStatus(true),
		WithWriter(sink),
	)
	if err != nil {
		t.Fatalf("create standard writer: %v", err)
	}
	t.Cleanup(writer.Close)

	internal := InternalEvent{
		"template-id":   "write-failure-packet-regression",
		"template-path": "write-failure-packet-regression.yaml",
		"template-info": model.Info{
			Name:           "WriteFailure packet regression",
			SeverityHolder: severity.Holder{Severity: severity.Info},
		},
		"host":         "https://scan.example.test/failure",
		"matched":      "https://scan.example.test/failure",
		"type":         "http",
		"request":      "main-failure-request",
		"response":     "main-failure-response",
		"curl-command": "curl --request GET https://scan.example.test/failure curl-failure-marker",
	}
	const stepCount = 25
	for index := 0; index < stepCount; index++ {
		internal[fmt.Sprintf("request_%d", index)] = fmt.Sprintf("failure-request-step-%d", index)
		internal[fmt.Sprintf("response_%d", index)] = fmt.Sprintf("failure-response-step-%d", index)
	}

	if err := writer.WriteFailure(&InternalWrappedEvent{InternalEvent: internal}); err != nil {
		t.Fatalf("write failure event: %v", err)
	}
	var result ResultEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(sink.String())), &result); err != nil {
		t.Fatalf("decode WriteFailure JSON: %v\noutput: %s", err, sink.String())
	}
	if result.CURLCommand != internal["curl-command"] {
		t.Errorf("CURL command = %q, want %q", result.CURLCommand, internal["curl-command"])
	}
	if len(result.Packet) != stepCount {
		t.Fatalf("WriteFailure packet count = %d, want %d", len(result.Packet), stepCount)
	}
	for index := 0; index < stepCount; index++ {
		pair, ok := result.Packet[index]
		if !ok {
			t.Errorf("WriteFailure packet is missing step %d", index)
			continue
		}
		if want := fmt.Sprintf("failure-request-step-%d", index); pair.Request != want {
			t.Errorf("packet[%d].Request = %q, want %q", index, pair.Request, want)
		}
		if want := fmt.Sprintf("failure-response-step-%d", index); pair.Response != want {
			t.Errorf("packet[%d].Response = %q, want %q", index, pair.Response, want)
		}
	}
}
